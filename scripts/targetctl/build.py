"""Pinned native build operation for targetctl.

Only stable identities and a digest of producer-redacted build output leave this
module.  Private source roots, target roots, and command output remain local.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import secrets
import stat
import tempfile
import subprocess
import time
from typing import Any, Mapping

from .common import TargetError, record_id_for, write_json_atomic
from .lifecycle import local_operation_lock
from .redaction import (
    REMOTE_REDACTION_EXTENSION,
    StreamingRedactor,
    redaction_canaries,
)
from .source import (
    SourceSnapshot,
    _SOURCE_EXTENSION,
    _expect_root_identities,
    _load_capabilities,
    _remote_payload,
    verify_applied_tree,
)
from .remote import _valid_run_state
from .transport import CommandResult, LocalTransport, SSHTransport

MAKE = "/usr/bin/make"
CUOBJDUMP = "/usr/local/cuda/bin/cuobjdump"
MAX_BUILD_OUTPUT_BYTES = 1_048_576
BUILD_TIMEOUT_SECONDS = 3_600.0
BUILD_LOCK_LEASE_SECONDS = 7_200
BUILD_RECONCILE_LEASE_SECONDS = 3_600
BUILD_RECONCILE_TIMEOUT_SECONDS = 3_300.0
_DS4_VERSION_OUTPUT = re.compile(rb"\Ads4-server v([0-9]+(?:\.[0-9]+)*)\n?\Z")
_LIST_ELF_ARCH = re.compile(rb"(?<![A-Za-z0-9_])sm_121a(?![A-Za-z0-9_])")
_SASS_HEADER = re.compile(rb"[ \t]*code for sm_121a[ \t]*\Z")
_SASS_ANY_HEADER = re.compile(rb"[ \t]*code for[ \t]+.*\Z")
_SASS_FUNCTION = re.compile(rb"[ \t]*Function[ \t]+:[ \t]+\S.*\Z")
_SASS_INSTRUCTION = re.compile(rb"[ \t]*/\*[0-9A-Fa-f]{4,16}\*/[ \t]+\S.*\Z")
_LIST_ELF_LIMIT_BYTES = 65_536
_SASS_SCAN_LIMIT_BYTES = 268_435_456
_SASS_STDERR_LIMIT_BYTES = 16_384
_SASS_WINDOW_BYTES = 8_192
_SASS_TIMEOUT_SECONDS = 30.0
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_LOCAL_BUILD_OUTPUTS = {
    ".": (
        ".ds4-cuda-config.mk",
        "ds4",
        "ds4-server",
        "ds4-bench",
        "ds4-eval",
        "ds4-agent",
        "ds4_weight_server",
        "ds4_cli.o",
        "linenoise.o",
        "ds4.o",
        "ds4_distributed.o",
        "ds4_cuda.o",
        "ds4_server.o",
        "ds4_kvstore.o",
        "rax.o",
        "ds4_bench.o",
        "ds4_eval.o",
        "ds4_agent.o",
        "ds4_web.o",
        "ds4_test",
        "ds4_test.o",
    ),
    "cuda/mmq": (
        "ds4_ggml_stubs.o",
        "ds4_mmq.o",
        "ds4_mmq_d2r.o",
        "quantize.o",
        "mmid.o",
        "mmvq.o",
        "ds4_repack.o",
    ),
    "tests": (
        "cuda_long_context_smoke",
        "cuda_long_context_smoke.o",
    ),
}


_REMOTE_RESULT_FIELDS = frozenset({
    "status", "failure_class", "source_snapshot_id", "source_applied_tree_hash",
    "build_id", "binary_sha256", "command", "version", "binary_size", "sass",
    "build_log_sha256", "exit_code", "duration_ns",
})
_REMOTE_FAILURE_CLASSES = frozenset({"timeout", "command_failed", "contract_failed"})
_VERSION_TEXT = re.compile(r"[0-9]+(?:\.[0-9]+)*\Z")
_REMOTE_REPORT_FIELDS = _REMOTE_RESULT_FIELDS | frozenset({
    "schema_version", "record_type", "attempt_id",
})
_REMOTE_RECONCILE_FIELDS = frozenset({
    "report", "report_sha256", "build_log_sha256", "lease_state",
})
_TARGET_BUILD_REFUSAL_CODES = frozenset({
    "build_dirty_unacknowledged", "source_lifecycle", "unexpected_entry",
    "entry_changed", "unsafe_mount", "unsafe_entry", "missing_path",
    "path_overlap",
})


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class BuildResult:
    status: str
    failure_class: str | None
    source_snapshot_id: str | None
    source_applied_tree_hash: str | None
    build_id: str | None
    binary_sha256: str | None
    command: str | None
    version: str | None
    binary_size: int | None
    sass: str | None
    build_log_sha256: str | None
    exit_code: int | None
    duration_ns: int | None

    def controller_payload(self) -> dict[str, Any]:
        return {
            "status": self.status, "failure_class": self.failure_class,
            "source_snapshot_id": self.source_snapshot_id,
            "source_applied_tree_hash": self.source_applied_tree_hash,
            "build_id": self.build_id, "binary_sha256": self.binary_sha256,
            "command": self.command, "version": self.version,
            "binary_size": self.binary_size, "sass": self.sass,
            "build_log_sha256": self.build_log_sha256,
            "exit_code": self.exit_code, "duration_ns": self.duration_ns,
        }

    to_payload = controller_payload
    as_dict = controller_payload


def _error(code: str, message: str = "target build failed") -> TargetError:
    return TargetError(code, message)


def _failure_class(code: str) -> str:
    if code in {"build_lock_busy"}:
        return "unavailable"
    if code in {"build_timeout"}:
        return "timeout"
    if code in {"build_command_failed", "build_output_oversize"}:
        return "command_failed"
    if code in {"build_source_mismatch", "build_dirty_unacknowledged", "build_running", "build_binary_invalid", "build_sass_invalid"}:
        return "contract_failed"
    return "preflight"


def _failed(code: str, snapshot: SourceSnapshot | None = None) -> BuildResult:
    return BuildResult("failed", _failure_class(code), None if snapshot is None else snapshot.snapshot_id, None if snapshot is None else snapshot.applied_tree_hash, None, None, None, None, None, None, None, None, None)


def _sha256_regular(path: Path, *, executable: bool = False) -> tuple[str, int]:
    try:
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or before.st_size < 1 or (executable and not before.st_mode & stat.S_IXUSR):
            raise OSError
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise _error("build_binary_invalid") from None
    try:
        pinned = os.fstat(fd)
        if (pinned.st_dev, pinned.st_ino, pinned.st_mode, pinned.st_uid, pinned.st_nlink, pinned.st_size) != (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink, before.st_size):
            raise _error("build_binary_invalid")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_nlink, after.st_size) != (pinned.st_dev, pinned.st_ino, pinned.st_mode, pinned.st_uid, pinned.st_nlink, pinned.st_size):
            raise _error("build_binary_invalid")
        return digest.hexdigest(), after.st_size
    finally:
        os.close(fd)

def _open_owned_directory(name: str, parent_fd: int) -> int:
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        item = os.fstat(fd)
    except OSError:
        raise _error("build_source_mismatch") from None
    if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.geteuid():
        os.close(fd)
        raise _error("build_source_mismatch")
    return fd


def _prepare_local_build_outputs(root: Path) -> None:
    """Unlink every fixed build or qualification output without following aliases."""

    try:
        root_fd = os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        raise _error("build_source_mismatch") from None
    engine_fd = ds4_fd = -1
    try:
        engine_fd = _open_owned_directory("engine", root_fd)
        ds4_fd = _open_owned_directory("ds4", engine_fd)
        for parent, names in _LOCAL_BUILD_OUTPUTS.items():
            parent_fd = os.dup(ds4_fd)
            try:
                if parent != ".":
                    for component in parent.split("/"):
                        next_fd = _open_owned_directory(component, parent_fd)
                        os.close(parent_fd)
                        parent_fd = next_fd
                changed = False
                for name in names:
                    try:
                        item = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    except OSError:
                        raise _error("build_source_mismatch") from None
                    if stat.S_ISDIR(item.st_mode):
                        raise _error("build_source_mismatch")
                    try:
                        os.unlink(name, dir_fd=parent_fd)
                    except OSError:
                        raise _error("build_source_mismatch") from None
                    changed = True
                if changed:
                    os.fsync(parent_fd)
            except OSError:
                raise _error("build_source_mismatch") from None
            finally:
                os.close(parent_fd)
    finally:
        if ds4_fd >= 0:
            os.close(ds4_fd)
        if engine_fd >= 0:
            os.close(engine_fd)
        os.close(root_fd)



def _safe_run_dir(path: Path) -> None:
    try:
        item = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        item = os.stat(path, follow_symlinks=False)
    except OSError:
        raise _error("build_run_dir_invalid") from None
    if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o700:
        raise _error("build_run_dir_invalid")




def _read_lifecycle(run_dir: Path) -> None:
    state_path = run_dir / "run.json"
    try:
        item = os.stat(state_path, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise _error("build_lifecycle_invalid") from None
    if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o600 or item.st_size > 65536:
        raise _error("build_lifecycle_invalid")
    try:
        import json
        with open(state_path, "rb") as handle:
            data = json.loads(handle.read(65537).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        raise _error("build_lifecycle_invalid") from None
    if not _valid_run_state(data, terminal=True) or not data["cleanup_complete"]:
        raise _error("build_running")




def _redacted_log(result: CommandResult, secrets: tuple[str, ...]) -> bytes:
    """Retain bounded producer output under the shared streaming policy."""

    redactor = StreamingRedactor(secrets, max_output=MAX_BUILD_OUTPUT_BYTES)
    return (redactor.feed(result.stdout) + redactor.feed(result.stderr) + redactor.finalize()).encode("utf-8")


def _atomic_bytes(path: Path, value: bytes) -> None:
    parent = path.parent
    _safe_run_dir(parent)
    fd = -1
    name = ""
    try:
        fd, name = tempfile.mkstemp(prefix=".targetctl-", dir=parent)
        os.fchmod(fd, 0o600)
        view = memoryview(value)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(parent / name, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        raise _error("build_state_write_failed") from None
    finally:
        if fd >= 0:
            os.close(fd)
        if name:
            try:
                os.unlink(parent / name)
            except FileNotFoundError:
                pass



def _remove_local_active_build(run_dir: Path) -> None:
    """Invalidate any prior active build after a post-build source mismatch."""

    try:
        os.unlink(run_dir / "build.json")
    except FileNotFoundError:
        return
    except OSError:
        raise _error("build_state_write_failed") from None
    try:
        directory_fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        raise _error("build_state_write_failed") from None

def _parse_ds4_version(value: bytes) -> str | None:
    match = _DS4_VERSION_OUTPUT.fullmatch(value)
    if match is None or len(match.group(1)) > 64:
        return None
    try:
        return match.group(1).decode("ascii")
    except UnicodeDecodeError:
        return None


def _version(transport: LocalTransport, binary: Path) -> str:
    result = transport.run((str(binary), "--version"), timeout=10.0, cwd="/", env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    version = None
    if not result.timed_out and result.exit_code == 0 and not result.stderr and len(result.stdout) <= 16 * 1024:
        version = _parse_ds4_version(result.stdout)
    if version is None:
        raise _error("build_binary_invalid")
    return version


def _sass_line(state: list[int | bool], line: bytes) -> None:
    if line.endswith(b"\r"):
        line = line[:-1]
    stage = int(state[0])
    header = _SASS_HEADER.fullmatch(line) is not None
    any_header = _SASS_ANY_HEADER.fullmatch(line) is not None
    if stage == 0:
        if header:
            state[0] = 1
        elif any_header:
            state[1] = True
        return
    if stage == 1:
        if header:
            return
        if _SASS_FUNCTION.fullmatch(line) is not None:
            state[0] = 2
        elif _SASS_INSTRUCTION.fullmatch(line) is not None or any_header:
            state[1] = True
        return
    if stage == 2:
        if _SASS_INSTRUCTION.fullmatch(line) is not None:
            state[0] = 3
        elif _SASS_FUNCTION.fullmatch(line) is not None or any_header:
            state[1] = True


def _kill_group(process_group: int | None) -> bool:
    if not isinstance(process_group, int) or process_group <= 1:
        return False
    try:
        os.killpg(process_group, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return True
    except OSError:
        return False


def _group_gone(process_group: int | None) -> bool:
    if not isinstance(process_group, int) or process_group <= 1:
        return False
    deadline = time.monotonic() + 1.0
    while True:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _stream_sass(
    args: tuple[str, ...],
    *,
    timeout: float = _SASS_TIMEOUT_SECONDS,
    scan_limit: int = _SASS_SCAN_LIMIT_BYTES,
    stderr_limit: int = _SASS_STDERR_LIMIT_BYTES,
    pass_fds: tuple[int, ...] = (),
) -> bool:
    """Prove the first sm_121a instruction without retaining cuobjdump output."""

    process: subprocess.Popen[bytes] | None = None
    process_group: int | None = None
    wait_attempted = False
    cleanup_ok = True
    interrupted = [False]
    old_handlers: dict[int, Any] = {}
    old_mask: set[signal.Signals] | None = None
    blocked = False
    state: list[int | bool] = [0, False]
    pending = bytearray()
    scanned = 0
    stderr_seen = 0

    def interrupted_handler(_signum: int, _frame: Any) -> None:
        interrupted[0] = True
        if process_group is not None:
            _kill_group(process_group)

    try:
        watched = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
        for signum in watched:
            old_handlers[signum] = signal.signal(signum, interrupted_handler)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
        blocked = True
        try:
            process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/",
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                start_new_session=True,
                pass_fds=pass_fds,
            )
        except OSError:
            return False
        process_group = process.pid
        if process_group <= 1:
            raise _error("build_process_unknown")
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        blocked = False
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            assert process.stdout is not None and process.stderr is not None
            for stream, is_stdout in ((process.stdout, True), (process.stderr, False)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, is_stdout)
            finished = False
            while selector.get_map() or process.poll() is None:
                if interrupted[0] or bool(state[1]) or scanned > scan_limit or stderr_seen > stderr_limit:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                for key, _ in selector.select(min(0.1, remaining)):
                    stream_room = (
                        _SASS_WINDOW_BYTES - len(pending)
                        if key.data
                        else stderr_limit - stderr_seen
                    )
                    try:
                        chunk = os.read(
                            key.fileobj.fileno(),
                            min(
                                4096,
                                max(1, scan_limit - scanned + 1),
                                max(1, stream_room + 1),
                            ),
                        )
                    except BlockingIOError:
                        continue
                    except OSError:
                        state[1] = True
                        break
                    if not chunk:
                        try:
                            selector.unregister(key.fileobj)
                        except (KeyError, OSError, ValueError):
                            pass
                        key.fileobj.close()
                        continue
                    scanned += len(chunk)
                    if key.data:
                        pending.extend(chunk)
                        while True:
                            newline = pending.find(b"\n")
                            if newline < 0:
                                break
                            _sass_line(state, bytes(pending[:newline]))
                            del pending[:newline + 1]
                            if int(state[0]) == 3 or bool(state[1]):
                                break
                        if len(pending) > _SASS_WINDOW_BYTES:
                            state[1] = True
                    else:
                        stderr_seen += len(chunk)
                    if int(state[0]) == 3 or bool(state[1]) or scanned > scan_limit or stderr_seen > stderr_limit:
                        break
                if int(state[0]) == 3:
                    finished = True
                    break
            if not finished and pending and process.poll() is not None:
                _sass_line(state, bytes(pending))
                finished = int(state[0]) == 3 and not bool(state[1])
            for key in tuple(selector.get_map().values()):
                try:
                    selector.unregister(key.fileobj)
                except (KeyError, OSError, ValueError):
                    pass
                try:
                    key.fileobj.close()
                except OSError:
                    pass
        cleanup_ok = _kill_group(process_group) and cleanup_ok
        wait_attempted = True
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            cleanup_ok = False
        cleanup_ok = _group_gone(process_group) and cleanup_ok
        if not cleanup_ok:
            raise _error("build_process_unknown")
        return (
            finished
            and not interrupted[0]
            and not bool(state[1])
            and scanned <= scan_limit
            and stderr_seen <= stderr_limit
        )
    finally:
        if process is not None and not wait_attempted:
            cleanup_ok = _kill_group(process_group) and cleanup_ok
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except OSError:
                        pass
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                cleanup_ok = False
            cleanup_ok = _group_gone(process_group) and cleanup_ok
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        if blocked and old_mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        if not cleanup_ok:
            raise _error("build_process_unknown")


def _sass(transport: LocalTransport, binary: Path) -> None:
    result = transport.run((CUOBJDUMP, "--list-elf", str(binary)), timeout=10.0, cwd="/", env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    if (
        result.timed_out
        or result.exit_code != 0
        or len(result.stdout) + len(result.stderr) > _LIST_ELF_LIMIT_BYTES
        or _LIST_ELF_ARCH.search(result.stdout) is None
        or not _stream_sass((CUOBJDUMP, "--dump-sass", str(binary)))
    ):
        raise _error("build_sass_invalid")


def _jobs(value: int | None) -> int:
    if value is None:
        value = os.cpu_count() or 1
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 256:
        raise _error("build_jobs_invalid")
    return value


def _validate_snapshot(snapshot: Any, allow_dirty: str | None, root: Path) -> SourceSnapshot:
    if not isinstance(snapshot, SourceSnapshot) or not _HEX.fullmatch(snapshot.snapshot_id) or not _HEX.fullmatch(snapshot.applied_tree_hash):
        raise _error("build_source_mismatch")
    if snapshot.dirty and allow_dirty != snapshot.snapshot_id:
        raise _error("build_dirty_unacknowledged")
    if not snapshot.dirty and allow_dirty is not None:
        raise _error("build_dirty_unacknowledged")
    try:
        applied = verify_applied_tree(root, snapshot)
    except TargetError:
        raise _error("build_source_mismatch") from None
    if applied != snapshot.applied_tree_hash:
        raise _error("build_source_mismatch")
    return snapshot


def _build_id(snapshot: SourceSnapshot, binary_hash: str, version: str, size: int) -> str:
    return record_id_for({"schema_version": 1, "source_snapshot_id": snapshot.snapshot_id, "source_applied_tree_hash": snapshot.applied_tree_hash, "binary_sha256": binary_hash, "version": version, "binary_size": size, "sass": "sm_121a"})


def _build_local(config: Any, transport: LocalTransport, snapshot: SourceSnapshot, *, jobs: int) -> BuildResult:
    root = Path(config.source_root)
    run_dir = Path(config.local_run_dir)
    with local_operation_lock(str(run_dir)):
        _read_lifecycle(run_dir)
        # Recheck while serialized; source may have changed after the caller's
        # initial snapshot/dirty decision.
        try:
            verify_applied_tree(root, snapshot)
        except TargetError:
            raise _error("build_source_mismatch") from None
        _prepare_local_build_outputs(root)
        try:
            verify_applied_tree(root, snapshot)
        except TargetError:
            raise _error("build_source_mismatch") from None
        result = transport.run((MAKE, "-C", "engine/ds4", "cuda-spark", f"-j{jobs}"), timeout=BUILD_TIMEOUT_SECONDS, cwd=str(root), env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
        private_paths = tuple(
            value
            for value in (
                getattr(config, "model_path", None),
                getattr(config, "drafter_path", None),
            )
            if isinstance(value, str)
        )
        secrets = redaction_canaries(private_paths, additional=(str(root), str(run_dir)))
        log = _redacted_log(result, secrets)
        _atomic_bytes(run_dir / "build.log", log)
        log_hash = hashlib.sha256(log).hexdigest()
        exit_code = result.exit_code if not result.timed_out and result.exit_code >= 0 else None
        attempted = dict(
            source_snapshot_id=snapshot.snapshot_id,
            source_applied_tree_hash=snapshot.applied_tree_hash,
            command="make-cuda-spark",
            build_log_sha256=log_hash,
            exit_code=exit_code,
            duration_ns=max(1, result.duration_ns),
        )
        if result.timed_out:
            return BuildResult("failed", "timeout", build_id=None, binary_sha256=None, **attempted, version=None, binary_size=None, sass=None)
        if result.exit_code != 0:
            return BuildResult("failed", "command_failed", build_id=None, binary_sha256=None, **attempted, version=None, binary_size=None, sass=None)
        try:
            binary = root / "engine" / "ds4" / "ds4-server"
            binary_hash, size = _sha256_regular(binary, executable=True)
            version = _version(transport, binary)
            _sass(transport, binary)
            build_id = _build_id(snapshot, binary_hash, version, size)
            try:
                applied = verify_applied_tree(root, snapshot)
            except TargetError:
                raise _error("build_source_mismatch") from None
            if applied != snapshot.applied_tree_hash:
                raise _error("build_source_mismatch")
            state = {"schema_version": 1, "record_type": "build", "source_snapshot_id": snapshot.snapshot_id, "source_applied_tree_hash": snapshot.applied_tree_hash, "build_id": build_id, "binary_sha256": binary_hash, "binary_size": size, "version": version, "sass": "verified", "build_log_sha256": log_hash, "exit_code": exit_code, "duration_ns": max(1, result.duration_ns)}
            write_json_atomic(run_dir / "build.json", state, mode=0o600)
        except TargetError as exc:
            if exc.code == "build_process_unknown":
                raise
            if exc.code == "build_source_mismatch":
                _remove_local_active_build(run_dir)
            return BuildResult("failed", _failure_class(exc.code), build_id=None, binary_sha256=None, **attempted, version=None, binary_size=None, sass=None)
        return BuildResult("succeeded", None, snapshot.snapshot_id, snapshot.applied_tree_hash, build_id, binary_hash, "make-cuda-spark", version, size, "verified", log_hash, exit_code, max(1, result.duration_ns))


def _remote_result(result: Any, snapshot: SourceSnapshot) -> BuildResult:
    """Accept only the fixed, identity-bound target_build response schema."""
    if (
        type(result) is not dict
        or set(result) != _REMOTE_RESULT_FIELDS
        or result["source_snapshot_id"] != snapshot.snapshot_id
        or result["source_applied_tree_hash"] != snapshot.applied_tree_hash
        or result["command"] != "make-cuda-spark"
        or not _digest(result["build_log_sha256"])
        or not isinstance(result["duration_ns"], int)
        or isinstance(result["duration_ns"], bool)
        or not 1 <= result["duration_ns"] <= int((BUILD_TIMEOUT_SECONDS + 30.0) * 1_000_000_000)
    ):
        raise _error("build_command_failed")
    status = result["status"]
    if status == "succeeded":
        if (
            result["failure_class"] is not None
            or not _digest(result["build_id"])
            or not _digest(result["binary_sha256"])
            or not isinstance(result["version"], str)
            or not 1 <= len(result["version"]) <= 64
            or _VERSION_TEXT.fullmatch(result["version"]) is None
            or not isinstance(result["binary_size"], int)
            or isinstance(result["binary_size"], bool)
            or not 1 <= result["binary_size"] <= (1 << 63) - 1
            or result["sass"] != "verified"
            or not isinstance(result["exit_code"], int)
            or isinstance(result["exit_code"], bool)
            or result["exit_code"] != 0
            or result["build_id"] != _build_id(snapshot, result["binary_sha256"], result["version"], result["binary_size"])
        ):
            raise _error("build_command_failed")
    elif status == "failed":
        exit_code = result["exit_code"]
        if (
            result["failure_class"] not in _REMOTE_FAILURE_CLASSES
            or any(result[key] is not None for key in ("build_id", "binary_sha256", "version", "binary_size", "sass"))
            or not (
                exit_code is None
                or (
                    isinstance(exit_code, int)
                    and not isinstance(exit_code, bool)
                    and 0 <= exit_code <= 255
                    and (exit_code > 0 or result["failure_class"] == "contract_failed")
                )
            )
        ):
            raise _error("build_command_failed")
    else:
        raise _error("build_command_failed")
    return BuildResult(
        status, result["failure_class"], snapshot.snapshot_id, snapshot.applied_tree_hash,
        result["build_id"], result["binary_sha256"], "make-cuda-spark", result["version"],
        result["binary_size"], result["sass"], result["build_log_sha256"],
        result["exit_code"], result["duration_ns"],
    )
def _remote_reconciled_result(result: Any, snapshot: SourceSnapshot, attempt_id: str) -> BuildResult:
    """Validate a target-side, attempt-bound durable report response."""
    if type(result) is not dict or set(result) != _REMOTE_RECONCILE_FIELDS:
        raise _error("build_reconciliation_failed")
    report = result["report"]
    if (
        type(report) is not dict
        or set(report) != _REMOTE_REPORT_FIELDS
        or report["schema_version"] != 1
        or report["record_type"] != "build-attempt"
        or report["attempt_id"] != attempt_id
        or not _digest(result["report_sha256"])
        or not _digest(result["build_log_sha256"])
        or result["lease_state"] not in {"released", "retained"}
    ):
        raise _error("build_reconciliation_failed")
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if (
        hashlib.sha256(encoded).hexdigest() != result["report_sha256"]
        or report["build_log_sha256"] != result["build_log_sha256"]
    ):
        raise _error("build_reconciliation_failed")
    payload = {key: report[key] for key in _REMOTE_RESULT_FIELDS}
    try:
        return _remote_result(payload, snapshot)
    except TargetError:
        raise _error("build_reconciliation_failed") from None


def _remote_build_payload(
    source_payload: Mapping[str, Any],
    snapshot: SourceSnapshot,
    allow_dirty: str | None,
    jobs: int,
    lock_token: str,
    attempt_id: str,
) -> dict[str, Any]:
    return {
        **source_payload,
        "snapshot_id": snapshot.snapshot_id,
        "applied_tree_hash": snapshot.applied_tree_hash,
        "dirty": snapshot.dirty,
        "allow_dirty": allow_dirty,
        "jobs": jobs,
        "lock_token": lock_token,
        "attempt_id": attempt_id,
    }


def _reconcile_remote_build(
    transport: SSHTransport,
    payload: Mapping[str, Any],
    snapshot: SourceSnapshot,
    attempt_id: str,
) -> BuildResult:
    try:
        reconciled = transport.run_helper(
            "target_build_reconcile",
            payload,
            extension_source=_SOURCE_EXTENSION + REMOTE_REDACTION_EXTENSION + REMOTE_BUILD_EXTENSION,
            allowed_error_codes={
                "build_reconcile_invalid", "build_reconcile_unavailable",
                "lock_busy", "lock_failed", "lock_release_failed",
                "unsafe_lock", "marker_mismatch", "unsafe_root", "unsafe_state",
                "unexpected_entry", "entry_changed", "unsafe_entry", "missing_path",
                "path_overlap",
            },
            timeout=BUILD_RECONCILE_TIMEOUT_SECONDS,
        )
    except TargetError as error:
        if error.code in {
            "build_reconcile_invalid", "build_reconcile_unavailable",
            "entry_changed", "unexpected_entry", "unsafe_entry", "missing_path",
        }:
            raise _error("build_reconciliation_failed") from None
        raise
    return _remote_reconciled_result(reconciled, snapshot, attempt_id)




def build(config: Any, transport: LocalTransport | SSHTransport, *, snapshot: SourceSnapshot, allow_dirty: str | None = None, jobs: int | None = None) -> BuildResult:
    """Build a previously synchronized snapshot with exact dirty acknowledgement."""
    checked: SourceSnapshot | None = snapshot if isinstance(snapshot, SourceSnapshot) else None
    try:
        config.validate_for("build")
        count = _jobs(jobs)
        root = Path(config.source_root)
        checked = _validate_snapshot(snapshot, allow_dirty, root)
        if getattr(config, "mode", None) == "local":
            if not isinstance(transport, LocalTransport):
                raise _error("transport_invalid")
            return _build_local(config, transport, checked, jobs=count)
        if getattr(config, "mode", None) != "ssh" or not isinstance(transport, SSHTransport):
            raise _error("transport_invalid")
        state = _load_capabilities(root, config.name)
        if state is None:
            raise _error("build_source_mismatch")
        source_payload = _remote_payload(config, state, checked.entries)
        verified = transport.run_helper(
            "source_verify", source_payload, extension_source=_SOURCE_EXTENSION,
            allowed_error_codes={"source_lifecycle", "unexpected_entry", "unsafe_mount", "entry_changed", "marker_mismatch", "unsafe_entry", "unsafe_root", "unsafe_state", "missing_path", "path_overlap"},
        )
        _expect_root_identities(verified, state)
        if not isinstance(verified, Mapping) or verified.get("sha256") != checked.applied_tree_hash or verified.get("entry_count") != len(checked.entries):
            raise _error("build_source_mismatch")
        attempt_id = secrets.token_hex(32)
        lock = transport.run_helper("acquire_lock", {"run_dir": config.run_dir, "run_token": state["run_token"], "lease_seconds": BUILD_LOCK_LEASE_SECONDS}, allowed_error_codes={"lock_busy", "lock_failed", "unsafe_lock", "invalid_lease", "marker_mismatch", "unsafe_root"})
        if (
            not isinstance(lock, Mapping)
            or set(lock) != {"lock_token", "reclaimed", "stale_receiver_pairs_cleaned", "stale_lock_stages_cleaned"}
            or not _digest(lock.get("lock_token"))
        ):
            raise _error("build_lock_failed")
        target_payload = _remote_build_payload(
            source_payload, checked, allow_dirty, count, lock["lock_token"], attempt_id,
        )
        try:
            result = transport.run_helper(
                "target_build",
                target_payload,
                extension_source=_SOURCE_EXTENSION + REMOTE_REDACTION_EXTENSION + REMOTE_BUILD_EXTENSION,
                allowed_error_codes={
                    "source_lifecycle", "unexpected_entry", "unsafe_mount",
                    "build_dirty_unacknowledged", "build_command_failed",
                    "build_binary_invalid", "build_sass_invalid",
                    "build_state_write_failed", "build_process_unknown",
                },
                timeout=BUILD_TIMEOUT_SECONDS + 30.0,
            )
            return _remote_result(result, checked)
        except BaseException as dispatch_error:
            if (
                isinstance(dispatch_error, TargetError)
                and dispatch_error.code in _TARGET_BUILD_REFUSAL_CODES
            ):
                raise
            try:
                return _reconcile_remote_build(
                    transport, target_payload, checked, attempt_id,
                )
            except BaseException as reconciliation_error:
                if not isinstance(dispatch_error, TargetError):
                    raise dispatch_error
                if (
                    isinstance(reconciliation_error, TargetError)
                    and reconciliation_error.code == "build_reconciliation_failed"
                ):
                    raise
                raise _error(
                    "build_reconciliation_required",
                    "target build completion remains ambiguous",
                ) from None
    except TargetError as exc:
        if exc.code in {"build_reconciliation_failed", "build_reconciliation_required"}:
            raise
        return _failed(exc.code, checked)


run_build = build
build_target = build



REMOTE_BUILD_EXTENSION = r'''
import hashlib as _build_hashlib, json as _build_json, os as _build_os, re as _build_re, selectors as _build_selectors, signal as _build_signal, stat as _build_stat, subprocess as _build_subprocess, secrets as _build_secrets, time as _build_time
_BUILD_RESULT_KEYS={'status','failure_class','source_snapshot_id','source_applied_tree_hash','build_id','binary_sha256','command','version','binary_size','sass','build_log_sha256','exit_code','duration_ns'}
_BUILD_REPORT_KEYS=_BUILD_RESULT_KEYS|{'schema_version','record_type','attempt_id'}
_BUILD_ACTIVE_KEYS={'schema_version','record_type','source_snapshot_id','source_applied_tree_hash','build_id','binary_sha256','binary_size','version','sass','build_log_sha256','exit_code','duration_ns'}
_BUILD_COMMIT_KEYS={'schema_version','record_type','attempt_id','attempt_report_sha256','attempt_log_sha256'}
_BUILD_RECONCILE_LEASE_SECONDS=3600
def _build_hex(value):
    return isinstance(value,str) and len(value)==64 and all(character in '0123456789abcdef' for character in value)
def _build_attempt_names(attempt_id):
    if not _build_hex(attempt_id): _fail('build_reconcile_invalid')
    stem='.targetctl-build-attempt-v1-'+attempt_id
    return stem+'.json',stem+'.log',stem+'.commit.json'
def _build_file_hash(path,executable=False):
    try:
        st=_build_os.stat(path,follow_symlinks=False)
        if not _build_stat.S_ISREG(st.st_mode) or st.st_uid!=_build_os.geteuid() or st.st_nlink!=1 or st.st_size<1 or executable and not st.st_mode&0o100: _fail('build_binary_invalid')
        fd=_build_os.open(path,_build_os.O_RDONLY|_build_os.O_CLOEXEC|getattr(_build_os,'O_NOFOLLOW',0))
    except HelperError: raise
    except OSError: _fail('build_binary_invalid')
    try:
        before=_build_os.fstat(fd); h=_build_hashlib.sha256()
        while True:
            block=_build_os.read(fd,1048576)
            if not block: break
            h.update(block)
        after=_build_os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_nlink,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns) or (after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_nlink,before.st_size,before.st_mtime_ns,before.st_ctime_ns): _fail('build_binary_invalid')
        return h.hexdigest(),after.st_size
    finally: _build_os.close(fd)
def _build_atomic(run_fd,name,value):
    temp='.'+name+'.'+_build_secrets.token_hex(16)
    try:
        fd=_build_os.open(temp,_build_os.O_WRONLY|_build_os.O_CREAT|_build_os.O_EXCL|_build_os.O_CLOEXEC|getattr(_build_os,'O_NOFOLLOW',0),0o600,dir_fd=run_fd)
        try:
            view=memoryview(value)
            while view:
                written=_build_os.write(fd,view)
                if written<=0: _fail('build_state_write_failed')
                view=view[written:]
            _build_os.fsync(fd)
        finally: _build_os.close(fd)
        _build_os.replace(temp,name,src_dir_fd=run_fd,dst_dir_fd=run_fd); _build_os.fsync(run_fd)
    except HelperError: raise
    except OSError: _fail('build_state_write_failed')
    finally:
        try: _build_os.unlink(temp,dir_fd=run_fd)
        except FileNotFoundError: pass
        except OSError: _fail('build_state_write_failed')
def _build_remove_active(run_fd):
    try: _build_os.unlink('build.json',dir_fd=run_fd)
    except FileNotFoundError: return
    except OSError: _fail('build_state_write_failed')
    try: _build_os.fsync(run_fd)
    except OSError: _fail('build_state_write_failed')
def _build_record_id(value):
    raw=_build_json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    parts=(b'targetctl.record.v1',raw); h=_build_hashlib.sha256()
    for part in parts: h.update(len(part).to_bytes(8,'big')); h.update(part)
    return h.hexdigest()
def _build_kill_group(process_group):
    if not isinstance(process_group,int) or process_group<=1: return False
    try: _build_os.killpg(process_group,_build_signal.SIGKILL); return True
    except ProcessLookupError: return True
    except OSError: return False
def _build_group_gone(process_group):
    if not isinstance(process_group,int) or process_group<=1: return False
    deadline=_build_time.monotonic()+1
    while True:
        try: _build_os.killpg(process_group,0)
        except ProcessLookupError: return True
        except OSError: return False
        if _build_time.monotonic()>=deadline: return False
        _build_time.sleep(0.01)
def _build_close_registered(selector):
    for key in tuple(selector.get_map().values()):
        try: selector.unregister(key.fileobj)
        except (KeyError,OSError,ValueError): pass
        try: key.fileobj.close()
        except OSError: pass
def _build_ds4_version(value):
    match=_build_re.fullmatch(rb'ds4-server v([0-9]+(?:\.[0-9]+)*)\n?',value)
    if match is None or len(match.group(1))>64: return None
    try: return match.group(1).decode('ascii')
    except UnicodeDecodeError: return None
def _build_sass_line(state,line):
    if line.endswith(b'\r'): line=line[:-1]
    stage=state[0]
    header=_build_re.fullmatch(rb'[ \t]*code for sm_121a[ \t]*',line) is not None
    any_header=_build_re.fullmatch(rb'[ \t]*code for[ \t]+.*',line) is not None
    function=_build_re.fullmatch(rb'[ \t]*Function[ \t]+:[ \t]+\S.*',line) is not None
    instruction=_build_re.fullmatch(rb'[ \t]*/\*[0-9A-Fa-f]{4,16}\*/[ \t]+\S.*',line) is not None
    if stage==0:
        if header: state[0]=1
        elif any_header: state[1]=True
    elif stage==1:
        if header: return
        if function: state[0]=2
        elif instruction or any_header: state[1]=True
    elif stage==2:
        if instruction: state[0]=3
        elif function or any_header: state[1]=True
def _build_stream_sass(args,timeout,scan_limit,stderr_limit,work_fd,activity):
    process=None; process_group=None; wait_attempted=False; cleanup_ok=True
    old_handlers={}; old_mask=None; blocked=False; interrupted=[False]
    state=[0,False]; pending=bytearray(); scanned=0; stderr_seen=0; finished=False
    watched=(_build_signal.SIGHUP,_build_signal.SIGINT,_build_signal.SIGTERM)
    def interrupted_handler(signum,frame):
        interrupted[0]=True
        if process_group is not None: _build_kill_group(process_group)
    try:
        for signum in watched: old_handlers[signum]=_build_signal.signal(signum,interrupted_handler)
        old_mask=_build_signal.pthread_sigmask(_build_signal.SIG_BLOCK,watched); blocked=True
        try:
            process=_build_subprocess.Popen(args,stdin=_build_subprocess.DEVNULL,stdout=_build_subprocess.PIPE,stderr=_build_subprocess.PIPE,cwd='/',env={'LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin'},start_new_session=True,pass_fds=(work_fd,))
        except OSError: _fail('build_command_failed')
        activity['process_groups_gone']=False
        process_group=process.pid
        if not isinstance(process_group,int) or process_group<=1: _fail('build_process_unknown')
        _build_signal.pthread_sigmask(_build_signal.SIG_SETMASK,old_mask); blocked=False
        deadline=_build_time.monotonic()+timeout
        with _build_selectors.DefaultSelector() as selector:
            for stream,is_stdout in ((process.stdout,True),(process.stderr,False)):
                _build_os.set_blocking(stream.fileno(),False); selector.register(stream,_build_selectors.EVENT_READ,is_stdout)
            while selector.get_map() or process.poll() is None:
                if interrupted[0] or state[1] or scanned>scan_limit or stderr_seen>stderr_limit: break
                remaining=deadline-_build_time.monotonic()
                if remaining<=0: break
                for key,_ in selector.select(min(0.1,remaining)):
                    stream_room=8192-len(pending) if key.data else stderr_limit-stderr_seen
                    try: chunk=_build_os.read(key.fileobj.fileno(),min(4096,max(1,scan_limit-scanned+1),max(1,stream_room+1)))
                    except BlockingIOError: continue
                    except OSError: state[1]=True; break
                    if not chunk:
                        try: selector.unregister(key.fileobj)
                        except (KeyError,OSError,ValueError): pass
                        key.fileobj.close(); continue
                    scanned+=len(chunk)
                    if key.data:
                        pending.extend(chunk)
                        while True:
                            newline=pending.find(b'\n')
                            if newline<0: break
                            _build_sass_line(state,bytes(pending[:newline])); del pending[:newline+1]
                            if state[0]==3 or state[1]: break
                        if len(pending)>8192: state[1]=True
                    else: stderr_seen+=len(chunk)
                    if state[0]==3 or state[1] or scanned>scan_limit or stderr_seen>stderr_limit: break
                if state[0]==3: finished=True; break
            if not finished and pending and process.poll() is not None:
                _build_sass_line(state,bytes(pending)); finished=state[0]==3 and not state[1]
            _build_close_registered(selector)
        cleanup_ok=_build_kill_group(process_group) and cleanup_ok
        wait_attempted=True
        try: process.wait(timeout=1)
        except _build_subprocess.TimeoutExpired: cleanup_ok=False
        cleanup_ok=_build_group_gone(process_group) and cleanup_ok
        if cleanup_ok: activity['process_groups_gone']=True
        if not cleanup_ok: _fail('build_process_unknown')
        return finished and not interrupted[0] and not state[1] and scanned<=scan_limit and stderr_seen<=stderr_limit
    finally:
        if process is not None and not wait_attempted:
            cleanup_ok=_build_kill_group(process_group) and cleanup_ok
            for stream in (process.stdout,process.stderr):
                if stream is not None and not stream.closed:
                    try: stream.close()
                    except OSError: pass
            wait_attempted=True
            try: process.wait(timeout=1)
            except _build_subprocess.TimeoutExpired: cleanup_ok=False
            cleanup_ok=_build_group_gone(process_group) and cleanup_ok
            if cleanup_ok: activity['process_groups_gone']=True
        for signum,handler in old_handlers.items(): _build_signal.signal(signum,handler)
        if blocked: _build_signal.pthread_sigmask(_build_signal.SIG_SETMASK,old_mask)
        if not cleanup_ok: _fail('build_process_unknown')
def _build_sass_probe(binary,work_fd,activity):
    if not _build_stream_sass(('/usr/local/cuda/bin/cuobjdump','--dump-sass',binary),30,268435456,16384,work_fd,activity): _fail('build_sass_invalid')
def _build_sass(binary,work_fd,activity):
    code,stdout,stderr,timed_out,oversize=_build_capture(('/usr/local/cuda/bin/cuobjdump','--list-elf',binary),10,65536,work_fd,activity)
    if timed_out or oversize or code or _build_re.search(rb'(?<![A-Za-z0-9_])sm_121a(?![A-Za-z0-9_])',stdout) is None: _fail('build_sass_invalid')
    _build_sass_probe(binary,work_fd,activity)
def _build_capture(args,timeout,limit,work_fd,activity):
    process=None; process_group=None; wait_attempted=False; cleanup_ok=True
    stdout=bytearray(); stderr=bytearray(); timed_out=False; oversize=False
    old_handlers={}; old_mask=None; blocked=False; interrupted=[False]
    watched=(_build_signal.SIGHUP,_build_signal.SIGINT,_build_signal.SIGTERM)
    def interrupted_handler(signum,frame):
        interrupted[0]=True
        if process_group is not None: _build_kill_group(process_group)
    try:
        for signum in watched: old_handlers[signum]=_build_signal.signal(signum,interrupted_handler)
        old_mask=_build_signal.pthread_sigmask(_build_signal.SIG_BLOCK,watched); blocked=True
        try:
            process=_build_subprocess.Popen(args,stdin=_build_subprocess.DEVNULL,stdout=_build_subprocess.PIPE,stderr=_build_subprocess.PIPE,cwd='/',env={'LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin'},start_new_session=True,pass_fds=(work_fd,))
        except OSError: _fail('build_command_failed')
        activity['process_groups_gone']=False
        process_group=process.pid
        if not isinstance(process_group,int) or process_group<=1: _fail('build_process_unknown')
        _build_signal.pthread_sigmask(_build_signal.SIG_SETMASK,old_mask); blocked=False
        deadline=_build_time.monotonic()+timeout
        with _build_selectors.DefaultSelector() as selector:
            for stream,output in ((process.stdout,stdout),(process.stderr,stderr)):
                _build_os.set_blocking(stream.fileno(),False); selector.register(stream,_build_selectors.EVENT_READ,output)
            while selector.get_map() or process.poll() is None:
                remaining=deadline-_build_time.monotonic()
                if not interrupted[0] and not oversize and remaining<=0: timed_out=True
                if timed_out or interrupted[0] or oversize:
                    cleanup_ok=_build_kill_group(process_group) and cleanup_ok
                    _build_close_registered(selector)
                    break
                for key,_ in selector.select(min(0.1,remaining)):
                    output=key.data; room=limit-len(stdout)-len(stderr)
                    try: chunk=_build_os.read(key.fileobj.fileno(),min(65536,max(1,room+1)))
                    except BlockingIOError: continue
                    except OSError: cleanup_ok=False; oversize=True; break
                    if not chunk:
                        try: selector.unregister(key.fileobj)
                        except (KeyError,OSError,ValueError): pass
                        key.fileobj.close(); continue
                    output.extend(chunk[:max(0,room)])
                    if len(chunk)>room: oversize=True; break
            cleanup_ok=_build_kill_group(process_group) and cleanup_ok
            wait_attempted=True
            try: process.wait(timeout=1)
            except _build_subprocess.TimeoutExpired: cleanup_ok=False
            cleanup_ok=_build_group_gone(process_group) and cleanup_ok
        if cleanup_ok: activity['process_groups_gone']=True
        if not cleanup_ok: _fail('build_process_unknown')
        return process.returncode,bytes(stdout),bytes(stderr),timed_out or interrupted[0],oversize
    finally:
        if process is not None and not wait_attempted:
            cleanup_ok=_build_kill_group(process_group) and cleanup_ok
            for stream in (process.stdout,process.stderr):
                if stream is not None and not stream.closed:
                    try: stream.close()
                    except OSError: pass
            wait_attempted=True
            try: process.wait(timeout=1)
            except _build_subprocess.TimeoutExpired: cleanup_ok=False
            cleanup_ok=_build_group_gone(process_group) and cleanup_ok
            if cleanup_ok: activity['process_groups_gone']=True
        for signum,handler in old_handlers.items(): _build_signal.signal(signum,handler)
        if blocked: _build_signal.pthread_sigmask(_build_signal.SIG_SETMASK,old_mask)
        if not cleanup_ok: _fail('build_process_unknown')
def _build_make(cwd,jobs,private_paths,additional_secrets,activity):
    process=None; process_group=None; wait_attempted=False; cleanup_ok=True
    old_handlers={}; old_mask=None; blocked=False; interrupted=[False]
    redactor=_targetctl_redactor(_targetctl_redaction_canaries(private_paths,additional_secrets)); started=_build_time.monotonic_ns()
    watched=(_build_signal.SIGHUP,_build_signal.SIGINT,_build_signal.SIGTERM)
    def interrupted_handler(signum,frame):
        interrupted[0]=True
        if process_group is not None: _build_kill_group(process_group)
    try:
        for signum in watched: old_handlers[signum]=_build_signal.signal(signum,interrupted_handler)
        old_mask=_build_signal.pthread_sigmask(_build_signal.SIG_BLOCK,watched); blocked=True
        try:
            process=_build_subprocess.Popen(('/usr/bin/make','-C','engine/ds4','cuda-spark','-j%d'%jobs),stdin=_build_subprocess.DEVNULL,stdout=_build_subprocess.PIPE,stderr=_build_subprocess.PIPE,cwd=cwd,env={'LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin'},start_new_session=True)
        except OSError:
            _targetctl_redact_feed(redactor,b'',True)
            return None,max(1,_build_time.monotonic_ns()-started),bytes(redactor['out']),False,False,True
        activity['mutation_dispatched']=True; activity['process_groups_gone']=False
        process_group=process.pid
        if not isinstance(process_group,int) or process_group<=1: _fail('build_process_unknown')
        _build_signal.pthread_sigmask(_build_signal.SIG_SETMASK,old_mask); blocked=False
        deadline=_build_time.monotonic()+3600; timed_out=False
        with _build_selectors.DefaultSelector() as selector:
            for stream in (process.stdout,process.stderr):
                _build_os.set_blocking(stream.fileno(),False); selector.register(stream,_build_selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                remaining=deadline-_build_time.monotonic()
                if not interrupted[0] and remaining<=0: timed_out=True
                if timed_out or interrupted[0]:
                    cleanup_ok=_build_kill_group(process_group) and cleanup_ok
                    _build_close_registered(selector)
                    break
                for key,_ in selector.select(min(0.1,remaining)):
                    try: chunk=_build_os.read(key.fileobj.fileno(),65536)
                    except BlockingIOError: continue
                    except OSError: cleanup_ok=False; interrupted[0]=True; break
                    if chunk: _targetctl_redact_feed(redactor,chunk)
                    else:
                        try: selector.unregister(key.fileobj)
                        except (KeyError,OSError,ValueError): pass
                        key.fileobj.close()
            cleanup_ok=_build_kill_group(process_group) and cleanup_ok
            wait_attempted=True
            try: process.wait(timeout=1)
            except _build_subprocess.TimeoutExpired: cleanup_ok=False
            cleanup_ok=_build_group_gone(process_group) and cleanup_ok
        _targetctl_redact_feed(redactor,b'',True)
        if cleanup_ok: activity['process_groups_gone']=True
        if not cleanup_ok: _fail('build_process_unknown')
        return (None if timed_out or interrupted[0] else process.returncode,max(1,_build_time.monotonic_ns()-started),bytes(redactor['out']),timed_out,interrupted[0],False)
    finally:
        if process is not None and not wait_attempted:
            cleanup_ok=_build_kill_group(process_group) and cleanup_ok
            for stream in (process.stdout,process.stderr):
                if stream is not None and not stream.closed:
                    try: stream.close()
                    except OSError: pass
            wait_attempted=True
            try: process.wait(timeout=1)
            except _build_subprocess.TimeoutExpired: cleanup_ok=False
            cleanup_ok=_build_group_gone(process_group) and cleanup_ok
            if cleanup_ok: activity['process_groups_gone']=True
        for signum,handler in old_handlers.items(): _build_signal.signal(signum,handler)
        if blocked: _build_signal.pthread_sigmask(_build_signal.SIG_SETMASK,old_mask)
        if not cleanup_ok: _fail('build_process_unknown')
def _build_failed(data,failure,log_hash,exit_code,duration_ns):
    return {'status':'failed','failure_class':failure,'source_snapshot_id':data['snapshot_id'],'source_applied_tree_hash':data['applied_tree_hash'],'build_id':None,'binary_sha256':None,'command':'make-cuda-spark','version':None,'binary_size':None,'sass':None,'build_log_sha256':log_hash,'exit_code':exit_code,'duration_ns':duration_ns}
def _build_success(data,log_hash,duration_ns,build_id,digest,version,size):
    return {'status':'succeeded','failure_class':None,'source_snapshot_id':data['snapshot_id'],'source_applied_tree_hash':data['applied_tree_hash'],'build_id':build_id,'binary_sha256':digest,'command':'make-cuda-spark','version':version,'binary_size':size,'sass':'verified','build_log_sha256':log_hash,'exit_code':0,'duration_ns':duration_ns}
def _build_report(data,result):
    report={'schema_version':1,'record_type':'build-attempt','attempt_id':data['attempt_id']}
    report.update(result)
    return report
def _build_active(result):
    if not isinstance(result,dict) or result.get('status')!='succeeded': _fail('build_state_write_failed')
    return {'schema_version':1,'record_type':'build','source_snapshot_id':result['source_snapshot_id'],'source_applied_tree_hash':result['source_applied_tree_hash'],'build_id':result['build_id'],'binary_sha256':result['binary_sha256'],'binary_size':result['binary_size'],'version':result['version'],'sass':result['sass'],'build_log_sha256':result['build_log_sha256'],'exit_code':result['exit_code'],'duration_ns':result['duration_ns']}
def _build_report_bytes(report):
    return _build_json.dumps(report,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
def _build_applied_hash(work_fd,entries,allow_build_outputs=False):
    if allow_build_outputs:
        if not isinstance(entries,list) or len(entries)>MAX_ENTRIES: _fail('invalid_entries')
        names=[_source_relative(item) for item in entries]
        if names!=sorted(set(names)): _fail('invalid_entries')
    else: names=_source_entries(work_fd,entries)
    hashed=[]
    for name in names:
        parent,leaf=_entry_parent(work_fd,name)
        try:
            fd,before=_open_entry_regular(leaf,dir_fd=parent)
            try:
                h=_build_hashlib.sha256(); size=0
                while True:
                    block=_build_os.read(fd,1048576)
                    if not block: break
                    h.update(block); size+=len(block)
                after=_build_os.fstat(fd)
            finally: _build_os.close(fd)
            if (before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid,after.st_size,after.st_mtime_ns,after.st_ctime_ns): _fail('entry_changed')
            hashed.append((name,'file',int(bool(after.st_mode&0o100)),size,h.digest()))
        finally: _build_os.close(parent)
    return _frame_hash(hashed)
def _build_assert_lock(run_fd,run_identity,run_token,lock_token,mismatch_code,expected=None):
    lock_fd,_=_open_regular(LOCK_NAME,dir_fd=run_fd)
    try:
        lock_identity=_identity(lock_fd); state=_lock_state(lock_fd)
        if not _build_hex(lock_token) or not hmac.compare_digest(state['token'],lock_token): _fail(mismatch_code)
        pin=(lock_identity['device'],lock_identity['inode'],state['boot_id'],state['deadline_monotonic_ns'])
        if expected is not None and pin!=expected: _fail(mismatch_code)
        _assert_named_identity(run_fd,LOCK_NAME,lock_identity,'unsafe_lock')
        _assert_pinned_root(run_fd,run_identity); _read_marker(run_fd,'run',run_token)
        if state['boot_id']!=_boot_id() or _build_time.monotonic_ns()>=state['deadline_monotonic_ns']: _fail(mismatch_code)
        return pin
    finally: _build_os.close(lock_fd)
def _build_read(run_fd,name,limit,missing_code):
    try: fd,before=_open_regular(name,dir_fd=run_fd)
    except HelperError:
        try: _build_os.stat(name,dir_fd=run_fd,follow_symlinks=False)
        except FileNotFoundError: _fail(missing_code)
        except OSError: pass
        _fail('build_reconcile_invalid')
    try:
        if before.st_nlink!=1 or before.st_size>limit: _fail('build_reconcile_invalid')
        content=bytearray()
        while len(content)<=limit:
            block=_build_os.read(fd,min(65536,limit+1-len(content)))
            if not block: break
            content.extend(block)
        after=_build_os.fstat(fd)
        expected=(before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_nlink,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
        actual=(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
        if len(content)>limit or len(content)!=before.st_size or actual!=expected: _fail('build_reconcile_invalid')
        _assert_named_identity(run_fd,name,_identity(fd),'build_reconcile_invalid')
        return bytes(content)
    finally: _build_os.close(fd)
def _build_load_report(content):
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value: _fail('build_reconcile_invalid')
            value[key]=item
        return value
    try: report=_build_json.loads(content.decode('ascii'),object_pairs_hook=unique)
    except HelperError: raise
    except (UnicodeDecodeError,ValueError): _fail('build_reconcile_invalid')
    if not isinstance(report,dict) or set(report)!=_BUILD_REPORT_KEYS: _fail('build_reconcile_invalid')
    return report
def _build_parse_commit(content):
    duplicate=[False]
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value: duplicate[0]=True
            value[key]=item
        return value
    try: commit=_build_json.loads(content.decode('ascii'),object_pairs_hook=unique)
    except (UnicodeDecodeError,ValueError,RecursionError): return None
    if duplicate[0] or not isinstance(commit,dict) or set(commit)!=_BUILD_COMMIT_KEYS or commit['schema_version']!=1 or commit['record_type']!='build-attempt-commit' or not _build_hex(commit['attempt_id']) or not _build_hex(commit['attempt_report_sha256']) or not _build_hex(commit['attempt_log_sha256']): return None
    return commit
def _build_load_commit(content):
    commit=_build_parse_commit(content)
    if commit is None: _fail('build_reconcile_invalid')
    return commit
def _build_validate_result(data,result,log_hash,work_fd):
    if not isinstance(result,dict) or set(result)!=_BUILD_RESULT_KEYS or result['source_snapshot_id']!=data['snapshot_id'] or result['source_applied_tree_hash']!=data['applied_tree_hash'] or result['command']!='make-cuda-spark' or result['build_log_sha256']!=log_hash or not isinstance(result['duration_ns'],int) or isinstance(result['duration_ns'],bool) or not 1<=result['duration_ns']<=3630000000000: _fail('build_reconcile_invalid')
    if result['status']=='succeeded':
        version=result['version']; size=result['binary_size']
        if result['failure_class'] is not None or not _build_hex(result['build_id']) or not _build_hex(result['binary_sha256']) or not isinstance(version,str) or not 1<=len(version)<=64 or _build_re.fullmatch(r'[0-9]+(?:\.[0-9]+)*',version) is None or not isinstance(size,int) or isinstance(size,bool) or not 1<=size<=(1<<63)-1 or result['sass']!='verified' or result['exit_code']!=0 or isinstance(result['exit_code'],bool): _fail('build_reconcile_invalid')
        binary='/proc/self/fd/%d/engine/ds4/ds4-server'%work_fd
        digest,actual_size=_build_file_hash(binary,True)
        ident={'schema_version':1,'source_snapshot_id':data['snapshot_id'],'source_applied_tree_hash':data['applied_tree_hash'],'binary_sha256':digest,'version':version,'binary_size':actual_size,'sass':'sm_121a'}
        if not hmac.compare_digest(digest,result['binary_sha256']) or actual_size!=size or not hmac.compare_digest(_build_record_id(ident),result['build_id']): _fail('build_reconcile_invalid')
    elif result['status']=='failed':
        exit_code=result['exit_code']
        if result['failure_class'] not in {'timeout','command_failed','contract_failed'} or any(result[key] is not None for key in ('build_id','binary_sha256','version','binary_size','sass')) or not (exit_code is None or isinstance(exit_code,int) and not isinstance(exit_code,bool) and 0<=exit_code<=255 and (exit_code>0 or result['failure_class']=='contract_failed')): _fail('build_reconcile_invalid')
    else: _fail('build_reconcile_invalid')
def _build_payload(payload):
    keys={'workdir','run_dir','model_path','drafter_path','work_token','run_token','entries','snapshot_id','applied_tree_hash','dirty','allow_dirty','jobs','lock_token','attempt_id'}
    data=_require_object(payload,keys)
    if not _build_hex(data['snapshot_id']) or not _build_hex(data['applied_tree_hash']) or not _build_hex(data['lock_token']) or not _build_hex(data['attempt_id']) or not isinstance(data['dirty'],bool) or data['allow_dirty']!=(data['snapshot_id'] if data['dirty'] else None) or not isinstance(data['jobs'],int) or isinstance(data['jobs'],bool) or not 1<=data['jobs']<=256: _fail('build_dirty_unacknowledged')
    return data
@register_action('target_build')
def target_build(payload):
    data=_build_payload(payload)
    _,paths=_source_roots({key:data[key] for key in ('workdir','run_dir','model_path','drafter_path','work_token','run_token','entries')})
    work_fd,run_fd,work_identity,run_identity=_source_open(paths)
    release_ready=False; activity={'mutation_dispatched':False,'process_groups_gone':True}; completion_durable=False
    try:
        _build_assert_lock(run_fd,run_identity,paths['run_token'],data['lock_token'],'lock_token_mismatch'); release_ready=True
        if _build_applied_hash(work_fd,data['entries'])!=data['applied_tree_hash']: _fail('entry_changed')
        cwd='/proc/self/fd/%d'%work_fd
        made,duration_ns,log,timed_out,interrupted,spawn_failed=_build_make(cwd,data['jobs'],(data['model_path'],data['drafter_path']),(data['workdir'],data['run_dir']),activity)
        _build_atomic(run_fd,'build.log',log); log_hash=_build_hashlib.sha256(log).hexdigest()
        if spawn_failed: result=_build_failed(data,'command_failed',log_hash,None,duration_ns)
        elif timed_out: result=_build_failed(data,'timeout',log_hash,None,duration_ns)
        elif interrupted: result=_build_failed(data,'command_failed',log_hash,None,duration_ns)
        elif made: result=_build_failed(data,'command_failed',log_hash,made if made>=0 else None,duration_ns)
        else:
            try:
                binary=cwd+'/engine/ds4/ds4-server'; digest,size=_build_file_hash(binary,True)
                version_code,version_stdout,version_stderr,version_timed_out,version_oversize=_build_capture((binary,'--version'),10,16384,work_fd,activity)
                version=None if version_timed_out or version_oversize or version_code or version_stderr else _build_ds4_version(version_stdout)
                if version is None: _fail('build_binary_invalid')
                _build_sass(binary,work_fd,activity)
                ident={'schema_version':1,'source_snapshot_id':data['snapshot_id'],'source_applied_tree_hash':data['applied_tree_hash'],'binary_sha256':digest,'version':version,'binary_size':size,'sass':'sm_121a'}
                build_id=_build_record_id(ident)
                result=_build_success(data,log_hash,duration_ns,build_id,digest,version,size)
            except HelperError as error:
                if error.code=='build_process_unknown': raise
                if error.code not in {'build_binary_invalid','build_sass_invalid','build_command_failed'}: raise
                result=_build_failed(data,'contract_failed',log_hash,0,duration_ns)
        lease_pin=_build_assert_lock(run_fd,run_identity,paths['run_token'],data['lock_token'],'lock_token_mismatch')
        _assert_pinned_root(work_fd,work_identity)
        try: source_matches=hmac.compare_digest(_build_applied_hash(work_fd,data['entries'],True),data['applied_tree_hash'])
        except HelperError as error:
            if error.code not in {'entry_changed','unsafe_entry','missing_path','symlink_path','unsafe_path'}: raise
            source_matches=False
        except OSError: source_matches=False
        _assert_pinned_root(work_fd,work_identity)
        _build_assert_lock(run_fd,run_identity,paths['run_token'],data['lock_token'],'lock_token_mismatch',lease_pin)
        if not source_matches:
            result=_build_failed(data,'contract_failed',log_hash,result['exit_code'],duration_ns)
            _build_remove_active(run_fd)
        report=_build_report(data,result); report_bytes=_build_report_bytes(report)
        report_hash=_build_hashlib.sha256(report_bytes).hexdigest()
        report_name,attempt_log_name,commit_name=_build_attempt_names(data['attempt_id'])
        _build_atomic(run_fd,attempt_log_name,log)
        _build_atomic(run_fd,report_name,report_bytes)
        commit={'schema_version':1,'record_type':'build-attempt-commit','attempt_id':data['attempt_id'],'attempt_report_sha256':report_hash,'attempt_log_sha256':log_hash}
        _build_atomic(run_fd,commit_name,_build_report_bytes(commit))
        if result['status']=='succeeded': _build_atomic(run_fd,'build.json',_build_report_bytes(_build_active(result)))
        completion_durable=True
        _assert_pinned_root(work_fd,work_identity); _assert_pinned_root(run_fd,run_identity); _read_marker(run_fd,'run',paths['run_token'])
        return result
    finally:
        try:
            if release_ready and activity['process_groups_gone'] and (not activity['mutation_dispatched'] or completion_durable):
                _release_lock_at_root(run_fd,run_identity,paths['run_token'],data['lock_token'])
        finally:
            _build_os.close(work_fd); _build_os.close(run_fd)
@register_action('target_build_reconcile')
def target_build_reconcile(payload):
    data=_build_payload(payload)
    _,paths=_source_roots({key:data[key] for key in ('workdir','run_dir','model_path','drafter_path','work_token','run_token','entries')})
    work_fd,run_fd,work_identity,run_identity=_source_open(paths)
    reacquired_token=None; old_owned=False; accepted=False
    try:
        try: _build_os.stat(LOCK_NAME,dir_fd=run_fd,follow_symlinks=False)
        except FileNotFoundError:
            reacquired_token=_acquire_lock_at_root(run_fd,run_identity,paths['run_token'],_BUILD_RECONCILE_LEASE_SECONDS)
            current_token=reacquired_token
            lease_pin=_build_assert_lock(run_fd,run_identity,paths['run_token'],current_token,'build_reconcile_invalid')
        except OSError: _fail('unsafe_lock')
        else:
            current_token=data['lock_token']
            lease_pin=_build_assert_lock(run_fd,run_identity,paths['run_token'],current_token,'lock_busy')
            old_owned=True
        report_name,attempt_log_name,commit_name=_build_attempt_names(data['attempt_id'])
        try: commit_bytes=_build_read(run_fd,commit_name,4096,'build_reconcile_unavailable')
        except HelperError as error:
            if old_owned and error.code in {'build_reconcile_unavailable','build_reconcile_invalid'}: _fail('lock_busy')
            raise
        if old_owned:
            commit=_build_parse_commit(commit_bytes)
            if commit is None or commit['attempt_id']!=data['attempt_id']: _fail('lock_busy')
        else:
            commit=_build_load_commit(commit_bytes)
            if commit['attempt_id']!=data['attempt_id']: _fail('build_reconcile_invalid')
        report_bytes=_build_read(run_fd,report_name,65536,'build_reconcile_unavailable')
        report=_build_load_report(report_bytes)
        report_hash=_build_hashlib.sha256(report_bytes).hexdigest()
        if report['schema_version']!=1 or report['record_type']!='build-attempt' or report['attempt_id']!=data['attempt_id'] or not hmac.compare_digest(commit['attempt_report_sha256'],report_hash): _fail('build_reconcile_invalid')
        log=_build_read(run_fd,attempt_log_name,1048576,'build_reconcile_unavailable')
        log_hash=_build_hashlib.sha256(log).hexdigest()
        if not hmac.compare_digest(commit['attempt_log_sha256'],log_hash): _fail('build_reconcile_invalid')
        result={key:report[key] for key in _BUILD_RESULT_KEYS}
        _build_validate_result(data,result,log_hash,work_fd)
        if result['status']=='succeeded' and _build_applied_hash(work_fd,data['entries'],True)!=data['applied_tree_hash']: _fail('build_reconcile_invalid')
        _build_assert_lock(run_fd,run_identity,paths['run_token'],current_token,'build_reconcile_invalid',lease_pin)
        if result['status']=='succeeded': _build_atomic(run_fd,'build.json',_build_report_bytes(_build_active(result)))
        _assert_pinned_root(work_fd,work_identity)
        _build_assert_lock(run_fd,run_identity,paths['run_token'],current_token,'build_reconcile_invalid',lease_pin)
        lease_state='released'
        try: _release_lock_at_root(run_fd,run_identity,paths['run_token'],current_token)
        except HelperError as error:
            if error.code!='lock_release_failed': raise
            _build_assert_lock(run_fd,run_identity,paths['run_token'],current_token,'build_reconcile_invalid',lease_pin)
            lease_state='retained'
        accepted=True
        return {'report':report,'report_sha256':report_hash,'build_log_sha256':log_hash,'lease_state':lease_state}
    finally:
        try:
            if reacquired_token is not None and not accepted:
                try: _release_lock_at_root(run_fd,run_identity,paths['run_token'],reacquired_token)
                except HelperError: pass
        finally:
            _build_os.close(work_fd); _build_os.close(run_fd)
'''


BUILD_EXTENSION = REMOTE_BUILD_EXTENSION