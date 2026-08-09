"""Sanitized, fixed-input target doctor operation.

This module deliberately retains only the finite facts permitted in the
``target-doctor`` artifact payload.  Paths and command output are consumed
locally and never enter a result or exception message.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Protocol

from .common import TargetError
from .lifecycle import local_operation_lock
from .source import SourceSnapshot, _SOURCE_EXTENSION, _load_capabilities, _remote_payload, verify_applied_tree
from .transport import CommandResult, LocalTransport, SSHTransport

MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 5.0
_HASH_CHUNK_BYTES = 1024 * 1024
# A 1 TiB GGUF is far beyond current single-node deployment weights while
# bounding hostile sparse files before any hashing read is attempted.
MAX_WEIGHT_BYTES = 1 << 40
_VERSION = re.compile(rb"(?<![0-9])([0-9]+(?:\.[0-9]+){0,3})(?![0-9])")
_SAFE_SYSTEM = re.compile(r"[A-Za-z0-9._+@=-]{1,160}\Z")

# Order is artifact order.  These are not searched through PATH and are part of
_CUDA_VERSION = re.compile(
    rb"\brelease\s+([0-9]+(?:\.[0-9]+){1,3})(?:,|\s)",
    re.IGNORECASE,
)
# the public evidence contract.
DOCTOR_TOOLS: tuple[tuple[str, str], ...] = (
    ("nvidia-smi", "/usr/bin/nvidia-smi"),
    ("nvcc", "/usr/local/cuda/bin/nvcc"),
    ("gcc", "/usr/bin/gcc"),
    ("g++", "/usr/bin/g++"),
    ("make", "/usr/bin/make"),
    ("python3", "/usr/bin/python3"),
    ("git", "/usr/bin/git"),
    ("rsync", "/usr/bin/rsync"),
    ("cuobjdump", "/usr/local/cuda/bin/cuobjdump"),
)
NIX_COMMAND_TIMEOUT_SECONDS = 120.0
DOCTOR_LOCK_LEASE_SECONDS = 660
_NIX_CANDIDATES = (
    "/nix/var/nix/profiles/default/bin/nix",
    "/run/current-system/sw/bin/nix",
    "/nix/profile/bin/nix",
    "/usr/bin/nix",
)
_NIX_COMPARE_TOOLS = (
    ("nvcc", "/usr/local/cuda/bin/nvcc"),
    ("gcc", "/usr/bin/gcc"),
    ("g++", "/usr/bin/g++"),
)
_NIX_PROBE = (
    'p=$(command -v "$1") || exit 20; '
    'printf "TARGETCTL_PATH=%s\\n" "$p"; exec "$p" --version'
)


class _Transport(Protocol):
    def run(self, argv: tuple[str, ...], *, input_bytes: bytes | None = None, timeout: float | None = None, cwd: str = "/", env: Mapping[str, str] | None = None) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class RuntimeInput:
    """Private, per-invocation local runtime values; never serialize this."""

    model_path: str = field(repr=False)
    drafter_path: str = field(repr=False)
    port: int = field(repr=False)

    def __post_init__(self) -> None:
        for value in (self.model_path, self.drafter_path):
            if not isinstance(value, str) or not value.startswith("/") or "\x00" in value or len(value) > 4096:
                raise TargetError("runtime_input_invalid", "runtime input is invalid")
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise TargetError("runtime_input_invalid", "runtime input is invalid")


@dataclass(frozen=True, slots=True)
class DoctorResult:
    status: str
    failure_class: str | None
    os: str | None
    kernel: str | None
    arch: str | None
    tools: tuple[tuple[str, str | None, str | None], ...]
    gpu: tuple[str, str] | None
    memory_bytes: int | None
    disk_bytes: int | None
    time_sync: bool | None
    primary_weight_sha256: str | None
    draft_weight_sha256: str | None
    nix: tuple[str, str | None] = ("absent", None)

    def controller_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "failure_class": self.failure_class,
            "os": self.os,
            "kernel": self.kernel,
            "arch": self.arch,
            "tools": [{"name": name, "version": version, "location": location} for name, version, location in self.tools],
            "gpu": None if self.gpu is None else {"platform": self.gpu[0], "compute_capability": self.gpu[1]},
            "memory_bytes": self.memory_bytes,
            "disk_bytes": self.disk_bytes,
            "time_sync": self.time_sync,
            "primary_weight_sha256": self.primary_weight_sha256,
            "draft_weight_sha256": self.draft_weight_sha256,
            "nix": {"status": self.nix[0], "version": self.nix[1]},
        }

    to_payload = controller_payload
    as_dict = controller_payload


def _error(code: str, message: str = "target doctor failed") -> TargetError:
    return TargetError(code, message)


def _failure_class(code: str) -> str:
    if code in {"doctor_tool_missing"}:
        return "tool_missing"
    if code in {"doctor_command_timeout"}:
        return "timeout"
    if code in {"doctor_command_failed"}:
        return "command_failed"
    if code in {"doctor_weight_invalid", "doctor_gpu_invalid", "doctor_system_invalid", "doctor_time_unsynchronized", "doctor_nix_mismatch"}:
        return "contract_failed"
    return "preflight"


def _empty_result(code: str) -> DoctorResult:
    return DoctorResult("failed", _failure_class(code), None, None, None, tuple((name, None, None) for name, _ in DOCTOR_TOOLS), None, None, None, None, None, None, ("unavailable", None))


def _validate_result_payload(payload: Any) -> DoctorResult:
    fields = {"status", "failure_class", "os", "kernel", "arch", "tools", "gpu", "memory_bytes", "disk_bytes", "time_sync", "primary_weight_sha256", "draft_weight_sha256", "nix"}
    if not isinstance(payload, Mapping) or set(payload) != fields:
        raise _error("doctor_response_invalid")
    tools = payload["tools"]
    if not isinstance(tools, list) or len(tools) != len(DOCTOR_TOOLS):
        raise _error("doctor_response_invalid")
    clean_tools: list[tuple[str, str | None, str | None]] = []
    for expected, item in zip(DOCTOR_TOOLS, tools, strict=True):
        if not isinstance(item, Mapping) or set(item) != {"name", "version", "location"} or item["name"] != expected[0] or item["location"] != expected[1] or not isinstance(item["version"], str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", item["version"]):
            raise _error("doctor_response_invalid")
        clean_tools.append((expected[0], item["version"], expected[1]))
    gpu = payload["gpu"]
    if not isinstance(gpu, Mapping) or gpu != {"platform": "GB10", "compute_capability": "sm_121"}:
        raise _error("doctor_response_invalid")
    values = (payload["memory_bytes"], payload["disk_bytes"])
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in values) or payload["time_sync"] is not True:
        raise _error("doctor_response_invalid")
    if payload["status"] != "succeeded" or payload["failure_class"] is not None:
        raise _error("doctor_response_invalid")
    for key in ("os", "kernel", "arch"):
        if not isinstance(payload[key], str) or not _SAFE_SYSTEM.fullmatch(payload[key]):
            raise _error("doctor_response_invalid")
    for key in ("primary_weight_sha256", "draft_weight_sha256"):
        if not isinstance(payload[key], str) or not re.fullmatch(r"[0-9a-f]{64}", payload[key]):
            raise _error("doctor_response_invalid")
    nix = payload["nix"]
    if not isinstance(nix, Mapping) or set(nix) != {"status", "version"} or nix["status"] not in {"absent", "matched"} or (nix["status"] == "absent" and nix["version"] is not None) or (nix["status"] == "matched" and (not isinstance(nix["version"], str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", nix["version"]))):
        raise _error("doctor_response_invalid")
    return DoctorResult("succeeded", None, payload["os"], payload["kernel"], payload["arch"], tuple(clean_tools), ("GB10", "sm_121"), values[0], values[1], True, payload["primary_weight_sha256"], payload["draft_weight_sha256"], (nix["status"], nix["version"]))


def _run_checked(transport: _Transport, argv: tuple[str, ...], *, timeout: float = COMMAND_TIMEOUT_SECONDS) -> bytes:
    result = transport.run(argv, timeout=timeout, cwd="/", env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/local/cuda/bin:/usr/bin:/bin"})
    if result.timed_out:
        raise _error("doctor_command_timeout")
    if result.exit_code != 0:
        raise _error("doctor_command_failed")
    if len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES or len(result.stderr) > MAX_COMMAND_OUTPUT_BYTES:
        raise _error("doctor_command_failed")
    return result.stdout


def _version(name: str, output: bytes) -> str:
    match = _CUDA_VERSION.search(output) if name in {"nvcc", "cuobjdump"} else _VERSION.search(output)
    if match is None:
        raise _error("doctor_command_failed")
    return match.group(1).decode("ascii")


def _tool_version(transport: _Transport, name: str, path: str) -> str:
    try:
        item = os.stat(path, follow_symlinks=False)
    except OSError:
        raise _error("doctor_tool_missing") from None
    if not stat.S_ISREG(item.st_mode) or item.st_uid not in {0, os.geteuid()} or not (item.st_mode & stat.S_IXUSR):
        raise _error("doctor_tool_missing")
    return _version(name, _run_checked(transport, (path, "--version")))

def _find_nix() -> str | None:
    candidates = list(_NIX_CANDIDATES)
    home_candidate = os.path.expanduser("~/.nix-profile/bin/nix")
    if home_candidate.startswith("/"):
        candidates.append(home_candidate)
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if directory.startswith("/"):
            candidates.append(os.path.join(directory, "nix"))
    for candidate in dict.fromkeys(candidates):
        try:
            resolved = os.path.realpath(candidate)
            if not resolved.startswith("/") or len(resolved) > 4096 or not resolved.isascii():
                continue
            item = os.stat(resolved, follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISREG(item.st_mode) and item.st_uid in {0, os.geteuid()} and item.st_mode & stat.S_IXUSR:
            return resolved
    return None


def _nix_identity(
    transport: _Transport,
    workdir: Path,
    tools: tuple[tuple[str, str | None, str | None], ...],
) -> tuple[str, str | None]:
    nix = _find_nix()
    if nix is None:
        return "absent", None
    try:
        flake = os.stat(workdir / "flake.nix", follow_symlinks=False)
    except OSError:
        raise _error("doctor_nix_mismatch") from None
    if not stat.S_ISREG(flake.st_mode) or flake.st_uid != os.geteuid():
        raise _error("doctor_nix_mismatch")
    nix_output = _run_checked(transport, (nix, "--version"))
    nix_match = _VERSION.search(nix_output)
    if nix_match is None:
        raise _error("doctor_nix_mismatch")
    native = {name: version for name, version, _ in tools}
    flake_ref = "path:" + str(workdir)
    for name, expected_path in _NIX_COMPARE_TOOLS:
        output = _run_checked(
            transport,
            (
                nix, "--extra-experimental-features", "nix-command flakes",
                "develop", "--no-write-lock-file", flake_ref, "--command",
                "/bin/sh", "-c", _NIX_PROBE, "targetctl-nix-probe", name,
            ),
            timeout=NIX_COMMAND_TIMEOUT_SECONDS,
        )
        lines = output.splitlines()
        markers = [
            (index, line[len(b"TARGETCTL_PATH="):])
            for index, line in enumerate(lines)
            if line.startswith(b"TARGETCTL_PATH=")
        ]
        if len(markers) != 1:
            raise _error("doctor_nix_mismatch")
        position, resolved = markers[0]
        try:
            resolved_path = resolved.decode("ascii")
        except UnicodeDecodeError:
            raise _error("doctor_nix_mismatch") from None
        version_output = b"\n".join(lines[position + 1:])
        try:
            observed_version = _version(name, version_output)
        except TargetError:
            raise _error("doctor_nix_mismatch") from None
        if resolved_path != expected_path or observed_version != native.get(name):
            raise _error("doctor_nix_mismatch")
    return "matched", nix_match.group(1).decode("ascii")


def _weight_hash(path_value: str) -> str:
    try:
        item = os.stat(path_value, follow_symlinks=False)
        if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or not 1 <= item.st_size <= MAX_WEIGHT_BYTES:
            raise OSError
        fd = os.open(path_value, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise _error("doctor_weight_invalid") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or (before.st_dev, before.st_ino, before.st_size) != (item.st_dev, item.st_ino, item.st_size):
            raise _error("doctor_weight_invalid")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, _HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise _error("doctor_weight_invalid")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _local_facts(run_dir: Path) -> tuple[str, str, str, int, int, bool]:
    info = os.uname()
    if info.sysname != "Linux" or not all(_SAFE_SYSTEM.fullmatch(value) for value in (info.sysname, info.release, info.machine)):
        raise _error("doctor_system_invalid")
    try:
        memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        disk = os.statvfs(run_dir).f_bavail * os.statvfs(run_dir).f_frsize
    except (OSError, ValueError):
        raise _error("doctor_system_invalid") from None
    # This file is written by systemd-timesyncd; absence is deliberately a
    # failed fact rather than an optimistic assumption.
    try:
        time_sync = Path("/run/systemd/timesync/synchronized").read_bytes()[:8].strip() == b"yes"
    except OSError:
        time_sync = False
    if memory < 1 or disk < 1 or not time_sync:
        raise _error("doctor_time_unsynchronized" if not time_sync else "doctor_system_invalid")
    return info.sysname, info.release, info.machine, memory, disk, time_sync


def _gpu(transport: _Transport) -> tuple[str, str]:
    output = _run_checked(transport, ("/usr/bin/nvidia-smi", "--query-gpu=name,compute_cap", "--format=csv,noheader"))
    if len(output.splitlines()) != 1:
        raise _error("doctor_gpu_invalid")
    fields = [part.strip().lower() for part in output.decode("ascii", "ignore").split(",")]
    if len(fields) != 2 or "gb10" not in fields[0] or fields[1] not in {"12.1", "sm_121"}:
        raise _error("doctor_gpu_invalid")
    return "GB10", "sm_121"


def _runtime(config: Any, runtime: RuntimeInput | None) -> RuntimeInput:
    if getattr(config, "mode", None) == "local":
        if runtime is None:
            raise _error("runtime_input_required")
        return runtime
    if runtime is not None:
        raise _error("runtime_input_invalid")
    model, drafter = getattr(config, "model_path", None), getattr(config, "drafter_path", None)
    if not isinstance(model, str) or not isinstance(drafter, str):
        raise _error("runtime_input_invalid")
    # SSH port is not used by doctor, but RuntimeInput maintains one validated
    # object across local lifecycle operations.
    return RuntimeInput(model, drafter, 1)


def _authorized_snapshot(snapshot: Any, allow_dirty: str | None) -> SourceSnapshot:
    if (
        not isinstance(snapshot, SourceSnapshot)
        or not isinstance(snapshot.dirty, bool)
        or not re.fullmatch(r"[0-9a-f]{64}", snapshot.snapshot_id)
        or not re.fullmatch(r"[0-9a-f]{64}", snapshot.applied_tree_hash)
    ):
        raise _error("doctor_source_mismatch")
    if snapshot.dirty:
        if allow_dirty != snapshot.snapshot_id:
            raise _error("doctor_dirty_unacknowledged")
    elif allow_dirty is not None:
        raise _error("doctor_dirty_unacknowledged")
    return snapshot


def _local_doctor(config: Any, transport: LocalTransport, inputs: RuntimeInput, snapshot: SourceSnapshot) -> DoctorResult:
    run_dir = Path(config.local_run_dir)
    source_root = Path(config.source_root)
    with local_operation_lock(str(run_dir)):
        try:
            before = verify_applied_tree(source_root, snapshot)
        except TargetError:
            raise _error("doctor_source_mismatch") from None
        if before != snapshot.applied_tree_hash:
            raise _error("doctor_source_mismatch")
        facts = _local_facts(run_dir)
        tools = tuple((name, _tool_version(transport, name, path), path) for name, path in DOCTOR_TOOLS)
        _run_checked(transport, ("/usr/local/cuda/bin/nvcc", "-ccbin", "/usr/bin/g++", "--version"))
        nix = _nix_identity(transport, source_root, tools)
        result = DoctorResult("succeeded", None, facts[0], facts[1], facts[2], tools, _gpu(transport), facts[3], facts[4], facts[5], _weight_hash(inputs.model_path), _weight_hash(inputs.drafter_path), nix)
        try:
            after = verify_applied_tree(source_root, snapshot)
        except TargetError:
            raise _error("doctor_source_mismatch") from None
        if after != snapshot.applied_tree_hash:
            raise _error("doctor_source_mismatch")
        return result

def doctor(
    config: Any,
    transport: LocalTransport | SSHTransport,
    *,
    snapshot: SourceSnapshot,
    allow_dirty: str | None = None,
    runtime: RuntimeInput | None = None,
) -> DoctorResult:
    """Collect source-bound sanitized doctor facts for one target."""
    try:
        config.validate_for("doctor")
        checked = _authorized_snapshot(snapshot, allow_dirty)
        inputs = _runtime(config, runtime)
        if isinstance(transport, SSHTransport):
            state = _load_capabilities(Path(config.source_root), config.name)
            if state is None:
                raise _error("doctor_source_mismatch")
            source_payload = _remote_payload(config, state, checked.entries)
            lock = transport.run_helper(
                "acquire_lock",
                {"run_dir": config.run_dir, "run_token": state["run_token"], "lease_seconds": DOCTOR_LOCK_LEASE_SECONDS},
                allowed_error_codes={"lock_busy", "lock_failed", "unsafe_lock", "invalid_lease", "marker_mismatch", "unsafe_root"},
            )
            if (
                not isinstance(lock, Mapping)
                or set(lock) != {"lock_token", "reclaimed", "stale_receiver_pairs_cleaned", "stale_lock_stages_cleaned"}
                or not isinstance(lock["lock_token"], str)
                or len(lock["lock_token"]) != 64
                or not all(character in "0123456789abcdef" for character in lock["lock_token"])
                or not isinstance(lock["reclaimed"], bool)
                or any(not isinstance(lock[key], int) or isinstance(lock[key], bool) or lock[key] < 0 for key in ("stale_receiver_pairs_cleaned", "stale_lock_stages_cleaned"))
            ):
                raise _error("doctor_lock_failed")
            primary: BaseException | None = None
            try:
                payload = {
                    **source_payload,
                    "snapshot_id": checked.snapshot_id,
                    "applied_tree_hash": checked.applied_tree_hash,
                    "dirty": checked.dirty,
                    "allow_dirty": allow_dirty,
                    "lock_token": lock["lock_token"],
                }
                result = transport.run_helper(
                    "target_doctor",
                    payload,
                    extension_source=_SOURCE_EXTENSION + REMOTE_DOCTOR_EXTENSION,
                    allowed_error_codes={
                        "doctor_tool_missing", "doctor_command_timeout",
                        "doctor_command_failed", "doctor_weight_invalid",
                        "doctor_gpu_invalid", "doctor_system_invalid",
                        "doctor_time_unsynchronized", "doctor_nix_mismatch",
                        "doctor_source_mismatch", "doctor_dirty_unacknowledged",
                        "source_lifecycle", "unexpected_entry",
                        "unsafe_runtime_path",
                    },
                    timeout=600,
                )
                return _validate_result_payload(result)
            except BaseException as error:
                primary = error
                raise
            finally:
                try:
                    released = transport.run_helper(
                        "release_lock",
                        {"run_dir": config.run_dir, "run_token": state["run_token"], "lock_token": lock["lock_token"]},
                        allowed_error_codes={"lock_token_mismatch", "lock_release_failed", "unsafe_lock", "marker_mismatch", "unsafe_root"},
                    )
                    if not isinstance(released, Mapping) or released != {"released": True}:
                        raise _error("doctor_lock_release_failed")
                except BaseException:
                    if primary is None:
                        raise _error("doctor_lock_release_failed") from None
        if not isinstance(transport, LocalTransport):
            raise _error("transport_invalid")
        return _local_doctor(config, transport, inputs, checked)
    except TargetError as exc:
        return _empty_result(exc.code)


run_doctor = doctor
collect_doctor = doctor

# The extension has no imports from the synchronized source tree.  It is kept
# intentionally small: remote execution returns the same finite payload that
# the controller validates above; no command output or paths leave the target.
REMOTE_DOCTOR_EXTENSION = r'''
import hashlib as _doctor_hashlib, json as _doctor_json, os as _doctor_os, re as _doctor_re, selectors as _doctor_selectors, signal as _doctor_signal, stat as _doctor_stat, subprocess as _doctor_subprocess, time as _doctor_time
_DOCTOR_TOOLS=(('nvidia-smi','/usr/bin/nvidia-smi'),('nvcc','/usr/local/cuda/bin/nvcc'),('gcc','/usr/bin/gcc'),('g++','/usr/bin/g++'),('make','/usr/bin/make'),('python3','/usr/bin/python3'),('git','/usr/bin/git'),('rsync','/usr/bin/rsync'),('cuobjdump','/usr/local/cuda/bin/cuobjdump'))
_DOCTOR_NIX_TOOLS=(('nvcc','/usr/local/cuda/bin/nvcc'),('gcc','/usr/bin/gcc'),('g++','/usr/bin/g++'))
_DOCTOR_NIX_PROBE='p=$(command -v "$1") || exit 20; printf "TARGETCTL_PATH=%s\\n" "$p"; exec "$p" --version'
_DOCTOR_VERSION=rb'(?<![0-9])([0-9]+(?:\.[0-9]+){0,3})(?![0-9])'
_DOCTOR_CUDA_VERSION=rb'\brelease\s+([0-9]+(?:\.[0-9]+){1,3})(?:,|\s)'
_DOCTOR_MAX_WEIGHT_BYTES=1<<40
_DOCTOR_MAX_OUTPUT_BYTES=16384
_DOCTOR_SAFE_SYSTEM=_doctor_re.compile(r'[A-Za-z0-9._+@=-]{1,160}\Z')
def _doctor_hash(path):
    try:
        st=_doctor_os.stat(path,follow_symlinks=False)
        if not _doctor_stat.S_ISREG(st.st_mode) or st.st_uid!=_doctor_os.geteuid() or not 1<=st.st_size<=_DOCTOR_MAX_WEIGHT_BYTES: _fail('doctor_weight_invalid')
        fd=_doctor_os.open(path,_doctor_os.O_RDONLY|_doctor_os.O_CLOEXEC|getattr(_doctor_os,'O_NOFOLLOW',0))
    except HelperError: raise
    except OSError: _fail('doctor_weight_invalid')
    try:
        before=_doctor_os.fstat(fd); h=_doctor_hashlib.sha256()
        while True:
            block=_doctor_os.read(fd,1048576)
            if not block: break
            h.update(block)
        after=_doctor_os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size)!=(st.st_dev,st.st_ino,st.st_size) or (after.st_dev,after.st_ino,after.st_size)!=(before.st_dev,before.st_ino,before.st_size): _fail('doctor_weight_invalid')
        return h.hexdigest()
    finally: _doctor_os.close(fd)
def _doctor_kill_group(process_group):
    if not isinstance(process_group,int) or process_group<=1: return False
    try: _doctor_os.killpg(process_group,_doctor_signal.SIGKILL); return True
    except ProcessLookupError: return True
    except OSError: return False
def _doctor_close_registered(selector):
    for key in tuple(selector.get_map().values()):
        try: selector.unregister(key.fileobj)
        except (KeyError,OSError,ValueError): pass
        try: key.fileobj.close()
        except OSError: pass
def _doctor_cmd(argv,timeout=5,pass_fds=()):
    process=None; process_group=None; wait_attempted=False; cleanup_ok=True
    reason=None; streams={'stdout':bytearray(),'stderr':bytearray()}
    try:
        try:
            process=_doctor_subprocess.Popen(argv,stdin=_doctor_subprocess.DEVNULL,stdout=_doctor_subprocess.PIPE,stderr=_doctor_subprocess.PIPE,cwd='/',env={'LANG':'C','LC_ALL':'C','PATH':'/usr/local/cuda/bin:/usr/bin:/bin'},start_new_session=True,pass_fds=pass_fds)
        except OSError: _fail('doctor_command_failed')
        process_group=process.pid
        if not isinstance(process_group,int) or process_group<=1: _fail('doctor_command_failed')
        deadline=_doctor_time.monotonic()+timeout
        with _doctor_selectors.DefaultSelector() as selector:
            for name,stream in (('stdout',process.stdout),('stderr',process.stderr)):
                _doctor_os.set_blocking(stream.fileno(),False); selector.register(stream,_doctor_selectors.EVENT_READ,name)
            while selector.get_map() or process.poll() is None:
                remaining=deadline-_doctor_time.monotonic()
                if reason is None and remaining<=0: reason='timeout'
                if reason is not None:
                    cleanup_ok=_doctor_kill_group(process_group) and cleanup_ok
                    _doctor_close_registered(selector)
                    break
                for key,_ in selector.select(min(0.1,remaining)):
                    data=streams[key.data]; room=_DOCTOR_MAX_OUTPUT_BYTES+1-len(data)
                    try: block=_doctor_os.read(key.fileobj.fileno(),min(65536,max(1,room)))
                    except BlockingIOError: continue
                    except OSError: reason='failure'; break
                    if not block:
                        try: selector.unregister(key.fileobj)
                        except (KeyError,OSError,ValueError): pass
                        key.fileobj.close(); continue
                    if room>0: data.extend(block[:room])
                    if len(data)>_DOCTOR_MAX_OUTPUT_BYTES: reason='oversize'; break
            wait_attempted=True
            try: process.wait(timeout=1)
            except _doctor_subprocess.TimeoutExpired: cleanup_ok=False; reason='failure'
        if not cleanup_ok or reason=='failure': _fail('doctor_command_failed')
        if reason=='timeout': _fail('doctor_command_timeout')
        if reason=='oversize' or process.returncode: _fail('doctor_command_failed')
        return bytes(streams['stdout'])
    finally:
        if process is not None:
            if not wait_attempted:
                cleanup_ok=_doctor_kill_group(process_group) and cleanup_ok
            for stream in (process.stdout,process.stderr):
                if stream is not None and not stream.closed:
                    try: stream.close()
                    except OSError: pass
            if not wait_attempted:
                wait_attempted=True
                try: process.wait(timeout=1)
                except _doctor_subprocess.TimeoutExpired: cleanup_ok=False
            if not cleanup_ok: _fail('doctor_command_failed')
def _doctor_version(name,output):
    pattern=_DOCTOR_CUDA_VERSION if name in ('nvcc','cuobjdump') else _DOCTOR_VERSION
    match=_doctor_re.search(pattern,output,_doctor_re.IGNORECASE if name in ('nvcc','cuobjdump') else 0)
    return match.group(1).decode('ascii') if match else None
def _doctor_nix(tools,work_fd):
    candidates=['/nix/var/nix/profiles/default/bin/nix','/run/current-system/sw/bin/nix','/nix/profile/bin/nix','/usr/bin/nix']
    home_candidate=_doctor_os.path.expanduser('~/.nix-profile/bin/nix')
    if home_candidate.startswith('/'): candidates.append(home_candidate)
    for directory in _doctor_os.environ.get('PATH','').split(_doctor_os.pathsep):
        if directory.startswith('/'): candidates.append(_doctor_os.path.join(directory,'nix'))
    nix=None
    for candidate in dict.fromkeys(candidates):
        try:
            resolved=_doctor_os.path.realpath(candidate); item=_doctor_os.stat(resolved,follow_symlinks=False)
        except OSError: continue
        if resolved.startswith('/') and len(resolved)<=4096 and resolved.isascii() and _doctor_stat.S_ISREG(item.st_mode) and item.st_uid in (0,_doctor_os.geteuid()) and item.st_mode&0o100:
            nix=resolved; break
    if nix is None: return {'status':'absent','version':None}
    try: flake=_doctor_os.stat('flake.nix',dir_fd=work_fd,follow_symlinks=False)
    except OSError: _fail('doctor_nix_mismatch')
    if not _doctor_stat.S_ISREG(flake.st_mode) or flake.st_uid!=_doctor_os.geteuid(): _fail('doctor_nix_mismatch')
    match=_doctor_re.search(_DOCTOR_VERSION,_doctor_cmd((nix,'--version')))
    if not match: _fail('doctor_nix_mismatch')
    descriptor='/proc/self/fd/%d'%work_fd
    native={tool['name']:tool['version'] for tool in tools}
    for name,expected in _DOCTOR_NIX_TOOLS:
        out=_doctor_cmd((nix,'--extra-experimental-features','nix-command flakes','develop','--no-write-lock-file','path:'+descriptor,'--command','/bin/sh','-c',_DOCTOR_NIX_PROBE,'targetctl-nix-probe',name),120,(work_fd,))
        lines=out.splitlines(); markers=[(i,line[len(b'TARGETCTL_PATH='):]) for i,line in enumerate(lines) if line.startswith(b'TARGETCTL_PATH=')]
        if len(markers)!=1: _fail('doctor_nix_mismatch')
        position,resolved=markers[0]
        try: resolved=resolved.decode('ascii')
        except UnicodeDecodeError: _fail('doctor_nix_mismatch')
        version=_doctor_version(name,b'\n'.join(lines[position+1:]))
        if resolved!=expected or version!=native.get(name): _fail('doctor_nix_mismatch')
    return {'status':'matched','version':match.group(1).decode('ascii')}
def _doctor_live_lock(run_fd,run_identity,run_token,token):
    if not isinstance(token,str) or len(token)!=64 or any(c not in '0123456789abcdef' for c in token): _fail('doctor_source_mismatch')
    _assert_pinned_root(run_fd,run_identity); _read_marker(run_fd,'run',run_token)
    lock_fd,_=_open_regular(LOCK_NAME,dir_fd=run_fd)
    try:
        identity=_identity(lock_fd); state=_lock_state(lock_fd)
        if not hmac.compare_digest(state['token'],token) or not hmac.compare_digest(state['boot_id'],_boot_id()) or _doctor_time.monotonic_ns()>=state['deadline_monotonic_ns']: _fail('doctor_source_mismatch')
        _assert_named_identity(run_fd,LOCK_NAME,identity,'doctor_source_mismatch')
    finally: _doctor_os.close(lock_fd)
def _doctor_source_state(run_fd,data):
    fd,item=_open_regular('source.json',dir_fd=run_fd)
    try:
        raw=_doctor_os.read(fd,4097)
        if len(raw)>4096: _fail('doctor_source_mismatch')
    finally: _doctor_os.close(fd)
    try: state=_doctor_json.loads(raw.decode('ascii'))
    except (UnicodeDecodeError,ValueError): _fail('doctor_source_mismatch')
    if not isinstance(state,dict) or set(state)!={'schema_version','snapshot_id','applied_tree_hash','dirty'} or state.get('schema_version')!=1 or not isinstance(state.get('snapshot_id'),str) or not isinstance(state.get('applied_tree_hash'),str) or not isinstance(state.get('dirty'),bool) or not hmac.compare_digest(state['snapshot_id'],data['snapshot_id']) or not hmac.compare_digest(state['applied_tree_hash'],data['applied_tree_hash']) or state['dirty'] is not data['dirty']: _fail('doctor_source_mismatch')
    _assert_named_identity(run_fd,'source.json',{'device':item.st_dev,'inode':item.st_ino},'doctor_source_mismatch')
def _doctor_tree(work_fd,data):
    names=_source_entries(work_fd,data['entries']); hashed=[]
    for name in names:
        parent_fd,leaf=_entry_parent(work_fd,name)
        try:
            item=_doctor_os.stat(leaf,dir_fd=parent_fd,follow_symlinks=False)
            if not _doctor_stat.S_ISREG(item.st_mode): _fail('doctor_source_mismatch')
            fd,before=_open_entry_regular(leaf,dir_fd=parent_fd)
            try:
                digest=_doctor_hashlib.sha256(); size=0
                while True:
                    block=_doctor_os.read(fd,1048576)
                    if not block: break
                    digest.update(block); size+=len(block)
                after=_doctor_os.fstat(fd)
            finally: _doctor_os.close(fd)
            if (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size) or size!=after.st_size: _fail('doctor_source_mismatch')
            hashed.append((name,'file',int(bool(after.st_mode&_doctor_stat.S_IXUSR)),size,digest.digest()))
        finally: _doctor_os.close(parent_fd)
    if len(hashed)!=len(data['entries']) or _frame_hash(hashed)!=data['applied_tree_hash']: _fail('doctor_source_mismatch')
def _doctor_bound_source(work_fd,run_fd,work_identity,run_identity,paths,data):
    _assert_pinned_root(work_fd,work_identity); _read_marker(work_fd,'work',paths['work_token'])
    _doctor_live_lock(run_fd,run_identity,paths['run_token'],data['lock_token'])
    _source_validate_runtime_paths(paths,work_fd,run_fd)
    _assert_pinned_root(work_fd,work_identity); _assert_pinned_root(run_fd,run_identity)
    _read_marker(work_fd,'work',paths['work_token']); _doctor_live_lock(run_fd,run_identity,paths['run_token'],data['lock_token'])
    _doctor_source_state(run_fd,data); _doctor_tree(work_fd,data)
    _assert_pinned_root(work_fd,work_identity); _assert_pinned_root(run_fd,run_identity)
    _read_marker(work_fd,'work',paths['work_token']); _doctor_live_lock(run_fd,run_identity,paths['run_token'],data['lock_token'])
def _doctor_payload(data):
    if (not isinstance(data['snapshot_id'],str) or not isinstance(data['applied_tree_hash'],str) or
        any(len(data[key])!=64 or any(c not in '0123456789abcdef' for c in data[key]) for key in ('snapshot_id','applied_tree_hash')) or
        not isinstance(data['dirty'],bool) or data['allow_dirty']!=(data['snapshot_id'] if data['dirty'] else None)): _fail('doctor_dirty_unacknowledged')
@register_action('target_doctor')
def target_doctor(payload):
    d=_require_object(payload,{'model_path','drafter_path','run_dir','workdir','work_token','run_token','entries','snapshot_id','applied_tree_hash','dirty','allow_dirty','lock_token'})
    _doctor_payload(d)
    _,paths=_source_roots({key:d[key] for key in ('workdir','run_dir','model_path','drafter_path','work_token','run_token','entries')})
    work_fd,run_fd,work_identity,run_identity=_source_open(paths)
    try:
        _doctor_bound_source(work_fd,run_fd,work_identity,run_identity,paths,d)
        try: run_info=_doctor_os.fstat(run_fd); statvfs=_doctor_os.fstatvfs(run_fd); uname=_doctor_os.uname()
        except OSError: _fail('doctor_system_invalid')
        if not _doctor_stat.S_ISDIR(run_info.st_mode) or uname.sysname!='Linux' or not all(_DOCTOR_SAFE_SYSTEM.fullmatch(value) for value in (uname.sysname,uname.release,uname.machine)): _fail('doctor_system_invalid')
        tools=[]
        for name,path in _DOCTOR_TOOLS:
            try: item=_doctor_os.stat(path,follow_symlinks=False)
            except OSError: _fail('doctor_tool_missing')
            if not _doctor_stat.S_ISREG(item.st_mode) or item.st_uid not in (0,_doctor_os.geteuid()) or not item.st_mode&0o100: _fail('doctor_tool_missing')
            version=_doctor_version(name,_doctor_cmd((path,'--version')))
            if version is None: _fail('doctor_command_failed')
            tools.append({'name':name,'version':version,'location':path})
        _doctor_cmd(('/usr/local/cuda/bin/nvcc','-ccbin','/usr/bin/g++','--version'))
        nix=_doctor_nix(tools,work_fd)
        rows=_doctor_cmd(('/usr/bin/nvidia-smi','--query-gpu=name,compute_cap','--format=csv,noheader')).decode('ascii','ignore').strip().splitlines()
        if len(rows)!=1 or ',' not in rows[0]: _fail('doctor_gpu_invalid')
        name,cap=(value.strip().lower() for value in rows[0].split(',',1))
        if 'gb10' not in name or cap not in ('12.1','sm_121'): _fail('doctor_gpu_invalid')
        try: sync=open('/run/systemd/timesync/synchronized','rb').read(8).strip()==b'yes'
        except OSError: sync=False
        if not sync: _fail('doctor_time_unsynchronized')
        primary_weight_sha256=_doctor_hash(d['model_path']); draft_weight_sha256=_doctor_hash(d['drafter_path'])
        _doctor_bound_source(work_fd,run_fd,work_identity,run_identity,paths,d)
        memory=_doctor_os.sysconf('SC_PAGE_SIZE')*_doctor_os.sysconf('SC_PHYS_PAGES'); disk=statvfs.f_bavail*statvfs.f_frsize
        if memory<1 or disk<1: _fail('doctor_system_invalid')
        return {'status':'succeeded','failure_class':None,'os':'Linux','kernel':uname.release,'arch':uname.machine,'tools':tools,'gpu':{'platform':'GB10','compute_capability':'sm_121'},'memory_bytes':memory,'disk_bytes':disk,'time_sync':True,'primary_weight_sha256':primary_weight_sha256,'draft_weight_sha256':draft_weight_sha256,'nix':nix}
    finally:
        _doctor_os.close(work_fd); _doctor_os.close(run_fd)
'''



DOCTOR_EXTENSION = REMOTE_DOCTOR_EXTENSION