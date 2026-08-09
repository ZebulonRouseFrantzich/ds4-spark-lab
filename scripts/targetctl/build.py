"""Pinned native build operation for targetctl.

Only stable identities and a digest of producer-redacted build output leave this
module.  Private source roots, target roots, and command output remain local.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Mapping
from .common import TargetError, record_id_for, write_json_atomic
from .source import (
    SourceSnapshot,
    _SOURCE_EXTENSION,
    _expect_root_identities,
    _load_capabilities,
    _remote_payload,
    verify_applied_tree,
)
from .transport import CommandResult, LocalTransport, SSHTransport

MAKE = "/usr/bin/make"
CUOBJDUMP = "/usr/local/cuda/bin/cuobjdump"
MAX_BUILD_OUTPUT_BYTES = 1_048_576
BUILD_TIMEOUT_SECONDS = 3_600.0
_VERSION = re.compile(rb"(?<![0-9])([0-9]+(?:\.[0-9]+){0,3})(?![0-9])")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


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

    def controller_payload(self) -> dict[str, Any]:
        return {
            "status": self.status, "failure_class": self.failure_class,
            "source_snapshot_id": self.source_snapshot_id,
            "source_applied_tree_hash": self.source_applied_tree_hash,
            "build_id": self.build_id, "binary_sha256": self.binary_sha256,
            "command": self.command, "version": self.version,
            "binary_size": self.binary_size, "sass": self.sass,
            "build_log_sha256": self.build_log_sha256,
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
    return BuildResult("failed", _failure_class(code), None if snapshot is None else snapshot.snapshot_id, None if snapshot is None else snapshot.applied_tree_hash, None, None, None, None, None, None, None)


def _sha256_regular(path: Path, *, executable: bool = False) -> tuple[str, int]:
    try:
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_size < 1 or (executable and not before.st_mode & stat.S_IXUSR):
            raise OSError
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise _error("build_binary_invalid") from None
    try:
        pinned = os.fstat(fd)
        if (pinned.st_dev, pinned.st_ino, pinned.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise _error("build_binary_invalid")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size) != (pinned.st_dev, pinned.st_ino, pinned.st_size):
            raise _error("build_binary_invalid")
        return digest.hexdigest(), after.st_size
    finally:
        os.close(fd)


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


def _acquire_lock(run_dir: Path) -> int:
    try:
        fd = os.open(run_dir / ".targetctl-operation-lock-v1", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        item = os.fstat(fd)
        if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o600:
            raise OSError
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise _error("build_lock_busy") from None
        return fd
    except TargetError:
        raise
    except OSError:
        raise _error("build_lock_failed") from None


def _read_lifecycle(run_dir: Path) -> None:
    state_path = run_dir / "run.json"
    try:
        item = os.stat(state_path, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise _error("build_lifecycle_invalid") from None
    if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or item.st_size > 65536:
        raise _error("build_lifecycle_invalid")
    try:
        import json
        with open(state_path, "rb") as handle:
            data = json.loads(handle.read(65537).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        raise _error("build_lifecycle_invalid") from None
    if not isinstance(data, Mapping) or data.get("schema_version") != 1 or data.get("state") not in {"stopped", "stale_identity", "failed_startup"}:
        raise _error("build_running")


def _redacted_log(result: CommandResult, secrets: tuple[str, ...]) -> bytes:
    if len(result.stdout) > MAX_BUILD_OUTPUT_BYTES or len(result.stderr) > MAX_BUILD_OUTPUT_BYTES:
        raise _error("build_output_oversize")
    # Diagnostics can contain private roots and compiler environment.  Retain a
    # bounded producer-safe marker rather than a transformed raw fragment.
    return b"[REDACTED]\n"


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


def _version(transport: LocalTransport, binary: Path) -> str:
    result = transport.run((str(binary), "--version"), timeout=10.0, cwd="/", env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    if result.timed_out or result.exit_code != 0 or len(result.stdout) > 16 * 1024 or len(result.stderr) > 16 * 1024:
        raise _error("build_binary_invalid")
    match = _VERSION.search(result.stdout)
    if match is None:
        raise _error("build_binary_invalid")
    return match.group(1).decode("ascii")


def _sass(transport: LocalTransport, binary: Path) -> None:
    result = transport.run((CUOBJDUMP, "--dump-sass", str(binary)), timeout=30.0, cwd="/", env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    if result.timed_out or result.exit_code != 0 or len(result.stdout) > MAX_BUILD_OUTPUT_BYTES or len(result.stderr) > MAX_BUILD_OUTPUT_BYTES:
        raise _error("build_sass_invalid")
    # cuobjdump labels the architecture in the section header.  Both forms are
    # accepted because CUDA toolkits differ in their spelling, never an empty
    # or merely PTX-only result.
    if not result.stdout.strip() or not re.search(rb"\bsm_121a?\b", result.stdout):
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
    return record_id_for({"schema_version": 1, "source_snapshot_id": snapshot.snapshot_id, "source_applied_tree_hash": snapshot.applied_tree_hash, "binary_sha256": binary_hash, "version": version, "binary_size": size, "sass": "sm_121"})


def _build_local(config: Any, transport: LocalTransport, snapshot: SourceSnapshot, *, jobs: int | None) -> BuildResult:
    root = Path(config.source_root)
    run_dir = Path(config.local_run_dir)
    _safe_run_dir(run_dir)
    lock = _acquire_lock(run_dir)
    try:
        _read_lifecycle(run_dir)
        # Recheck while serialized; source may have changed after the caller's
        # initial snapshot/dirty decision.
        try:
            verify_applied_tree(root, snapshot)
        except TargetError:
            raise _error("build_source_mismatch") from None
        count = _jobs(jobs)
        result = transport.run((MAKE, "-C", "engine/ds4", "cuda-spark", f"-j{count}"), timeout=BUILD_TIMEOUT_SECONDS, cwd=str(root), env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
        log = _redacted_log(result, ())
        _atomic_bytes(run_dir / "build.log", log)
        log_hash = hashlib.sha256(log).hexdigest()
        if result.timed_out:
            raise _error("build_timeout")
        if result.exit_code != 0:
            raise _error("build_command_failed")
        binary = root / "engine" / "ds4" / "ds4-server"
        binary_hash, size = _sha256_regular(binary, executable=True)
        version = _version(transport, binary)
        _sass(transport, binary)
        build_id = _build_id(snapshot, binary_hash, version, size)
        state = {"schema_version": 1, "record_type": "build", "source_snapshot_id": snapshot.snapshot_id, "source_applied_tree_hash": snapshot.applied_tree_hash, "build_id": build_id, "binary_sha256": binary_hash, "binary_size": size, "version": version, "sass": "verified", "build_log_sha256": log_hash}
        write_json_atomic(run_dir / "build.json", state, mode=0o600)
        return BuildResult("succeeded", None, snapshot.snapshot_id, snapshot.applied_tree_hash, build_id, binary_hash, "make-cuda-spark", version, size, "verified", log_hash)
    finally:
        try:
            fcntl.flock(lock, fcntl.LOCK_UN)
        finally:
            os.close(lock)


def _remote_result(result: Mapping[str, Any]) -> BuildResult:
    """Parse the target_build helper response dict into a BuildResult."""
    if not isinstance(result, Mapping):
        raise _error("build_command_failed")
    return BuildResult(
        status=result.get("status", "failed"),
        failure_class=result.get("failure_class"),
        source_snapshot_id=result.get("source_snapshot_id"),
        source_applied_tree_hash=result.get("source_applied_tree_hash"),
        build_id=result.get("build_id"),
        binary_sha256=result.get("binary_sha256"),
        command=result.get("command"),
        version=result.get("version"),
        binary_size=result.get("binary_size"),
        sass=result.get("sass"),
        build_log_sha256=result.get("build_log_sha256"),
    )


def build(config: Any, transport: LocalTransport | SSHTransport, *, snapshot: SourceSnapshot, allow_dirty: str | None = None, jobs: int | None = None) -> BuildResult:
    """Build a previously synchronized snapshot with exact dirty acknowledgement."""
    checked: SourceSnapshot | None = snapshot if isinstance(snapshot, SourceSnapshot) else None
    try:
        config.validate_for("build")
        root = Path(config.source_root)
        checked = _validate_snapshot(snapshot, allow_dirty, root)
        if getattr(config, "mode", None) == "local":
            if not isinstance(transport, LocalTransport):
                raise _error("transport_invalid")
            return _build_local(config, transport, checked, jobs=jobs)
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
        lock = transport.run_helper("acquire_lock", {"run_dir": config.run_dir, "run_token": state["run_token"]}, allowed_error_codes={"lock_busy", "lock_failed", "unsafe_lock", "marker_mismatch", "unsafe_root"})
        if not isinstance(lock, Mapping) or not isinstance(lock.get("lock_token"), str):
            raise _error("build_lock_failed")
        primary: BaseException | None = None
        try:
            result = transport.run_helper(
                "target_build",
                {**source_payload, "snapshot_id": checked.snapshot_id, "applied_tree_hash": checked.applied_tree_hash, "dirty": checked.dirty, "allow_dirty": allow_dirty, "jobs": _jobs(jobs)},
                extension_source=_SOURCE_EXTENSION + REMOTE_BUILD_EXTENSION,
                allowed_error_codes={"source_lifecycle", "unexpected_entry", "unsafe_mount", "entry_changed", "marker_mismatch", "unsafe_entry", "unsafe_root", "unsafe_state", "missing_path", "path_overlap", "build_dirty_unacknowledged", "build_timeout", "build_command_failed", "build_output_oversize", "build_binary_invalid", "build_sass_invalid", "build_state_write_failed"},
                timeout=BUILD_TIMEOUT_SECONDS + 30.0,
            )
            return _remote_result(result)
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                transport.run_helper("release_lock", {"run_dir": config.run_dir, "run_token": state["run_token"], "lock_token": lock["lock_token"]}, allowed_error_codes={"lock_token_mismatch", "lock_release_failed", "unsafe_lock", "marker_mismatch", "unsafe_root"})
            except BaseException:
                if primary is None:
                    raise _error("build_lock_release_failed") from None
    except TargetError as exc:
        return _failed(exc.code, checked)


run_build = build
build_target = build



REMOTE_BUILD_EXTENSION = r'''
import hashlib as _build_hashlib, json as _build_json, os as _build_os, re as _build_re, stat as _build_stat, subprocess as _build_subprocess, secrets as _build_secrets
def _build_file_hash(path, executable=False):
    try:
        st=_build_os.stat(path,follow_symlinks=False)
        if not _build_stat.S_ISREG(st.st_mode) or st.st_uid!=_build_os.geteuid() or st.st_size<1 or executable and not st.st_mode&0o100: _fail('build_binary_invalid')
        fd=_build_os.open(path,_build_os.O_RDONLY|_build_os.O_CLOEXEC|getattr(_build_os,'O_NOFOLLOW',0))
    except HelperError: raise
    except OSError: _fail('build_binary_invalid')
    try:
        before=_build_os.fstat(fd); h=_build_hashlib.sha256()
        while True:
            b=_build_os.read(fd,1048576)
            if not b: break
            h.update(b)
        after=_build_os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size)!=(st.st_dev,st.st_ino,st.st_size) or (after.st_dev,after.st_ino,after.st_size)!=(before.st_dev,before.st_ino,before.st_size): _fail('build_binary_invalid')
        return h.hexdigest(),after.st_size
    finally: _build_os.close(fd)
def _build_atomic(run_fd,name,value):
    temp='.'+name+'.'+_build_secrets.token_hex(16)
    try:
        fd=_build_os.open(temp,_build_os.O_WRONLY|_build_os.O_CREAT|_build_os.O_EXCL|_build_os.O_CLOEXEC|getattr(_build_os,'O_NOFOLLOW',0),0o600,dir_fd=run_fd)
        try:
            view=memoryview(value)
            while view: view=view[_build_os.write(fd,view):]
            _build_os.fsync(fd)
        finally: _build_os.close(fd)
        _build_os.replace(temp,name,src_dir_fd=run_fd,dst_dir_fd=run_fd); _build_os.fsync(run_fd)
    except OSError: _fail('build_state_write_failed')
def _build_record_id(value):
    raw=_build_json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    parts=(b'targetctl.record.v1',raw); h=_build_hashlib.sha256()
    for part in parts: h.update(len(part).to_bytes(8,'big')); h.update(part)
    return h.hexdigest()
@register_action('target_build')
def target_build(payload):
    keys={'workdir','run_dir','model_path','drafter_path','work_token','run_token','entries','snapshot_id','applied_tree_hash','dirty','allow_dirty','jobs'}
    data=_require_object(payload,keys)
    if not isinstance(data['dirty'],bool) or data['allow_dirty'] != (data['snapshot_id'] if data['dirty'] else None) or not isinstance(data['jobs'],int) or not 1<=data['jobs']<=256: _fail('build_dirty_unacknowledged')
    _,paths=_source_roots({key:data[key] for key in ('workdir','run_dir','model_path','drafter_path','work_token','run_token','entries')})
    work_fd,run_fd,work_identity,run_identity=_source_open(paths)
    try:
        names=_source_entries(work_fd,data['entries']); hashed=[]
        for name in names:
            parent,leaf=_entry_parent(work_fd,name)
            try:
                fd,before=_open_entry_regular(leaf,dir_fd=parent)
                try:
                    h=_build_hashlib.sha256(); size=0
                    while True:
                        b=_build_os.read(fd,1048576)
                        if not b: break
                        h.update(b); size+=len(b)
                    after=_build_os.fstat(fd)
                finally: _build_os.close(fd)
                if (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size): _fail('entry_changed')
                hashed.append((name,'file',int(bool(after.st_mode&0o100)),size,h.digest()))
            finally: _build_os.close(parent)
        if _frame_hash(hashed)!=data['applied_tree_hash']: _fail('entry_changed')
        cwd='/proc/self/fd/%d'%work_fd
        try: made=_build_subprocess.run(('/usr/bin/make','-C','engine/ds4','cuda-spark','-j%d'%data['jobs']),stdin=_build_subprocess.DEVNULL,stdout=_build_subprocess.PIPE,stderr=_build_subprocess.PIPE,cwd=cwd,env={'LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin'},timeout=3600,check=False)
        except _build_subprocess.TimeoutExpired: _build_atomic(run_fd,'build.log',b'[REDACTED]\\n'); _fail('build_timeout')
        if len(made.stdout)>1048576 or len(made.stderr)>1048576: _build_atomic(run_fd,'build.log',b'[REDACTED_OVERSIZE]\\n'); _fail('build_output_oversize')
        # Raw producer output never reaches disk: this fixed log marker is safe and bounded.
        log=b'[REDACTED]\\n'; _build_atomic(run_fd,'build.log',log)
        if made.returncode: _fail('build_command_failed')
        binary=cwd+'/engine/ds4/ds4-server'; digest,size=_build_file_hash(binary,True)
        try: version_run=_build_subprocess.run((binary,'--version'),stdin=_build_subprocess.DEVNULL,stdout=_build_subprocess.PIPE,stderr=_build_subprocess.PIPE,cwd='/',env={'LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin'},timeout=10,check=False)
        except _build_subprocess.TimeoutExpired: _fail('build_binary_invalid')
        version_match=None if version_run.returncode or len(version_run.stdout)>16384 or len(version_run.stderr)>16384 else _build_re.search(rb'(?<![0-9])([0-9]+(?:\\.[0-9]+){0,3})(?![0-9])',version_run.stdout)
        if not version_match: _fail('build_binary_invalid')
        version=version_match.group(1).decode('ascii')
        try: sass=_build_subprocess.run(('/usr/local/cuda/bin/cuobjdump','--dump-sass',binary),stdin=_build_subprocess.DEVNULL,stdout=_build_subprocess.PIPE,stderr=_build_subprocess.PIPE,cwd='/',env={'LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin'},timeout=30,check=False)
        except _build_subprocess.TimeoutExpired: _fail('build_sass_invalid')
        if sass.returncode or len(sass.stdout)>1048576 or len(sass.stderr)>1048576 or not sass.stdout.strip() or not _build_re.search(rb'\\bsm_121a?\\b',sass.stdout): _fail('build_sass_invalid')
        ident={'schema_version':1,'source_snapshot_id':data['snapshot_id'],'source_applied_tree_hash':data['applied_tree_hash'],'binary_sha256':digest,'version':version,'binary_size':size,'sass':'sm_121'}
        build_id=_build_record_id(ident); log_hash=_build_hashlib.sha256(log).hexdigest()
        state={'schema_version':1,'record_type':'build','source_snapshot_id':data['snapshot_id'],'source_applied_tree_hash':data['applied_tree_hash'],'build_id':build_id,'binary_sha256':digest,'binary_size':size,'version':version,'sass':'verified','build_log_sha256':log_hash}
        _build_atomic(run_fd,'build.json',_build_json.dumps(state,sort_keys=True,separators=(',',':')).encode('ascii'))
        _assert_pinned_root(work_fd,work_identity); _assert_pinned_root(run_fd,run_identity); _read_marker(run_fd,'run',paths['run_token'])
        return {'status':'succeeded','failure_class':None,'source_snapshot_id':data['snapshot_id'],'source_applied_tree_hash':data['applied_tree_hash'],'build_id':build_id,'binary_sha256':digest,'command':'make-cuda-spark','version':version,'binary_size':size,'sass':'verified','build_log_sha256':log_hash}
    finally:
        _build_os.close(work_fd); _build_os.close(run_fd)
'''


BUILD_EXTENSION = REMOTE_BUILD_EXTENSION