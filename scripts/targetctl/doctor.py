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
    if code in {"doctor_weight_invalid", "doctor_gpu_invalid", "doctor_system_invalid", "doctor_time_unsynchronized"}:
        return "contract_failed"
    return "preflight"


def _empty_result(code: str) -> DoctorResult:
    return DoctorResult("failed", _failure_class(code), None, None, None, tuple((name, None, None) for name, _ in DOCTOR_TOOLS), None, None, None, None, None, None)


def _validate_result_payload(payload: Any) -> DoctorResult:
    if not isinstance(payload, Mapping) or set(payload) != {"status", "failure_class", "os", "kernel", "arch", "tools", "gpu", "memory_bytes", "disk_bytes", "time_sync", "primary_weight_sha256", "draft_weight_sha256"}:
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
    return DoctorResult("succeeded", None, payload["os"], payload["kernel"], payload["arch"], tuple(clean_tools), ("GB10", "sm_121"), values[0], values[1], True, payload["primary_weight_sha256"], payload["draft_weight_sha256"])


def _run_checked(transport: _Transport, argv: tuple[str, ...]) -> bytes:
    result = transport.run(argv, timeout=COMMAND_TIMEOUT_SECONDS, cwd="/", env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    if result.timed_out:
        raise _error("doctor_command_timeout")
    if result.exit_code != 0:
        raise _error("doctor_command_failed")
    if len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES or len(result.stderr) > MAX_COMMAND_OUTPUT_BYTES:
        raise _error("doctor_command_failed")
    return result.stdout


def _tool_version(transport: _Transport, name: str, path: str) -> str:
    try:
        item = os.stat(path, follow_symlinks=False)
    except OSError:
        raise _error("doctor_tool_missing") from None
    if not stat.S_ISREG(item.st_mode) or item.st_uid not in {0, os.geteuid()} or not (item.st_mode & stat.S_IXUSR):
        raise _error("doctor_tool_missing")
    output = _run_checked(transport, (path, "--version"))
    match = _VERSION.search(output)
    if match is None:
        raise _error("doctor_command_failed")
    return match.group(1).decode("ascii")


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


def doctor(config: Any, transport: LocalTransport | SSHTransport, *, runtime: RuntimeInput | None = None) -> DoctorResult:
    """Collect the exact sanitized doctor facts for one target."""
    try:
        config.validate_for("doctor")
        inputs = _runtime(config, runtime)
        if isinstance(transport, SSHTransport):
            payload = {"model_path": inputs.model_path, "drafter_path": inputs.drafter_path, "run_dir": str(config.run_dir)}
            result = transport.run_helper("target_doctor", payload, extension_source=REMOTE_DOCTOR_EXTENSION, allowed_error_codes={"doctor_tool_missing", "doctor_command_timeout", "doctor_command_failed", "doctor_weight_invalid", "doctor_gpu_invalid", "doctor_system_invalid", "doctor_time_unsynchronized"})
            return _validate_result_payload(result)
        if not isinstance(transport, LocalTransport):
            raise _error("transport_invalid")
        run_dir = Path(config.local_run_dir)
        facts = _local_facts(run_dir)
        tools = tuple((name, _tool_version(transport, name, path), path) for name, path in DOCTOR_TOOLS)
        # Require NVCC to accept the fixed host C++ toolchain rather than merely
        # reporting that independently installed compiler binaries exist.
        _run_checked(transport, ("/usr/local/cuda/bin/nvcc", "-ccbin", "/usr/bin/g++", "--version"))
        return DoctorResult("succeeded", None, facts[0], facts[1], facts[2], tools, _gpu(transport), facts[3], facts[4], facts[5], _weight_hash(inputs.model_path), _weight_hash(inputs.drafter_path))
    except TargetError as exc:
        return _empty_result(exc.code)


run_doctor = doctor
collect_doctor = doctor

# The extension has no imports from the synchronized source tree.  It is kept
# intentionally small: remote execution returns the same finite payload that
# the controller validates above; no command output or paths leave the target.
REMOTE_DOCTOR_EXTENSION = r'''
import hashlib as _doctor_hashlib, os as _doctor_os, re as _doctor_re, stat as _doctor_stat, subprocess as _doctor_subprocess
_DOCTOR_TOOLS=(('nvidia-smi','/usr/bin/nvidia-smi'),('nvcc','/usr/local/cuda/bin/nvcc'),('gcc','/usr/bin/gcc'),('g++','/usr/bin/g++'),('make','/usr/bin/make'),('python3','/usr/bin/python3'),('git','/usr/bin/git'),('rsync','/usr/bin/rsync'),('cuobjdump','/usr/local/cuda/bin/cuobjdump'))
_DOCTOR_MAX_WEIGHT_BYTES=1<<40
def _doctor_hash(path):
    st=_doctor_os.stat(path,follow_symlinks=False)
    if not _doctor_stat.S_ISREG(st.st_mode) or st.st_uid!=_doctor_os.geteuid() or not 1<=st.st_size<=_DOCTOR_MAX_WEIGHT_BYTES: _fail('doctor_weight_invalid')
    fd=_doctor_os.open(path,_doctor_os.O_RDONLY|_doctor_os.O_CLOEXEC|getattr(_doctor_os,'O_NOFOLLOW',0))
    try:
        before=_doctor_os.fstat(fd); h=_doctor_hashlib.sha256()
        while True:
            b=_doctor_os.read(fd,1048576)
            if not b: break
            h.update(b)
        after=_doctor_os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size)!=(st.st_dev,st.st_ino,st.st_size) or (after.st_dev,after.st_ino,after.st_size)!=(before.st_dev,before.st_ino,before.st_size): _fail('doctor_weight_invalid')
        return h.hexdigest()
    finally: _doctor_os.close(fd)
def _doctor_cmd(argv):
    try: p=_doctor_subprocess.run(argv,stdin=_doctor_subprocess.DEVNULL,stdout=_doctor_subprocess.PIPE,stderr=_doctor_subprocess.PIPE,timeout=5,env={'LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin'},cwd='/',check=False)
    except _doctor_subprocess.TimeoutExpired: _fail('doctor_command_timeout')
    if p.returncode or len(p.stdout)>16384 or len(p.stderr)>16384: _fail('doctor_command_failed')
    return p.stdout
@register_action('target_doctor')
def target_doctor(payload):
    d=_require_object(payload,{'model_path','drafter_path','run_dir'})
    try: st=_doctor_os.stat(d['run_dir'],follow_symlinks=False); sv=_doctor_os.statvfs(d['run_dir']); u=_doctor_os.uname()
    except OSError: _fail('doctor_system_invalid')
    if not _doctor_stat.S_ISDIR(st.st_mode) or u.sysname!='Linux': _fail('doctor_system_invalid')
    tools=[]
    for n,p in _DOCTOR_TOOLS:
        try: x=_doctor_os.stat(p,follow_symlinks=False)
        except OSError: _fail('doctor_tool_missing')
        if not _doctor_stat.S_ISREG(x.st_mode) or x.st_uid not in (0,_doctor_os.geteuid()) or not x.st_mode&0o100: _fail('doctor_tool_missing')
        m=_doctor_re.search(rb'(?<![0-9])([0-9]+(?:\.[0-9]+){0,3})(?![0-9])',_doctor_cmd((p,'--version')))
        if not m: _fail('doctor_command_failed')
        tools.append({'name':n,'version':m.group(1).decode('ascii'),'location':p})
    _doctor_cmd(('/usr/local/cuda/bin/nvcc','-ccbin','/usr/bin/g++','--version'))
    rows=_doctor_cmd(('/usr/bin/nvidia-smi','--query-gpu=name,compute_cap','--format=csv,noheader')).decode('ascii','ignore').strip().splitlines()
    if len(rows)!=1 or ',' not in rows[0]: _fail('doctor_gpu_invalid')
    name,cap=(v.strip().lower() for v in rows[0].split(',',1))
    if 'gb10' not in name or cap not in ('12.1','sm_121'): _fail('doctor_gpu_invalid')
    try: sync=open('/run/systemd/timesync/synchronized','rb').read(8).strip()==b'yes'
    except OSError: sync=False
    if not sync: _fail('doctor_time_unsynchronized')
    return {'status':'succeeded','failure_class':None,'os':'Linux','kernel':u.release,'arch':u.machine,'tools':tools,'gpu':{'platform':'GB10','compute_capability':'sm_121'},'memory_bytes':_doctor_os.sysconf('SC_PAGE_SIZE')*_doctor_os.sysconf('SC_PHYS_PAGES'),'disk_bytes':sv.f_bavail*sv.f_frsize,'time_sync':True,'primary_weight_sha256':_doctor_hash(d['model_path']),'draft_weight_sha256':_doctor_hash(d['drafter_path'])}
'''



DOCTOR_EXTENSION = REMOTE_DOCTOR_EXTENSION