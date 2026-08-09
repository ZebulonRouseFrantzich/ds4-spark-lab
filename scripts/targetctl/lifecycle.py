"""Safe loopback lifecycle operations for the targetctl Phase 01 target."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Iterator, Mapping

from .common import TargetError
from .redaction import REMOTE_REDACTION_EXTENSION
# These names are also present when the embedded extension executes in the
# standalone remote-helper namespace; importing them documents that contract.
from .remote import LAUNCH_PROFILE, RUN_STATE_SCHEMA_VERSION, _is_hex_digest, _valid_run_state
from .transport import LocalTransport, SSHForward, SSHTransport

RUN_SCHEMA_VERSION = 1
MAX_LOG_BYTES = 1_048_576
MAX_HTTP_BODY_BYTES = 1_048_576
MAX_RUN_ID_LENGTH = 64
DEFAULT_LEASE_SECONDS = 120
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_RUN_ID = re.compile(r"[a-z0-9][a-z0-9-]{7,63}\Z", re.ASCII)
_STATES = frozenset(("starting", "running", "stopped", "stale_identity", "failed_startup"))
# Lifecycle-specific codes emitted by _LIFECYCLE_EXTENSION.  transport adds its
# base helper codes separately, so controller-only failures and base codes do
# not belong in this bounded extension allowlist.
_ERRORS = frozenset((
    "invalid_runtime_inputs",
    "run_active",
    "run_cleanup_required",
    "startup_failed",
    "startup_timeout",
    "log_unavailable",
    "serve_not_dispatched",
))


def _fail(code: str, message: str = "target lifecycle is unavailable") -> None:
    raise TargetError(code, message)


def _hex(value: Any) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        _fail("invalid_runtime_inputs", "runtime inputs are invalid")
    return value


def _path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or not value.isascii() or "\x00" in value or not value.startswith("/"):
        _fail("invalid_runtime_inputs", "runtime inputs are invalid")
    return value


@dataclass(frozen=True, slots=True)
class RuntimeInputs:
    """Invocation-only private values. They are never copied into artifacts."""
    model_path: str
    drafter_path: str
    source_snapshot_id: str
    applied_tree_hash: str
    build_id: str
    work_token: str = ""
    run_token: str = ""
    port: int = 0
    binary_path: str = "engine/ds4/ds4-server"
    startup_timeout: float = 45.0
    smoke_timeout: float = 45.0
    lease_seconds: int = DEFAULT_LEASE_SECONDS

    def __post_init__(self) -> None:
        _path(self.model_path)
        _path(self.drafter_path)
        for item in (self.source_snapshot_id, self.applied_tree_hash, self.build_id):
            _hex(item)
        if bool(self.work_token) != bool(self.run_token):
            _fail("invalid_runtime_inputs", "runtime inputs are invalid")
        if self.work_token:
            _hex(self.work_token)
            _hex(self.run_token)
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            _fail("invalid_runtime_inputs", "runtime inputs are invalid")
        if not isinstance(self.binary_path, str) or not self.binary_path or self.binary_path.startswith("/") or ".." in self.binary_path.split("/"):
            _fail("invalid_runtime_inputs", "runtime inputs are invalid")
        for value in (self.startup_timeout, self.smoke_timeout):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 < value <= 600:
                _fail("invalid_runtime_inputs", "runtime inputs are invalid")
        if not isinstance(self.lease_seconds, int) or isinstance(self.lease_seconds, bool) or not 1 <= self.lease_seconds <= 7185:
            _fail("invalid_runtime_inputs", "runtime inputs are invalid")


@dataclass(frozen=True, slots=True)
class LaunchProfile:
    """Bounded non-private evidence for the one supported Phase 01 launch."""

    schema_version: int = 1
    accelerator: str = "cuda"
    context_tokens: int = 32768
    bind: str = "loopback"
    continuation_mtp_mode: int = 2
    dspark_enabled: bool = True
    drafter_enabled: bool = True

    def controller_payload(self) -> dict[str, Any]:
        return {
            key: getattr(self, key)
            for key in (
                "schema_version", "accelerator", "context_tokens", "bind",
                "continuation_mtp_mode", "dspark_enabled", "drafter_enabled",
            )
        }


FIXED_LAUNCH_PROFILE = LaunchProfile(**LAUNCH_PROFILE)


@dataclass(frozen=True, slots=True)
class RunResult:
    run_id: str
    state: str
    port: int
    source_snapshot_id: str
    build_id: str
    binary_sha256: str | None = None
    supervisor_pid: int | None = None
    supervisor_start_ticks: int | None = None
    child_pid: int | None = None
    child_start_ticks: int | None = None
    launch_profile: LaunchProfile = FIXED_LAUNCH_PROFILE

    def controller_payload(self) -> dict[str, Any]:
        payload = {
            key: getattr(self, key)
            for key in (
                "run_id", "state", "source_snapshot_id", "build_id",
                "binary_sha256", "supervisor_pid", "supervisor_start_ticks",
                "child_pid", "child_start_ticks", "port",
            )
        }
        payload["launch_profile"] = self.launch_profile.controller_payload()
        return payload


@dataclass(frozen=True, slots=True)
class StatusResult:
    run_id: str | None
    state: str
    active: bool
    run: RunResult | None = None


@dataclass(frozen=True, slots=True)
class SmokeResult:
    run_id: str
    status: str
    failure_class: str | None = None
    readiness_http: int | None = None
    models_http: int | None = None
    contract: str = "failed"
    primary_weight_sha256: str | None = None
    draft_weight_sha256: str | None = None
    duration_ns: int = 0
    run: RunResult | None = None
    cleanup: CleanupResult | None = None

    def controller_payload(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in ("run_id", "status", "failure_class", "readiness_http", "models_http", "contract", "primary_weight_sha256", "draft_weight_sha256", "duration_ns")}


@dataclass(frozen=True, slots=True)
class CleanupResult:
    run_id: str | None
    status: str
    process: str = "unknown"
    socket: str = "unknown"
    lock: str = "unknown"
    temp: str = "unknown"
    server_log_sha256: str | None = None
    failure_class: str | None = None

    def controller_payload(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in ("run_id", "status", "failure_class", "process", "socket", "lock", "temp", "server_log_sha256")}


def _run_id(value: str | None = None) -> str:
    if value is None:
        return "run-" + secrets.token_hex(12)
    if not isinstance(value, str) or _RUN_ID.fullmatch(value) is None:
        _fail("invalid_run_id", "run ID is invalid")
    return value


def _roots(config: Any, runtime: RuntimeInputs) -> dict[str, Any]:
    local_mode = getattr(config, "mode", None) == "local"
    run_dir = str(getattr(config, "local_run_dir")) if local_mode else getattr(config, "run_dir", None)
    workdir = str(getattr(config, "source_root")) if local_mode else getattr(config, "workdir", None)
    if not local_mode and not runtime.work_token:
        _fail("invalid_runtime_inputs", "runtime inputs are invalid")
    return {
        "workdir": _path(workdir), "run_dir": _path(run_dir),
        "model_path": runtime.model_path, "drafter_path": runtime.drafter_path,
        "local_mode": local_mode, "work_token": runtime.work_token,
        "run_token": runtime.run_token,
    }


def _request_roots(config: Any, runtime: RuntimeInputs) -> dict[str, Any]:
    """Compatibility wrapper for read-only lifecycle requests."""
    return _roots(config, runtime)


def _lc_payload(config: Any, runtime: RuntimeInputs, **extra: Any) -> dict[str, Any]:
    """Build the full helper payload dict from controller config+runtime."""
    return {**_roots(config, runtime), **extra}


@contextmanager
def local_operation_lock(run_dir: str) -> Iterator[None]:
    """Acquire the build-compatible XDG operation lock without touching source."""
    root = Path(_path(run_dir))
    fd: int | None = None
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        item = root.stat(follow_symlinks=False)
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o700:
            raise OSError
        fd = os.open(root / ".targetctl-operation-lock-v1", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        item = os.fstat(fd)
        if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o600:
            raise OSError
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        _fail("run_active", "target lifecycle is active")
    except OSError:
        if fd is not None:
            os.close(fd)
        _fail("unsafe_root", "local run root is unsafe")
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _call(transport: LocalTransport | SSHTransport, action: str, payload: Mapping[str, Any], *, timeout: float | None = 60.0) -> Any:
    """Invoke one lifecycle helper with the extension and bounded response timeout."""
    return transport.run_helper(action, payload, extension_source=_LIFECYCLE_EXTENSION, allowed_error_codes=_ERRORS, timeout=timeout)

# ---------------------------------------------------------------------------
# Helper extension - runs inside the remote.py module namespace.
# ---------------------------------------------------------------------------
_LIFECYCLE_EXTENSION = r'''_LC_SUPERVISOR_SOURCE = """import hashlib
import json
import os
import select
import signal
import subprocess
import stat
import sys
import time

RUN_FD = int(os.environ['TARGETCTL_SV_RUN_FD'])
MAX_LOG_BYTES = 1048576

def _read_json(name):
  fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0), dir_fd=RUN_FD)
  try:
    raw = os.read(fd, 65537)
    if len(raw) > 65536 or os.read(fd, 1):
      raise ValueError('invalid_spec')
  finally:
    os.close(fd)
  return json.loads(raw.decode('ascii'))

def _atom_json(name, value):
  raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
  temp = '.' + name + '.' + str(os.getpid()) + '.' + str(time.monotonic_ns())
  try:
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=RUN_FD)
    try:
      os.write(fd, raw)
      os.fsync(fd)
    finally:
      os.close(fd)
    os.replace(temp, name, src_dir_fd=RUN_FD, dst_dir_fd=RUN_FD)
    os.fsync(RUN_FD)
  except BaseException:
    try:
      os.unlink(temp, dir_fd=RUN_FD)
    except OSError:
      pass
    raise

def _ticks(pid):
  try:
    with open('/proc/%d/stat' % pid, encoding='ascii') as handle:
      raw = handle.read(4096)
    return int(raw[raw.rfind(')') + 2:].split()[19])
  except (OSError, ValueError, IndexError):
    return None

def _cmdline_hash(pid):
  try:
    with open('/proc/%d/cmdline' % pid, 'rb') as handle:
      raw = handle.read(4096).rstrip(b'\0')
    if not raw:
      return None
    return hashlib.sha256(b' '.join(raw.split(b'\0'))).hexdigest()
  except OSError:
    return None

def _group_present(pgid):
  if not isinstance(pgid, int) or pgid <= 1:
    return None
  try:
    os.killpg(pgid, 0)
    return True
  except ProcessLookupError:
    return False
  except OSError:
    return None

def _unlink_owned(name):
  try:
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0), dir_fd=RUN_FD)
  except OSError:
    return
  try:
    item = os.fstat(fd)
    if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o600:
      return
  finally:
    os.close(fd)
  try:
    os.unlink(name, dir_fd=RUN_FD)
  except OSError:
    pass

def _release_lifecycle_lease(run_id):
  if not isinstance(run_id, str):
    return
  lock_fd = None
  try:
    lock_fd = os.open('.targetctl-operation-lock-v1', os.O_RDONLY | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0), dir_fd=RUN_FD)
    item = os.fstat(lock_fd)
    raw = os.read(lock_fd, 1025)
    lock = json.loads(raw.decode('ascii'))
    named = os.stat('.targetctl-operation-lock-v1', dir_fd=RUN_FD, follow_symlinks=False)
    if (
      len(raw) > 1024
      or not stat.S_ISREG(item.st_mode)
      or item.st_uid != os.geteuid()
      or stat.S_IMODE(item.st_mode) != 0o600
      or item.st_nlink != 1
      or (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_nlink) !=
         (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_nlink)
      or not isinstance(lock, dict)
      or set(lock) != {'boot_id', 'deadline_monotonic_ns', 'token', 'lifecycle_run_id'}
      or lock.get('lifecycle_run_id') != run_id
      or not isinstance(lock.get('token'), str)
      or len(lock['token']) != 64
      or any(character not in '0123456789abcdef' for character in lock['token'])
      or not isinstance(lock.get('boot_id'), str)
      or len(lock['boot_id']) != 36
      or any(character not in '0123456789abcdef-' for character in lock['boot_id'])
      or not isinstance(lock.get('deadline_monotonic_ns'), int)
      or isinstance(lock['deadline_monotonic_ns'], bool)
      or lock['deadline_monotonic_ns'] < 1
    ):
      return
    os.unlink('.targetctl-operation-lock-v1', dir_fd=RUN_FD)
    os.fsync(RUN_FD)
  except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
    pass
  finally:
    if lock_fd is not None:
      try:
        os.close(lock_fd)
      except OSError:
        pass

spec = {}

child = None
child_pgid = None
log_fd = None
redactor = None
written = 0
stopping = False
deadline = None
failure_stage = 'spec'

def _flush():
  global written
  if redactor is None or log_fd is None:
    return
  try:
    if written >= MAX_LOG_BYTES:
      redactor['full'] = True
      return
    data = bytes(redactor['out'])[:MAX_LOG_BYTES - written]
    while data:
      count = os.write(log_fd, data)
      written += count
      data = data[count:]
  finally:
    redactor['out'].clear()

def _stop(signum, frame):
  global stopping
  stopping = True

def _consume(chunk):
  _targetctl_redact_feed(redactor, chunk)
  _flush()

def _drain():
  if child is None or child.stdout is None:
    return
  while True:
    try:
      chunk = os.read(child.stdout.fileno(), 65536)
    except BlockingIOError:
      break
    except OSError:
      break
    if not chunk:
      break
    _consume(chunk)

signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGHUP, _stop)
try:
  spec = _read_json(sys.argv[1])
  profile = {
    'schema_version': 1, 'accelerator': 'cuda', 'context_tokens': 32768,
    'bind': 'loopback', 'continuation_mtp_mode': 2,
    'dspark_enabled': True, 'drafter_enabled': True,
  }
  if (
    not isinstance(spec, dict)
    or set(spec) != {'argv', 'drafter', 'secrets', 'lease_seconds', 'run_id', 'launch_profile'}
    or not isinstance(spec['argv'], list)
    or not isinstance(spec['lease_seconds'], int)
    or not isinstance(spec['run_id'], str)
    or spec['launch_profile'] != profile
    or spec['lease_seconds'] < 1
  ):
    raise ValueError('invalid_spec')
  state = _read_json('run.json')
  supervisor_ticks = _ticks(os.getpid())
  supervisor_cmdline_sha256 = _cmdline_hash(os.getpid())
  if (
    not isinstance(state, dict)
    or state.get('run_id') != spec['run_id']
    or state.get('state') != 'starting'
    or state.get('supervisor_pid') is not None
    or state.get('launch_profile') != profile
    or supervisor_ticks is None
    or supervisor_cmdline_sha256 is None
  ):
    raise ValueError('invalid_state')
  state['supervisor_pid'] = os.getpid()
  state['supervisor_start_ticks'] = supervisor_ticks
  state['supervisor_cmdline_sha256'] = supervisor_cmdline_sha256
  _atom_json('run.json', state)
  failure_stage = 'log_open'
  redactor = _targetctl_redactor(spec.get('secrets', ()))
  log_fd = os.open('server.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=RUN_FD)
  failure_stage = 'child_spawn'
  env = {'LANG': 'C', 'LC_ALL': 'C', 'PATH': '/usr/bin:/bin', 'DS4_CONT_MTP_MODE':'2', 'DS4_CONT_DSPARK':'1', 'DS4_DSPARK_MODEL': spec.get('drafter', '')}
  child = subprocess.Popen(spec['argv'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True, pass_fds=(int(os.environ['TARGETCTL_SV_DIR_FD']),), env=env)
  failure_stage = 'child_identity'
  child_pgid = child.pid
  child_ticks = None
  child_cmdline_sha256 = None
  previous_identity = None
  identity_deadline = time.monotonic() + 1
  while time.monotonic() < identity_deadline and child.poll() is None:
    candidate = (_ticks(child.pid), _cmdline_hash(child.pid), os.getpgid(child.pid))
    if candidate == previous_identity and candidate[0] is not None and candidate[1] is not None and candidate[2] == child_pgid:
      child_ticks, child_cmdline_sha256, _ = candidate
      break
    previous_identity = candidate
    time.sleep(.01)
  if child_ticks is None or child_cmdline_sha256 is None:
    raise OSError('unexpected_child_identity')
  state = _read_json('run.json')
  if state.get('run_id') != spec['run_id'] or state.get('supervisor_pid') != os.getpid():
    raise ValueError('invalid_state')
  state['child_pid'] = child.pid
  state['child_start_ticks'] = child_ticks
  state['child_pgid'] = child_pgid
  state['child_cmdline_sha256'] = child_cmdline_sha256
  _atom_json('run.json', state)
  _atom_json('ack.json', {
    'child_pid': child.pid, 'child_start_ticks': child_ticks,
    'child_pgid': child_pgid, 'child_cmdline_sha256': child_cmdline_sha256,
    'supervisor_pid': os.getpid(), 'supervisor_start_ticks': supervisor_ticks,
    'supervisor_cmdline_sha256': supervisor_cmdline_sha256,
  })
  failure_stage = 'monitor'
  os.set_blocking(child.stdout.fileno(), False)
  deadline = time.monotonic() + spec['lease_seconds']
  while child.poll() is None and not stopping and time.monotonic() < deadline:
    ready, _, _ = select.select([child.stdout], [], [], min(0.1, max(0, deadline - time.monotonic())))
    if ready:
      _drain()
except BaseException:
  if log_fd is not None:
    try:
      os.write(log_fd, ('[targetctl-supervisor:%s]\n' % failure_stage).encode('ascii'))
      os.fsync(log_fd)
    except OSError:
      pass
finally:
  if child is not None:
    try:
      if child.poll() is None and child_pgid is not None:
        os.killpg(child_pgid, signal.SIGTERM)
    except OSError:
      pass
    try:
      child.wait(timeout=3)
    except subprocess.TimeoutExpired:
      try:
        if child_pgid is not None:
          os.killpg(child_pgid, signal.SIGKILL)
      except OSError:
        pass
      try:
        child.wait()
      except OSError:
        pass
    except OSError:
      pass
    try:
      _drain()
    except (OSError, ValueError):
      pass
    try:
      child.stdout.close()
    except (AttributeError, OSError):
      pass
  child_group_cleared = child_pgid is None
  if child_pgid is not None:
    group_present = _group_present(child_pgid)
    if group_present:
      try:
        os.killpg(child_pgid, signal.SIGKILL)
      except OSError:
        pass
      group_deadline = time.monotonic() + 3
      while time.monotonic() < group_deadline:
        group_present = _group_present(child_pgid)
        if group_present is not True:
          break
        time.sleep(.05)
    child_group_cleared = group_present is False
  if redactor is not None:
    try:
      _targetctl_redact_feed(redactor, b'', final=True)
      _flush()
    except (OSError, ValueError):
      pass
    finally:
      redactor['out'].clear()
  if log_fd is not None:
    try:
      os.close(log_fd)
    except OSError:
      pass
  owned_run = False
  try:
    state = _read_json('run.json')
    if isinstance(state, dict) and state.get('run_id') == spec.get('run_id'):
      owned_run = True
      if state.get('state') in ('starting', 'running'):
        intentional = stopping or (deadline is not None and time.monotonic() >= deadline)
        state['state'] = 'failed_startup' if child is None else ('stopped' if intentional else 'stale_identity')
        _atom_json('run.json', state)
  except (OSError, ValueError, json.JSONDecodeError):
    pass
  if owned_run and child_group_cleared:
    _release_lifecycle_lease(spec.get('run_id'))
  for name in ('launch.json', 'ack.json', 'supervisor.py'):
    _unlink_owned(name)
"""

_LC_MAX_LOG=1048576
_LC_MAX_STATE=65536
_LC_STATES={'starting','running','stopped','stale_identity','failed_startup'}
def _lc_hex(value):
  return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)
def _lc_id(value):
  return isinstance(value,str) and 8<=len(value)<=64 and all(c.islower() or c.isdigit() or c=='-' for c in value) and value[0].isalnum()
def _lc_atom(root_fd,name,data):
  raw=json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
  if len(raw)>_LC_MAX_STATE:_fail('unsafe_state')
  temp='.'+name+'.'+secrets.token_hex(12)
  try:
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=root_fd)
    try:os.write(fd,raw);os.fsync(fd)
    finally:os.close(fd)
    os.replace(temp,name,src_dir_fd=root_fd,dst_dir_fd=root_fd);os.fsync(root_fd)
  except OSError:_fail('unsafe_state')
def _lc_read(root_fd,name):
  fd,item=_open_regular(name,dir_fd=root_fd)
  try:
    raw=os.read(fd,_LC_MAX_STATE+1);after=os.fstat(fd)
    if len(raw)>_LC_MAX_STATE or os.read(fd,1) or (item.st_dev,item.st_ino,item.st_size)!=(after.st_dev,after.st_ino,after.st_size) or item.st_size!=len(raw):_fail('unsafe_state')
  finally:os.close(fd)
  try:data=json.loads(raw.decode('ascii'))
  except(UnicodeDecodeError,json.JSONDecodeError):_fail('unsafe_state')
  return data
def _lc_read_state(root_fd):
  state=_lc_read(root_fd,'run.json')
  if not _valid_run_state(state):_fail('unsafe_state')
  return state
def _lc_write_state(root_fd,state):
  if not _valid_run_state(state):_fail('unsafe_state')
  _lc_atom(root_fd,'run.json',state)
def _lc_ticks(pid):
  try:
    with open('/proc/%d/stat'%pid,'r') as f:raw=f.read(4096)
    close=raw.rfind(')');fields=raw[close+2:].split()
    return int(fields[19])
  except(OSError,ValueError,IndexError):return None
def _lc_pgid(pid):
  try:return os.getpgid(pid)
  except OSError:return None
def _lc_group_present(pgid):
  if not isinstance(pgid,int)or pgid<=1:return None
  try:os.killpg(pgid,0);return True
  except ProcessLookupError:return False
  except OSError:return None
def _lc_pid_identity(state):
  pid=state.get('supervisor_pid');ticks=state.get('supervisor_start_ticks')
  try:
    return isinstance(pid,int) and pid>1 and isinstance(ticks,int) and _lc_ticks(pid)==ticks and os.stat('/proc/%d'%pid).st_uid==os.geteuid()
  except OSError:return False
def _lc_supervisor_identity(state):
  pid=state.get('supervisor_pid')
  if not isinstance(pid,int) or pid<=1:return False
  ticks=state.get('supervisor_start_ticks');expected=state.get('supervisor_cmdline_sha256')
  if not isinstance(ticks,int) or _lc_ticks(pid)!=ticks or not _is_hex_digest(expected):return False
  try:
    if os.stat('/proc/%d'%pid).st_uid!=os.geteuid():return False
    cmdline=open('/proc/%d/cmdline'%pid,'rb').read(4096).rstrip(b'\0')
    return bool(cmdline) and hmac.compare_digest(hashlib.sha256(b' '.join(cmdline.split(b'\0'))).hexdigest(),expected)
  except OSError:return False
def _lc_child_identity(state):
  pid=state.get('child_pid');ticks=state.get('child_start_ticks');pgid=state.get('child_pgid');expected=state.get('child_cmdline_sha256')
  if not isinstance(pid,int) or pid<=1 or not isinstance(ticks,int) or pgid!=pid or not _is_hex_digest(expected) or _lc_ticks(pid)!=ticks or _lc_pgid(pid)!=pid:return False
  try:
    cmdline=open('/proc/%d/cmdline'%pid,'rb').read(4096).rstrip(b'\0')
    return os.stat('/proc/%d'%pid).st_uid==os.geteuid() and bool(cmdline) and hmac.compare_digest(hashlib.sha256(b' '.join(cmdline.split(b'\0'))).hexdigest(),expected)
  except OSError:return False
def _lc_live(state):
  return _lc_supervisor_identity(state) and _lc_child_identity(state) and _lc_listener(state.get('port'),state.get('child_pid',0),state.get('listener_inode')) is not None

def _lc_listener(port,pid,expected=None):
  wanted='%04X'%port;inodes=set()
  for name in('/proc/net/tcp','/proc/net/tcp6'):
    try:
      for line in open(name,encoding='ascii').read().splitlines()[1:]:
        fields=line.split();host,number=fields[1].rsplit(':',1)
        if len(fields)>9 and fields[3]=='0A' and number==wanted and host in('0100007F','00000000000000000000000000000001') and fields[7]==str(os.geteuid()):inodes.add(fields[9])
    except OSError:pass
  try:owned=set(os.listdir('/proc/%d/fd'%pid))
  except OSError:return None
  for fd in owned:
    try:
      link=os.readlink('/proc/%d/fd/%s'%(pid,fd))
      if link.startswith('socket:[') and link[8:-1]in inodes and(expected is None or link[8:-1]==expected):return link[8:-1]
    except OSError:pass
  return None
def _lc_hash_fd(fd, executable=False):
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or (executable and not (before.st_mode&0o111)):_fail('startup_failed')
  digest=hashlib.sha256()
  while True:
    block=os.read(fd,65536)
    if not block:break
    digest.update(block)
  after=os.fstat(fd)
  if(before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid,after.st_size,after.st_mtime_ns,after.st_ctime_ns):_fail('startup_failed')
  return digest.hexdigest()
def _lc_binary_hash(path):
  try:
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|getattr(os,'O_NOFOLLOW',0))
  except OSError:_fail('startup_failed')
  try:return _lc_hash_fd(fd)
  except OSError:_fail('startup_failed')
  finally:os.close(fd)
def _lc_binary_hash_at(root_fd,path):
  if not isinstance(path,str) or not path or path.startswith('/') or any(part in ('','.','..') for part in path.split('/')):_fail('startup_failed')
  try:directory=os.dup(root_fd)
  except OSError:_fail('startup_failed')
  try:
    for part in path.split('/')[:-1]:
      next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|getattr(os,'O_NOFOLLOW',0),dir_fd=directory)
      os.close(directory);directory=next_fd
    fd=os.open(path.rsplit('/',1)[-1],os.O_RDONLY|os.O_CLOEXEC|getattr(os,'O_NOFOLLOW',0),dir_fd=directory)
  except OSError:
    _fail('startup_failed')
  finally:
    os.close(directory)
  try:return _lc_hash_fd(fd,executable=True)
  except OSError:_fail('startup_failed')
  finally:os.close(fd)
def _lc_roots(payload):
  if payload.get('local_mode'):
    for key in('workdir','run_dir','model_path','drafter_path'):_validate_absolute_path(payload[key])
    return payload
  fields={k:payload[k] for k in('workdir','run_dir','model_path','drafter_path','work_token','run_token')}
  return _root_payload(fields,require_tokens=True)
def _lc_open_dir(paths):
  run_fd=_open_root(paths['run_dir'],create_leaf=bool(paths.get('local_mode')))
  sv_fd=None
  try:
    if not paths.get('local_mode'):_root_identity(run_fd,'run',paths['run_token'])
    sv_fd=_open_root(paths['workdir'],create_leaf=bool(paths.get('local_mode')))
    if not paths.get('local_mode'):_root_identity(sv_fd,'work',paths['work_token'])
    return run_fd,sv_fd
  except BaseException:
    os.close(run_fd)
    if sv_fd is not None:os.close(sv_fd)
    raise
def _lc_secret_values(paths):
  values=(paths['workdir'],paths['run_dir'],paths['model_path'],paths['drafter_path'],os.path.basename(paths['model_path']),os.path.basename(paths['drafter_path']))
  result=[]
  for value in values:
    try:encoded=value.encode('utf-8')
    except UnicodeEncodeError:continue
    if 4<=len(encoded)<=512 and value not in result:result.append(value)
  return result
def _lc_file_present(root_fd,name):
  try:
    os.stat(name,dir_fd=root_fd,follow_symlinks=False)
    return True
  except FileNotFoundError:return False
  except OSError:return None
def _lc_remove_owned(root_fd,name):
  try:fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|getattr(os,'O_NOFOLLOW',0),dir_fd=root_fd)
  except FileNotFoundError:return 'not_found'
  except OSError:return 'unknown'
  try:
    before=os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o600:return 'unknown'
  finally:os.close(fd)
  try:
    after=os.stat(name,dir_fd=root_fd,follow_symlinks=False)
    if(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):return 'unknown'
    os.unlink(name,dir_fd=root_fd)
    return 'cleared'
  except FileNotFoundError:return 'cleared'
  except OSError:return 'unknown'
def _lc_temp_outcome(root_fd):
  seen=False
  for name in('supervisor.py','launch.json','ack.json'):
    outcome=_lc_remove_owned(root_fd,name)
    if outcome=='unknown':return 'unknown'
    seen=seen or outcome=='cleared'
  return 'cleared' if seen else 'not_found'
def _lc_release_lease(paths,root_fd,run_id):
  if paths.get('local_mode'):return 'cleared'
  return _release_lifecycle_lock_at_root(root_fd,_identity(root_fd),paths['run_token'],run_id)
def _lc_guard(root_fd):
  fd=None
  try:
    fd=os.open('.targetctl-lifecycle-v1.lock',os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=root_fd)
    item=os.fstat(fd)
    if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o600:raise OSError()
    fcntl.flock(fd,fcntl.LOCK_EX)
    return fd
  except OSError:
    if fd is not None:
      try:os.close(fd)
      except OSError:pass
    _fail('unsafe_state')
def _lc_unguard(fd):
  try:fcntl.flock(fd,fcntl.LOCK_UN)
  finally:os.close(fd)
def _lc_digest(root_fd):
  try:
    fd,item=_open_regular('server.log',dir_fd=root_fd)
    try:
      body=os.read(fd,_LC_MAX_LOG+1)
      if len(body)>_LC_MAX_LOG or os.read(fd,1):return None
      return hashlib.sha256(body).hexdigest()
    finally:os.close(fd)
  except (HelperError,OSError):return None
def _lc_process_present(pid):
  if not isinstance(pid,int) or pid<=1:return False
  try:
    with open('/proc/%d/stat'%pid,encoding='ascii')as f:raw=f.read(4096)
    fields=raw[raw.rfind(')')+2:].split()
    return not fields or fields[0]not in('Z','X','x')
  except OSError:return False
def _lc_stale_groups(state):
  groups={}
  pid=state.get('supervisor_pid')
  if _lc_supervisor_identity(state)and _lc_pgid(pid)==pid:groups['supervisor_pid']=pid
  pid=state.get('child_pid')
  if _lc_child_identity(state):groups['child_pid']=pid
  return groups
def _lc_stale_process_outcome(state,groups):
  present=False
  for name in('supervisor_pid','child_pid'):
    pid=state.get(name)
    if not _lc_process_present(pid):continue
    if groups.get(name)==pid:
      if name=='supervisor_pid'and _lc_supervisor_identity(state)and _lc_pgid(pid)==pid:present=True;continue
      if name=='child_pid'and _lc_child_identity(state):present=True;continue
    return'unknown'
  owned_pgids=set(groups.values())
  tracked_pgids={pgid for pgid in(state.get('supervisor_pid'),state.get('child_pgid'))if isinstance(pgid,int)}
  for pgid in tracked_pgids:
    group_present=_lc_group_present(pgid)
    if group_present is None or(group_present and pgid not in owned_pgids):return'unknown'
    present=present or group_present
  return'present'if present else'not_found'
def _lc_stop_stale_owned(state):
  groups=_lc_stale_groups(state)
  for pgid in set(groups.values()):
    try:os.killpg(pgid,signal.SIGTERM)
    except ProcessLookupError:pass
    except OSError:return'unknown','unknown'
  started=time.monotonic();deadline=started+15;kill_after=started+3;killed=False;socket_seen=False
  while time.monotonic()<deadline:
    listener=_lc_listener(state['port'],state['child_pid']or 0)
    socket_seen=socket_seen or listener is not None
    process=_lc_stale_process_outcome(state,groups)
    if process=='unknown':return 'unknown','unknown'if listener is not None else'not_found'
    if process=='not_found'and listener is None:
      return('cleared'if groups else'not_found'),'cleared'if socket_seen else'not_found'
    if not killed and time.monotonic()>=kill_after:
      for pgid in set(groups.values()):
        group_present=_lc_group_present(pgid)
        if group_present is None:return'unknown','unknown'if listener is not None else'not_found'
        if group_present:
          try:os.killpg(pgid,signal.SIGKILL)
          except ProcessLookupError:pass
          except OSError:return'unknown','unknown'if listener is not None else'not_found'
      killed=True
    time.sleep(.05)
  return 'unknown','unknown'if socket_seen else'not_found'
@register_action('lifecycle_serve')
def lifecycle_serve(payload):
  data=_require_object(payload,{'workdir','run_dir','model_path','drafter_path','work_token','run_token','local_mode','run_id','source_snapshot_id','applied_tree_hash','build_id','binary_path','port','startup_timeout_ms','lease_seconds'})
  if not _lc_id(data['run_id']) or not all(_lc_hex(data[k]) for k in('source_snapshot_id','applied_tree_hash','build_id')) or not isinstance(data['binary_path'],str) or not isinstance(data['port'],int) or not 1<=data['port']<=65535 or not isinstance(data['startup_timeout_ms'],int) or not 1<=data['startup_timeout_ms']<=600000 or not isinstance(data['lease_seconds'],int) or not 1<=data['lease_seconds']<=7200:_fail('invalid_runtime_inputs')
  paths=None
  root_fd=None
  sv_dir_fd=None
  guard_fd=None
  lease_owned=False
  dispatch_recorded=False
  try:
    paths=_lc_roots(data)
    root_fd,sv_dir_fd=_lc_open_dir(paths)
    guard_fd=_lc_guard(root_fd)
    present=_lc_file_present(root_fd,'run.json')
    if present is None:_fail('unsafe_state')
    state=_lc_read_state(root_fd)if present else None
    if state:
      if state['state']=='starting':
        if _lc_live(state):_fail('run_active')
      elif state['state']=='running':
        if _lc_live(state):_fail('run_active')
        state['state']='stale_identity';_lc_write_state(root_fd,state)
      if not state['cleanup_complete']:_fail('run_cleanup_required')
    if not paths.get('local_mode'):
      lease_owned=True
      _acquire_lock_at_root(root_fd,_identity(root_fd),paths['run_token'],min(7200,data['lease_seconds']+15),data['run_id'])
    try:binary_hash=_lc_binary_hash_at(sv_dir_fd,data['binary_path'])
    except HelperError:_fail('startup_failed')
    try:build=_lc_read(root_fd,'build.json')
    except HelperError:_fail('startup_failed')
    expected_hash=build.get('binary_sha256')if isinstance(build,dict)else None
    if not isinstance(build,dict)or build.get('schema_version')!=1 or build.get('build_id')!=data['build_id']or build.get('source_snapshot_id')!=data['source_snapshot_id']or build.get('source_applied_tree_hash')!=data['applied_tree_hash']or build.get('exit_code')!=0 or not isinstance(build.get('duration_ns'),int) or isinstance(build.get('duration_ns'),bool) or build['duration_ns']<=0 or not _lc_hex(expected_hash)or not hmac.compare_digest(expected_hash,binary_hash):_fail('startup_failed')
    binary_exec='/proc/self/fd/%d/%s'%(sv_dir_fd,data['binary_path'])
    argv=(['/usr/bin/python3',binary_exec]if data['binary_path'].endswith('.py')else[binary_exec])+['--cuda','-m',paths['model_path'],'-c','32768','--host','127.0.0.1','--port',str(data['port'])]
    try:
      log_fd=os.open('server.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=root_fd)
    except FileExistsError:
      log_fd,_=_open_regular('server.log',dir_fd=root_fd,flags=os.O_WRONLY)
    try:os.ftruncate(log_fd,0);os.fsync(log_fd)
    finally:os.close(log_fd)
    profile=dict(LAUNCH_PROFILE)
    state={
      'schema_version':RUN_STATE_SCHEMA_VERSION,'run_id':data['run_id'],'state':'starting',
      'source_snapshot_id':data['source_snapshot_id'],'applied_tree_hash':data['applied_tree_hash'],
      'build_id':data['build_id'],'binary_sha256':binary_hash,'port':data['port'],
      'launch_profile':profile,'supervisor_pid':None,'supervisor_start_ticks':None,
      'supervisor_cmdline_sha256':None,'child_pid':None,'child_start_ticks':None,
      'child_pgid':None,'child_cmdline_sha256':None,'listener_inode':None,
      'cleanup_complete':False,
      'cleanup':None,
    }
    _lc_write_state(root_fd,state)
    dispatch_recorded=True
    spec={'argv':argv,'drafter':paths['drafter_path'],'secrets':_lc_secret_values(paths),'lease_seconds':data['lease_seconds'],'run_id':data['run_id'],'launch_profile':profile}
    _lc_atom(root_fd,'launch.json',spec)
    sv_script='supervisor.py'
    sv_temp='.'+sv_script+'.'+secrets.token_hex(12)
    try:
      sv_fd=os.open(sv_temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=root_fd)
      try:os.write(sv_fd,_LC_SUPERVISOR_SOURCE.encode('ascii'));os.fsync(sv_fd)
      finally:os.close(sv_fd)
      os.replace(sv_temp,sv_script,src_dir_fd=root_fd,dst_dir_fd=root_fd)
      sv_temp=None
    finally:
      if sv_temp is not None:_lc_remove_owned(root_fd,sv_temp)
    env=dict(os.environ)
    env['TARGETCTL_SV_DIR_FD']=str(sv_dir_fd);env['TARGETCTL_SV_RUN_FD']=str(root_fd)
    sv_program='/proc/self/fd/%d/supervisor.py'%root_fd
    try:
      p=subprocess.Popen(['/usr/bin/python3','-I','-S',sv_program,'launch.json'],cwd='/',stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,pass_fds=(sv_dir_fd,root_fd),env=env)
    except BaseException:
      state['state']='failed_startup';_lc_write_state(root_fd,state);_lc_temp_outcome(root_fd)
      _fail('startup_failed')
    lease_owned=False
    deadline=time.monotonic()+data['startup_timeout_ms']/1000
    process_exited=False
    while time.monotonic()<deadline:
      observed=_lc_read_state(root_fd)
      if observed['run_id']!=data['run_id']:_fail('unsafe_state')
      if observed['supervisor_pid']is not None and observed['supervisor_pid']!=p.pid:_fail('unsafe_state')
      if observed['child_pid']is not None:
        inode=_lc_listener(data['port'],observed['child_pid'])
        if inode and _lc_supervisor_identity(observed) and _lc_child_identity(observed):
          observed['listener_inode']=inode;observed['state']='running';_lc_write_state(root_fd,observed)
          return{'run_id':data['run_id'],'state':'running','port':data['port'],'binary_sha256':binary_hash,'supervisor_pid':observed['supervisor_pid'],'supervisor_start_ticks':observed['supervisor_start_ticks'],'child_pid':observed['child_pid'],'child_start_ticks':observed['child_start_ticks'],'launch_profile':profile}
      if p.poll()is not None:process_exited=True;break
      time.sleep(.05)
    observed=_lc_read_state(root_fd)
    observed['state']='failed_startup';_lc_write_state(root_fd,observed)
    if _lc_supervisor_identity(observed)and _lc_pgid(observed['supervisor_pid'])==observed['supervisor_pid']:
      try:os.killpg(observed['supervisor_pid'],signal.SIGTERM)
      except OSError:pass
    _fail('startup_failed' if process_exited else 'startup_timeout')
  except HelperError:
    if not dispatch_recorded:_fail('serve_not_dispatched')
    raise
  finally:
    if lease_owned and paths is not None and root_fd is not None:_lc_release_lease(paths,root_fd,data['run_id'])
    if guard_fd is not None:_lc_unguard(guard_fd)
    if root_fd is not None:os.close(root_fd)
    if sv_dir_fd is not None:os.close(sv_dir_fd)
def _lc_public_run(state):
  return{
    'run_id':state['run_id'],'state':state['state'],
    'source_snapshot_id':state['source_snapshot_id'],'build_id':state['build_id'],
    'binary_sha256':state['binary_sha256'],'supervisor_pid':state['supervisor_pid'],
    'supervisor_start_ticks':state['supervisor_start_ticks'],'child_pid':state['child_pid'],
    'child_start_ticks':state['child_start_ticks'],'port':state['port'],
    'launch_profile':state['launch_profile'],
  }
@register_action('lifecycle_status')
def lifecycle_status(payload):
  data=_require_object(payload,{'workdir','run_dir','model_path','drafter_path','work_token','run_token','local_mode','run_id'})
  paths=_lc_roots(data)
  root_fd,sv_dir_fd=_lc_open_dir(paths)
  guard_fd=None
  try:
    guard_fd=_lc_guard(root_fd)
    present=_lc_file_present(root_fd,'run.json')
    if present is None:_fail('unsafe_state')
    if not present:return{'run_id':None,'state':'stopped','active':False,'run':None}
    state=_lc_read_state(root_fd)
    if data['run_id']is not None and state['run_id']!=data['run_id']:return{'run_id':None,'state':'stopped','active':False,'run':None}
    active=_lc_live(state)
    if state['state']=='running'and not active:state['state']='stale_identity';_lc_write_state(root_fd,state)
    return{'run_id':state['run_id'],'state':state['state'],'active':active,'run':_lc_public_run(state)}
  finally:
    if guard_fd is not None:_lc_unguard(guard_fd)
    os.close(root_fd);os.close(sv_dir_fd)
@register_action('lifecycle_stop')
def lifecycle_stop(payload):
  data=_require_object(payload,{'workdir','run_dir','model_path','drafter_path','work_token','run_token','local_mode','run_id'})
  paths=_lc_roots(data)
  root_fd,sv_dir_fd=_lc_open_dir(paths)
  guard_fd=None
  try:
    guard_fd=_lc_guard(root_fd)
    absent={'run_id':None,'status':'not_run','process':'not_run','socket':'not_run','lock':'not_found','temp':'not_found','server_log_sha256':None,'failure_class':None}
    present=_lc_file_present(root_fd,'run.json')
    if present is None:_fail('unsafe_state')
    if not present:return absent
    state=_lc_read_state(root_fd)
    if data['run_id']is not None and state['run_id']!=data['run_id']:return absent
    if state['cleanup_complete']:
      settled=state['cleanup']
      return{'run_id':state['run_id'],'status':'stopped','process':settled['process'],'socket':settled['socket'],'lock':settled['lock'],'temp':settled['temp'],'server_log_sha256':settled['server_log_sha256'],'failure_class':None}
    def outcomes(stopped):
      digest=_lc_digest(root_fd)
      if not stopped:return'unknown','unknown',digest
      return _lc_temp_outcome(root_fd),_lc_release_lease(paths,root_fd,state['run_id']),digest
    process='not_found';socket='not_found'
    sv_pid=state['supervisor_pid'];sv_pgid=_lc_pgid(sv_pid)if isinstance(sv_pid,int)else None
    is_live=_lc_live(state)and sv_pgid==sv_pid
    if not is_live:
      if state['state']in('starting','running'):
        state['state']='stale_identity';_lc_write_state(root_fd,state)
      process,socket=_lc_stop_stale_owned(state)
      stopped=process in('cleared','not_found')and socket in('cleared','not_found')
      temp,lock,digest=outcomes(stopped)
      clean=stopped and temp in('cleared','not_found')and lock in('cleared','not_found')
      if clean:
        state['cleanup_complete']=True;state['cleanup']={'process':process,'socket':socket,'lock':lock,'temp':temp,'server_log_sha256':digest};_lc_write_state(root_fd,state)
      return{'run_id':state['run_id'],'status':'stopped'if clean else'failed','process':process,'socket':socket,'lock':lock,'temp':temp,'server_log_sha256':digest,'failure_class':None if clean else'stop_failed'}
    try:os.killpg(sv_pgid,signal.SIGTERM);process='cleared'
    except OSError:process='unknown'
    if _lc_listener(state['port'],state['child_pid'],state['listener_inode']):socket='unknown'
    owned_groups=(sv_pgid,state['child_pgid'])
    started=time.monotonic();deadline=started+15;kill_after=started+4;killed=False
    stopped=False
    while time.monotonic()<deadline:
      proc_alive=False
      try:os.kill(sv_pid,0);proc_alive=True
      except OSError:pass
      sock_alive=bool(_lc_listener(state['port'],state['child_pid']))
      group_states=tuple(_lc_group_present(pgid)for pgid in owned_groups)
      if any(item is None for item in group_states):process='unknown';break
      if not proc_alive and not sock_alive and not any(group_states):
        process='cleared';socket='cleared'if socket!='not_found'else socket;stopped=True;break
      if not killed and time.monotonic()>=kill_after:
        for pgid,group_present in zip(owned_groups,group_states):
          if group_present:
            try:os.killpg(pgid,signal.SIGKILL)
            except ProcessLookupError:pass
            except OSError:process='unknown'
        killed=True
      time.sleep(.05)
    if stopped:
      state['state']='stopped';_lc_write_state(root_fd,state)
    temp,lock,digest=outcomes(stopped)
    clean=stopped and process=='cleared'and socket in('cleared','not_found')and temp in('cleared','not_found')and lock in('cleared','not_found')
    if clean:
      state['cleanup_complete']=True;state['cleanup']={'process':process,'socket':socket,'lock':lock,'temp':temp,'server_log_sha256':digest};_lc_write_state(root_fd,state)
    return{'run_id':state['run_id'],'status':'stopped'if clean else'failed','process':process,'socket':socket,'lock':lock,'temp':temp,'server_log_sha256':digest,'failure_class':None if clean else'stop_failed'}
  finally:
    if guard_fd is not None:_lc_unguard(guard_fd)
    os.close(root_fd);os.close(sv_dir_fd)
@register_action('lifecycle_logs')
def lifecycle_logs(payload):
  data=_require_object(payload,{'workdir','run_dir','model_path','drafter_path','work_token','run_token','local_mode','run_id'})
  paths=_lc_roots(data)
  root_fd,sv_dir_fd=_lc_open_dir(paths)
  try:
    present=_lc_file_present(root_fd,'run.json')
    if not present:_fail('log_unavailable')
    state=_lc_read_state(root_fd)
    if data['run_id']is not None and state['run_id']!=data['run_id']:_fail('log_unavailable')
    fd,item=_open_regular('server.log',dir_fd=root_fd)
    try:
      body=os.read(fd,_LC_MAX_LOG+1)
      if len(body)>_LC_MAX_LOG or os.read(fd,1):_fail('log_unavailable')
    finally:os.close(fd)
    return{'content_b64':base64.b64encode(body).decode('ascii')}
  finally:os.close(root_fd);os.close(sv_dir_fd)

@register_action('lifecycle_weights')
def lifecycle_weights(payload):
  paths=_lc_roots(_require_object(payload,{'workdir','run_dir','model_path','drafter_path','work_token','run_token','local_mode'}))
  return {'primary_weight_sha256':_lc_binary_hash(paths['model_path']),'draft_weight_sha256':_lc_binary_hash(paths['drafter_path'])}
'''

# The sanitizer executes both in remote.py's helper namespace and in the
# isolated supervisor interpreter; its source is deliberately shared.
_LIFECYCLE_EXTENSION = REMOTE_REDACTION_EXTENSION + "import fcntl\nimport signal\nimport subprocess\n" + _LIFECYCLE_EXTENSION
_LIFECYCLE_EXTENSION = _LIFECYCLE_EXTENSION.replace('"""import hashlib', 'r"""' + REMOTE_REDACTION_EXTENSION + '\nimport hashlib', 1)




def _launch_profile(value: Any) -> LaunchProfile:
    if not isinstance(value, Mapping) or dict(value) != LAUNCH_PROFILE:
        _fail("unsafe_state", "target launch profile is invalid")
    return FIXED_LAUNCH_PROFILE


def _serve_result(value, runtime, identifier):
    keys = ("supervisor_pid", "supervisor_start_ticks", "child_pid", "child_start_ticks")
    if not isinstance(value, Mapping) or set(value) != {"run_id", "state", "port", "binary_sha256", *keys, "launch_profile"} or value.get("run_id") != identifier or value.get("state") != "running" or value.get("port") != runtime.port or not isinstance(value.get("binary_sha256"), str) or _HEX.fullmatch(value["binary_sha256"]) is None or any(not isinstance(value.get(key), int) or isinstance(value[key], bool) or value[key] <= 1 for key in keys):
        _fail("startup_failed", "target server identity is invalid")
    return RunResult(identifier, "running", runtime.port, runtime.source_snapshot_id, runtime.build_id, value["binary_sha256"], value["supervisor_pid"], value["supervisor_start_ticks"], value["child_pid"], value["child_start_ticks"], _launch_profile(value["launch_profile"]))


def _observed_run(value: Any, runtime: RuntimeInputs, identifier: str) -> RunResult:
    fields = {
        "run_id", "state", "source_snapshot_id", "build_id", "binary_sha256",
        "supervisor_pid", "supervisor_start_ticks", "child_pid",
        "child_start_ticks", "port", "launch_profile",
    }
    if not isinstance(value, Mapping) or set(value) != fields or value.get("run_id") != identifier or value.get("state") not in _STATES or value.get("source_snapshot_id") != runtime.source_snapshot_id or value.get("build_id") != runtime.build_id or value.get("port") != runtime.port or not isinstance(value.get("binary_sha256"), str) or _HEX.fullmatch(value["binary_sha256"]) is None:
        _fail("unsafe_state", "target run state is invalid")
    pairs = (
        (value["supervisor_pid"], value["supervisor_start_ticks"]),
        (value["child_pid"], value["child_start_ticks"]),
    )
    for pid, ticks in pairs:
        if (pid is None) != (ticks is None) or (pid is not None and (not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1 or not isinstance(ticks, int) or isinstance(ticks, bool) or ticks <= 1)):
            _fail("unsafe_state", "target run state is invalid")
    if value["state"] == "running" and any(item is None for pair in pairs for item in pair):
        _fail("unsafe_state", "target run state is invalid")
    return RunResult(
        identifier, value["state"], runtime.port, runtime.source_snapshot_id,
        runtime.build_id, value["binary_sha256"], value["supervisor_pid"],
        value["supervisor_start_ticks"], value["child_pid"],
        value["child_start_ticks"], _launch_profile(value["launch_profile"]),
    )


def _serve_call(transport, payload, runtime):
    try:
        return _call(transport, "lifecycle_serve", payload, timeout=runtime.startup_timeout + 15)
    except TargetError as error:
        if error.code in {"run_active", "run_cleanup_required", "lock_busy", "lock_failed", "unsafe_lock"}:
            _fail("serve_not_dispatched", "target server launch was refused")
        if error.code == "missing_path":
            _fail("serve_not_dispatched", "target server launch was refused")
        raise


def serve(config, transport, runtime, *, run_id=None):
    if hasattr(config, "validate_for"):
        config.validate_for("serve")
    identifier = _run_id(run_id)
    roots = _roots(config, runtime)
    payload = {**roots, "run_id": identifier, "source_snapshot_id": runtime.source_snapshot_id, "applied_tree_hash": runtime.applied_tree_hash, "build_id": runtime.build_id, "binary_path": runtime.binary_path, "port": runtime.port, "startup_timeout_ms": int(runtime.startup_timeout * 1000), "lease_seconds": runtime.lease_seconds}
    if roots["local_mode"]:
        try:
            with local_operation_lock(roots["run_dir"]):
                return _serve_result(_serve_call(transport, payload, runtime), runtime, identifier)
        except TargetError as error:
            if error.code == "run_active":
                _fail("serve_not_dispatched", "target server launch was refused")
            raise
    return _serve_result(_serve_call(transport, payload, runtime), runtime, identifier)

def status(config, transport, runtime, *, run_id=None):
    if hasattr(config, "validate_for"): config.validate_for("status")
    requested = _run_id(run_id) if run_id is not None else None
    value = _call(transport, "lifecycle_status", {**_roots(config, runtime), "run_id": requested})
    if not isinstance(value, Mapping) or set(value) != {"run_id", "state", "active", "run"} or value.get("state") not in _STATES or not isinstance(value.get("active"), bool):
        _fail("unsafe_state", "target run state is invalid")
    identifier = value["run_id"]
    observed = value["run"]
    if identifier is None:
        if observed is not None or value["state"] != "stopped" or value["active"]:
            _fail("unsafe_state", "target run state is invalid")
        return StatusResult(None, "stopped", False, None)
    _run_id(identifier)
    if requested is not None and identifier != requested:
        _fail("unsafe_state", "target run state is invalid")
    run = _observed_run(observed, runtime, identifier)
    if run.state != value["state"]:
        _fail("unsafe_state", "target run state is invalid")
    return StatusResult(identifier, value["state"], value["active"], run)


def logs(config, transport, runtime, *, run_id=None):
    if hasattr(config, "validate_for"): config.validate_for("logs")
    value = _call(transport, "lifecycle_logs", {**_roots(config, runtime), "run_id": _run_id(run_id) if run_id is not None else None})
    if not isinstance(value, Mapping) or set(value) != {"content_b64"} or not isinstance(value["content_b64"], str): _fail("log_unavailable", "sanitized server log is unavailable")
    try: data = base64.b64decode(value["content_b64"], validate=True)
    except (ValueError, UnicodeEncodeError): _fail("log_unavailable", "sanitized server log is unavailable")
    if len(data) > MAX_LOG_BYTES: _fail("log_unavailable", "sanitized server log is unavailable")
    return data


def _cleanup_result(value):
    fields = {"run_id", "status", "failure_class", "process", "socket", "lock", "temp", "server_log_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields or value["status"] not in ("stopped", "not_run", "failed"):
        _fail("stop_failed", "target server could not be stopped")
    identifier = value["run_id"]
    if identifier is not None: _run_id(identifier)
    outcomes = (value["process"], value["socket"], value["lock"], value["temp"])
    if any(item not in {"cleared", "not_found", "not_run", "unknown"} for item in outcomes):
        _fail("stop_failed", "target server cleanup evidence is invalid")
    digest = value["server_log_sha256"]
    if digest is not None and (not isinstance(digest, str) or _HEX.fullmatch(digest) is None):
        _fail("stop_failed", "target server cleanup evidence is invalid")
    if value["status"] == "not_run":
        if identifier is not None or outcomes != ("not_run", "not_run", "not_found", "not_found") or digest is not None or value["failure_class"] is not None:
            _fail("stop_failed", "target server cleanup evidence is invalid")
    elif value["status"] == "stopped":
        if identifier is None or any(item not in {"cleared", "not_found"} for item in outcomes) or value["failure_class"] is not None:
            _fail("stop_failed", "target server cleanup evidence is invalid")
    elif identifier is None or value["failure_class"] != "stop_failed":
        _fail("stop_failed", "target server cleanup evidence is invalid")
    status_value = {"stopped": "succeeded", "not_run": "not_run", "failed": "failed"}[value["status"]]
    return CleanupResult(identifier, status_value, *outcomes, digest, value["failure_class"])

def stop(config, transport, runtime, *, run_id=None):
    if hasattr(config, "validate_for"): config.validate_for("stop")
    roots = _roots(config, runtime); payload = {**roots, "run_id": _run_id(run_id) if run_id is not None else None}
    if roots["local_mode"]:
        with local_operation_lock(roots["run_dir"]): return _cleanup_result(_call(transport, "lifecycle_stop", payload, timeout=30))
    return _cleanup_result(_call(transport, "lifecycle_stop", payload, timeout=30))

def cleanup(config, transport, runtime, *, run_id=None):
    return stop(config, transport, runtime, run_id=run_id)

def _http_contract(port, timeout):
    models = False; connection = None
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout); connection.request("GET", "/v1/models", headers={"Accept": "application/json"}); response = connection.getresponse(); body = response.read(MAX_HTTP_BODY_BYTES + 1)
        if response.status != 200 or len(body) > MAX_HTTP_BODY_BYTES: return False, False, False
        parsed = json.loads(body.decode("utf-8")); models = isinstance(parsed, Mapping) and isinstance(parsed.get("data"), list)
        if not models: return True, False, False
        connection.close(); connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        request = {"messages": [{"role": "user", "content": "What is the capital of France? Answer in one sentence."}], "max_tokens": 64}
        connection.request("POST", "/v1/chat/completions", body=json.dumps(request, separators=(",", ":")).encode("utf-8"), headers={"Content-Type": "application/json", "Accept": "application/json"}); response = connection.getresponse(); body = response.read(MAX_HTTP_BODY_BYTES + 1)
        if response.status != 200 or len(body) > MAX_HTTP_BODY_BYTES: return True, True, False
        content = json.loads(body.decode("utf-8"))["choices"][0]["message"]["content"]
        return True, True, isinstance(content, str) and 0 < len(content) <= 16384 and "paris" in content.lower()
    except (OSError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError): return False, models, False
    finally:
        if connection is not None: connection.close()

def _weight_evidence(config, transport, runtime):
    value = _call(transport, "lifecycle_weights", _roots(config, runtime))
    if not isinstance(value, Mapping): return None, None
    primary, draft = value.get("primary_weight_sha256"), value.get("draft_weight_sha256")
    if not isinstance(primary, str) or not isinstance(draft, str) or _HEX.fullmatch(primary) is None or _HEX.fullmatch(draft) is None: return None, None
    return primary, draft

def _failure_code(error: BaseException) -> str:
    if isinstance(error, KeyboardInterrupt):
        return "interrupted"
    if isinstance(error, TargetError):
        return error.code
    return "internal_error"


def _failed_cleanup(identifier: str, error: BaseException) -> CleanupResult:
    return CleanupResult(
        identifier, "failed", "unknown", "unknown", "unknown", "unknown",
        None, _failure_code(error),
    )


def _reconcile_failed_serve(config, transport, runtime, identifier, started, error):
    observed: RunResult | None = None
    try:
        result = status(config, transport, runtime, run_id=identifier)
        if result.run_id == identifier:
            observed = result.run
    except BaseException as status_error:
        if not isinstance(status_error, (Exception, KeyboardInterrupt)):
            raise
    if observed is None:
        observed = RunResult(
            identifier, "failed_startup", runtime.port,
            runtime.source_snapshot_id, runtime.build_id,
            launch_profile=FIXED_LAUNCH_PROFILE,
        )
    try:
        cleaned = stop(config, transport, runtime, run_id=identifier)
    except BaseException as cleanup_error:
        if not isinstance(cleanup_error, (Exception, KeyboardInterrupt)):
            raise
        cleaned = _failed_cleanup(identifier, cleanup_error)
    return SmokeResult(
        identifier, "failed", _failure_code(error), None, None, "failed",
        None, None, __import__("time").monotonic_ns() - started,
        observed, cleaned,
    )


def smoke(config, transport, runtime, *, run_id=None):
    identifier = _run_id(run_id)
    started = __import__("time").monotonic_ns()
    try:
        run = serve(config, transport, runtime, run_id=identifier)
    except BaseException as error:
        if not isinstance(error, (Exception, KeyboardInterrupt)):
            raise
        if isinstance(error, TargetError) and error.code == "serve_not_dispatched":
            raise
        return _reconcile_failed_serve(config, transport, runtime, identifier, started, error)
    readiness = models = contract = False
    primary = draft = None
    failure = None
    try:
        if isinstance(transport, SSHTransport):
            with SSHForward(transport, target_port=runtime.port, timeout=runtime.smoke_timeout) as forward:
                readiness, models, contract = _http_contract(forward.local_port, runtime.smoke_timeout)
        else:
            readiness, models, contract = _http_contract(runtime.port, runtime.smoke_timeout)
        primary, draft = _weight_evidence(config, transport, runtime)
        if not (readiness and models and contract and primary and draft):
            failure = "http_contract_failed"
    except BaseException as error:
        if not isinstance(error, (Exception, KeyboardInterrupt)):
            raise
        failure = _failure_code(error)
    try:
        cleaned = stop(config, transport, runtime, run_id=run.run_id)
    except BaseException as error:
        if not isinstance(error, (Exception, KeyboardInterrupt)):
            raise
        cleaned = _failed_cleanup(identifier, error)
    if cleaned.status != "succeeded" and failure is None:
        failure = cleaned.failure_class or "stop_failed"
    return SmokeResult(
        identifier, "succeeded" if failure is None else "failed", failure,
        200 if readiness else None, 200 if models else None,
        "passed" if contract else "failed", primary, draft,
        __import__("time").monotonic_ns() - started, run, cleaned,
    )
