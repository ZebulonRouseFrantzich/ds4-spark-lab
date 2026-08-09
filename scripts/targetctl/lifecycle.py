"""Safe loopback lifecycle operations for the targetctl Phase 01 target."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import base64
import http.client
import json
import re
import secrets
from typing import Any, Iterator, Mapping

from .common import TargetError
from .transport import LocalTransport, SSHForward, SSHTransport

RUN_SCHEMA_VERSION = 1
MAX_LOG_BYTES = 1_048_576
MAX_HTTP_BODY_BYTES = 1_048_576
MAX_RUN_ID_LENGTH = 64
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_RUN_ID = re.compile(r"[a-z0-9][a-z0-9-]{7,63}\Z", re.ASCII)
_STATES = frozenset(("starting", "running", "stopped", "stale_identity", "failed_startup"))
_ERRORS = frozenset(("invalid_runtime_inputs", "invalid_run_id", "run_active", "run_not_found", "run_identity_stale", "startup_failed", "startup_timeout", "unsafe_state", "unsafe_listener", "stop_failed", "cleanup_failed", "log_unavailable", "smoke_failed", "smoke_timeout", "http_contract_failed", "source_identity_missing"))


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
    work_token: str
    run_token: str
    port: int
    binary_path: str = "engine/ds4/ds4-server"
    startup_timeout: float = 45.0
    smoke_timeout: float = 45.0

    def __post_init__(self) -> None:
        _path(self.model_path)
        _path(self.drafter_path)
        for item in (self.source_snapshot_id, self.applied_tree_hash, self.build_id, self.work_token, self.run_token):
            _hex(item)
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            _fail("invalid_runtime_inputs", "runtime inputs are invalid")
        if not isinstance(self.binary_path, str) or not self.binary_path or self.binary_path.startswith("/") or ".." in self.binary_path.split("/"):
            _fail("invalid_runtime_inputs", "runtime inputs are invalid")
        for value in (self.startup_timeout, self.smoke_timeout):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 < value <= 600:
                _fail("invalid_runtime_inputs", "runtime inputs are invalid")


@dataclass(frozen=True, slots=True)
class RunResult:
    run_id: str
    state: str
    port: int
    source_snapshot_id: str
    build_id: str


@dataclass(frozen=True, slots=True)
class StatusResult:
    run_id: str | None
    state: str
    active: bool


@dataclass(frozen=True, slots=True)
class SmokeResult:
    run_id: str
    status: str


@dataclass(frozen=True, slots=True)
class CleanupResult:
    run_id: str | None
    status: str


def _run_id(value: str | None = None) -> str:
    if value is None:
        return "run-" + secrets.token_hex(12)
    if not isinstance(value, str) or _RUN_ID.fullmatch(value) is None:
        _fail("invalid_run_id", "run ID is invalid")
    return value


def _roots(config: Any, runtime: RuntimeInputs) -> dict[str, Any]:
    run_dir = getattr(config, "run_dir", None)
    workdir = getattr(config, "workdir", None)
    if getattr(config, "mode", None) == "local":
        run_dir = str(getattr(config, "local_run_dir"))
        workdir = str(getattr(config, "source_root"))
    return {"workdir": _path(workdir), "run_dir": _path(run_dir), "model_path": runtime.model_path, "drafter_path": runtime.drafter_path}


def _request_roots(config: Any, runtime: RuntimeInputs) -> dict[str, Any]:
    roots = _roots(config, runtime)
    roots["work_token"] = runtime.work_token
    roots["run_token"] = runtime.run_token
    return roots



@contextmanager
def _locked(transport: LocalTransport | SSHTransport, roots: Mapping[str, Any]) -> Iterator[None]:
    lock = transport.run_helper(
        "acquire_lock",
        {"run_dir": roots["run_dir"], "run_token": roots["run_token"]},
        allowed_error_codes={"lock_busy", "lock_failed", "unsafe_lock", "marker_mismatch", "unsafe_root"},
    )
    if not isinstance(lock, Mapping) or not isinstance(lock.get("lock_token"), str):
        _fail("unsafe_state", "target lifecycle lock is invalid")
    primary: BaseException | None = None
    try:
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            transport.run_helper(
                "release_lock",
                {"run_dir": roots["run_dir"], "run_token": roots["run_token"], "lock_token": lock["lock_token"]},
                allowed_error_codes={"lock_token_mismatch", "lock_release_failed", "unsafe_lock", "marker_mismatch", "unsafe_root"},
            )
        except BaseException:
            if primary is None:
                _fail("cleanup_failed", "target lifecycle lock could not be released")

def _call(transport: LocalTransport | SSHTransport, action: str, payload: Mapping[str, Any], *, timeout: float | None = 60.0) -> Any:
    return transport.run_helper(action, payload, extension_source=_LIFECYCLE_EXTENSION, allowed_error_codes=_ERRORS, timeout=timeout)


def serve(config: Any, transport: LocalTransport | SSHTransport, runtime: RuntimeInputs, *, run_id: str | None = None) -> RunResult:
    """Start one owned server and wait until its loopback listener is proven."""
    if hasattr(config, "validate_for"): config.validate_for("serve")
    identifier = _run_id(run_id)
    roots = _request_roots(config, runtime)
    payload = {**roots, "run_id": identifier, "source_snapshot_id": runtime.source_snapshot_id, "applied_tree_hash": runtime.applied_tree_hash, "build_id": runtime.build_id, "binary_path": runtime.binary_path, "port": runtime.port, "startup_timeout_ms": int(runtime.startup_timeout * 1000)}
    with _locked(transport, roots):
        result = _call(transport, "lifecycle_serve", payload, timeout=runtime.startup_timeout + 15)
    if not isinstance(result, Mapping) or result.get("run_id") != identifier or result.get("state") != "running" or result.get("port") != runtime.port:
        _fail("startup_failed", "target server did not become ready")
    return RunResult(identifier, "running", runtime.port, runtime.source_snapshot_id, runtime.build_id)

def status(config: Any, transport: LocalTransport | SSHTransport, runtime: RuntimeInputs, *, run_id: str | None = None) -> StatusResult:
    if hasattr(config, "validate_for"): config.validate_for("status")
    roots = _request_roots(config, runtime)
    with _locked(transport, roots):
        result = _call(transport, "lifecycle_status", {**roots, "run_id": _run_id(run_id) if run_id is not None else None})
    if not isinstance(result, Mapping) or result.get("state") not in _STATES or not isinstance(result.get("active"), bool):
        _fail("unsafe_state", "target run state is invalid")
    got = result.get("run_id")
    if got is not None: _run_id(got)
    return StatusResult(got, result["state"], result["active"])


def logs(config: Any, transport: LocalTransport | SSHTransport, runtime: RuntimeInputs) -> bytes:
    if hasattr(config, "validate_for"): config.validate_for("logs")
    result = _call(transport, "lifecycle_logs", _request_roots(config, runtime))
    if not isinstance(result, Mapping) or not isinstance(result.get("content_b64"), str): _fail("log_unavailable", "sanitized server log is unavailable")
    try: content = base64.b64decode(result["content_b64"], validate=True)
    except ValueError: _fail("log_unavailable", "sanitized server log is unavailable")
    if len(content) > MAX_LOG_BYTES: _fail("log_unavailable", "sanitized server log is unavailable")
    return content


def stop(config: Any, transport: LocalTransport | SSHTransport, runtime: RuntimeInputs, *, run_id: str | None = None) -> CleanupResult:
    if hasattr(config, "validate_for"): config.validate_for("stop")
    requested = _run_id(run_id) if run_id is not None else None
    roots = _request_roots(config, runtime)
    with _locked(transport, roots):
        result = _call(transport, "lifecycle_stop", {**roots, "run_id": requested}, timeout=30)
    if not isinstance(result, Mapping) or result.get("status") not in ("stopped", "not_run"):
        _fail("stop_failed", "target server could not be stopped")
    got = result.get("run_id")
    if got is not None: _run_id(got)
    return CleanupResult(got, result["status"])


def cleanup(config: Any, transport: LocalTransport | SSHTransport, runtime: RuntimeInputs, *, run_id: str | None = None) -> CleanupResult:
    """Idempotently stop and remove only files owned by the validated run."""
    result = stop(config, transport, runtime, run_id=run_id)
    return CleanupResult(result.run_id, result.status)


def _http_contract(port: int, timeout: float) -> None:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", "/v1/models", headers={"Accept": "application/json"})
        response = connection.getresponse(); body = response.read(MAX_HTTP_BODY_BYTES + 1)
        if response.status != 200 or len(body) > MAX_HTTP_BODY_BYTES: _fail("http_contract_failed", "target HTTP contract failed")
        request = {"messages": [{"role": "user", "content": "What is the capital of France? Answer in one sentence."}], "max_tokens": 64}
        connection.close(); connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        connection.request("POST", "/v1/chat/completions", body=json.dumps(request, separators=(",", ":")).encode("ascii"), headers={"Content-Type": "application/json", "Accept": "application/json"})
        response = connection.getresponse(); body = response.read(MAX_HTTP_BODY_BYTES + 1)
        if response.status != 200 or len(body) > MAX_HTTP_BODY_BYTES: _fail("http_contract_failed", "target HTTP contract failed")
        parsed = json.loads(body.decode("utf-8"))
        content = parsed["choices"][0]["message"]["content"]
        if not isinstance(content, str) or len(content) > 16384 or "paris" not in content.lower(): _fail("http_contract_failed", "target HTTP contract failed")
    except (OSError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError):
        _fail("smoke_failed", "target HTTP smoke failed")
    finally:
        connection.close()


def smoke(config: Any, transport: LocalTransport | SSHTransport, runtime: RuntimeInputs, *, run_id: str | None = None) -> SmokeResult:
    """Run direct no-proxy HTTP smoke, always stopping the owned run afterwards."""
    run = serve(config, transport, runtime, run_id=run_id)
    try:
        if isinstance(transport, SSHTransport):
            with SSHForward(transport, target_port=runtime.port, timeout=runtime.smoke_timeout) as forward:
                _http_contract(forward.local_port, runtime.smoke_timeout)
        else:
            _http_contract(runtime.port, runtime.smoke_timeout)
        return SmokeResult(run.run_id, "succeeded")
    finally:
        stop(config, transport, runtime, run_id=run.run_id)


# This extension intentionally uses only stdlib names available from remote.py. It writes
# private launch specifications under the owned run root and exposes only fixed records.
_LIFECYCLE_EXTENSION = r'''
import errno
import hashlib
import signal
import subprocess
import time

_LC_MAX_LOG=1048576
_LC_MAX_STATE=65536
_LC_STATES={"starting","running","stopped","stale_identity","failed_startup"}

def _lc_hex(value):
    return isinstance(value,str) and len(value)==64 and all(c in "0123456789abcdef" for c in value)
def _lc_id(value):
    return isinstance(value,str) and 8<=len(value)<=64 and all(c.islower() or c.isdigit() or c=="-" for c in value) and value[0].isalnum()
def _lc_atom(root_fd,name,data):
    raw=json.dumps(data,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
    if len(raw)>_LC_MAX_STATE:_fail("unsafe_state")
    temp="."+name+"."+secrets.token_hex(12)
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=root_fd)
        try: os.write(fd,raw);os.fsync(fd)
        finally: os.close(fd)
        os.replace(temp,name,src_dir_fd=root_fd,dst_dir_fd=root_fd);os.fsync(root_fd)
    except OSError:_fail("unsafe_state")
def _lc_read(root_fd,name):
    fd,item=_open_regular(name,dir_fd=root_fd)
    try:
        raw=os.read(fd,_LC_MAX_STATE+1)
        if len(raw)>_LC_MAX_STATE or os.read(fd,1):_fail("unsafe_state")
    finally: os.close(fd)
    try: data=json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError,json.JSONDecodeError):_fail("unsafe_state")
    return data
def _lc_ticks(pid):
    try:
        raw=open("/proc/%d/stat"%pid,"rb").read(4096).decode("ascii")
        close=raw.rfind(")"); fields=raw[close+2:].split()
        return int(fields[19])
    except (OSError,ValueError,IndexError): return None
def _lc_pid_identity(state):
    pid=state.get("supervisor_pid"); ticks=state.get("supervisor_start_ticks")
    return isinstance(pid,int) and pid>1 and isinstance(ticks,int) and _lc_ticks(pid)==ticks
def _lc_listener(port,pid):
    wanted="%04X"%port; inodes=set()
    for name in ("/proc/net/tcp","/proc/net/tcp6"):
      try:
       for line in open(name,encoding="ascii").read().splitlines()[1:]:
        fields=line.split(); local=fields[1]; state=fields[3]
        host,number=local.rsplit(":",1)
        if state=="0A" and number==wanted and host in ("0100007F","00000000000000000000000000000001"): inodes.add(fields[9])
      except OSError: pass
    if not inodes:return False
    try: owned=set(os.listdir("/proc/%d/fd"%pid))
    except OSError:return False
    for fd in owned:
      try:
       link=os.readlink("/proc/%d/fd/%s"%(pid,fd))
       if link.startswith("socket:[") and link[8:-1] in inodes:return True
      except OSError:pass
    return False
def _lc_binary_hash(path):
    try:
      fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0))
      before=os.fstat(fd)
      if not stat.S_ISREG(before.st_mode):_fail("startup_failed")
      digest=hashlib.sha256()
      while True:
       block=os.read(fd,65536)
       if not block:break
       digest.update(block)
      after=os.fstat(fd); os.close(fd)
    except OSError:_fail("startup_failed")
    if (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size):_fail("startup_failed")
    return digest.hexdigest()
def _lc_supervisor_cmd(state):
    try: return b"supervisor.py" in open("/proc/%d/cmdline"%state["supervisor_pid"],"rb").read(4096) and b"launch.json" in open("/proc/%d/cmdline"%state["supervisor_pid"],"rb").read(4096)
    except (OSError,KeyError): return False
def _lc_live(state):
    return _lc_pid_identity(state) and _lc_supervisor_cmd(state) and isinstance(state.get("child_pid"),int) and isinstance(state.get("child_start_ticks"),int) and _lc_ticks(state["child_pid"])==state["child_start_ticks"] and _lc_listener(state.get("port"),state["child_pid"])
def _lc_roots(payload):
    fields={k:payload[k] for k in ("workdir","run_dir","model_path","drafter_path","work_token","run_token")}
    return _root_payload(fields,require_tokens=True)
def _lc_open(paths):
    run_fd=_open_root(paths["run_dir"])
    _root_identity(run_fd,"run",paths["run_token"])
    return run_fd
def _lc_redact(data,secrets_):
    value=data
    for secret in secrets_:
      if secret: value=value.replace(secret.encode(),b"[REDACTED]")
    value=value.replace(b"\x1b",b"")
    return value

def _lc_supervisor_source():
 return ("import json,os,re,subprocess,sys\n"
  "spec=json.load(open(sys.argv[1],encoding='ascii')); log=open(spec['log'],'ab',buffering=0)\n"
  "secrets_=[x.encode() for x in spec['secrets']]\n"
  "def ticks(pid):\n"
  " try:\n"
  "  v=open('/proc/%d/stat'%pid,'rb').read(4096).decode('ascii'); return int(v[v.rfind(')')+2:].split()[19])\n"
  " except (OSError,ValueError,IndexError): return None\n"
  "def atom(path,value):\n"
  " tmp=path+'.tmp'; f=open(tmp,'w',encoding='ascii'); json.dump(value,f,sort_keys=True,separators=(',',':')); f.flush(); os.fsync(f.fileno()); f.close(); os.replace(tmp,path)\n"
  "def redact(v):\n"
  " for x in secrets_:\n"
  "  if x:v=v.replace(x,b'[REDACTED]')\n"
  " return re.sub(br'\\x1b\\[[0-?]*[ -/]*[@-~]',b'',v).replace(b'\\x1b',b'')\n"
  "env={'LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin','DS4_NO_UPDATE_CHECK':'1','DS4_CONT_MTP_MODE':'2','DS4_CONT_DSPARK':'1','DS4_DSPARK_MODEL':spec['drafter']}\n"
  "for key in list(os.environ):\n"
  " if key.startswith('DS4_') or 'MODEL' in key: os.environ.pop(key,None)\n"
  "p=subprocess.Popen(spec['argv'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,start_new_session=False)\n"
  "atom(spec['ack'],{'child_pid':p.pid,'child_start_ticks':ticks(p.pid),'supervisor_pid':os.getpid(),'supervisor_start_ticks':ticks(os.getpid())})\n"
  "pending=b''; written=0\n"
  "while True:\n"
  " b=p.stdout.read(4096)\n"
  " if not b:break\n"
  " pending+=b\n"
  " cut=max(0,len(pending)-4096); out=redact(pending[:cut]); pending=pending[cut:]\n"
  " if written < 1048576:\n"
  "  out=out[:1048576-written]; log.write(out); written+=len(out)\n"
  "out=redact(pending)\n"
  "if written < 1048576: log.write(out[:1048576-written])\n"
  "p.wait(); log.close()\n")
@register_action("lifecycle_serve")
def lifecycle_serve(payload):
 data=_require_object(payload,{"workdir","run_dir","model_path","drafter_path","work_token","run_token","run_id","source_snapshot_id","applied_tree_hash","build_id","binary_path","port","startup_timeout_ms"})
 if not _lc_id(data["run_id"]) or not all(_lc_hex(data[k]) for k in ("source_snapshot_id","applied_tree_hash","build_id")) or not isinstance(data["port"],int) or not 1<=data["port"]<=65535 or not isinstance(data["startup_timeout_ms"],int) or not 1<=data["startup_timeout_ms"]<=600000: _fail("invalid_runtime_inputs")
 paths=_lc_roots(data); root=_lc_open(paths)
 try:
  try: state=_lc_read(root,"run.json")
  except HelperError as e:
   if e.code!="unsafe_state":raise
   state=None
  if state and state.get("state") in ("starting","running"):
   if _lc_live(state): _fail("run_active")
   state["state"]="stale_identity";_lc_atom(root,"run.json",state)
  binary=os.path.join(paths["workdir"],data["binary_path"])
  try: bstat=os.stat(binary,follow_symlinks=False)
  except OSError:_fail("startup_failed")
  if not stat.S_ISREG(bstat.st_mode) or not (bstat.st_mode&0o111):_fail("startup_failed")
  try: build=_lc_read(root,"build.json")
  except HelperError:_fail("startup_failed")
  binary_hash=build.get("binary_sha256") if isinstance(build,dict) else None
  if not isinstance(build,dict) or build.get("schema_version")!=1 or build.get("build_id")!=data["build_id"] or build.get("source_snapshot_id")!=data["source_snapshot_id"] or build.get("source_applied_tree_hash")!=data["applied_tree_hash"] or not _lc_hex(binary_hash) or not hmac.compare_digest(binary_hash,_lc_binary_hash(binary)):_fail("startup_failed")
  fd=os.open("server.log",os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=root)
  os.close(fd)
  spec={"argv":[binary,"--cuda","-m",paths["model_path"],"-c","32768","--host","127.0.0.1","--port",str(data["port"])],"drafter":paths["drafter_path"],"log":os.path.join(paths["run_dir"],"server.log"),"ack":os.path.join(paths["run_dir"],"ack.json"),"secrets":[paths["workdir"],paths["run_dir"],paths["model_path"],paths["drafter_path"]]}
  _lc_atom(root,"launch.json",spec); script=os.path.join(paths["run_dir"],"supervisor.py")
  fd=os.open("supervisor.py",os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=root)
  try: os.write(fd,_lc_supervisor_source().encode("ascii"));os.fsync(fd)
  finally:os.close(fd)
  p=subprocess.Popen(["/usr/bin/python3","-I","-S",script,os.path.join(paths["run_dir"],"launch.json")],cwd="/",stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,env={"LANG":"C","LC_ALL":"C","PATH":"/usr/bin:/bin"})
  state={"schema_version":1,"run_id":data["run_id"],"state":"starting","source_snapshot_id":data["source_snapshot_id"],"applied_tree_hash":data["applied_tree_hash"],"build_id":data["build_id"],"binary_sha256":binary_hash,"port":data["port"],"supervisor_pid":p.pid,"supervisor_start_ticks":_lc_ticks(p.pid),"child_pid":0}
  _lc_atom(root,"run.json",state); deadline=time.monotonic()+data["startup_timeout_ms"]/1000
  while time.monotonic()<deadline:
   try: ack=_lc_read(root,"ack.json")
   except HelperError: ack=None
   if isinstance(ack,dict) and ack.get("supervisor_pid")==p.pid and ack.get("supervisor_start_ticks")==state["supervisor_start_ticks"] and isinstance(ack.get("child_pid"),int) and isinstance(ack.get("child_start_ticks"),int):
    state["child_pid"]=ack["child_pid"]; state["child_start_ticks"]=ack["child_start_ticks"]
    if _lc_listener(data["port"],state["child_pid"]): state["state"]="running";_lc_atom(root,"run.json",state);return {"run_id":data["run_id"],"state":"running","port":data["port"]}
   if p.poll() is not None:break
   time.sleep(.05)
  state["state"]="failed_startup";_lc_atom(root,"run.json",state)
  if _lc_pid_identity(state): os.killpg(p.pid,signal.SIGTERM)
  _fail("startup_timeout")
 finally: os.close(root)
@register_action("lifecycle_status")
def lifecycle_status(payload):
 data=_require_object(payload,{"workdir","run_dir","model_path","drafter_path","work_token","run_token","run_id"}); paths=_lc_roots(data);root=_lc_open(paths)
 try:
  try:state=_lc_read(root,"run.json")
  except HelperError:return {"run_id":None,"state":"stopped","active":False}
  if payload["run_id"] is not None and state.get("run_id")!=payload["run_id"]:return {"run_id":None,"state":"stopped","active":False}
  active=_lc_live(state)
  if state.get("state") in ("starting","running") and not active:state["state"]="stale_identity";_lc_atom(root,"run.json",state)
  return {"run_id":state.get("run_id"),"state":state.get("state","stale_identity"),"active":active}
 finally:os.close(root)
@register_action("lifecycle_stop")
def lifecycle_stop(payload):
 data=_require_object(payload,{"workdir","run_dir","model_path","drafter_path","work_token","run_token","run_id"});paths=_lc_roots(data);root=_lc_open(paths)
 try:
  try:state=_lc_read(root,"run.json")
  except HelperError:return {"run_id":None,"status":"not_run"}
  if data["run_id"] is not None and state.get("run_id")!=data["run_id"]:return {"run_id":None,"status":"not_run"}
  if state.get("state") in ("stopped","stale_identity","failed_startup"):return {"run_id":state.get("run_id"),"status":"not_run"}
  if not _lc_pid_identity(state) or not _lc_live(state):state["state"]="stale_identity";_lc_atom(root,"run.json",state);return {"run_id":state.get("run_id"),"status":"not_run"}
  try:os.killpg(state["supervisor_pid"],signal.SIGTERM)
  except OSError:_fail("stop_failed")
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   if not _lc_pid_identity(state) and not _lc_listener(state["port"],state["child_pid"]):break
   time.sleep(.05)
  else:_fail("stop_failed")
  state["state"]="stopped";_lc_atom(root,"run.json",state)
  for n in ("supervisor.py","launch.json","ack.json"):
   try:os.unlink(n,dir_fd=root)
   except FileNotFoundError:pass
   except OSError:_fail("cleanup_failed")
  return {"run_id":state.get("run_id"),"status":"stopped"}
 finally:os.close(root)
@register_action("lifecycle_logs")
def lifecycle_logs(payload):
 paths=_lc_roots(_require_object(payload,{"workdir","run_dir","model_path","drafter_path","work_token","run_token"}));root=_lc_open(paths)
 try:
  fd,item=_open_regular("server.log",dir_fd=root)
  try:
   body=os.read(fd,_LC_MAX_LOG+1)
   if len(body)>_LC_MAX_LOG or os.read(fd,1):_fail("log_unavailable")
  finally:os.close(fd)
  return {"content_b64":base64.b64encode(body).decode("ascii")}
 finally:os.close(root)
'''
