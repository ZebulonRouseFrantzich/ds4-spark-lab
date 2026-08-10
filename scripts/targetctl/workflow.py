"""Private-safe Phase 01 workflow composition."""
from __future__ import annotations
from contextlib import contextmanager

from base64 import b64decode, b64encode
from datetime import UTC, datetime
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import stat
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from .artifacts import ArtifactBundle, MAX_TEXT_BYTES, _validate_source_snapshot, controller_provenance
from .build import BuildResult, build
from .common import TargetError, read_json_file, write_json_atomic
from .config import TargetConfig, load_target
from .doctor import DoctorResult, RuntimeInput as DoctorRuntimeInput, doctor
from .lifecycle import RuntimeInputs, cleanup, logs, serve, smoke, status, stop
from .redaction import StreamingRedactor, redaction_canaries
from .source import RepositoryState, SourceEntry, SourceSnapshot, SyncResult, build_snapshot, sync_source
from .transport import select_transport

DEFAULT_LOCAL_PORT = 8000
_CONFIG = Path("targets") / "targets.toml"
_HEX = frozenset("0123456789abcdef")
_WORKFLOW_STATE_SCHEMA = 2
_MAX_WORKFLOW_GENERATION = (1 << 63) - 1


def _fail(code: str, message: str = "target workflow is unavailable") -> None:
    raise TargetError(code, message)


def _root(value: str | os.PathLike[str]) -> Path:
    try:
        return Path(value).resolve(strict=True)
    except OSError:
        _fail("workflow_root_invalid")


def _config_path(root: Path) -> Path:
    path = root / _CONFIG
    try:
        info = os.lstat(path)
    except OSError:
        _fail("config_read_failed", "target configuration is unavailable")
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > 1_048_576
    ):
        _fail("config_private_invalid", "target configuration is unavailable")
    return path


def load_operational_target(repo_root: str | os.PathLike[str], target: str) -> TargetConfig:
    """Parse the one descriptor-pinned private configuration file."""
    root = _root(repo_root)
    path = _config_path(root)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        _fail("config_private_invalid", "target configuration is unavailable")
    try:
        info = os.fstat(fd)
        identity = (info.st_mode, info.st_uid, info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 1_048_576
        ):
            _fail("config_private_invalid", "target configuration is unavailable")
        config = load_target(root, target, f"/proc/self/fd/{fd}")
        after = os.fstat(fd)
        if (after.st_mode, after.st_uid, after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != identity:
            _fail("config_private_invalid", "target configuration is unavailable")
        return config
    finally:
        os.close(fd)


def _state_path(root: Path, target: str) -> Path:
    if target not in {"local", "spark"}:
        _fail("target_name_invalid", "target name is invalid")
    for directory in (root / "targets", root / "targets" / ".state"):
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            info = os.lstat(directory)
        except OSError:
            _fail("workflow_state_invalid", "controller state is unavailable")
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            _fail("workflow_state_invalid", "controller state is unavailable")
    return root / "targets" / ".state" / f"{target}.workflow-v2.json"


def _read_state_unlocked(root: Path, target: str, required: bool) -> dict[str, Any]:
    path = _state_path(root, target)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if required:
            _fail("workflow_state_missing", "controller state is unavailable")
        return {
            "schema": _WORKFLOW_STATE_SCHEMA,
            "generation": 0,
            "source": None,
            "build": None,
            "pending": None,
        }
    except OSError:
        _fail("workflow_state_invalid", "controller state is unavailable")
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _fail("workflow_state_invalid", "controller state is unavailable")
    result = read_json_file(
        path,
        allowed_keys=("schema", "generation", "source", "build", "pending"),
        required_keys=("schema", "generation", "source", "build", "pending"),
        max_bytes=32 * 1024 * 1024,
    )
    if (
        result["schema"] != _WORKFLOW_STATE_SCHEMA
        or not isinstance(result["generation"], int)
        or isinstance(result["generation"], bool)
        or not 0 <= result["generation"] <= _MAX_WORKFLOW_GENERATION
        or not isinstance(result["source"], (dict, type(None)))
        or not isinstance(result["build"], (dict, type(None)))
        or not isinstance(result["pending"], (dict, type(None)))
    ):
        _fail("workflow_state_invalid", "controller state is unavailable")
    return result


def _write_state_unlocked(root: Path, target: str, value: Mapping[str, Any]) -> None:
    if (
        set(value) != {"schema", "generation", "source", "build", "pending"}
        or value.get("schema") != _WORKFLOW_STATE_SCHEMA
        or not isinstance(value.get("generation"), int)
        or isinstance(value.get("generation"), bool)
        or not 0 <= value["generation"] <= _MAX_WORKFLOW_GENERATION
    ):
        _fail("workflow_state_invalid", "controller state is unavailable")
    write_json_atomic(
        _state_path(root, target), value,
        allowed_keys=("schema", "generation", "source", "build", "pending"),
        required_keys=("schema", "generation", "source", "build", "pending"),
        mode=0o600,
    )


def _advance_generation(state: dict[str, Any]) -> None:
    generation = state.get("generation")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or not 0 <= generation < _MAX_WORKFLOW_GENERATION
    ):
        _fail("workflow_state_invalid", "controller state is unavailable")
    state["generation"] = generation + 1


def _commit_state_unlocked(
    root: Path,
    target: str,
    state: dict[str, Any],
) -> None:
    """Commit one state transition and advance its exact CAS revision."""
    _advance_generation(state)
    _write_state_unlocked(root, target, state)


@contextmanager
def _controller_state_lock(root: Path, target: str):
    """Serialize controller-side read/modify/write ownership transitions."""
    lock_path = _state_path(root, target).parent / ".targetctl-controller-lock-v1"
    fd = -1
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(fd, 0o600)
        item = os.fstat(fd)
        if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o600:
            _fail("workflow_state_invalid", "controller state is unavailable")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError:
        _fail("workflow_busy", "controller operation is already active")
    except OSError:
        _fail("workflow_state_invalid", "controller state is unavailable")
    finally:
        if fd >= 0:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)


def _read_state(root: Path, target: str, required: bool) -> dict[str, Any]:
    with _controller_state_lock(root, target):
        return _read_state_unlocked(root, target, required)



def _snapshot(value: Any) -> SourceSnapshot:
    try:
        payload = _validate_source_snapshot({"snapshot": value})["snapshot"]
        repos = tuple(RepositoryState(**item) for item in payload["repositories"])
        entries = tuple(SourceEntry(item["path"], item["executable"], item["size"], item["sha256"], item["origin"]) for item in payload["entries"])
        return SourceSnapshot(repos, entries, payload["dirty"], payload["applied_tree_hash"], payload["snapshot_id"])
    except (KeyError, TypeError, TargetError):
        _fail("workflow_state_invalid", "controller state is unavailable")


def _build_state(value: Any, source: SourceSnapshot) -> dict[str, Any]:
    fields = {"source_snapshot_id", "source_applied_tree_hash", "build_id", "binary_sha256", "version", "binary_size", "sass", "build_log_sha256"}
    if not isinstance(value, dict) or set(value) != fields or value["source_snapshot_id"] != source.snapshot_id or value["source_applied_tree_hash"] != source.applied_tree_hash:
        _fail("workflow_state_invalid", "controller state is unavailable")
    for key in ("source_snapshot_id", "source_applied_tree_hash", "build_id", "binary_sha256", "build_log_sha256"):
        item = value[key]
        if not isinstance(item, str) or len(item) != 64 or any(char not in _HEX for char in item):
            _fail("workflow_state_invalid", "controller state is unavailable")
    if not isinstance(value["version"], str) or not value["version"] or not isinstance(value["binary_size"], int) or isinstance(value["binary_size"], bool) or value["binary_size"] < 1 or value["sass"] != "verified":
        _fail("workflow_state_invalid", "controller state is unavailable")
    return dict(value)


def _paths(config: TargetConfig) -> tuple[str, str]:
    if config.mode == "ssh":
        if config.model_path is None or config.drafter_path is None:
            _fail("runtime_input_missing", "runtime inputs are unavailable")
        return config.model_path, config.drafter_path
    model, drafter = os.environ.get("TARGETCTL_MODEL_PATH"), os.environ.get("TARGETCTL_DRAFTER_PATH")
    if not model or not drafter:
        _fail("runtime_input_missing", "runtime inputs are unavailable")
    return model, drafter


def _port(config: TargetConfig) -> int:
    if config.mode == "local":
        return DEFAULT_LOCAL_PORT
    try:
        parsed = urlsplit(config.api_base_url or "")
        port = parsed.port
    except ValueError:
        _fail("config_port_invalid", "target configuration is unavailable")
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or port is None or not 1 <= port <= 65535:
        _fail("config_port_invalid", "target configuration is unavailable")
    return port


def _runtime(config: TargetConfig, source: SourceSnapshot, built: Mapping[str, Any]) -> RuntimeInputs:
    model, drafter = _paths(config)
    if config.mode == "local":
        return RuntimeInputs(model_path=model, drafter_path=drafter, source_snapshot_id=source.snapshot_id, applied_tree_hash=source.applied_tree_hash, build_id=built["build_id"], port=_port(config))
    from .source import _load_capabilities
    capability = _load_capabilities(Path(config.source_root), config.name)
    if capability is None:
        _fail("workflow_capability_missing", "source capability state is unavailable")
    return RuntimeInputs(model, drafter, source.snapshot_id, source.applied_tree_hash, built["build_id"], capability["work_token"], capability["run_token"], _port(config))


def _doctor_runtime(config: TargetConfig) -> DoctorRuntimeInput | None:
    if config.mode != "local":
        return None
    model, drafter = _paths(config)
    return DoctorRuntimeInput(model, drafter, 1)


def _save_source(root: Path, target: str, source: SourceSnapshot) -> None:
    with _controller_state_lock(root, target):
        state = _read_state_unlocked(root, target, False)
        if state["pending"] is not None:
            _fail("workflow_run_pending", "target run reconciliation is required")
        state["source"] = source.as_dict()
        state["build"] = None
        state["pending"] = None
        _commit_state_unlocked(root, target, state)

def _sync_and_save_source(
    root: Path,
    target: str,
    config: TargetConfig,
    transport: Any,
    *,
    snapshot: SourceSnapshot | None = None,
) -> SyncResult:
    """Serialize sync with its all-or-nothing controller invalidation."""
    with _controller_state_lock(root, target):
        state = _read_state_unlocked(root, target, False)
        if state["pending"] is not None:
            _fail("workflow_run_pending", "target run reconciliation is required")
        result = sync_source(config, transport, snapshot=snapshot)
        synchronized = snapshot if snapshot is not None else result.snapshot
        if result.applied_tree_hash != synchronized.applied_tree_hash:
            _fail("source_identity_mismatch", "source synchronization is unavailable")
        state["source"] = synchronized.as_dict()
        state["build"] = None
        state["pending"] = None
        _commit_state_unlocked(root, target, state)
        return result


def _build_generation(
    root: Path,
    target: str,
    source: SourceSnapshot,
) -> int:
    """Pin the exact controller revision that a target build may publish into."""
    with _controller_state_lock(root, target):
        state = _read_state_unlocked(root, target, True)
        if state["pending"] is not None:
            _fail("workflow_run_pending", "target run reconciliation is required")
        if state["source"] != source.as_dict():
            _fail("workflow_source_stale", "source must be synchronized again")
        return state["generation"]


def _save_build(
    root: Path,
    target: str,
    source: SourceSnapshot,
    result: BuildResult,
    *,
    expected_generation: int,
) -> None:
    if (
        not isinstance(expected_generation, int)
        or isinstance(expected_generation, bool)
        or not 0 <= expected_generation <= _MAX_WORKFLOW_GENERATION
    ):
        _fail("workflow_state_invalid", "controller state is unavailable")
    if result.status != "succeeded":
        return
    with _controller_state_lock(root, target):
        state = _read_state_unlocked(root, target, True)
        if (
            state["generation"] != expected_generation
            or state["source"] != source.as_dict()
        ):
            _fail("workflow_source_stale", "source must be synchronized again")
        if state["pending"] is not None:
            _fail("workflow_run_pending", "target run reconciliation is required")
        payload = result.controller_payload()
        state["build"] = {
            key: payload[key]
            for key in (
                "source_snapshot_id",
                "source_applied_tree_hash",
                "build_id",
                "binary_sha256",
                "version",
                "binary_size",
                "sass",
                "build_log_sha256",
            )
        }
        _commit_state_unlocked(root, target, state)


def _build_and_save(
    root: Path,
    target: str,
    config: TargetConfig,
    transport: Any,
    source: SourceSnapshot,
    *,
    allow_dirty: str | None,
    jobs: int | None,
) -> BuildResult:
    """Build against one state revision and publish only through its exact CAS."""
    generation = _build_generation(root, target, source)
    result = build(
        config,
        transport,
        snapshot=source,
        allow_dirty=allow_dirty,
        jobs=jobs,
    )
    _save_build(
        root,
        target,
        source,
        result,
        expected_generation=generation,
    )
    return result


def _source_ready(root: Path, target: str) -> SourceSnapshot:
    return _snapshot(_read_state(root, target, True)["source"])


def _ready(root: Path, target: str) -> tuple[SourceSnapshot, dict[str, Any]]:
    state = _read_state(root, target, True)
    source = _snapshot(state["source"])
    return source, _build_state(state["build"], source)


def _store_pending_run(root: Path, target: str, source: SourceSnapshot, built: Mapping[str, Any], run_id: str) -> None:
    """Persist one public launch identity without replacing unresolved ownership."""
    if (
        not isinstance(run_id, str)
        or not 8 <= len(run_id) <= 64
        or not run_id.startswith("run-")
        or not run_id.isascii()
        or any(not (character.islower() or character.isdigit() or character == "-") for character in run_id)
    ):
        _fail("workflow_state_invalid", "controller state is unavailable")
    with _controller_state_lock(root, target):
        state = _read_state_unlocked(root, target, True)
        if state["pending"] is not None:
            _fail("workflow_run_pending", "target run reconciliation is required")
        if state["source"] != source.as_dict():
            _fail("workflow_state_invalid", "controller state is unavailable")
        current = _build_state(state["build"], source)
        if current != dict(built):
            _fail("workflow_state_invalid", "controller state is unavailable")
        state["pending"] = {
            "schema": 1,
            "run_id": run_id,
            "source_snapshot_id": source.snapshot_id,
            "build_id": current["build_id"],
            "binary_sha256": current["binary_sha256"],
        }
        _commit_state_unlocked(root, target, state)


def _pending_run(root: Path, target: str) -> str | None:
    with _controller_state_lock(root, target):
        state = _read_state_unlocked(root, target, True)
        pending = state["pending"]
        if pending is None:
            return None
        if (
            set(pending) != {"schema", "run_id", "source_snapshot_id", "build_id", "binary_sha256"}
            or pending.get("schema") != 1
            or not isinstance(pending["run_id"], str)
            or not 8 <= len(pending["run_id"]) <= 64
            or not pending["run_id"].startswith("run-")
            or not pending["run_id"].isascii()
            or any(not (character.islower() or character.isdigit() or character == "-") for character in pending["run_id"])
            or any(not isinstance(pending[key], str) or len(pending[key]) != 64 or any(char not in _HEX for char in pending[key]) for key in ("source_snapshot_id", "build_id", "binary_sha256"))
        ):
            _fail("workflow_state_invalid", "controller state is unavailable")
        source = _snapshot(state["source"])
        built = _build_state(state["build"], source)
        if (
            pending["source_snapshot_id"] != source.snapshot_id
            or pending["build_id"] != built["build_id"]
            or pending["binary_sha256"] != built["binary_sha256"]
        ):
            _fail("workflow_state_invalid", "controller state is unavailable")
        return pending["run_id"]


def _clear_pending_run(root: Path, target: str, run_id: str | None) -> None:
    if run_id is None:
        return
    with _controller_state_lock(root, target):
        state = _read_state_unlocked(root, target, True)
        pending = state["pending"]
        if pending is not None and pending.get("run_id") == run_id:
            state["pending"] = None
            _commit_state_unlocked(root, target, state)

def _clear_new_pending_on_refusal(root: Path, target: str, run_id: str, error: TargetError) -> None:
    """CAS-clear only the launch identity rejected before target dispatch."""
    if error.code == "serve_not_dispatched":
        _clear_pending_run(root, target, run_id)


def _assert_no_pending_run(root: Path, target: str) -> None:
    with _controller_state_lock(root, target):
        if _read_state_unlocked(root, target, False)["pending"] is not None:
            _fail("workflow_run_pending", "target run reconciliation is required")



def _verify_current_binary(config: TargetConfig, built: Mapping[str, Any]) -> None:
    """Stream and pin the local executable before using its build identity."""
    if config.mode != "local":
        return
    path = Path(config.source_root) / "engine" / "ds4" / "ds4-server"
    try:
        before = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or not before.st_mode & stat.S_IXUSR
            or before.st_size != built["binary_size"]
        ):
            raise OSError
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except (KeyError, OSError):
        _fail("workflow_binary_invalid", "build identity is unavailable")
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            _fail("workflow_binary_invalid", "build identity is unavailable")
        digest = hashlib.sha256()
        while block := os.read(fd, 1024 * 1024):
            digest.update(block)
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
            _fail("workflow_binary_invalid", "build identity is unavailable")
    except OSError:
        _fail("workflow_binary_invalid", "build identity is unavailable")
    finally:
        os.close(fd)
    if digest.hexdigest() != built["binary_sha256"]:
        _fail("workflow_binary_stale", "build identity is unavailable")

def _not_run_build() -> dict[str, Any]:
    return {"status": "not_run", "failure_class": None, "source_snapshot_id": None, "source_applied_tree_hash": None, "build_id": None, "binary_sha256": None, "command": None, "version": None, "binary_size": None, "sass": "not_run", "build_log_sha256": None, "exit_code": None, "duration_ns": None}


def _not_run_run() -> dict[str, Any]:
    return {"status": "not_run", "failure_class": None, "state": None, "run_id": None, "source_snapshot_id": None, "build_id": None, "binary_sha256": None, "supervisor_pid": None, "supervisor_start_ticks": None, "child_pid": None, "child_start_ticks": None, "port": None, "launch_profile": None}


def _not_run_smoke() -> dict[str, Any]:
    return {"status": "not_run", "failure_class": None, "readiness_http": None, "models_http": None, "contract": "not_run", "primary_weight_sha256": None, "draft_weight_sha256": None, "duration_ns": None}


def _not_run_cleanup() -> dict[str, Any]:
    return {"status": "not_run", "failure_class": None, "process": "not_run", "socket": "not_run", "lock": "not_run", "temp": "not_run", "server_log_sha256": None}


def _cleanup_artifact_payload(result: Any) -> dict[str, Any]:
    """Map observed cleanup evidence into an artifact-safe record."""
    fields = {"process": getattr(result, "process", "unknown"), "socket": getattr(result, "socket", "unknown"), "lock": getattr(result, "lock", "unknown"), "temp": getattr(result, "temp", "unknown")}
    if getattr(result, "status", "not_run") == "not_run" or all(v in (None, "not_run") for v in fields.values()):
        return {"status": "not_run", "failure_class": None, "process": "not_run", "socket": "not_run", "lock": "not_run", "temp": "not_run", "server_log_sha256": None}
    all_cleared = all(v in ("cleared", "not_found") for v in fields.values())
    has_digest = isinstance(getattr(result, "server_log_sha256", None), str)
    if all_cleared and has_digest:
        return {"status": "succeeded", "failure_class": None, "server_log_sha256": result.server_log_sha256, **fields}
    return {"status": "failed", "failure_class": "command_failed", "server_log_sha256": getattr(result, "server_log_sha256", None), **fields}


def _lifecycle_run_record(run_result: Any) -> dict[str, Any]:
    """Map observed run evidence into an artifact-safe record."""
    payload = run_result.controller_payload()
    state = payload.get("state")
    if state in {"running", "stopped"}:
        return {"status": "succeeded", "failure_class": None, **payload}
    if state in {"starting", "failed_startup", "stale_identity"}:
        failure = {
            "starting": "unavailable",
            "failed_startup": "preflight",
            "stale_identity": "identity_mismatch",
        }[state]
        return {"status": "failed", "failure_class": failure, **payload}
    return _not_run_run()


def _lifecycle_smoke_record(smoke_result: Any, run_status: str) -> dict[str, Any]:
    """Map observed smoke evidence into an artifact-safe record."""
    if run_status != "succeeded":
        return _not_run_smoke()
    return {
        "status": getattr(smoke_result, "status", "failed"),
        "failure_class": None if getattr(smoke_result, "status", None) == "succeeded" else "contract_failed",
        "readiness_http": getattr(smoke_result, "readiness_http", None),
        "models_http": getattr(smoke_result, "models_http", None),
        "contract": getattr(smoke_result, "contract", None),
        "primary_weight_sha256": getattr(smoke_result, "primary_weight_sha256", None),
        "draft_weight_sha256": getattr(smoke_result, "draft_weight_sha256", None),
        "duration_ns": getattr(smoke_result, "duration_ns", None),
    }


def _status_runtime(root: Path, target: str, config: TargetConfig) -> RuntimeInputs:
    """Construct identity-only runtime for status/logs/stop/cleanup without env."""
    source, built = _ready(root, target)
    if config.mode == "ssh":
        from .source import _load_capabilities
        capability = _load_capabilities(Path(config.source_root), config.name)
        if capability is None:
            _fail("workflow_capability_missing", "source capability state is unavailable")
        return RuntimeInputs(config.model_path, config.drafter_path, source.snapshot_id, source.applied_tree_hash, built["build_id"], capability["work_token"], capability["run_token"], _port(config))
    return RuntimeInputs("/dev/null", "/dev/null", source.snapshot_id, source.applied_tree_hash, built["build_id"], port=_port(config))


def _time() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _stored_log_identity(item: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    """Return the pathname/file identity that must remain stable during promotion."""
    return (item.st_mode, item.st_uid, item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def _read_stored_log_snapshot(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> tuple[bytes, tuple[int, int, int, int, int, int, int]]:
    """Read a stored log and retain its pinned identity for a later stability check."""
    try:
        before = os.lstat(path)
    except OSError:
        _fail("artifact_log_unavailable", "sanitized stored report is unavailable")
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size > max_bytes
    ):
        _fail("artifact_log_unavailable", "sanitized stored report is unavailable")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        _fail("artifact_log_unavailable", "sanitized stored report is unavailable")
    try:
        opened = os.fstat(fd)
        before_identity = _stored_log_identity(before)
        if _stored_log_identity(opened) != before_identity:
            _fail("artifact_log_unavailable", "sanitized stored report is unavailable")
        content = bytearray()
        while True:
            chunk = os.read(fd, 65_536)
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > max_bytes:
                _fail("artifact_too_large", "artifact text exceeds its size limit")
        after = os.fstat(fd)
        if _stored_log_identity(after) != before_identity:
            _fail("artifact_log_unavailable", "sanitized stored report is unavailable")
    except OSError:
        _fail("artifact_log_unavailable", "sanitized stored report is unavailable")
    finally:
        os.close(fd)
    return bytes(content), before_identity


def _read_stored_log(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> bytes:
    """Read a stored log through a pinned descriptor without accepting a pathname swap."""
    return _read_stored_log_snapshot(path, max_bytes)[0]


def _assert_stored_log_unchanged(path: Path, expected: tuple[int, int, int, int, int, int, int]) -> None:
    """Reject a live report that changed while its controller copy was promoted."""
    try:
        current = os.lstat(path)
    except OSError:
        _fail("artifact_log_unavailable", "sanitized stored report is unavailable")
    if _stored_log_identity(current) != expected:
        _fail("artifact_log_unavailable", "sanitized stored report is unavailable")

def _private_canaries(config: TargetConfig) -> tuple[str, ...]:
    """Return bounded invocation/config values that must never survive promotion."""
    model, drafter = _paths(config)
    if config.mode == "local":
        additional = (str(config.source_root), str(config.local_run_dir))
    else:
        # Target-produced reports never observe the controller-only SSH alias.
        additional = (config.workdir, config.run_dir)
    try:
        return redaction_canaries((model, drafter), additional=additional)
    except TargetError:
        _fail("artifact_canary_invalid", "artifact canary is invalid")


def _promote_log_content(bundle: ArtifactBundle, text_name: str, content: bytes, digest: str, config: TargetConfig, spool_dir: Path) -> None:
    """Verify and promote a bounded producer-sanitized log."""
    private = _private_canaries(config)
    if hashlib.sha256(content).hexdigest() != digest:
        _fail("artifact_log_mismatch", "advertised artifact log does not match promoted text")
    verified_path = spool_dir / f".artifact-{text_name}-{secrets.token_hex(8)}.log"
    try:
        fd = os.open(verified_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        bundle.promote_text(text_name, verified_path, StreamingRedactor(private, max_output=MAX_TEXT_BYTES), canaries=private)
    finally:
        try:
            verified_path.unlink()
        except OSError:
            pass


def _remote_report(config: TargetConfig, transport: Any, name: str) -> bytes:
    """Retrieve one fixed bounded report through the target-owned helper."""
    from .source import _load_capabilities
    capability = _load_capabilities(Path(config.source_root), config.name)
    if capability is None:
        _fail("workflow_capability_missing", "source capability state is unavailable")
    result = transport.run_helper(
        "read_report",
        {"run_dir": config.run_dir, "run_token": capability["run_token"], "name": name},
        allowed_error_codes=("invalid_report", "marker_mismatch", "report_too_large", "unsafe_root", "unsafe_state"),
    )
    if not isinstance(result, Mapping) or set(result) != {"sha256", "content_b64"} or not isinstance(result["sha256"], str):
        _fail("artifact_log_unavailable", "sanitized target report is unavailable")
    try:
        content = b64decode(result["content_b64"], validate=True)
    except (TypeError, ValueError):
        _fail("artifact_log_unavailable", "sanitized target report is unavailable")
    if len(content) > MAX_TEXT_BYTES or hashlib.sha256(content).hexdigest() != result["sha256"]:
        _fail("artifact_log_mismatch", "sanitized target report identity is invalid")
    return content


def _promote_build_log(bundle: ArtifactBundle, root: Path, target: str, digest: str, config: TargetConfig, transport: Any) -> None:
    """Promote the actual producer-sanitized build log."""
    if config.mode == "local":
        content = _read_stored_log(Path(config.local_run_dir) / "build.log")
        spool_dir = Path(config.local_run_dir)
    else:
        content = _remote_report(config, transport, "build.log")
        spool_dir = _state_path(root, target).parent
    _promote_log_content(bundle, "build-log", content, digest, config, spool_dir)


def _promote_server_log(bundle: ArtifactBundle, root: Path, target: str, digest: str, config: TargetConfig, transport: Any) -> None:
    """Promote a stable producer-sanitized server log without consuming the live file."""
    if config.mode == "local":
        live_path = Path(config.local_run_dir) / "server.log"
        content, identity = _read_stored_log_snapshot(live_path)
        _promote_log_content(bundle, "server-log", content, digest, config, Path(config.local_run_dir))
        _assert_stored_log_unchanged(live_path, identity)
        return
    content = _remote_report(config, transport, "server.log")
    _promote_log_content(bundle, "server-log", content, digest, config, _state_path(root, target).parent)
    current = _remote_report(config, transport, "server.log")
    if hashlib.sha256(current).hexdigest() != digest:
        _fail("artifact_log_mismatch", "advertised artifact log changed during promotion")


def _cleanup_allows_server_log_removal(cleanup_record: Mapping[str, Any]) -> bool:
    """Return whether cleanup proved that no process can still write the server log."""
    return all(cleanup_record.get(field) in {"cleared", "not_found"} for field in ("process", "socket"))

def _cleanup_promoted_reports(config: TargetConfig, transport: Any, reports: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    """Remove only digest-matching reports after their artifact copy is finalized."""
    if not reports:
        return {"status": "succeeded", "reports": []}
    if config.mode == "ssh":
        from .source import _load_capabilities
        capability = _load_capabilities(Path(config.source_root), config.name)
        if capability is None:
            return {"status": "failed", "reports": []}
        try:
            result = transport.run_helper(
                "remove_reports",
                {"run_dir": config.run_dir, "run_token": capability["run_token"], "reports": [{"name": name, "sha256": digest} for name, digest in reports]},
                allowed_error_codes=("invalid_report", "marker_mismatch", "unsafe_root", "unsafe_state"),
            )
        except TargetError:
            return {"status": "failed", "reports": []}
        if not isinstance(result, Mapping) or set(result) != {"reports"} or not isinstance(result["reports"], list) or len(result["reports"]) != len(reports):
            return {"status": "failed", "reports": []}
        outcomes = result["reports"]
        if any(
            not isinstance(item, Mapping)
            or set(item) != {"name", "result"}
            or item["name"] != expected_name
            or item["result"] not in {"cleared", "not_found"}
            for item, (expected_name, _) in zip(outcomes, reports, strict=True)
        ):
            return {"status": "failed", "reports": []}
        clean = [{"name": item["name"], "result": item["result"]} for item in outcomes]
        return {"status": "succeeded" if all(item["result"] == "cleared" for item in clean) else "failed", "reports": clean}
    from .lifecycle import local_operation_lock
    outcomes: list[str] = []
    try:
        with local_operation_lock(str(config.local_run_dir)):
            for name, digest in reports:
                path = Path(config.local_run_dir) / name
                try:
                    before = os.lstat(path)
                    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1:
                        outcomes.append("not_found")
                        continue
                    content = _read_stored_log(path)
                    after = os.lstat(path)
                    if hashlib.sha256(content).hexdigest() != digest or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns):
                        outcomes.append("not_found")
                        continue
                    path.unlink()
                    outcomes.append("cleared")
                except (OSError, TargetError):
                    outcomes.append("not_found")
    except TargetError:
        return {"status": "failed", "reports": outcomes}
    return {
        "status": "succeeded" if len(outcomes) == len(reports) and all(value == "cleared" for value in outcomes) else "failed",
        "reports": [{"name": name, "result": outcome} for (name, _), outcome in zip(reports, outcomes, strict=True)],
    }


def _public_doctor(result: DoctorResult) -> dict[str, Any]:
    return result.controller_payload()


def _public_build(result: BuildResult) -> dict[str, Any]:
    return result.controller_payload()


def run_bundle(repo_root: str | os.PathLike[str], target: str, *, allow_dirty: str | None = None, jobs: int | None = None) -> dict[str, Any]:
    """Run doctor/sync/build/serve/smoke/cleanup and publish one dependency-consistent bundle."""
    root = _root(repo_root)
    config = load_operational_target(root, target)
    transport = select_transport(config, repo_root=root)
    source = build_snapshot(root)
    bundle = ArtifactBundle(root, config.name, f"bundle-{time.time_ns()}-{secrets.token_hex(6)}", operation="bundle")
    doctor_result: DoctorResult | None = None
    build_result: BuildResult | None = None
    run_record = _not_run_run()
    smoke_record = _not_run_smoke()
    cleanup_record = _not_run_cleanup()
    promoted_reports: list[tuple[str, str]] = []
    try:
        bundle.write_record("controller", {"provenance": controller_provenance(root)}, created_at=_time())
        bundle.write_record("source", {"snapshot": source.as_dict()}, created_at=_time())
        _sync_and_save_source(
            root, config.name, config, transport, snapshot=source,
        )
        doctor_result = doctor(config, transport, snapshot=source, allow_dirty=allow_dirty, runtime=_doctor_runtime(config))
        bundle.write_record("target-doctor", doctor_result.controller_payload(), created_at=_time())
        if doctor_result.status == "succeeded":
            build_result = _build_and_save(
                root,
                config.name,
                config,
                transport,
                source,
                allow_dirty=allow_dirty,
                jobs=jobs,
            )
            build_payload = build_result.controller_payload()
        else:
            build_payload = _not_run_build()
        bundle.write_record("build", build_payload, created_at=_time())
        if build_payload["build_log_sha256"] is not None:
            _promote_build_log(bundle, root, config.name, build_payload["build_log_sha256"], config, transport)
            promoted_reports.append(("build.log", build_payload["build_log_sha256"]))
        if build_payload["status"] == "succeeded":
            source_snap, built = _ready(root, config.name)
            _verify_current_binary(config, built)
            runtime = _runtime(config, source_snap, built)
            run_id = "run-" + secrets.token_hex(12)
            _store_pending_run(root, config.name, source_snap, built, run_id)
            try:
                smoke_result = smoke(config, transport, runtime, run_id=run_id)
            except TargetError as error:
                _clear_new_pending_on_refusal(root, config.name, run_id, error)
                raise
            observed_run = getattr(smoke_result, "run", None)
            observed_cleanup = getattr(smoke_result, "cleanup", None)
            if observed_run is None or observed_cleanup is None:
                _fail("lifecycle_evidence_unavailable", "lifecycle evidence is unavailable")
            run_record = _lifecycle_run_record(observed_run)
            smoke_record = _lifecycle_smoke_record(smoke_result, run_record["status"])
            cleanup_record = _cleanup_artifact_payload(observed_cleanup)
            if (
                getattr(observed_cleanup, "run_id", None) == run_id
                and getattr(observed_cleanup, "status", None) in {"succeeded", "not_run"}
                and getattr(smoke_result, "status", None) == "succeeded"
            ):
                _clear_pending_run(root, config.name, run_id)
            if cleanup_record.get("server_log_sha256"):
                _promote_server_log(bundle, root, config.name, cleanup_record["server_log_sha256"], config, transport)
                if _cleanup_allows_server_log_removal(cleanup_record):
                    promoted_reports.append(("server.log", cleanup_record["server_log_sha256"]))
        bundle.write_record("run", run_record, created_at=_time())
        bundle.write_record("smoke", smoke_record, created_at=_time())
        bundle.write_record("cleanup", cleanup_record, created_at=_time())
        artifact = bundle.finalize()
    except BaseException:
        bundle.discard()
        raise
    report_cleanup = _cleanup_promoted_reports(config, transport, tuple(promoted_reports))
    completed = (
        doctor_result is not None
        and doctor_result.status == "succeeded"
        and build_payload["status"] == "succeeded"
        and run_record["status"] == "succeeded"
        and smoke_record["status"] == "succeeded"
        and cleanup_record["status"] == "succeeded"
        and report_cleanup["status"] == "succeeded"
    )
    response = {"status": "succeeded" if completed else "failed", "doctor": _public_doctor(doctor_result), "build": _public_build(build_result) if build_result else None, "artifact": artifact, "report_cleanup": report_cleanup}
    if report_cleanup["status"] != "succeeded":
        response["error"] = "report_cleanup_failed"
    return response


def execute(repo_root: str | os.PathLike[str], target: str, operation: str, *, allow_dirty: str | None = None, jobs: int | None = None) -> dict[str, Any]:
    """Run one controller operation and expose only fixed sanitized fields."""
    if operation == "bundle":
        return run_bundle(repo_root, target, allow_dirty=allow_dirty, jobs=jobs)
    if operation not in {"doctor", "sync", "build", "serve", "status", "logs", "stop", "smoke", "cleanup"}:
        _fail("operation_invalid", "target operation is invalid")
    root = _root(repo_root)
    config = load_operational_target(root, target)
    transport = select_transport(config, repo_root=root)
    if operation == "doctor":
        source_snap = _source_ready(root, config.name)
        if build_snapshot(root).as_dict() != source_snap.as_dict():
            _fail("workflow_source_stale", "source must be synchronized again")
        return _public_doctor(doctor(config, transport, snapshot=source_snap, allow_dirty=allow_dirty, runtime=_doctor_runtime(config)))
    if operation == "sync":
        result = _sync_and_save_source(root, config.name, config, transport)
        return {"status": "succeeded", "snapshot_id": result.snapshot.snapshot_id, "applied_tree_hash": result.snapshot.applied_tree_hash, "initialized": result.initialized}
    if operation == "build":
        _assert_no_pending_run(root, config.name)
        source_snap = _source_ready(root, config.name)
        if build_snapshot(root).as_dict() != source_snap.as_dict():
            _fail("workflow_source_stale", "source must be synchronized again")
        result = _build_and_save(
            root,
            config.name,
            config,
            transport,
            source_snap,
            allow_dirty=allow_dirty,
            jobs=jobs,
        )
        return _public_build(result)
    if operation in {"status", "logs", "stop", "cleanup"}:
        runtime = _status_runtime(root, config.name, config)
        pending_run_id = _pending_run(root, config.name)
        if operation == "status":
            result = status(config, transport, runtime, run_id=pending_run_id)
            return {"status": "succeeded", "run_id": result.run_id, "state": result.state, "active": result.active}
        if operation == "logs":
            content = logs(config, transport, runtime, run_id=pending_run_id)
            if not isinstance(content, bytes) or len(content) > MAX_TEXT_BYTES:
                _fail("log_unavailable", "sanitized server log is unavailable")
            return {
                "status": "succeeded",
                "content_b64": b64encode(content).decode("ascii"),
                "log_sha256": hashlib.sha256(content).hexdigest(),
                "log_bytes": len(content),
            }
        result = stop(config, transport, runtime, run_id=pending_run_id) if operation == "stop" else cleanup(config, transport, runtime, run_id=pending_run_id)
        if (
            pending_run_id is not None
            and result.status in {"succeeded", "not_run"}
            and (result.run_id == pending_run_id or (result.status == "not_run" and result.run_id is None))
        ):
            _clear_pending_run(root, config.name, pending_run_id)
        payload = result.controller_payload()
        outcome = payload.pop("status")
        return {
            "status": "failed" if outcome == "failed" else "succeeded",
            "outcome": outcome,
            **payload,
        }
    source, built = _ready(root, config.name)
    if build_snapshot(root).as_dict() != source.as_dict():
        _fail("workflow_source_stale", "source must be synchronized again")
    _verify_current_binary(config, built)
    runtime = _runtime(config, source, built)
    if operation == "serve":
        run_id = "run-" + secrets.token_hex(12)
        _store_pending_run(root, config.name, source, built, run_id)
        try:
            result = serve(config, transport, runtime, run_id=run_id)
        except TargetError as error:
            _clear_new_pending_on_refusal(root, config.name, run_id, error)
            raise
        return {"status": "succeeded", **result.controller_payload()}
    run_id = "run-" + secrets.token_hex(12)
    _store_pending_run(root, config.name, source, built, run_id)
    try:
        result = smoke(config, transport, runtime, run_id=run_id)
    except TargetError as error:
        _clear_new_pending_on_refusal(root, config.name, run_id, error)
        raise
    observed_cleanup = getattr(result, "cleanup", None)
    if (
        observed_cleanup is not None
        and getattr(observed_cleanup, "run_id", None) == run_id
        and getattr(observed_cleanup, "status", None) in {"succeeded", "not_run"}
        and getattr(result, "status", None) == "succeeded"
    ):
        _clear_pending_run(root, config.name, run_id)
    observed_run = getattr(result, "run", None)
    if observed_run is None or observed_cleanup is None:
        _fail("lifecycle_evidence_unavailable", "lifecycle evidence is unavailable")
    return {
        "status": result.status,
        "smoke": result.controller_payload(),
        "run": observed_run.controller_payload(),
        "cleanup": observed_cleanup.controller_payload(),
    }


def structured_result(repo_root: str | os.PathLike[str], target: str, operation: str, *, allow_dirty: str | None = None, jobs: int | None = None) -> dict[str, Any]:
    try:
        return {"schema": 1, "operation": operation, "target": target, **execute(repo_root, target, operation, allow_dirty=allow_dirty, jobs=jobs)}
    except KeyboardInterrupt:
        return {"schema": 1, "operation": operation, "target": target, "status": "failed", "error": "interrupted"}
    except TargetError as exc:
        return {"schema": 1, "operation": operation, "target": target, "status": "failed", "error": exc.code}
    except Exception:
        return {"schema": 1, "operation": operation, "target": target, "status": "failed", "error": "internal_error"}
