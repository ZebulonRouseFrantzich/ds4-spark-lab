"""Private-safe, atomic controller artifacts for Phase 01.

This module deliberately has a small, fixed on-disk vocabulary.  A bundle is
assembled in a private sibling staging directory and becomes visible at its
operation ID only after its complete parent chain and index have been written.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import time
from typing import Any, Iterable, Mapping

from .common import (
    TargetError,
    canonical_json_bytes,
    read_json_file,
    record_id_for,
    validate_object_keys,
    write_json_atomic,
)
from .redaction import StreamingRedactor


ARTIFACT_SCHEMA = 1
ARTIFACT_ROOT = Path("artifacts") / "phase-01-runs"
MAX_TEXT_BYTES = 1_048_576
MAX_SOURCE_ENTRIES = 100_000
MAX_SOURCE_RECORD_BYTES = 32 * 1024 * 1024
MAX_RECORD_BYTES = 1_048_576
MAX_SOURCE_FILE_BYTES = MAX_SOURCE_RECORD_BYTES + 65_536
MAX_VALUE_TEXT = 512
MAX_TOOL_VERSION = 160
_RECORD_NAMES = (
    "controller",
    "source",
    "target-doctor",
    "build",
    "run",
    "smoke",
    "cleanup",
)
_RECORD_PARENTS = {
    name: (() if index == 0 else (_RECORD_NAMES[index - 1],))
    for index, name in enumerate(_RECORD_NAMES)
}
_COMPONENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_TEXT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
_HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_SYSTEM_RE = re.compile(r"[A-Za-z0-9._+@=-]{1,160}\Z")
_SOURCE_PATH_RE = re.compile(r"(?:[A-Za-z0-9][A-Za-z0-9._+@%=-]{0,127}/)*[A-Za-z0-9][A-Za-z0-9._+@%=-]{0,127}\Z")
_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){0,3}\Z")
_SYSTEM_TOOL_PATHS = {
    "nvidia-smi": frozenset(("/usr/bin/nvidia-smi",)),
    "nvcc": frozenset(("/usr/local/cuda/bin/nvcc",)),
    "gcc": frozenset(("/usr/bin/gcc",)),
    "g++": frozenset(("/usr/bin/g++",)),
    "make": frozenset(("/usr/bin/make",)),
    "python3": frozenset(("/usr/bin/python3",)),
    "git": frozenset(("/usr/bin/git",)),
    "rsync": frozenset(("/usr/bin/rsync",)),
    "cuobjdump": frozenset(("/usr/local/cuda/bin/cuobjdump",)),
}
_DOCTOR_TOOLS = tuple(_SYSTEM_TOOL_PATHS)
_FAILURE_CLASSES = frozenset(
    ("configuration", "preflight", "tool_missing", "command_failed", "timeout", "contract_failed", "identity_mismatch", "unavailable")
)
_LIFECYCLE_STATES = frozenset(("starting", "running", "stopped", "stale_identity", "failed_startup"))
_SOURCE_EXCLUSIONS = (
    ".git", "targets", "models", "drafters", "artifacts/phase-01-runs", "build", "dist", "result",
    ".direnv", ".nix-cache", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
)


def _fail(code: str, message: str) -> TargetError:
    return TargetError(code, message)


def _artifact_record_id(value: Mapping[str, Any]) -> str:
    """Identify semantic provenance, excluding observational clock fields."""

    identity = dict(value)
    identity.pop("record_id", None)
    identity.pop("created_at", None)
    identity.pop("duration_ns", None)
    return record_id_for(identity)


def _safe_component(value: Any, *, code: str = "artifact_name_invalid") -> str:
    if not isinstance(value, str) or not _COMPONENT_RE.fullmatch(value):
        raise _fail(code, "artifact name is invalid")
    return value


def _safe_text_name(value: Any) -> str:
    if not isinstance(value, str) or not _TEXT_NAME_RE.fullmatch(value):
        raise _fail("artifact_name_invalid", "artifact name is invalid")
    return value


def _ensure_private_directory(path: Path, *, create: bool) -> None:
    """Create/check one directory without accepting a symlink or special file."""

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if not create:
            raise _fail("artifact_path_invalid", "artifact path is unavailable")
        try:
            path.mkdir(mode=0o700)
        except OSError:
            raise _fail("artifact_write_failed", "artifact directory could not be created") from None
        try:
            info = os.lstat(path)
        except OSError:
            raise _fail("artifact_path_invalid", "artifact path is unavailable") from None
    except OSError:
        raise _fail("artifact_path_invalid", "artifact path is unavailable") from None
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise _fail("artifact_path_unsafe", "artifact directory is unsafe")
    try:
        os.chmod(path, 0o700, follow_symlinks=False)
    except OSError:
        raise _fail("artifact_path_invalid", "artifact directory is unavailable") from None


def _private_tree(repo_root: Path, target_name: str) -> Path:
    """Return the bounded artifact parent after a no-symlink component walk."""

    root = repo_root.resolve(strict=True)
    if not root.is_dir():
        raise _fail("artifact_root_invalid", "artifact root is unavailable")
    current = root
    for component in (*ARTIFACT_ROOT.parts, target_name):
        current = current / component
        _ensure_private_directory(current, create=True)
    return current


def _atomic_bytes(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    """Install bounded bytes as a private regular file without a final symlink."""

    if not isinstance(mode, int) or mode != 0o600:
        raise _fail("artifact_mode_invalid", "artifact mode is invalid")
    parent = path.parent
    _ensure_private_directory(parent, create=False)
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    except OSError:
        raise _fail("artifact_path_invalid", "artifact path is unavailable") from None
    if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)):
        raise _fail("artifact_path_unsafe", "artifact destination is unsafe")
    temp = parent / f".targetctl-{secrets.token_hex(16)}.tmp"
    fd = -1
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
        os.fchmod(fd, mode)
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        try:
            existing = os.lstat(path)
        except FileNotFoundError:
            existing = None
        if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)):
            raise _fail("artifact_path_unsafe", "artifact destination is unsafe")
        os.replace(temp, path)
        os.chmod(path, mode, follow_symlinks=False)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except TargetError:
        raise
    except OSError:
        raise _fail("artifact_write_failed", "artifact could not be written") from None
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _safe_relative(repo_root: Path, path: Path) -> str:
    try:
        relative = path.relative_to(repo_root.resolve(strict=True))
    except ValueError:
        raise _fail("artifact_path_invalid", "artifact path is invalid") from None
    if any(part in ("", ".", "..") for part in relative.parts):
        raise _fail("artifact_path_invalid", "artifact path is invalid")
    return relative.as_posix()


def _hex_digest(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    return value


def _git_commit_id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    return value


def _validate_controller_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    validate_object_keys(payload, allowed=("provenance",), required=("provenance",))
    provenance = payload["provenance"]
    validate_object_keys(
        provenance,
        allowed=("repositories", "flake_lock_hash", "nixpkgs_revision", "system", "tools"),
        required=("repositories", "flake_lock_hash", "nixpkgs_revision", "system", "tools"),
    )
    repositories = provenance["repositories"]
    if not isinstance(repositories, list) or len(repositories) != 3:
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    expected_identities = ("lab", "engine/ds4", "spark/ds4-on-spark")
    clean_repositories: list[dict[str, Any]] = []
    for position, repository in enumerate(repositories):
        allowed = ("identity", "commit", "clean") if position == 0 else ("identity", "commit", "gitlink", "clean")
        validate_object_keys(repository, allowed=allowed, required=allowed)
        if repository["identity"] != expected_identities[position] or not isinstance(repository["clean"], bool):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        clean_repository = {
            "identity": repository["identity"],
            "commit": _git_commit_id(repository["commit"]),
            "clean": repository["clean"],
        }
        if position:
            gitlink = repository["gitlink"]
            if not isinstance(gitlink, str) or not re.fullmatch(r"[0-9a-f]{40}", gitlink):
                raise _fail("artifact_value_invalid", "artifact value is invalid")
            clean_repository["gitlink"] = gitlink
        clean_repositories.append(clean_repository)
    system = provenance["system"]
    validate_object_keys(system, allowed=("os", "kernel", "arch"), required=("os", "kernel", "arch"))
    tools = provenance["tools"]
    validate_object_keys(tools, allowed=("git", "nix", "python"), required=("git", "nix", "python"))
    clean_system: dict[str, str] = {}
    for key in ("os", "kernel", "arch"):
        value = system[key]
        if not isinstance(value, str) or not _SAFE_SYSTEM_RE.fullmatch(value):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        clean_system[key] = value
    clean_tools: dict[str, str] = {}
    for key in ("git", "nix", "python"):
        value = tools[key]
        if not isinstance(value, str) or (value != "unavailable" and not _SAFE_SYSTEM_RE.fullmatch(value)):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        clean_tools[key] = value
    return {
        "provenance": {
            "repositories": clean_repositories,
            "flake_lock_hash": _hex_digest(provenance["flake_lock_hash"]),
            "nixpkgs_revision": _git_commit_id(provenance["nixpkgs_revision"]),
            "system": clean_system,
            "tools": clean_tools,
        }
    }


def _nullable_digest(value: Any) -> str | None:
    return None if value is None else _hex_digest(value)


def _nullable_positive(value: Any, *, maximum: int = 1 << 63) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    return value


def _status_fields(payload: Mapping[str, Any]) -> tuple[str, str | None]:
    status, failure_class = payload["status"], payload["failure_class"]
    if status not in ("succeeded", "failed", "not_run"):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if failure_class is not None and failure_class not in _FAILURE_CLASSES:
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if (
        (status in ("succeeded", "not_run") and failure_class is not None)
        or (status == "failed" and failure_class is None)
    ):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    return status, failure_class


def _known_or_none(value: Any, validator: Any, *, required: bool) -> Any:
    if value is None:
        if required:
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        return None
    return validator(value)


def _validate_source_snapshot(payload: Mapping[str, Any]) -> dict[str, Any]:
    validate_object_keys(payload, allowed=("snapshot",), required=("snapshot",))
    snapshot = payload["snapshot"]
    if not isinstance(snapshot, Mapping):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    validate_object_keys(
        snapshot,
        allowed=("schema_version", "exclusion_policy_version", "repositories", "dirty", "entries", "applied_tree_hash", "snapshot_id"),
        required=("schema_version", "exclusion_policy_version", "repositories", "dirty", "entries", "applied_tree_hash", "snapshot_id"),
    )
    if snapshot["schema_version"] != 1 or snapshot["exclusion_policy_version"] != 1 or not isinstance(snapshot["dirty"], bool):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    repositories = snapshot["repositories"]
    if not isinstance(repositories, list) or len(repositories) != 3:
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    clean_repositories: list[dict[str, Any]] = []
    for expected_name, repository in zip(("lab", "engine", "integration"), repositories, strict=True):
        if not isinstance(repository, Mapping):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        validate_object_keys(
            repository,
            allowed=("name", "head", "pinned_head", "dirty", "status_sha256", "tracked_diff_sha256"),
            required=("name", "head", "pinned_head", "dirty", "status_sha256", "tracked_diff_sha256"),
        )
        if repository["name"] != expected_name or not isinstance(repository["dirty"], bool):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        pinned_head = repository["pinned_head"]
        if pinned_head is not None:
            pinned_head = _git_commit_id(pinned_head)
        clean_repositories.append(
            {
                "name": expected_name,
                "head": _git_commit_id(repository["head"]),
                "pinned_head": pinned_head,
                "dirty": repository["dirty"],
                "status_sha256": _hex_digest(repository["status_sha256"]),
                "tracked_diff_sha256": _hex_digest(repository["tracked_diff_sha256"]),
            }
        )
    entries = snapshot["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_SOURCE_ENTRIES:
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    clean_entries: list[dict[str, Any]] = []
    previous_path = ""
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        validate_object_keys(entry, allowed=("path", "type", "executable", "size", "sha256", "origin"), required=("path", "type", "executable", "size", "sha256", "origin"))
        path = entry["path"]
        if (
            not isinstance(path, str)
            or not _SOURCE_PATH_RE.fullmatch(path)
            or path <= previous_path
            or entry["type"] != "file"
            or entry["executable"] not in (0, 1)
            or isinstance(entry["executable"], bool)
            or not isinstance(entry["size"], int)
            or isinstance(entry["size"], bool)
            or not 0 <= entry["size"] <= 16 * 1024 * 1024 * 1024
            or entry["origin"] not in ("tracked", "untracked")
        ):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        previous_path = path
        clean_entries.append({"path": path, "type": "file", "executable": entry["executable"], "size": entry["size"], "sha256": _hex_digest(entry["sha256"]), "origin": entry["origin"]})
    clean_snapshot = {
        "schema_version": 1,
        "exclusion_policy_version": 1,
        "repositories": clean_repositories,
        "dirty": snapshot["dirty"],
        "entries": clean_entries,
        "applied_tree_hash": _hex_digest(snapshot["applied_tree_hash"]),
        "snapshot_id": _hex_digest(snapshot["snapshot_id"]),
    }
    if clean_snapshot["dirty"] != any(repository["dirty"] for repository in clean_repositories):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    tree_digest = hashlib.sha256(b"targetctl-entry-hash-v1\0")
    for entry in clean_entries:
        for field in (entry["path"].encode("utf-8"), b"file", str(entry["executable"]).encode("ascii"), str(entry["size"]).encode("ascii"), bytes.fromhex(entry["sha256"])):
            tree_digest.update(len(field).to_bytes(8, "big"))
            tree_digest.update(field)
    if clean_snapshot["applied_tree_hash"] != tree_digest.hexdigest():
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    identity = {
        "schema_version": 1,
        "exclusion_policy_version": 1,
        "exclusions": list(_SOURCE_EXCLUSIONS),
        "repositories": clean_repositories,
        "entries": clean_entries,
        "applied_tree_hash": clean_snapshot["applied_tree_hash"],
    }
    expected_snapshot_id = hashlib.sha256(b"targetctl-source-snapshot-v1\0" + canonical_json_bytes(identity)).hexdigest()
    if clean_snapshot["snapshot_id"] != expected_snapshot_id:
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if len(canonical_json_bytes({"snapshot": clean_snapshot})) > MAX_SOURCE_RECORD_BYTES:
        raise _fail("artifact_too_large", "artifact source record exceeds its size limit")
    return {"snapshot": clean_snapshot}


def _validate_doctor(payload: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "status", "failure_class", "os", "kernel", "arch", "tools", "gpu",
        "memory_bytes", "disk_bytes", "time_sync", "primary_weight_sha256",
        "draft_weight_sha256",
    )
    validate_object_keys(payload, allowed=fields, required=fields)
    status, failure_class = _status_fields(payload)
    succeeded = status == "succeeded"
    not_run = status == "not_run"
    system: dict[str, str | None] = {}
    for key in ("os", "kernel", "arch"):
        value = payload[key]
        if value is None:
            if succeeded:
                raise _fail("artifact_value_invalid", "artifact value is invalid")
            system[key] = None
        elif not not_run and isinstance(value, str) and _SAFE_SYSTEM_RE.fullmatch(value) and (key != "os" or value == "Linux"):
            system[key] = value
        else:
            raise _fail("artifact_value_invalid", "artifact value is invalid")
    tools = payload["tools"]
    if not isinstance(tools, list) or len(tools) != len(_DOCTOR_TOOLS):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    clean_tools: list[dict[str, str | None]] = []
    for expected_name, tool in zip(_DOCTOR_TOOLS, tools, strict=True):
        if not isinstance(tool, Mapping):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        validate_object_keys(tool, allowed=("name", "version", "location"), required=("name", "version", "location"))
        version, location = tool["version"], tool["location"]
        if tool["name"] != expected_name or (version is None) != (location is None):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        if version is None:
            if succeeded:
                raise _fail("artifact_value_invalid", "artifact value is invalid")
        elif not not_run and isinstance(version, str) and _VERSION_RE.fullmatch(version) and isinstance(location, str) and location in _SYSTEM_TOOL_PATHS[expected_name]:
            pass
        else:
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        clean_tools.append({"name": expected_name, "version": version, "location": location})
    gpu = payload["gpu"]
    if gpu is None:
        if succeeded:
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        clean_gpu = None
    elif not not_run and isinstance(gpu, Mapping):
        validate_object_keys(gpu, allowed=("platform", "compute_capability"), required=("platform", "compute_capability"))
        if gpu["platform"] != "GB10" or gpu["compute_capability"] != "sm_121":
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        clean_gpu = {"platform": "GB10", "compute_capability": "sm_121"}
    else:
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    memory_bytes = _known_or_none(payload["memory_bytes"], _nullable_positive, required=succeeded)
    disk_bytes = _known_or_none(payload["disk_bytes"], _nullable_positive, required=succeeded)
    time_sync = payload["time_sync"]
    if time_sync is None:
        if succeeded:
            raise _fail("artifact_value_invalid", "artifact value is invalid")
    elif not not_run and isinstance(time_sync, bool):
        if succeeded and not time_sync:
            raise _fail("artifact_value_invalid", "artifact value is invalid")
    else:
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    return {
        "status": status, "failure_class": failure_class, **system, "tools": clean_tools, "gpu": clean_gpu,
        "memory_bytes": memory_bytes, "disk_bytes": disk_bytes, "time_sync": time_sync,
        "primary_weight_sha256": _known_or_none(payload["primary_weight_sha256"], _hex_digest, required=succeeded),
        "draft_weight_sha256": _known_or_none(payload["draft_weight_sha256"], _hex_digest, required=succeeded),
    }


def _validate_build(payload: Mapping[str, Any]) -> dict[str, Any]:
    fields = ("status", "failure_class", "source_snapshot_id", "source_applied_tree_hash", "build_id", "binary_sha256", "command", "version", "binary_size", "sass", "build_log_sha256")
    validate_object_keys(payload, allowed=fields, required=fields)
    status, failure_class = _status_fields(payload)
    succeeded = status == "succeeded"
    not_run = status == "not_run"
    command = payload["command"]
    sass = payload["sass"]
    if command is not None and command != "make-cuda-spark":
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if sass not in (None, "verified", "missing", "not_checked", "not_run"):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    version = payload["version"]
    if version is not None and (not isinstance(version, str) or not _VERSION_RE.fullmatch(version)):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if not_run and (
        any(payload[key] is not None for key in ("source_snapshot_id", "source_applied_tree_hash", "build_id", "binary_sha256", "command", "version", "binary_size", "build_log_sha256"))
        or sass not in (None, "not_run")
    ):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if succeeded and (command != "make-cuda-spark" or sass != "verified"):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    return {
        "status": status, "failure_class": failure_class,
        "source_snapshot_id": _known_or_none(payload["source_snapshot_id"], _hex_digest, required=succeeded),
        "source_applied_tree_hash": _known_or_none(payload["source_applied_tree_hash"], _hex_digest, required=succeeded),
        "build_id": _known_or_none(payload["build_id"], _hex_digest, required=succeeded),
        "binary_sha256": _known_or_none(payload["binary_sha256"], _hex_digest, required=succeeded),
        "command": command, "version": version,
        "binary_size": _known_or_none(payload["binary_size"], _nullable_positive, required=succeeded), "sass": sass,
        "build_log_sha256": _known_or_none(payload["build_log_sha256"], _nullable_digest, required=succeeded),
    }


def _validate_run(payload: Mapping[str, Any]) -> dict[str, Any]:
    fields = ("status", "failure_class", "state", "run_id", "source_snapshot_id", "build_id", "binary_sha256", "supervisor_pid", "supervisor_start_ticks", "child_pid", "child_start_ticks", "port")
    validate_object_keys(payload, allowed=fields, required=fields)
    status, failure_class = _status_fields(payload)
    state = payload["state"]
    identity_keys = ("run_id", "source_snapshot_id", "build_id", "binary_sha256", "supervisor_pid", "supervisor_start_ticks", "child_pid", "child_start_ticks", "port")
    if status == "not_run":
        if state is not None or any(payload[key] is not None for key in identity_keys):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        return {
            "status": status, "failure_class": failure_class, "state": None, "run_id": None,
            "source_snapshot_id": None, "build_id": None, "binary_sha256": None,
            "supervisor_pid": None, "supervisor_start_ticks": None,
            "child_pid": None, "child_start_ticks": None, "port": None,
        }
    if state not in _LIFECYCLE_STATES or state == "starting":
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    run_id = payload["run_id"]
    if run_id is not None and (not isinstance(run_id, str) or not _COMPONENT_RE.fullmatch(run_id)):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    supervisor_pid = _nullable_positive(payload["supervisor_pid"])
    supervisor_ticks = _nullable_positive(payload["supervisor_start_ticks"])
    child_pid = _nullable_positive(payload["child_pid"])
    child_ticks = _nullable_positive(payload["child_start_ticks"])
    port = _nullable_positive(payload["port"], maximum=65535)
    if (supervisor_pid is None) != (supervisor_ticks is None) or (child_pid is None) != (child_ticks is None):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    succeeded = status == "succeeded"
    if (succeeded and state not in {"running", "stopped"}) or (status == "failed" and state not in {"failed_startup", "stale_identity"}):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if succeeded and (run_id is None or any(value is None for value in (supervisor_pid, supervisor_ticks, child_pid, child_ticks, port))):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    return {
        "status": status, "failure_class": failure_class, "state": state, "run_id": run_id,
        "source_snapshot_id": _known_or_none(payload["source_snapshot_id"], _hex_digest, required=succeeded),
        "build_id": _known_or_none(payload["build_id"], _hex_digest, required=succeeded),
        "binary_sha256": _known_or_none(payload["binary_sha256"], _hex_digest, required=succeeded),
        "supervisor_pid": supervisor_pid, "supervisor_start_ticks": supervisor_ticks,
        "child_pid": child_pid, "child_start_ticks": child_ticks, "port": port,
    }


def _validate_smoke(payload: Mapping[str, Any]) -> dict[str, Any]:
    fields = ("status", "failure_class", "readiness_http", "models_http", "contract", "primary_weight_sha256", "draft_weight_sha256", "duration_ns")
    validate_object_keys(payload, allowed=fields, required=fields)
    status, failure_class = _status_fields(payload)
    succeeded = status == "succeeded"
    not_run = status == "not_run"
    readiness_http = _nullable_positive(payload["readiness_http"], maximum=599)
    models_http = _nullable_positive(payload["models_http"], maximum=599)
    contract = payload["contract"]
    if contract not in (None, "passed", "failed", "not_run"):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if not_run and (
        any(payload[key] is not None for key in ("readiness_http", "models_http", "primary_weight_sha256", "draft_weight_sha256", "duration_ns"))
        or contract not in (None, "not_run")
    ):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if succeeded and (readiness_http != 200 or models_http != 200 or contract != "passed"):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    return {
        "status": status, "failure_class": failure_class, "readiness_http": readiness_http, "models_http": models_http, "contract": contract,
        "primary_weight_sha256": _known_or_none(payload["primary_weight_sha256"], _hex_digest, required=succeeded),
        "draft_weight_sha256": _known_or_none(payload["draft_weight_sha256"], _hex_digest, required=succeeded),
        "duration_ns": _known_or_none(payload["duration_ns"], _nullable_positive, required=succeeded),
    }


def _validate_cleanup(payload: Mapping[str, Any]) -> dict[str, Any]:
    fields = ("status", "failure_class", "process", "socket", "lock", "temp", "server_log_sha256")
    validate_object_keys(payload, allowed=fields, required=fields)
    status, failure_class = _status_fields(payload)
    results = {key: payload[key] for key in ("process", "socket", "lock", "temp")}
    if any(value not in (None, "cleared", "not_found", "unknown", "not_run") for value in results.values()):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if status == "not_run" and (any(value not in (None, "not_run") for value in results.values()) or payload["server_log_sha256"] is not None):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    if status == "succeeded" and any(value not in ("cleared", "not_found") for value in results.values()):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    server_log_sha256 = _nullable_digest(payload["server_log_sha256"])
    if status == "succeeded" and server_log_sha256 is None:
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    return {"status": status, "failure_class": failure_class, **results, "server_log_sha256": server_log_sha256}

def _validate_record_relationships(records: Mapping[str, Mapping[str, Any]], *, code: str) -> None:
    """Enforce the status dependency graph and shared public identities."""

    doctor = records["target-doctor"]
    build = records["build"]
    run = records["run"]
    smoke = records["smoke"]
    if doctor["status"] != "succeeded" and any(records[name]["status"] != "not_run" for name in ("build", "run", "smoke")):
        raise _fail(code, "artifact dependency statuses are invalid")
    if build["status"] in ("failed", "not_run") and any(records[name]["status"] != "not_run" for name in ("run", "smoke")):
        raise _fail(code, "artifact dependency statuses are invalid")
    if run["status"] in ("failed", "not_run") and smoke["status"] != "not_run":
        raise _fail(code, "artifact dependency statuses are invalid")
    if (
        (build["status"] == "succeeded" and doctor["status"] != "succeeded")
        or (run["status"] == "succeeded" and build["status"] != "succeeded")
        or (smoke["status"] == "succeeded" and run["status"] != "succeeded")
    ):
        raise _fail(code, "artifact dependency statuses are invalid")
    source = records["source"]["snapshot"]
    controller_repositories = records["controller"]["provenance"]["repositories"]
    source_repositories = source["repositories"]
    for position, (controller_repository, source_repository) in enumerate(
        zip(controller_repositories, source_repositories, strict=True)
    ):
        if (
            controller_repository["commit"] != source_repository["head"]
            or controller_repository["clean"] == source_repository["dirty"]
            or (
                position > 0
                and controller_repository["gitlink"] != source_repository["pinned_head"]
            )
        ):
            raise _fail(code, "artifact repository identities do not agree")
    for actual, expected in (
        (build["source_snapshot_id"], source["snapshot_id"]),
        (build["source_applied_tree_hash"], source["applied_tree_hash"]),
        (run["source_snapshot_id"], source["snapshot_id"]),
        (run["build_id"], build["build_id"]),
        (run["binary_sha256"], build["binary_sha256"]),
        (smoke["primary_weight_sha256"], doctor["primary_weight_sha256"]),
        (smoke["draft_weight_sha256"], doctor["draft_weight_sha256"]),
    ):
        if actual is not None and actual != expected:
            raise _fail(code, "artifact identities do not agree")

def _validate_record_payload(name: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate exact bounded, typed provenance for one Phase 01 record."""

    if not isinstance(payload, Mapping):
        raise _fail("artifact_value_invalid", "artifact value is invalid")
    validators = {
        "controller": _validate_controller_payload,
        "source": _validate_source_snapshot,
        "target-doctor": _validate_doctor,
        "build": _validate_build,
        "run": _validate_run,
        "smoke": _validate_smoke,
        "cleanup": _validate_cleanup,
    }
    return validators[name](payload)



def _read_bounded_regular(path: Path, *, max_bytes: int) -> bytes:
    """Read one stable regular local file without accepting a symlink."""

    try:
        before = os.lstat(path)
    except OSError:
        raise _fail("artifact_path_invalid", "artifact file is unavailable") from None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
        raise _fail("artifact_path_unsafe", "artifact file is unsafe")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise _fail("artifact_path_invalid", "artifact file is unavailable") from None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
            raise _fail("artifact_path_unsafe", "artifact file is unsafe")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
    except TargetError:
        raise
    except OSError:
        raise _fail("artifact_read_failed", "artifact file is unavailable") from None
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) > max_bytes or after.st_dev != before.st_dev or after.st_ino != before.st_ino:
        raise _fail("artifact_path_unsafe", "artifact file changed during reading")
    return raw

def _sha256_file(path: Path) -> tuple[str, int]:
    try:
        info = os.lstat(path)
    except OSError:
        raise _fail("artifact_path_invalid", "artifact file is unavailable") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise _fail("artifact_path_unsafe", "artifact file is unsafe")
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb", buffering=0) as handle:
            while True:
                chunk = handle.read(65_536)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
            after = os.fstat(handle.fileno())
    except OSError:
        raise _fail("artifact_read_failed", "artifact file is unavailable") from None
    if not stat.S_ISREG(after.st_mode) or after.st_dev != info.st_dev or after.st_ino != info.st_ino:
        raise _fail("artifact_path_unsafe", "artifact file changed during hashing")
    return digest.hexdigest(), total


def _git_output(root: Path, *args: str) -> bytes:
    try:
        completed = subprocess.run(
            ("git", "-C", os.fspath(root), *args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise _fail("provenance_git_failed", "controller Git identity is unavailable") from None
    if completed.returncode != 0 or len(completed.stdout) > 4096:
        raise _fail("provenance_git_failed", "controller Git identity is unavailable")
    return completed.stdout


def _git_commit(root: Path) -> str:
    raw = _git_output(root, "rev-parse", "--verify", "HEAD^{commit}")
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise _fail("provenance_git_invalid", "controller Git identity is invalid") from None
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise _fail("provenance_git_invalid", "controller Git identity is invalid")
    return value


def _git_clean(root: Path) -> bool:
    return _git_output(root, "status", "--porcelain=v1", "--untracked-files=all") == b""


def _gitlink(root: Path, relative: str) -> str:
    raw = _git_output(root, "ls-tree", "HEAD", "--", relative)
    expected = re.compile(rf"160000 commit ([0-9a-f]{{40}})\t{re.escape(relative)}\n?\Z")
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError:
        raise _fail("provenance_git_invalid", "controller Git identity is invalid") from None
    match = expected.fullmatch(value)
    if match is None:
        raise _fail("provenance_git_invalid", "controller Git identity is invalid")
    return match.group(1)


def _bounded_tool_version(command: str) -> str:
    try:
        completed = subprocess.run(
            (command, "--version"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    if completed.returncode != 0:
        return "unavailable"
    line = completed.stdout.splitlines()[0] if completed.stdout.splitlines() else b""
    try:
        value = line.decode("ascii")
    except UnicodeDecodeError:
        return "unavailable"
    # Store only a short version-like token, never tool output or a path.
    match = re.search(r"\b[0-9]+(?:\.[0-9A-Za-z+._-]+)+\b", value)
    if match is None or len(match.group(0)) > MAX_TOOL_VERSION:
        return "unavailable"
    return match.group(0)


def controller_provenance(repo_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Collect only public, bounded controller identity from the fixed workspace."""

    try:
        root = Path(repo_root).resolve(strict=True)
    except OSError:
        raise _fail("provenance_root_invalid", "controller workspace is unavailable") from None
    repositories: list[dict[str, Any]] = []
    root_commit = _git_commit(root)
    repositories.append({"identity": "lab", "commit": root_commit, "clean": _git_clean(root)})
    for identity in ("engine/ds4", "spark/ds4-on-spark"):
        worktree = root / identity
        repositories.append(
            {
                "identity": identity,
                "commit": _git_commit(worktree),
                "gitlink": _gitlink(root, identity),
                "clean": _git_clean(worktree),
            }
        )
    lock_path = root / "flake.lock"
    try:
        lock_raw = _read_bounded_regular(lock_path, max_bytes=1_048_576)
        lock = json.loads(lock_raw.decode("utf-8"))
        nixpkgs_revision = lock["nodes"]["nixpkgs"]["locked"]["rev"]
    except TargetError:
        raise _fail("provenance_lock_invalid", "controller lock identity is invalid") from None
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        raise _fail("provenance_lock_invalid", "controller lock identity is invalid") from None
    lock_hash = hashlib.sha256(lock_raw).hexdigest()
    if not isinstance(nixpkgs_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", nixpkgs_revision):
        raise _fail("provenance_lock_invalid", "controller lock identity is invalid")
    system = {"os": platform.system(), "kernel": platform.release(), "arch": platform.machine()}
    if any(not isinstance(value, str) or not _SAFE_SYSTEM_RE.fullmatch(value) for value in system.values()):
        raise _fail("provenance_system_invalid", "controller system identity is invalid")
    return {
        "repositories": repositories,
        "flake_lock_hash": lock_hash,
        "nixpkgs_revision": nixpkgs_revision,
        "system": system,
        "tools": {
            "git": _bounded_tool_version("git"),
            "nix": _bounded_tool_version("nix"),
            "python": platform.python_version() if _SAFE_SYSTEM_RE.fullmatch(platform.python_version()) else "unavailable",
        },
    }


class ArtifactBundle:
    """One private, atomically-promoted Phase 01 controller bundle."""

    __slots__ = (
        "_repo_root",
        "_parent",
        "_staging",
        "_final",
        "_target_name",
        "_operation_id",
        "_operation",
        "_record_ids",
        "_last_duration_ns",
        "_started_ns",
        "_closed",
    )

    def __init__(
        self,
        repo_root: str | os.PathLike[str],
        target_name: str,
        operation_id: str,
        *,
        operation: str = "phase-01",
    ) -> None:
        try:
            self._repo_root = Path(repo_root).resolve(strict=True)
        except OSError:
            raise _fail("artifact_root_invalid", "artifact root is unavailable") from None
        self._target_name = _safe_component(target_name)
        self._operation_id = _safe_component(operation_id)
        self._operation = _safe_component(operation)
        self._parent = _private_tree(self._repo_root, self._target_name)
        self._final = self._parent / self._operation_id
        try:
            existing = os.lstat(self._final)
        except FileNotFoundError:
            existing = None
        except OSError:
            raise _fail("artifact_path_invalid", "artifact path is unavailable") from None
        if existing is not None:
            raise _fail("artifact_exists", "artifact operation already exists")
        self._staging = self._parent / f".pending-{self._operation_id}-{secrets.token_hex(12)}"
        _ensure_private_directory(self._staging, create=True)
        self._record_ids: dict[str, str] = {}
        self._last_duration_ns = 0
        self._started_ns = time.monotonic_ns()
        self._closed = False

    @property
    def relative_path(self) -> str:
        """The final, repository-relative safe path (never a host path)."""

        return _safe_relative(self._repo_root, self._final)

    @property
    def operation_id(self) -> str:
        return self._operation_id

    def _require_open(self) -> None:
        if self._closed:
            raise _fail("artifact_closed", "artifact bundle is closed")

    def _duration(self) -> int:
        value = time.monotonic_ns() - self._started_ns
        if value < self._last_duration_ns:
            value = self._last_duration_ns
        self._last_duration_ns = value
        return value

    def write_record(
        self,
        name: str,
        payload: Mapping[str, Any],
        *,
        created_at: str,
    ) -> str:
        """Atomically write one fixed-schema record in its required parent order."""

        self._require_open()
        if name not in _RECORD_NAMES or name in self._record_ids:
            raise _fail("artifact_record_invalid", "artifact record is invalid")
        if not isinstance(created_at, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]{1,48}Z", created_at):
            raise _fail("artifact_time_invalid", "artifact timestamp is invalid")
        if not isinstance(payload, Mapping):
            raise _fail("artifact_value_invalid", "artifact value is invalid")
        if tuple(self._record_ids) != _RECORD_NAMES[: len(self._record_ids)]:
            raise _fail("artifact_parent_invalid", "artifact parent chain is invalid")
        expected_parent_names = _RECORD_PARENTS[name]
        if any(parent not in self._record_ids for parent in expected_parent_names):
            raise _fail("artifact_parent_invalid", "artifact parent chain is invalid")
        expected_parent_ids = [self._record_ids[parent] for parent in expected_parent_names]
        value: dict[str, Any] = {
            "schema": ARTIFACT_SCHEMA,
            "record_id": "",
            "created_at": created_at,
            "operation": self._operation,
            "target_name": self._target_name,
            "parent_ids": expected_parent_ids,
            "duration_ns": self._duration(),
            "payload": _validate_record_payload(name, payload),
        }
        value["record_id"] = _artifact_record_id(value)
        validate_object_keys(
            value,
            allowed=("schema", "record_id", "created_at", "operation", "target_name", "parent_ids", "duration_ns", "payload"),
            required=("schema", "record_id", "created_at", "operation", "target_name", "parent_ids", "duration_ns", "payload"),
        )
        write_json_atomic(
            self._staging / f"{name}.json",
            value,
            allowed_keys=("schema", "record_id", "created_at", "operation", "target_name", "parent_ids", "duration_ns", "payload"),
            required_keys=("schema", "record_id", "created_at", "operation", "target_name", "parent_ids", "duration_ns", "payload"),
            mode=0o600,
        )
        self._record_ids[name] = value["record_id"]
        return value["record_id"]

    def write_controller_provenance(self, *, created_at: str) -> str:
        """Write the first controller record from the fixed public provenance view."""

        return self.write_record("controller", {"provenance": controller_provenance(self._repo_root)}, created_at=created_at)

    def promote_text(
        self,
        name: str,
        source: str | os.PathLike[str],
        redactor: StreamingRedactor,
        *,
        canaries: Iterable[str] = (),
        max_bytes: int = MAX_TEXT_BYTES,
        chunk_bytes: int = 65_536,
    ) -> str:
        """Redact a regular source file and atomically retain only safe text."""

        self._require_open()
        text_name = _safe_text_name(name)
        if not isinstance(redactor, StreamingRedactor):
            raise _fail("artifact_redactor_invalid", "artifact redactor is invalid")
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_TEXT_BYTES:
            raise _fail("artifact_limit_invalid", "artifact size limit is invalid")
        if not isinstance(chunk_bytes, int) or isinstance(chunk_bytes, bool) or not 1 <= chunk_bytes <= 65_536:
            raise _fail("artifact_limit_invalid", "artifact chunk limit is invalid")
        checked_canaries: list[str] = []
        try:
            iterator = iter(canaries)
        except TypeError:
            raise _fail("artifact_canary_invalid", "artifact canary is invalid") from None
        for canary in iterator:
            if not isinstance(canary, str) or not canary or len(canary) > MAX_VALUE_TEXT:
                raise _fail("artifact_canary_invalid", "artifact canary is invalid")
            checked_canaries.append(canary)
        source_path = Path(source)
        try:
            before = os.lstat(source_path)
        except OSError:
            raise _fail("artifact_source_invalid", "artifact text source is unavailable") from None
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise _fail("artifact_source_unsafe", "artifact text source is unsafe")
        if before.st_size > max_bytes:
            raise _fail("artifact_too_large", "artifact text exceeds its size limit")
        output: list[str] = []
        total = 0
        try:
            fd = os.open(source_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError:
            raise _fail("artifact_source_invalid", "artifact text source is unavailable") from None
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
                raise _fail("artifact_source_unsafe", "artifact text source is unsafe")
            while True:
                chunk = os.read(fd, chunk_bytes)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise _fail("artifact_too_large", "artifact text exceeds its size limit")
                output.append(redactor.feed(chunk))
            after = os.fstat(fd)
        except TargetError:
            raise
        except OSError:
            raise _fail("artifact_read_failed", "artifact text source is unavailable") from None
        finally:
            os.close(fd)
        if not stat.S_ISREG(after.st_mode) or after.st_dev != before.st_dev or after.st_ino != before.st_ino:
            raise _fail("artifact_source_unsafe", "artifact text source changed during reading")
        output.append(redactor.finalize())
        safe_text = "".join(output)
        if len(safe_text.encode("utf-8")) > MAX_TEXT_BYTES:
            raise _fail("artifact_too_large", "artifact text exceeds its size limit")
        if any(canary in safe_text for canary in checked_canaries):
            raise _fail("artifact_canary_detected", "artifact redaction did not remove a canary")
        destination_dir = self._staging / "texts"
        _ensure_private_directory(destination_dir, create=True)
        destination = destination_dir / f"{text_name}.txt"
        _atomic_bytes(destination, safe_text.encode("utf-8"))
        return _safe_relative(self._repo_root, self._final / "texts" / f"{text_name}.txt")

    def finalize(self) -> str:
        """Write the sufficient final index then atomically promote the bundle."""

        self._require_open()
        if tuple(self._record_ids) != _RECORD_NAMES:
            raise _fail("artifact_incomplete", "artifact bundle is incomplete")
        record_payloads: dict[str, dict[str, Any]] = {}
        for record_name in _RECORD_NAMES:
            record = read_json_file(
                self._staging / f"{record_name}.json",
                allowed_keys=("schema", "record_id", "created_at", "operation", "target_name", "parent_ids", "duration_ns", "payload"),
                required_keys=("schema", "record_id", "created_at", "operation", "target_name", "parent_ids", "duration_ns", "payload"),
                max_bytes=MAX_SOURCE_FILE_BYTES if record_name == "source" else MAX_RECORD_BYTES,
            )
            clean_payload = _validate_record_payload(record_name, record["payload"])
            if clean_payload != record["payload"]:
                raise _fail("artifact_record_invalid", "artifact record payload is invalid")
            record_payloads[record_name] = clean_payload
        _validate_record_relationships(record_payloads, code="artifact_record_invalid")
        advertised_logs = (
            ("build", "build_log_sha256", "build-log.txt"),
            ("cleanup", "server_log_sha256", "server-log.txt"),
        )
        for record_name, hash_key, text_name in advertised_logs:
            record = read_json_file(
                self._staging / f"{record_name}.json",
                allowed_keys=("schema", "record_id", "created_at", "operation", "target_name", "parent_ids", "duration_ns", "payload"),
                required_keys=("schema", "record_id", "created_at", "operation", "target_name", "parent_ids", "duration_ns", "payload"),
            )
            advertised = record["payload"][hash_key]
            if advertised is None:
                continue
            try:
                actual, _ = _sha256_file(self._staging / "texts" / text_name)
            except TargetError:
                raise _fail("artifact_log_missing", "advertised artifact log is unavailable") from None
            if advertised != actual:
                raise _fail("artifact_log_mismatch", "advertised artifact log does not match promoted text")
        entries: list[dict[str, Any]] = []
        for name in _RECORD_NAMES:
            file_name = f"{name}.json"
            digest, size = _sha256_file(self._staging / file_name)
            entries.append({"name": file_name, "sha256": digest, "size": size})
        text_dir = self._staging / "texts"
        try:
            text_info = os.lstat(text_dir)
        except FileNotFoundError:
            text_info = None
        except OSError:
            raise _fail("artifact_path_invalid", "artifact path is unavailable") from None
        if text_info is not None:
            if stat.S_ISLNK(text_info.st_mode) or not stat.S_ISDIR(text_info.st_mode):
                raise _fail("artifact_path_unsafe", "artifact text directory is unsafe")
            try:
                names = sorted(entry.name for entry in text_dir.iterdir())
            except OSError:
                raise _fail("artifact_path_invalid", "artifact path is unavailable") from None
            if not names:
                raise _fail("artifact_path_unsafe", "artifact text directory is unsafe")
            for file_name in names:
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\.txt", file_name):
                    raise _fail("artifact_path_unsafe", "artifact file is unsafe")
                digest, size = _sha256_file(text_dir / file_name)
                entries.append({"name": f"texts/{file_name}", "sha256": digest, "size": size})
        index: dict[str, Any] = {
            "schema": ARTIFACT_SCHEMA,
            "operation_id": self._operation_id,
            "operation": self._operation,
            "target_name": self._target_name,
            "complete": True,
            "record_ids": dict(self._record_ids),
            "files": entries,
        }
        validate_object_keys(
            index,
            allowed=("schema", "operation_id", "operation", "target_name", "complete", "record_ids", "files"),
            required=("schema", "operation_id", "operation", "target_name", "complete", "record_ids", "files"),
        )
        write_json_atomic(
            self._staging / "index.json",
            index,
            allowed_keys=("schema", "operation_id", "operation", "target_name", "complete", "record_ids", "files"),
            required_keys=("schema", "operation_id", "operation", "target_name", "complete", "record_ids", "files"),
            mode=0o600,
        )
        try:
            final_info = os.lstat(self._final)
        except FileNotFoundError:
            final_info = None
        except OSError:
            raise _fail("artifact_path_invalid", "artifact path is unavailable") from None
        if final_info is not None:
            raise _fail("artifact_exists", "artifact operation already exists")
        try:
            os.replace(self._staging, self._final)
            parent_fd = os.open(self._parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError:
            raise _fail("artifact_promote_failed", "artifact bundle could not be promoted") from None
        self._closed = True
        return self.relative_path

    def discard(self) -> None:
        """Best-effort removal of an unpromoted private staging directory."""

        if self._closed:
            return
        try:
            for child in self._staging.iterdir():
                if child.is_dir() and not child.is_symlink():
                    for nested in child.iterdir():
                        nested.unlink()
                    child.rmdir()
                else:
                    child.unlink()
            self._staging.rmdir()
        except OSError:
            pass
        self._closed = True


# Deliberately concise aliases for operation modules.
ArtifactStore = ArtifactBundle
collect_controller_provenance = controller_provenance


def validate_bundle_index(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Verify a completed bundle index against its exact private file set."""

    bundle = Path(path)
    try:
        info = os.lstat(bundle)
    except OSError:
        raise _fail("artifact_path_invalid", "artifact bundle is unavailable") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise _fail("artifact_path_unsafe", "artifact bundle is unsafe")
    index = read_json_file(
        bundle / "index.json",
        allowed_keys=("schema", "operation_id", "operation", "target_name", "complete", "record_ids", "files"),
        required_keys=("schema", "operation_id", "operation", "target_name", "complete", "record_ids", "files"),
    )
    if (
        index["schema"] != ARTIFACT_SCHEMA
        or index["complete"] is not True
        or not isinstance(index["record_ids"], dict)
        or frozenset(index["record_ids"]) != frozenset(_RECORD_NAMES)
        or not isinstance(index["files"], list)
    ):
        raise _fail("artifact_index_invalid", "artifact index is invalid")
    expected_files = {f"{name}.json" for name in _RECORD_NAMES}
    indexed_hashes: dict[str, str] = {}
    seen: set[str] = set()
    for entry in index["files"]:
        validate_object_keys(entry, allowed=("name", "sha256", "size"), required=("name", "sha256", "size"))
        name, digest, size = entry["name"], entry["sha256"], entry["size"]
        if (
            not isinstance(name, str)
            or name in seen
            or not isinstance(digest, str)
            or not _HEX_RE.fullmatch(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise _fail("artifact_index_invalid", "artifact index is invalid")
        if name.startswith("texts/"):
            if not re.fullmatch(r"texts/[A-Za-z0-9][A-Za-z0-9._-]{0,79}\.txt", name):
                raise _fail("artifact_index_invalid", "artifact index is invalid")
        elif name not in expected_files:
            raise _fail("artifact_index_invalid", "artifact index is invalid")
        digest_actual, size_actual = _sha256_file(bundle / name)
        if digest != digest_actual or size != size_actual:
            raise _fail("artifact_index_invalid", "artifact index does not match files")
        indexed_hashes[name] = digest
        seen.add(name)
    if not expected_files.issubset(seen):
        raise _fail("artifact_index_invalid", "artifact index is incomplete")
    if (
        not isinstance(index["operation_id"], str)
        or not _COMPONENT_RE.fullmatch(index["operation_id"])
        or not isinstance(index["operation"], str)
        or not _COMPONENT_RE.fullmatch(index["operation"])
        or not isinstance(index["target_name"], str)
        or not _COMPONENT_RE.fullmatch(index["target_name"])
        or any(not isinstance(record_id, str) or not _HEX_RE.fullmatch(record_id) for record_id in index["record_ids"].values())
    ):
        raise _fail("artifact_index_invalid", "artifact index is invalid")
    record_keys = ("schema", "record_id", "created_at", "operation", "target_name", "parent_ids", "duration_ns", "payload")
    record_payloads: dict[str, dict[str, Any]] = {}
    previous_duration = -1
    for position, record_name in enumerate(_RECORD_NAMES):
        record = read_json_file(
            bundle / f"{record_name}.json",
            allowed_keys=record_keys,
            required_keys=record_keys,
            max_bytes=MAX_SOURCE_FILE_BYTES if record_name == "source" else MAX_RECORD_BYTES,
        )
        parent_ids = [] if position == 0 else [index["record_ids"][_RECORD_NAMES[position - 1]]]
        if (
            record["schema"] != ARTIFACT_SCHEMA
            or record["record_id"] != index["record_ids"][record_name]
            or record["record_id"] != _artifact_record_id(record)
            or record["operation"] != index["operation"]
            or record["target_name"] != index["target_name"]
            or record["parent_ids"] != parent_ids
            or not isinstance(record["duration_ns"], int)
            or isinstance(record["duration_ns"], bool)
            or record["duration_ns"] < previous_duration
        ):
            raise _fail("artifact_index_invalid", "artifact record chain is invalid")
        if _validate_record_payload(record_name, record["payload"]) != record["payload"]:
            raise _fail("artifact_index_invalid", "artifact record payload is invalid")
        record_payloads[record_name] = record["payload"]
        previous_duration = record["duration_ns"]
    _validate_record_relationships(record_payloads, code="artifact_index_invalid")
    for record_name, hash_key, text_name in (("build", "build_log_sha256", "build-log.txt"), ("cleanup", "server_log_sha256", "server-log.txt")):
        advertised = record_payloads[record_name][hash_key]
        if advertised is not None and indexed_hashes.get(f"texts/{text_name}") != advertised:
            raise _fail("artifact_index_invalid", "advertised artifact log does not match promoted text")
    try:
        actual = {entry.name for entry in bundle.iterdir() if entry.name != "index.json"}
        text_dir = bundle / "texts"
        try:
            text_info = os.lstat(text_dir)
        except FileNotFoundError:
            text_info = None
        expected_texts = any(name.startswith("texts/") for name in seen)
        if text_info is not None:
            if stat.S_ISLNK(text_info.st_mode) or not stat.S_ISDIR(text_info.st_mode):
                raise _fail("artifact_path_unsafe", "artifact text directory is unsafe")
            if expected_texts:
                actual.update(f"texts/{entry.name}" for entry in text_dir.iterdir())
                actual.discard("texts")
    except OSError:
        raise _fail("artifact_path_invalid", "artifact bundle is unavailable") from None
    if actual != seen:
        raise _fail("artifact_index_invalid", "artifact index has an unexpected file")
    return index


verify_bundle_index = validate_bundle_index
