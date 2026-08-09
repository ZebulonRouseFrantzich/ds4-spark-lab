"""Standalone target-side helper for targetctl.

This module deliberately imports only the Python standard library: transport sends its
source to an isolated interpreter, optionally followed by extension source.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import time
from pathlib import PurePosixPath
from typing import Any, Callable

SCHEMA_VERSION = 1
PROTOCOL_VERSION = 1
MARKER_PREFIX = ".targetctl-owner-v"
LOCK_NAME = ".targetctl-operation-lock-v1"
REPORT_NAMES = frozenset({"doctor.json", "source.json", "build.json", "run.json", "status.json", "build.log", "server.log"})
MAX_REPORT_BYTES = 1024 * 1024
MAX_ENTRIES = 100_000
RUN_STATE_SCHEMA_VERSION = 1
RUN_STATE_FIELDS = frozenset({
    "schema_version", "run_id", "state", "source_snapshot_id",
    "applied_tree_hash", "build_id", "binary_sha256", "port",
    "launch_profile", "supervisor_pid", "supervisor_start_ticks",
    "supervisor_cmdline_sha256", "child_pid", "child_start_ticks",
    "child_pgid", "child_cmdline_sha256", "listener_inode",
    "cleanup_complete", "cleanup",
})
RUN_STATE_STATES = frozenset({
    "starting", "running", "stopped", "stale_identity", "failed_startup",
})
RUN_STATE_TERMINAL_STATES = frozenset({
    "stopped", "stale_identity", "failed_startup",
})
LAUNCH_PROFILE = {
    "schema_version": 1,
    "accelerator": "cuda",
    "context_tokens": 32768,
    "bind": "loopback",
    "continuation_mtp_mode": 2,
    "dspark_enabled": True,
    "drafter_enabled": True,
}


def _is_hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_run_state(value: Any, *, terminal: bool = False) -> bool:
    """Validate the one target-side run-state schema shared by all actions."""

    if not isinstance(value, dict) or set(value) != RUN_STATE_FIELDS:
        return False
    run_id = value["run_id"]
    if (
        value["schema_version"] != RUN_STATE_SCHEMA_VERSION
        or value["state"] not in RUN_STATE_STATES
        or (terminal and value["state"] not in RUN_STATE_TERMINAL_STATES)
        or not isinstance(run_id, str)
        or not 8 <= len(run_id) <= 64
        or not run_id[0].isalnum()
        or not run_id.isascii()
        or any(not (character.islower() or character.isdigit() or character == "-") for character in run_id)
        or any(not _is_hex_digest(value[key]) for key in (
            "source_snapshot_id", "applied_tree_hash", "build_id", "binary_sha256",
        ))
        or not isinstance(value["port"], int)
        or isinstance(value["port"], bool)
        or not 1 <= value["port"] <= 65535
        or value["launch_profile"] != LAUNCH_PROFILE
        or not isinstance(value["cleanup_complete"], bool)
    ):
        return False
    cleanup = value["cleanup"]
    if value["cleanup_complete"]:
        if (
            value["state"] not in RUN_STATE_TERMINAL_STATES
            or not isinstance(cleanup, dict)
            or set(cleanup) != {"process", "socket", "lock", "temp", "server_log_sha256"}
            or any(cleanup[key] not in {"cleared", "not_found"} for key in ("process", "socket", "lock", "temp"))
            or (cleanup["server_log_sha256"] is not None and not _is_hex_digest(cleanup["server_log_sha256"]))
        ):
            return False
    elif cleanup is not None:
        return False
    supervisor = (
        value["supervisor_pid"],
        value["supervisor_start_ticks"],
        value["supervisor_cmdline_sha256"],
    )
    child = (
        value["child_pid"],
        value["child_start_ticks"],
        value["child_pgid"],
        value["child_cmdline_sha256"],
    )
    if not (
        all(item is None for item in supervisor)
        or (
            all(isinstance(item, int) and not isinstance(item, bool) and item > 1 for item in supervisor[:2])
            and _is_hex_digest(supervisor[2])
        )
    ):
        return False
    if not (
        all(item is None for item in child)
        or (
            all(isinstance(item, int) and not isinstance(item, bool) and item > 1 for item in child[:3])
            and child[0] == child[2]
            and _is_hex_digest(child[3])
        )
    ):
        return False
    listener = value["listener_inode"]
    if listener is not None and (
        child[0] is None
        or not isinstance(listener, str)
        or not 1 <= len(listener) <= 32
        or not listener.isascii()
        or not listener.isdigit()
    ):
        return False
    if value["state"] == "running" and (
        supervisor[0] is None or child[0] is None or listener is None
    ):
        return False
    return True


class HelperError(Exception):
    def __init__(self, code: str, safe_message: str = "target helper rejected the request") -> None:
        self.code = code
        self.safe_message = safe_message
        super().__init__(safe_message)


def _fail(code: str, message: str = "target helper rejected the request") -> None:
    raise HelperError(code, message)


def _is_owned_directory(st: os.stat_result) -> bool:
    return stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700


def _validate_absolute_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        _fail("invalid_path")
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        _fail("invalid_path")
    if "\x00" in value or not value.startswith("/"):
        _fail("invalid_path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        _fail("invalid_path")
    if any(not all(ch.isalnum() or ch in "._-" for ch in part) for part in parts[1:]):
        _fail("invalid_path")
    return value


def _canonical(path: str) -> str:
    # _validate_absolute_path has already rejected all path-normalizing syntax.
    return os.path.abspath(path)


def _overlaps(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _require_object(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail("invalid_payload")
    return value


def _marker_name(kind: str) -> str:
    if kind not in {"work", "run"}:
        _fail("invalid_payload")
    return f"{MARKER_PREFIX}{SCHEMA_VERSION}-{kind}.json"


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)


def _open_directory(parent_fd: int, name: str, *, missing_code: str = "missing_path") -> int:
    """Open one directory component without ever resolving it by pathname."""
    try:
        fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        _fail(missing_code)
    except OSError:
        # O_NOFOLLOW | O_DIRECTORY reports symlinks as a platform-specific
        # error; an lstat relative to the already pinned parent gives the
        # stable public classification without using the component afterward.
        try:
            item = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            _fail(missing_code)
        except OSError:
            _fail("unsafe_path")
        if stat.S_ISLNK(item.st_mode):
            _fail("symlink_path")
        _fail("unsafe_path")
    item = os.fstat(fd)
    if not stat.S_ISDIR(item.st_mode):
        os.close(fd)
        _fail("unsafe_path")
    return fd


def _open_root(path: str, *, create_leaf: bool = False) -> int:
    """Pin an absolute directory by walking from a pinned descriptor for /."""
    parts = path.split("/")[1:]
    try:
        current_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _fail("unsafe_path")
    try:
        for index, part in enumerate(parts):
            is_leaf = index == len(parts) - 1
            try:
                next_fd = _open_directory(current_fd, part)
            except HelperError as error:
                if not (create_leaf and is_leaf and error.code == "missing_path"):
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=current_fd)
                    os.fsync(current_fd)
                except FileExistsError:
                    pass
                except OSError:
                    _fail("root_create_failed")
                next_fd = _open_directory(current_fd, part, missing_code="root_create_failed")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _identity(fd: int) -> dict[str, int]:
    item = os.fstat(fd)
    return {"device": item.st_dev, "inode": item.st_ino}


def _assert_pinned_root(fd: int, identity: dict[str, int]) -> None:
    item = os.fstat(fd)
    if not _is_owned_directory(item) or (item.st_dev, item.st_ino) != (identity["device"], identity["inode"]):
        _fail("unsafe_root")


def _assert_named_identity(parent_fd: int, name: str, identity: dict[str, int], code: str) -> None:
    try:
        item = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        _fail(code)
    if (item.st_dev, item.st_ino) != (identity["device"], identity["inode"]):
        _fail(code)


def _open_regular(name: str, *, dir_fd: int, flags: int = os.O_RDONLY) -> tuple[int, os.stat_result]:
    try:
        fd = os.open(name, flags | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=dir_fd)
        item = os.fstat(fd)
    except OSError:
        _fail("unsafe_state")
    if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o600:
        os.close(fd)
        _fail("unsafe_state")
    return fd, item

def _open_entry_regular(name: str, *, dir_fd: int) -> tuple[int, os.stat_result]:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=dir_fd)
        item = os.fstat(fd)
    except OSError:
        _fail("unsafe_entry")
    if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid():
        os.close(fd)
        _fail("unsafe_entry")
    return fd, item




def _read_marker(root_fd: int, kind: str, expected_token: Any = None) -> dict[str, Any]:
    fd, _ = _open_regular(_marker_name(kind), dir_fd=root_fd)
    try:
        raw = os.read(fd, 4096)
        if os.read(fd, 1):
            _fail("unsafe_state")
    finally:
        os.close(fd)
    try:
        marker = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("unsafe_state")
    if not isinstance(marker, dict) or set(marker) != {"kind", "token", "version"}:
        _fail("unsafe_state")
    token = marker.get("token")
    if marker.get("version") != SCHEMA_VERSION or marker.get("kind") != kind or not isinstance(token, str) or len(token) != 64:
        _fail("unsafe_state")
    if any(ch not in "0123456789abcdef" for ch in token):
        _fail("unsafe_state")
    if expected_token is not None and (not isinstance(expected_token, str) or not hmac.compare_digest(token, expected_token)):
        _fail("marker_mismatch")
    return marker


def _write_marker(root_fd: int, kind: str, token: str) -> None:
    data = json.dumps({"kind": kind, "token": token, "version": SCHEMA_VERSION}, sort_keys=True, separators=(",", ":")).encode("ascii")
    try:
        fd = os.open(_marker_name(kind), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=root_fd)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(root_fd)
    except FileExistsError:
        _fail("marker_exists")
    except OSError:
        _fail("unsafe_state")


def _root_identity(root_fd: int, kind: str, token: Any = None) -> dict[str, int]:
    identity = _identity(root_fd)
    _assert_pinned_root(root_fd, identity)
    _read_marker(root_fd, kind, token)
    _assert_pinned_root(root_fd, identity)
    return identity


def _init_root(root: str, kind: str) -> dict[str, Any]:
    root_fd = _open_root(root, create_leaf=True)
    try:
        identity = _identity(root_fd)
        _assert_pinned_root(root_fd, identity)
        try:
            with os.scandir(os.dup(root_fd)) as entries:
                names = []
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > 1:
                        _fail("unmarked_populated_root")
        except HelperError:
            raise
        except OSError:
            _fail("unsafe_root")
        marker = _marker_name(kind)
        if names == [marker]:
            token = _read_marker(root_fd, kind)["token"]
        else:
            if names:
                _fail("unmarked_populated_root")
            token = secrets.token_hex(32)
            _write_marker(root_fd, kind, token)
        _assert_pinned_root(root_fd, identity)
        _read_marker(root_fd, kind, token)
        return {"identity": identity, "token": token}
    finally:
        os.close(root_fd)


def _root_payload(payload: Any, *, require_tokens: bool = False) -> dict[str, Any]:
    keys = {"workdir", "run_dir", "model_path", "drafter_path"}
    if require_tokens:
        keys |= {"work_token", "run_token"}
    data = _require_object(payload, keys)
    values = {name: _canonical(_validate_absolute_path(data[name])) for name in ("workdir", "run_dir", "model_path", "drafter_path")}
    ordered = list(values.values())
    if any(_overlaps(left, right) for index, left in enumerate(ordered) for right in ordered[index + 1:]):
        _fail("path_overlap")
    if require_tokens:
        values["work_token"] = data["work_token"]
        values["run_token"] = data["run_token"]
    return values


def _frame_hash(entries: list[tuple[str, str, int, int, bytes]]) -> str:
    digest = hashlib.sha256(b"targetctl-entry-hash-v1\0")
    for path, kind, executable, size, content_hash in entries:
        for field in (path.encode("utf-8"), kind.encode("ascii"), str(executable).encode("ascii"), str(size).encode("ascii"), content_hash):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return digest.hexdigest()


def _relative_entry(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        _fail("invalid_entry")
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        _fail("invalid_entry")
    if value.startswith("/") or "\x00" in value:
        _fail("invalid_entry")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or not all(ch.isalnum() or ch in "._-" for ch in part) for part in parts):
        _fail("invalid_entry")
    return value


def _entry_parent(root_fd: int, relative: str) -> tuple[int, str]:
    parent_fd = os.dup(root_fd)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            next_fd = _open_directory(parent_fd, part)
            os.close(parent_fd)
            parent_fd = next_fd
        return parent_fd, parts[-1]
    except Exception:
        os.close(parent_fd)
        raise


def _entry_hash(root_fd: int, relative: str) -> tuple[str, str, int, int, bytes]:
    parent_fd, name = _entry_parent(root_fd, relative)
    try:
        try:
            item = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            _fail("unsafe_entry")
        if item.st_uid != os.geteuid():
            _fail("unsafe_entry")
        if stat.S_ISLNK(item.st_mode):
            try:
                target = os.readlink(name, dir_fd=parent_fd)
                after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                target_bytes = target.encode("ascii")
            except (OSError, UnicodeEncodeError):
                _fail("unsafe_entry")
            if (item.st_dev, item.st_ino) != (after.st_dev, after.st_ino):
                _fail("entry_changed")
            if not target or target.startswith("/") or "\x00" in target:
                _fail("unsafe_entry")
            resolved = PurePosixPath(relative).parent.joinpath(target)
            if any(part in {"", ".", ".."} or not all(ch.isalnum() or ch in "._-" for ch in part) for part in resolved.parts):
                _fail("unsafe_entry")
            return relative, "symlink", 0, len(target_bytes), hashlib.sha256(target_bytes).digest()
        if not stat.S_ISREG(item.st_mode):
            _fail("unsupported_entry")
        fd, before = _open_entry_regular(name, dir_fd=parent_fd)
        try:
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size) or size != after.st_size:
            _fail("entry_changed")
        return relative, "file", int(bool(after.st_mode & stat.S_IXUSR)), size, digest.digest()
    finally:
        os.close(parent_fd)


ACTIONS: dict[str, Callable[[Any], Any]] = {}


def register_action(name: str) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
    if not isinstance(name, str) or not name or name in ACTIONS:
        raise ValueError("invalid action registration")
    def decorator(function: Callable[[Any], Any]) -> Callable[[Any], Any]:
        ACTIONS[name] = function
        return function
    return decorator


@register_action("handshake")
def handshake(payload: Any) -> dict[str, Any]:
    _require_object(payload, set())
    return {"schema_version": SCHEMA_VERSION}


@register_action("initialize_roots")
def initialize_roots(payload: Any) -> dict[str, Any]:
    paths = _root_payload(payload)
    work = _init_root(paths["workdir"], "work")
    run = _init_root(paths["run_dir"], "run")
    return {"work": work, "run": run}


@register_action("inspect_roots")
def inspect_roots(payload: Any) -> dict[str, Any]:
    paths = _root_payload(payload, require_tokens=True)
    work_fd = _open_root(paths["workdir"])
    try:
        run_fd = _open_root(paths["run_dir"])
        try:
            work = _root_identity(work_fd, "work", paths["work_token"])
            run = _root_identity(run_fd, "run", paths["run_token"])
            return {"work": work, "run": run}
        finally:
            os.close(run_fd)
    finally:
        os.close(work_fd)


def _boot_id() -> str:
    try:
        fd = os.open("/proc/sys/kernel/random/boot_id", os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        try:
            value = os.read(fd, 64)
            if os.read(fd, 1):
                _fail("unsafe_lock")
        finally:
            os.close(fd)
    except HelperError:
        raise
    except OSError:
        _fail("unsafe_lock")
    try:
        text = value.decode("ascii").strip()
    except UnicodeDecodeError:
        _fail("unsafe_lock")
    if len(text) != 36 or any(character not in "0123456789abcdef-" for character in text):
        _fail("unsafe_lock")
    return text


def _lease_seconds(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 7200:
        _fail("invalid_lease")
    return value


def _lock_state(lock_fd: int) -> dict[str, Any]:
    try:
        os.lseek(lock_fd, 0, os.SEEK_SET)
        raw = os.read(lock_fd, 1024)
        if os.read(lock_fd, 1):
            _fail("unsafe_lock")
    except OSError:
        _fail("unsafe_lock")
    try:
        state = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("unsafe_lock")
    fields = set(state) if isinstance(state, dict) else set()
    if fields not in ({"boot_id", "deadline_monotonic_ns", "token"}, {"boot_id", "deadline_monotonic_ns", "token", "lifecycle_run_id"}):
        _fail("unsafe_lock")
    token, boot_id, deadline = state["token"], state["boot_id"], state["deadline_monotonic_ns"]
    owner = state.get("lifecycle_run_id")
    if (not isinstance(token, str) or len(token) != 64 or any(character not in "0123456789abcdef" for character in token) or
            not isinstance(boot_id, str) or len(boot_id) != 36 or any(character not in "0123456789abcdef-" for character in boot_id) or
            not isinstance(deadline, int) or isinstance(deadline, bool) or deadline < 1 or
            ("lifecycle_run_id" in state and
             (not isinstance(owner, str) or not 8 <= len(owner) <= 64 or not owner[0].isalnum() or not owner.isascii() or
              any(not (character.islower() or character.isdigit() or character == "-") for character in owner)))):
        _fail("unsafe_lock")
    return state


def _install_lock(root_fd: int, state: dict[str, Any]) -> bool:
    name = ".targetctl-lock-stage-" + secrets.token_hex(16)
    data = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("ascii")
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=root_fd)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    _fail("unsafe_lock")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(name, LOCK_NAME, src_dir_fd=root_fd, dst_dir_fd=root_fd, follow_symlinks=False)
        except FileExistsError:
            return False
        os.unlink(name, dir_fd=root_fd)
        os.fsync(root_fd)
        return True
    except HelperError:
        raise
    except OSError:
        _fail("lock_failed")
    finally:
        try:
            os.unlink(name, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        except OSError:
            _fail("unsafe_lock")


def _remove_lock(root_fd: int, lock_fd: int, lock_identity: dict[str, int]) -> None:
    _assert_named_identity(root_fd, LOCK_NAME, lock_identity, "unsafe_lock")
    try:
        os.unlink(LOCK_NAME, dir_fd=root_fd)
        os.fsync(root_fd)
    except OSError:
        _fail("lock_release_failed")


def _cleanup_stale_receiver_pairs(root_fd: int) -> int:
    prefix = ".targetctl-source-receiver-"
    pairs: dict[str, set[str]] = {}
    try:
        with os.scandir(os.dup(root_fd)) as entries:
            for count, entry in enumerate(entries, start=1):
                if count > MAX_ENTRIES:
                    _fail("unsafe_lock")
                name = entry.name
                extension = ".py" if name.endswith(".py") else ".json" if name.endswith(".json") else None
                if extension is None or not name.startswith(prefix):
                    continue
                nonce = name[len(prefix):-len(extension)]
                if len(nonce) != 32 or any(character not in "0123456789abcdef" for character in nonce):
                    continue
                pairs.setdefault(nonce, set()).add(extension)
    except HelperError:
        raise
    except OSError:
        _fail("unsafe_lock")
    cleaned = 0
    for nonce, extensions in pairs.items():
        if extensions != {".py", ".json"}:
            continue
        records: list[tuple[str, dict[str, int], int]] = []
        try:
            for extension, mode in ((".py", 0o700), (".json", 0o600)):
                name = prefix + nonce + extension
                fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd)
                item = os.fstat(fd)
                if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != mode:
                    os.close(fd)
                    _fail("unsafe_lock")
                records.append((name, _identity(fd), fd))
            for name, identity, fd in records:
                _assert_named_identity(root_fd, name, identity, "unsafe_lock")
                os.unlink(name, dir_fd=root_fd)
                os.close(fd)
            os.fsync(root_fd)
        except HelperError:
            for _, _, fd in records:
                try: os.close(fd)
                except OSError: pass
            raise
        except OSError:
            for _, _, fd in records:
                try: os.close(fd)
                except OSError: pass
            _fail("unsafe_lock")
        cleaned += 1
    return cleaned


def _cleanup_stale_lock_stages(root_fd: int) -> int:
    prefix = ".targetctl-lock-stage-"
    candidates: list[str] = []
    try:
        with os.scandir(os.dup(root_fd)) as entries:
            for count, entry in enumerate(entries, start=1):
                if count > MAX_ENTRIES:
                    _fail("unsafe_lock")
                name = entry.name
                nonce = name[len(prefix):] if name.startswith(prefix) else ""
                if len(nonce) == 32 and all(character in "0123456789abcdef" for character in nonce):
                    candidates.append(name)
    except OSError:
        _fail("unsafe_lock")
    cleaned = 0
    for name in candidates:
        try:
            item = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o600 or item.st_nlink != 1:
            continue
        try:
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd)
            identity = _identity(fd)
            current = os.fstat(fd)
            if (current.st_dev, current.st_ino, current.st_nlink) != (item.st_dev, item.st_ino, 1):
                os.close(fd)
                continue
            _assert_named_identity(root_fd, name, identity, "unsafe_lock")
            os.unlink(name, dir_fd=root_fd)
            os.close(fd)
            cleaned += 1
        except OSError:
            continue
    if cleaned:
        try: os.fsync(root_fd)
        except OSError: _fail("unsafe_lock")
    return cleaned


def _reclaim_expired_lock(root_fd: int, current_boot_id: str) -> tuple[bool, int]:
    try:
        os.stat(LOCK_NAME, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True, 0
    except OSError:
        _fail("unsafe_lock")
    lock_fd, _ = _open_regular(LOCK_NAME, dir_fd=root_fd)
    try:
        lock_identity = _identity(lock_fd)
        state = _lock_state(lock_fd)
        _assert_named_identity(root_fd, LOCK_NAME, lock_identity, "unsafe_lock")
        if state["boot_id"] == current_boot_id and time.monotonic_ns() < state["deadline_monotonic_ns"]:
            return False, 0
        _remove_lock(root_fd, lock_fd, lock_identity)
        return True, _cleanup_stale_receiver_pairs(root_fd)
    finally:
        os.close(lock_fd)


def _acquire_lock_at_root(
    root_fd: int,
    identity: dict[str, int],
    run_token: Any,
    lease_seconds: int,
    lifecycle_run_id: str | None = None,
) -> str:
    boot_id = _boot_id()
    _cleanup_stale_lock_stages(root_fd)
    token = secrets.token_hex(32)
    state = {"boot_id": boot_id, "deadline_monotonic_ns": time.monotonic_ns() + lease_seconds * 1_000_000_000, "token": token}
    if lifecycle_run_id is not None:
        state["lifecycle_run_id"] = lifecycle_run_id
    for attempt in range(2):
        if _install_lock(root_fd, state):
            break
        available, _ = _reclaim_expired_lock(root_fd, boot_id)
        if not available:
            _fail("lock_busy")
    else:
        _fail("lock_busy")
    lock_fd, _ = _open_regular(LOCK_NAME, dir_fd=root_fd)
    try:
        lock_identity = _identity(lock_fd)
        installed = _lock_state(lock_fd)
        if not hmac.compare_digest(installed["token"], token):
            _fail("unsafe_lock")
        _assert_named_identity(root_fd, LOCK_NAME, lock_identity, "unsafe_lock")
        _assert_pinned_root(root_fd, identity)
        _read_marker(root_fd, "run", run_token)
        return token
    finally:
        os.close(lock_fd)


def _release_lock_at_root(root_fd: int, identity: dict[str, int], run_token: Any, lock_token: Any) -> None:
    lock_fd, _ = _open_regular(LOCK_NAME, dir_fd=root_fd)
    try:
        lock_identity = _identity(lock_fd)
        state = _lock_state(lock_fd)
        if not isinstance(lock_token, str) or not hmac.compare_digest(state["token"], lock_token):
            _fail("lock_token_mismatch")
        _remove_lock(root_fd, lock_fd, lock_identity)
        _assert_pinned_root(root_fd, identity)
        _read_marker(root_fd, "run", run_token)
    finally:
        os.close(lock_fd)


def _release_lifecycle_lock_at_root(
    root_fd: int,
    identity: dict[str, int],
    run_token: Any,
    lifecycle_run_id: str,
) -> str:
    """Release only the operation lease bound to one persisted lifecycle run."""

    try:
        os.stat(LOCK_NAME, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        _assert_pinned_root(root_fd, identity)
        _read_marker(root_fd, "run", run_token)
        return "not_found"
    except OSError:
        return "unknown"
    try:
        lock_fd, _ = _open_regular(LOCK_NAME, dir_fd=root_fd)
    except HelperError:
        return "unknown"
    try:
        lock_identity = _identity(lock_fd)
        state = _lock_state(lock_fd)
        if state.get("lifecycle_run_id") != lifecycle_run_id:
            return "unknown"
        _assert_pinned_root(root_fd, identity)
        _read_marker(root_fd, "run", run_token)
        _remove_lock(root_fd, lock_fd, lock_identity)
        _assert_pinned_root(root_fd, identity)
        _read_marker(root_fd, "run", run_token)
        return "cleared"
    except HelperError:
        return "unknown"
    finally:
        os.close(lock_fd)


def _cleanup_reports(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 2:
        _fail("invalid_payload")
    reports: list[dict[str, str]] = []
    names: set[str] = set()
    for report in value:
        if not isinstance(report, dict) or set(report) != {"name", "sha256"}:
            _fail("invalid_payload")
        name, digest = report["name"], report["sha256"]
        if name not in {"build.log", "server.log"}:
            _fail("invalid_report")
        if name in names or not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            _fail("invalid_payload")
        names.add(name)
        reports.append({"name": name, "sha256": digest})
    return reports


def _report_signature(item: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def _assert_cleanup_report(root_fd: int, name: str, expected: tuple[int, int, int, int, int, int, int, int]) -> None:
    try:
        item = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except OSError:
        _fail("unsafe_state")
    if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o600 or
            item.st_nlink != 1 or _report_signature(item) != expected):
        _fail("unsafe_state")


def _remove_report(root_fd: int, identity: dict[str, int], run_token: Any, name: str, expected_digest: str) -> str:
    try:
        os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return "not_found"
    except OSError:
        _fail("unsafe_state")
    fd, before = _open_regular(name, dir_fd=root_fd)
    try:
        expected = _report_signature(before)
        if before.st_nlink != 1:
            _fail("unsafe_state")
        digest = hashlib.sha256()
        size = 0
        while size <= MAX_REPORT_BYTES:
            block = os.read(fd, min(65536, MAX_REPORT_BYTES + 1 - size))
            if not block:
                break
            size += len(block)
            digest.update(block)
        after = os.fstat(fd)
        if size > MAX_REPORT_BYTES or size != before.st_size:
            _fail("report_too_large")
        if _report_signature(after) != expected:
            _fail("unsafe_state")
        if not hmac.compare_digest(digest.hexdigest(), expected_digest):
            _fail("unsafe_state")
        _assert_pinned_root(root_fd, identity)
        _read_marker(root_fd, "run", run_token)
        _assert_cleanup_report(root_fd, name, expected)
        try:
            os.unlink(name, dir_fd=root_fd)
            os.fsync(root_fd)
        except OSError:
            _fail("unsafe_state")
        return "cleared"
    finally:
        os.close(fd)


@register_action("acquire_lock")
def acquire_lock(payload: Any) -> dict[str, Any]:
    data = _require_object(payload, {"run_dir", "run_token", "lease_seconds"})
    lease_seconds = _lease_seconds(data["lease_seconds"])
    root_fd = _open_root(_canonical(_validate_absolute_path(data["run_dir"])))
    try:
        identity = _root_identity(root_fd, "run", data["run_token"])
        boot_id = _boot_id()
        stale_lock_stages_cleaned = _cleanup_stale_lock_stages(root_fd)
        token = secrets.token_hex(32)
        state = {"boot_id": boot_id, "deadline_monotonic_ns": time.monotonic_ns() + lease_seconds * 1_000_000_000, "token": token}
        reclaimed = False
        stale_receiver_pairs_cleaned = 0
        for attempt in range(2):
            if _install_lock(root_fd, state):
                break
            available, cleaned = _reclaim_expired_lock(root_fd, boot_id)
            if not available:
                _fail("lock_busy")
            reclaimed = True
            stale_receiver_pairs_cleaned += cleaned
        else:
            _fail("lock_busy")
        lock_fd, _ = _open_regular(LOCK_NAME, dir_fd=root_fd)
        try:
            lock_identity = _identity(lock_fd)
            installed = _lock_state(lock_fd)
            if not hmac.compare_digest(installed["token"], token):
                _fail("unsafe_lock")
            _assert_named_identity(root_fd, LOCK_NAME, lock_identity, "unsafe_lock")
            _assert_pinned_root(root_fd, identity)
            _read_marker(root_fd, "run", data["run_token"])
            return {"lock_token": token, "reclaimed": reclaimed, "stale_receiver_pairs_cleaned": stale_receiver_pairs_cleaned, "stale_lock_stages_cleaned": stale_lock_stages_cleaned}
        finally:
            os.close(lock_fd)
    finally:
        os.close(root_fd)


@register_action("release_lock")
def release_lock(payload: Any) -> dict[str, Any]:
    data = _require_object(payload, {"run_dir", "run_token", "lock_token"})
    root_fd = _open_root(_canonical(_validate_absolute_path(data["run_dir"])))
    try:
        identity = _root_identity(root_fd, "run", data["run_token"])
        lock_fd, _ = _open_regular(LOCK_NAME, dir_fd=root_fd)
        try:
            lock_identity = _identity(lock_fd)
            state = _lock_state(lock_fd)
            expected = data["lock_token"]
            if not isinstance(expected, str) or not hmac.compare_digest(state["token"], expected):
                _fail("lock_token_mismatch")
            _remove_lock(root_fd, lock_fd, lock_identity)
            _assert_pinned_root(root_fd, identity)
            _read_marker(root_fd, "run", data["run_token"])
            return {"released": True}
        finally:
            os.close(lock_fd)
    finally:
        os.close(root_fd)


@register_action("remove_reports")
def remove_reports(payload: Any) -> dict[str, Any]:
    data = _require_object(payload, {"run_dir", "run_token", "reports"})
    reports = _cleanup_reports(data["reports"])
    root_fd = _open_root(_canonical(_validate_absolute_path(data["run_dir"])))
    try:
        identity = _root_identity(root_fd, "run", data["run_token"])
        lock_token = _acquire_lock_at_root(root_fd, identity, data["run_token"], 60)
        try:
            results = [{"name": report["name"], "result": _remove_report(root_fd, identity, data["run_token"], report["name"], report["sha256"])} for report in reports]
            _assert_pinned_root(root_fd, identity)
            _read_marker(root_fd, "run", data["run_token"])
            return {"reports": results}
        finally:
            _release_lock_at_root(root_fd, identity, data["run_token"], lock_token)
    finally:
        os.close(root_fd)


@register_action("read_report")
def read_report(payload: Any) -> dict[str, Any]:
    data = _require_object(payload, {"run_dir", "run_token", "name"})
    if data["name"] not in REPORT_NAMES:
        _fail("invalid_report")
    root_fd = _open_root(_canonical(_validate_absolute_path(data["run_dir"])))
    try:
        identity = _root_identity(root_fd, "run", data["run_token"])
        fd, item = _open_regular(data["name"], dir_fd=root_fd)
        try:
            content = bytearray()
            while len(content) <= MAX_REPORT_BYTES:
                block = os.read(fd, min(65536, MAX_REPORT_BYTES + 1 - len(content)))
                if not block:
                    break
                content.extend(block)
            after = os.fstat(fd)
            if len(content) > MAX_REPORT_BYTES or item.st_size != len(content) or (item.st_dev, item.st_ino, item.st_size) != (after.st_dev, after.st_ino, after.st_size):
                _fail("report_too_large")
        finally:
            os.close(fd)
        _assert_pinned_root(root_fd, identity)
        _read_marker(root_fd, "run", data["run_token"])
        return {"sha256": hashlib.sha256(content).hexdigest(), "content_b64": base64.b64encode(content).decode("ascii")}
    finally:
        os.close(root_fd)


@register_action("hash_entries")
def hash_entries(payload: Any) -> dict[str, Any]:
    data = _require_object(payload, {"root", "entries"})
    root_fd = _open_root(_canonical(_validate_absolute_path(data["root"])))
    try:
        identity = _identity(root_fd)
        _assert_pinned_root(root_fd, identity)
        entries = data["entries"]
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            _fail("invalid_entries")
        relative = [_relative_entry(entry) for entry in entries]
        if relative != sorted(set(relative)):
            _fail("invalid_entries")
        hashed = [_entry_hash(root_fd, entry) for entry in relative]
        _assert_pinned_root(root_fd, identity)
        return {"entry_count": len(hashed), "sha256": _frame_hash(hashed)}
    finally:
        os.close(root_fd)


def dispatch(action: Any, payload: Any) -> Any:
    if not isinstance(action, str) or action not in ACTIONS:
        _fail("unknown_action")
    return ACTIONS[action](payload)


def _response(*, ok: bool, helper_digest: str, result: Any = None, error: HelperError | None = None) -> bytes:
    response: dict[str, Any] = {"protocol_version": PROTOCOL_VERSION, "helper_sha256": helper_digest, "ok": ok}
    if ok:
        response["result"] = result
    else:
        response["error"] = {"code": error.code if error else "internal_error", "message": error.safe_message if error else "target helper failed"}
    return json.dumps(response, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def run(request_bytes: bytes | None = None) -> None:
    helper_digest = os.environ.get("TARGETCTL_HELPER_DIGEST", "")
    if len(helper_digest) != 64 or any(char not in "0123456789abcdef" for char in helper_digest):
        helper_digest = "0" * 64
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1) if request_bytes is None else request_bytes
        if len(raw) > 1024 * 1024:
            _fail("request_too_large")
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict) or set(request) != {"protocol_version", "action", "payload"}:
            _fail("invalid_request")
        if request["protocol_version"] != PROTOCOL_VERSION:
            _fail("protocol_mismatch")
        result = dispatch(request["action"], request["payload"])
        sys.stdout.buffer.write(_response(ok=True, helper_digest=helper_digest, result=result))
    except HelperError as error:
        sys.stdout.buffer.write(_response(ok=False, helper_digest=helper_digest, error=error))
    except Exception:
        sys.stdout.buffer.write(_response(ok=False, helper_digest=helper_digest, error=HelperError("internal_error", "target helper failed")))


if __name__ == "__main__" and os.environ.get("TARGETCTL_HELPER_DEFERRED") != "1":
    run()
