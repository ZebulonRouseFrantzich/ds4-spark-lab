"""Reproducible source snapshots and deliberately narrow synchronization.

This module treats the three checked-out repositories as the authority.  It never
imports code from a destination tree and never writes a source manifest there.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import shutil
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
from typing import Any, Iterable, Mapping, Sequence

from .common import SCHEMA_VERSION, TargetError, canonical_json_bytes
# The embedded source extension executes after this same validator is defined
# by the standalone target helper.
from .remote import _valid_run_state
from .transport import LocalTransport, MAX_RSYNC_FILTER_BYTES, SSHTransport

SNAPSHOT_SCHEMA_VERSION = 1
EXCLUSION_POLICY_VERSION = 1
STATE_SCHEMA_VERSION = 1
MAX_ENTRIES = 100_000
MAX_FILE_BYTES = 1024 * 1024 * 1024 * 16
SOURCE_LOCK_LEASE_SECONDS = 3_600
_COMPONENT = re.compile(r"^[A-Za-z0-9._+@%=-]+$", re.ASCII)
_HEX = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_MARKER = ".targetctl-owner-v1-work.json"
_EXCLUDED_ROOTS = (
    ".git",
    "targets",
    "models",
    "drafters",
    "artifacts/phase-01-runs",
    "build",
    "dist",
    "result",
    ".direnv",
    ".nix-cache",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
)
_REPOSITORIES = (
    ("lab", ""),
    ("engine", "engine/ds4"),
    ("integration", "spark/ds4-on-spark"),
)


def _error(code: str, message: str = "source synchronization is unavailable") -> TargetError:
    return TargetError(code, message)


@dataclass(frozen=True, slots=True)
class SourceEntry:
    """One regular file in the transfer inventory."""

    path: str
    executable: int
    size: int
    sha256: str
    origin: str

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "type": "file", "executable": self.executable, "size": self.size, "sha256": self.sha256, "origin": self.origin}


@dataclass(frozen=True, slots=True)
class RepositoryState:
    name: str
    head: str
    pinned_head: str | None
    dirty: bool
    status_sha256: str
    tracked_diff_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "head": self.head, "pinned_head": self.pinned_head, "dirty": self.dirty, "status_sha256": self.status_sha256, "tracked_diff_sha256": self.tracked_diff_sha256}


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    """Versioned metadata plus an exact regular-file inventory."""

    repositories: tuple[RepositoryState, ...]
    entries: tuple[SourceEntry, ...]
    dirty: bool
    applied_tree_hash: str
    snapshot_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "exclusion_policy_version": EXCLUSION_POLICY_VERSION,
            "repositories": [item.as_dict() for item in self.repositories],
            "dirty": self.dirty,
            "entries": [item.as_dict() for item in self.entries],
            "applied_tree_hash": self.applied_tree_hash,
            "snapshot_id": self.snapshot_id,
        }


@dataclass(frozen=True, slots=True)
class SyncResult:
    snapshot: SourceSnapshot
    initialized: bool
    applied_tree_hash: str | None


def _run_git(root: Path, args: Sequence[str]) -> bytes:
    try:
        result = subprocess.run(("git", "-C", os.fspath(root), *args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise _error("git_unavailable", "source repository is unavailable") from None
    if result.returncode != 0:
        raise _error("git_invalid", "source repository is unavailable")
    return result.stdout


def _nul_paths(raw: bytes) -> tuple[str, ...]:
    if not raw or raw[-1:] != b"\0":
        if raw:
            raise _error("git_invalid", "source repository is unavailable")
        return ()
    values: list[str] = []
    for item in raw[:-1].split(b"\0"):
        try:
            text = item.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise _error("unsafe_filename", "source inventory contains an unsupported filename") from None
        values.append(text)
    return tuple(values)


def _safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\x00" in value:
        raise _error("unsafe_filename", "source inventory contains an unsupported filename")
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise _error("unsafe_filename", "source inventory contains an unsupported filename") from None
    parts = value.split("/")
    if any(part in {"", ".", ".."} or _COMPONENT.fullmatch(part) is None for part in parts):
        raise _error("unsafe_filename", "source inventory contains an unsupported filename")
    return value


def _joined_relative(prefix: str, value: str) -> str:
    value = _safe_relative(value)
    return value if not prefix else _safe_relative(prefix + "/" + value)


def _is_excluded(path: str) -> bool:
    for prefix in _EXCLUDED_ROOTS:
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _open_file(root: Path, relative: str) -> tuple[int, os.stat_result]:
    """Open a safe regular file while pinning each directory component."""
    root_fd = -1
    parent_fd = -1
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        parent_fd = root_fd
        root_fd = -1
        parts = relative.split("/")
        for part in parts[:-1]:
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            except OSError:
                raise _error("unsafe_entry", "source inventory changed or contains an unsupported entry") from None
            os.close(parent_fd)
            parent_fd = next_fd
        try:
            before = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            raise _error("unsafe_entry", "source inventory changed or contains an unsupported entry") from None
        if not stat.S_ISREG(before.st_mode):
            raise _error("unsupported_entry", "source inventory contains an unsupported entry")
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        except OSError:
            raise _error("unsafe_entry", "source inventory changed or contains an unsupported entry") from None
        return fd, before
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _hash_file(root: Path, relative: str) -> tuple[int, int, str]:
    fd, before = _open_file(root, relative)
    try:
        digest = hashlib.sha256()
        size = 0
        while True:
            try:
                chunk = os.read(fd, 1024 * 1024)
            except OSError:
                raise _error("unsafe_entry", "source inventory changed or contains an unsupported entry") from None
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise _error("entry_too_large", "source inventory contains an unsupported entry")
            digest.update(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or size != after.st_size:
        raise _error("entry_changed", "source inventory changed during hashing")
    return int(bool(after.st_mode & stat.S_IXUSR)), size, digest.hexdigest()


def _tree_hash(entries: Iterable[SourceEntry]) -> str:
    digest = hashlib.sha256(b"targetctl-entry-hash-v1\0")
    for entry in entries:
        for field in (entry.path.encode("utf-8"), b"file", str(entry.executable).encode("ascii"), str(entry.size).encode("ascii"), bytes.fromhex(entry.sha256)):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return digest.hexdigest()


def _repository_state(name: str, root: Path) -> RepositoryState:
    head = _run_git(root, ("rev-parse", "--verify", "HEAD")).strip()
    try:
        head_text = head.decode("ascii")
    except UnicodeDecodeError:
        raise _error("git_invalid", "source repository is unavailable") from None
    if not re.fullmatch(r"[0-9a-f]{40,64}", head_text):
        raise _error("git_invalid", "source repository is unavailable")
    status = _run_git(root, ("status", "--porcelain=v1", "-z", "--untracked-files=all"))
    diff = _run_git(root, ("diff", "--binary", "--no-ext-diff", "HEAD", "--"))
    return RepositoryState(name, head_text, None, bool(status), hashlib.sha256(status).hexdigest(), hashlib.sha256(diff).hexdigest())


def _gitlink(root: Path, relative: str) -> str:
    raw = _run_git(root, ("ls-tree", "-z", "HEAD", "--", relative))
    if raw.count(b"\0") != 1:
        raise _error("git_invalid", "source repository is unavailable")
    try:
        record = raw[:-1].decode("ascii")
        mode, kind, object_id, path = record.split(None, 3)
    except (UnicodeDecodeError, ValueError):
        raise _error("git_invalid", "source repository is unavailable") from None
    if mode != "160000" or kind != "commit" or path != relative or re.fullmatch(r"[0-9a-f]{40,64}", object_id) is None:
        raise _error("git_invalid", "source repository is unavailable")
    return object_id


def _inventory(root: Path) -> tuple[tuple[RepositoryState, ...], tuple[SourceEntry, ...]]:
    """Return the exact eligible files, with repository-local exclusions applied."""
    repos: list[RepositoryState] = []
    inventory: dict[str, SourceEntry] = {}
    for name, prefix in _REPOSITORIES:
        worktree = root / prefix if prefix else root
        if not worktree.is_dir():
            raise _error("subrepository_missing", "source repository is unavailable")
        state = _repository_state(name, worktree)
        if prefix:
            state = RepositoryState(state.name, state.head, _gitlink(root, prefix), state.dirty, state.status_sha256, state.tracked_diff_sha256)
        repos.append(state)
        deleted = set(_nul_paths(_run_git(worktree, ("ls-files", "-z", "--deleted"))))
        tracked = _nul_paths(_run_git(worktree, ("ls-files", "-z", "--cached")))
        untracked = set(_nul_paths(_run_git(worktree, ("ls-files", "-z", "--others", "--exclude-standard"))))
        for local in (*tracked, *sorted(untracked)):
            if local in deleted or _is_excluded(local):
                continue
            path = _joined_relative(prefix, local)
            # The root repository represents subrepositories as gitlinks only;
            # their contents are sourced exclusively from their own worktrees.
            if not prefix and (path == "engine/ds4" or path.startswith("engine/ds4/") or path == "spark/ds4-on-spark" or path.startswith("spark/ds4-on-spark/")):
                continue
            if path == _MARKER:
                raise _error("reserved_path", "source inventory contains a reserved pathname")
            if _is_excluded(path) or path in inventory:
                continue
            if len(inventory) >= MAX_ENTRIES:
                raise _error("inventory_too_large", "source inventory is too large")
            executable, size, content_hash = _hash_file(root, path)
            inventory[path] = SourceEntry(path, executable, size, content_hash, "untracked" if local in untracked else "tracked")
    return tuple(repos), tuple(inventory[path] for path in sorted(inventory))


def build_snapshot(repo_root: str | os.PathLike[str]) -> SourceSnapshot:
    """Inventory the authoritative root and its two required subrepositories."""
    try:
        root = Path(repo_root).resolve(strict=True)
    except (OSError, RuntimeError):
        raise _error("repo_root_invalid", "source repository is unavailable") from None
    if not root.is_dir():
        raise _error("repo_root_invalid", "source repository is unavailable")
    repos, entries = _inventory(root)
    applied = _tree_hash(entries)
    dirty = any(item.dirty for item in repos)
    identity = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "exclusion_policy_version": EXCLUSION_POLICY_VERSION,
        "exclusions": list(_EXCLUDED_ROOTS),
        "repositories": [item.as_dict() for item in repos],
        "entries": [item.as_dict() for item in entries],
        "applied_tree_hash": applied,
    }
    snapshot_id = hashlib.sha256(b"targetctl-source-snapshot-v1\0" + canonical_json_bytes(identity)).hexdigest()
    return SourceSnapshot(repos, entries, dirty, applied, snapshot_id)


# Intentional explicit names for callers in later waves.
generate_snapshot = build_snapshot
snapshot_source = build_snapshot


def verify_applied_tree(repo_root: str | os.PathLike[str], snapshot: SourceSnapshot) -> str:
    """Re-enumerate and verify the complete authoritative transfer inventory."""
    if not isinstance(snapshot, SourceSnapshot):
        raise _error("invalid_snapshot", "source snapshot is invalid")
    try:
        root = Path(repo_root).resolve(strict=True)
    except (OSError, RuntimeError):
        raise _error("repo_root_invalid", "source repository is unavailable") from None
    _, actual = _inventory(root)
    digest = _tree_hash(actual)
    if actual != snapshot.entries or digest != snapshot.applied_tree_hash:
        raise _error("applied_hash_mismatch", "source contents no longer match the snapshot")
    return digest


def qualified_clean(snapshot: SourceSnapshot, *, expected_engine_head: str | None = None, expected_integration_head: str | None = None) -> bool:
    """Return whether a snapshot is a clean, exactly pinned qualification input."""
    if not isinstance(snapshot, SourceSnapshot) or snapshot.dirty or len(snapshot.repositories) != 3:
        return False
    states = {item.name: item for item in snapshot.repositories}
    if (
        set(states) != {"lab", "engine", "integration"}
        or any(item.dirty for item in states.values())
        or states["engine"].pinned_head != states["engine"].head
        or states["integration"].pinned_head != states["integration"].head
    ):
        return False
    if expected_engine_head is not None and states["engine"].head != expected_engine_head:
        return False
    if expected_integration_head is not None and states["integration"].head != expected_integration_head:
        return False
    return True


def require_qualified_clean(snapshot: SourceSnapshot, *, expected_engine_head: str, expected_integration_head: str) -> None:
    if not qualified_clean(snapshot, expected_engine_head=expected_engine_head, expected_integration_head=expected_integration_head):
        raise _error("qualification_source_not_clean", "source snapshot is not a qualified clean baseline")


def _state_filename(target_name: str) -> str:
    if not isinstance(target_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", target_name, re.ASCII):
        raise _error("state_invalid", "source synchronization state is unavailable")
    return target_name + ".source.json"


def _state_path(repo_root: Path, target_name: str) -> Path:
    """Return the conventional state pathname for callers that need its parent."""
    return repo_root / "targets" / ".state" / _state_filename(target_name)


def _open_controller_state_dir(repo_root: Path, *, create: bool) -> int | None:
    """Open ``targets/.state`` through pinned, private directory descriptors."""
    root_fd = -1
    targets_fd = -1
    state_fd = -1
    try:
        root_fd = os.open(repo_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid():
            raise _error("state_invalid", "source synchronization state is unavailable")
        try:
            targets_fd = os.open("targets", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd)
        except FileNotFoundError:
            if not create:
                return None
            os.mkdir("targets", 0o700, dir_fd=root_fd)
            targets_fd = os.open("targets", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd)
        targets_info = os.fstat(targets_fd)
        if not stat.S_ISDIR(targets_info.st_mode) or targets_info.st_uid != os.geteuid():
            raise _error("state_invalid", "source synchronization state is unavailable")
        if stat.S_IMODE(targets_info.st_mode) != 0o700:
            if not create:
                raise _error("state_invalid", "source synchronization state is unavailable")
            os.fchmod(targets_fd, 0o700)
        try:
            state_fd = os.open(".state", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=targets_fd)
        except FileNotFoundError:
            if not create:
                return None
            os.mkdir(".state", 0o700, dir_fd=targets_fd)
            state_fd = os.open(".state", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=targets_fd)
        info = os.fstat(state_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise _error("state_invalid", "source synchronization state is unavailable")
        result = state_fd
        state_fd = -1
        return result
    except TargetError:
        raise
    except OSError:
        raise _error("state_write_failed" if create else "state_invalid", "source synchronization state is unavailable") from None
    finally:
        for fd in (state_fd, targets_fd, root_fd):
            if fd >= 0:
                os.close(fd)


def _read_state_json(state_fd: int, name: str) -> dict[str, Any] | None:
    try:
        info = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise _error("state_invalid", "source synchronization state is unavailable") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024 * 1024:
        raise _error("state_invalid", "source synchronization state is unavailable")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=state_fd)
        try:
            current = os.fstat(fd)
            if (current.st_dev, current.st_ino, current.st_size) != (info.st_dev, info.st_ino, info.st_size):
                raise _error("state_invalid", "source synchronization state is unavailable")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(map(len, chunks)) > 1024 * 1024:
                    raise _error("state_invalid", "source synchronization state is unavailable")
        finally:
            os.close(fd)
        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        value = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=no_duplicates)
    except TargetError:
        raise
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise _error("state_invalid", "source synchronization state is unavailable") from None
    if not isinstance(value, dict):
        raise _error("state_invalid", "source synchronization state is unavailable")
    return value


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError
        view = view[written:]

def _identity(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != {"device", "inode"}:
        raise _error("state_invalid", "source synchronization state is unavailable")
    result = dict(value)
    if any(isinstance(result[key], bool) or not isinstance(result[key], int) or result[key] < 0 for key in result):
        raise _error("state_invalid", "source synchronization state is unavailable")
    return result


def _load_capabilities(repo_root: Path, target_name: str) -> dict[str, Any] | None:
    state_fd = _open_controller_state_dir(repo_root, create=False)
    if state_fd is None:
        return None
    try:
        value = _read_state_json(state_fd, _state_filename(target_name))
    finally:
        os.close(state_fd)
    if value is None:
        return None
    allowed = {"schema_version", "target_name", "work_token", "run_token", "work_identity", "run_identity"}
    if set(value) != allowed:
        raise _error("state_invalid", "source synchronization state is unavailable")
    if value["schema_version"] != STATE_SCHEMA_VERSION or value["target_name"] != target_name or not all(isinstance(value[item], str) and _HEX.fullmatch(value[item]) for item in ("work_token", "run_token")):
        raise _error("state_invalid", "source synchronization state is unavailable")
    _identity(value["work_identity"])
    _identity(value["run_identity"])
    return value


def _store_capabilities(repo_root: Path, target_name: str, value: Mapping[str, Any]) -> None:
    state = {
        "schema_version": STATE_SCHEMA_VERSION,
        "target_name": target_name,
        "work_token": value["work"]["token"],
        "run_token": value["run"]["token"],
        "work_identity": _identity(value["work"]["identity"]),
        "run_identity": _identity(value["run"]["identity"]),
    }
    if not all(isinstance(state[item], str) and _HEX.fullmatch(state[item]) for item in ("work_token", "run_token")):
        raise _error("state_invalid", "source synchronization state is unavailable")
    state_fd = _open_controller_state_dir(repo_root, create=True)
    assert state_fd is not None
    temporary: str | None = None
    fd = -1
    try:
        payload = canonical_json_bytes(state) + b"\n"
        for _ in range(128):
            candidate = ".source-state-" + secrets.token_hex(16) + ".tmp"
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=state_fd)
                temporary = candidate
                break
            except FileExistsError:
                continue
        if fd < 0 or temporary is None:
            raise OSError
        _write_all(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        name = _state_filename(target_name)
        try:
            existing = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode) or existing.st_uid != os.geteuid() or stat.S_IMODE(existing.st_mode) != 0o600:
                raise _error("state_invalid", "source synchronization state is unavailable")
        except FileNotFoundError:
            pass
        os.replace(temporary, name, src_dir_fd=state_fd, dst_dir_fd=state_fd)
        temporary = None
        os.fsync(state_fd)
    except TargetError:
        raise
    except OSError:
        raise _error("state_write_failed", "source synchronization state could not be stored") from None
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=state_fd)
            except OSError:
                pass
        os.close(state_fd)


def _filters(entries: Sequence[SourceEntry]) -> tuple[str, ...]:
    """Include only the exact inventory, then exclude every other source path."""
    directories: set[str] = set()
    for entry in entries:
        components = entry.path.split("/")[:-1]
        for index in range(1, len(components) + 1):
            directories.add("/".join(components[:index]))
    filters = ["H /.targetctl-owner-v1-work.json", "P /.targetctl-owner-v1-work.json", "- /.git", "- /engine/ds4/.git", "- /spark/ds4-on-spark/.git"]
    filters.extend("+ /" + directory + "/" for directory in sorted(directories))
    filters.extend("+ /" + entry.path for entry in entries)
    filters.append("- /***")
    return tuple(filters)


def _open_private_child(parent_fd: int, name: str) -> int:
    """Create or pin one controller-owned 0700 staging directory component."""
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            raise _error("staging_failed", "source synchronization staging could not be prepared")
        return fd
    except TargetError:
        raise
    except OSError:
        raise _error("staging_failed", "source synchronization staging could not be prepared") from None


def _stage_snapshot(root: Path, source: SourceSnapshot, repo_root: Path) -> tuple[Path, Path]:
    """Copy descriptor-pinned source bytes to a component-pinned private input."""
    stage: Path | None = None
    state_fd = -1
    stage_fd = -1
    try:
        state_fd = _open_controller_state_dir(repo_root, create=True)
        assert state_fd is not None
        # tempfile supplies its platform-safe random prefix; creation itself is
        # descriptor-relative so a pathname swap cannot redirect the stage.
        for _ in range(128):
            name = tempfile.gettempprefix() + "targetctl-source-stage-" + secrets.token_hex(16)
            try:
                os.mkdir(name, 0o700, dir_fd=state_fd)
                stage_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=state_fd)
                break
            except FileExistsError:
                continue
        if stage_fd < 0:
            raise OSError
        state_path = os.readlink(f"/proc/self/fd/{state_fd}")
        if not state_path.startswith("/") or state_path.endswith(" (deleted)"):
            raise OSError
        stage = Path(state_path) / name
        for entry in source.entries:
            parent_fd = os.dup(stage_fd)
            try:
                for component in entry.path.split("/")[:-1]:
                    next_fd = _open_private_child(parent_fd, component)
                    os.close(parent_fd)
                    parent_fd = next_fd
                fd, before = _open_file(root, entry.path)
                out_fd = -1
                try:
                    out_fd = os.open(entry.path.rsplit("/", 1)[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o700 if entry.executable else 0o600, dir_fd=parent_fd)
                    digest = hashlib.sha256()
                    size = 0
                    while True:
                        chunk = os.read(fd, 1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_FILE_BYTES:
                            raise _error("entry_too_large", "source inventory contains an unsupported entry")
                        digest.update(chunk)
                        _write_all(out_fd, chunk)
                    after = os.fstat(fd)
                    if (not stat.S_ISREG(after.st_mode) or
                        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                        (size, digest.hexdigest(), int(bool(after.st_mode & stat.S_IXUSR))) != (entry.size, entry.sha256, entry.executable)):
                        raise _error("entry_changed", "source inventory changed before transfer")
                    os.fsync(out_fd)
                finally:
                    if out_fd >= 0:
                        os.close(out_fd)
                    os.close(fd)
            finally:
                os.close(parent_fd)
        staged_entries = []
        for item in source.entries:
            executable, size, digest = _hash_file(stage, item.path)
            staged_entries.append(SourceEntry(item.path, executable, size, digest, item.origin))
        if tuple(staged_entries) != source.entries or _tree_hash(staged_entries) != source.applied_tree_hash:
            raise _error("entry_changed", "source inventory changed before transfer")
        filter_path = stage / ".targetctl-source.filters"
        filter_fd = os.open(".targetctl-source.filters", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=stage_fd)
        try:
            data = ("\n".join(_filters(source.entries)) + "\n").encode("ascii")
            if len(data) > MAX_RSYNC_FILTER_BYTES:
                raise _error("staging_failed", "source synchronization staging could not be prepared")
            _write_all(filter_fd, data)
            os.fsync(filter_fd)
        finally:
            os.close(filter_fd)
        return stage, filter_path
    except (OSError, RuntimeError):
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        raise _error("staging_failed", "source synchronization staging could not be prepared") from None
    except BaseException:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        raise
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        if state_fd >= 0:
            os.close(state_fd)


_SOURCE_EXTENSION = r'''
def _source_relative(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        _fail("invalid_entries")
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        _fail("invalid_entries")
    bits = value.split("/")
    if value.startswith("/") or any(not bit or bit in (".", "..") or not all(c.isalnum() or c in "._+@%=-" for c in bit) for bit in bits):
        _fail("invalid_entries")
    return value

def _source_entries(root_fd, entries):
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _fail("invalid_entries")
    names = [_source_relative(item) for item in entries]
    if names != sorted(set(names)):
        _fail("invalid_entries")
    expected = set(names)
    prefixes = set()
    for name in names:
        bits = name.split("/")[:-1]
        for index in range(1, len(bits) + 1):
            prefixes.add("/".join(bits[:index]))
    count = [0]
    def visit(fd, prefix=""):
        try:
            scan_fd = os.dup(fd)
            with os.scandir(scan_fd) as scan:
                for child in scan:
                    count[0] += 1
                    if count[0] > MAX_ENTRIES:
                        _fail("unsafe_entry")
                    name = child.name
                    relative = name if not prefix else prefix + "/" + name
                    item = child.stat(follow_symlinks=False)
                    if prefix == "" and name == ".targetctl-owner-v1-work.json":
                        if not stat.S_ISREG(item.st_mode):
                            _fail("unsafe_entry")
                        continue
                    if stat.S_ISDIR(item.st_mode):
                        if relative not in prefixes:
                            _fail("unexpected_entry")
                        next_fd = _open_directory(fd, name)
                        try:
                            visit(next_fd, relative)
                        finally:
                            os.close(next_fd)
                    elif not stat.S_ISREG(item.st_mode) or relative not in expected:
                        _fail("unexpected_entry")
        except HelperError:
            raise
        except OSError:
            _fail("unsafe_entry")
    visit(root_fd)
    return names

def _source_roots(payload):
    data = _require_object(payload, {"workdir", "run_dir", "model_path", "drafter_path", "work_token", "run_token", "entries"})
    paths = _root_payload({key: data[key] for key in ("workdir", "run_dir", "model_path", "drafter_path", "work_token", "run_token")}, require_tokens=True)
    return data, paths

def _source_lifecycle(run_fd):
    try:
        fd, item = _open_regular("run.json", dir_fd=run_fd)
    except HelperError:
        try:
            os.stat("run.json", dir_fd=run_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            pass
        _fail("source_lifecycle")
    try:
        if item.st_size > 65536:
            _fail("source_lifecycle")
        raw = os.read(fd, 65537)
    finally:
        os.close(fd)
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        _fail("source_lifecycle")
    if not _valid_run_state(state, terminal=True) or not state["cleanup_complete"]:
        _fail("source_lifecycle")

def _source_open(paths):
    work_fd = _open_root(paths["workdir"])
    try:
        run_fd = _open_root(paths["run_dir"])
    except Exception:
        os.close(work_fd)
        raise
    try:
        work_identity = _root_identity(work_fd, "work", paths["work_token"])
        run_identity = _root_identity(run_fd, "run", paths["run_token"])
        _source_lifecycle(run_fd)
        return work_fd, run_fd, work_identity, run_identity
    except Exception:
        os.close(work_fd)
        os.close(run_fd)
        raise


def _source_mount_path(value):
    decoded = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            decoded.append(value[index])
            index += 1
            continue
        if index + 3 >= len(value) or any(bit not in "01234567" for bit in value[index + 1:index + 4]):
            _fail("unsafe_mount")
        decoded.append(chr(int(value[index + 1:index + 4], 8)))
        index += 4
    return "".join(decoded)


def _source_no_nested_mounts(root_fd):
    try:
        root_path = os.readlink("/proc/self/fd/%d" % root_fd)
        root_info = os.fstat(root_fd)
        live_info = os.stat(root_path)
        if (not root_path.startswith("/") or root_path.endswith(" (deleted)") or
            (live_info.st_dev, live_info.st_ino) != (root_info.st_dev, root_info.st_ino)):
            _fail("unsafe_mount")
        prefix = root_path.rstrip("/") + "/"
        with open("/proc/self/mountinfo", "rt", encoding="ascii", errors="strict") as mounts:
            for line in mounts:
                fields = line.split()
                if len(fields) <= 4:
                    _fail("unsafe_mount")
                if _source_mount_path(fields[4]).startswith(prefix):
                    _fail("unsafe_mount")
    except HelperError:
        raise
    except (OSError, UnicodeError):
        _fail("unsafe_mount")


def _source_safe_tree(root_fd):
    root = os.fstat(root_fd)
    count = [0]
    def visit(fd):
        try:
            scan_fd = os.dup(fd)
            with os.scandir(scan_fd) as scan:
                for child in scan:
                    count[0] += 1
                    if count[0] > MAX_ENTRIES:
                        _fail("unsafe_entry")
                    item = child.stat(follow_symlinks=False)
                    if not (stat.S_ISREG(item.st_mode) or stat.S_ISDIR(item.st_mode)) or item.st_dev != root.st_dev:
                        _fail("unsafe_entry")
                    if stat.S_ISDIR(item.st_mode):
                        next_fd = _open_directory(fd, child.name)
                        try:
                            visit(next_fd)
                        finally:
                            os.close(next_fd)
        except HelperError:
            raise
        except OSError:
            _fail("unsafe_entry")
    _source_no_nested_mounts(root_fd)
    visit(root_fd)
def _source_fd_path(fd):
    try:
        value = os.readlink("/proc/self/fd/%d" % fd)
    except OSError:
        _fail("unsafe_runtime_path")
    if not value.startswith("/") or value.endswith(" (deleted)"):
        _fail("unsafe_runtime_path")
    return _canonical(value)


def _source_open_runtime_file(path):
    parts = path.split("/")[1:]
    try:
        parent_fd = os.open("/", _DIRECTORY_FLAGS)
        for part in parts[:-1]:
            next_fd = _open_directory(parent_fd, part)
            os.close(parent_fd)
            parent_fd = next_fd
        fd, item = _open_entry_regular(parts[-1], dir_fd=parent_fd)
        return parent_fd, fd, item
    except HelperError:
        try: os.close(parent_fd)
        except (OSError, UnboundLocalError): pass
        raise
    except OSError:
        try: os.close(parent_fd)
        except (OSError, UnboundLocalError): pass
        _fail("unsafe_runtime_path")


def _source_reject_tree_identity(root_fd, identity):
    root = os.fstat(root_fd)
    count = [0]
    def visit(fd):
        try:
            with os.scandir(os.dup(fd)) as children:
                for child in children:
                    count[0] += 1
                    if count[0] > MAX_ENTRIES: _fail("unsafe_runtime_path")
                    item = child.stat(follow_symlinks=False)
                    if (item.st_dev, item.st_ino) == (identity.st_dev, identity.st_ino):
                        _fail("unsafe_runtime_path")
                    if not (stat.S_ISREG(item.st_mode) or stat.S_ISDIR(item.st_mode)) or item.st_dev != root.st_dev:
                        _fail("unsafe_runtime_path")
                    if stat.S_ISDIR(item.st_mode):
                        child_fd = _open_directory(fd, child.name)
                        try: visit(child_fd)
                        finally: os.close(child_fd)
        except HelperError: raise
        except OSError: _fail("unsafe_runtime_path")
    visit(root_fd)


def _source_validate_runtime_paths(paths, work_fd, run_fd):
    opened = []
    try:
        for key in ("model_path", "drafter_path"):
            parent_fd, fd, item = _source_open_runtime_file(paths[key])
            opened.append((parent_fd, fd, item, _source_fd_path(fd)))
        model, drafter = opened
        if ((model[2].st_dev, model[2].st_ino) == (drafter[2].st_dev, drafter[2].st_ino)):
            _fail("unsafe_runtime_path")
        roots = (_source_fd_path(work_fd), _source_fd_path(run_fd))
        for _, _, item, resolved in opened:
            if any(_overlaps(resolved, root) for root in roots):
                _fail("unsafe_runtime_path")
            for root_fd in (work_fd, run_fd):
                _source_reject_tree_identity(root_fd, item)
    finally:
        for parent_fd, fd, _, _ in opened:
            os.close(fd); os.close(parent_fd)
def _source_receiver_program(run_dir, auth_name):
    return """#!/usr/bin/python3
import hashlib, hmac, json, os, stat, sys, time
RUN = %r
AUTH = %r
MARKER = ".targetctl-owner-v1-work.json"
LOCK = ".targetctl-operation-lock-v1"
EXPECTED_PREFIX = ["--server", "-tprxe.iLsfxCIvu", "--delete-excluded", "."]
def fail():
    raise SystemExit(126)
def dopen(path):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        for part in path.split("/")[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            os.close(fd); fd = nxt
        return fd
    except OSError:
        os.close(fd); fail()
def regular(fd, name):
    try:
        out = os.open(name, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        info = os.fstat(out)
    except OSError: fail()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(out); fail()
    return out
def contents(fd, name, limit=65536):
    out = regular(fd, name)
    try:
        data = os.read(out, limit + 1)
        if len(data) > limit: fail()
        return data
    finally: os.close(out)
def root(path, kind, token, identity):
    fd = dopen(path); info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or
        (info.st_dev, info.st_ino) != (identity["device"], identity["inode"])): os.close(fd); fail()
    try: marker = json.loads(contents(fd, ".targetctl-owner-v1-" + kind + ".json", 4096).decode("ascii"))
    except Exception: os.close(fd); fail()
    if not isinstance(marker, dict) or marker.get("kind") != kind or marker.get("version") != 1 or not hmac.compare_digest(marker.get("token", ""), token): os.close(fd); fail()
    return fd
def mount_path(value):
    decoded = []
    index = 0
    while index < len(value):
        if value[index] != "\\\\":
            decoded.append(value[index]); index += 1; continue
        if index + 3 >= len(value) or any(bit not in "01234567" for bit in value[index + 1:index + 4]): fail()
        decoded.append(chr(int(value[index + 1:index + 4], 8))); index += 4
    return "".join(decoded)
def no_nested_mounts(fd):
    try:
        path = os.readlink("/proc/self/fd/%%d" %% fd)
        pinned = os.fstat(fd)
        live = os.stat(path)
        if (not path.startswith("/") or path.endswith(" (deleted)") or
            (pinned.st_dev, pinned.st_ino) != (live.st_dev, live.st_ino)): fail()
        prefix = path.rstrip("/") + "/"
        with open("/proc/self/mountinfo", "rt", encoding="ascii", errors="strict") as mounts:
            for line in mounts:
                fields = line.split()
                if len(fields) <= 4: fail()
                if mount_path(fields[4]).startswith(prefix): fail()
    except OSError: fail()
run_fd = dopen(RUN)
try:
    raw = contents(run_fd, AUTH)
    auth = json.loads(raw.decode("ascii"))
    if not isinstance(auth, dict) or set(auth) != {"workdir","work_token","run_token","work_identity","run_identity","lock_token","lock_boot_id","lock_deadline_monotonic_ns"}: fail()
    run_info = os.fstat(run_fd)
    if (not stat.S_ISDIR(run_info.st_mode) or run_info.st_uid != os.geteuid() or stat.S_IMODE(run_info.st_mode) != 0o700 or
        (run_info.st_dev, run_info.st_ino) != (auth["run_identity"]["device"], auth["run_identity"]["inode"])): fail()
    marker = json.loads(contents(run_fd, ".targetctl-owner-v1-run.json", 4096).decode("ascii"))
    if not isinstance(marker, dict) or marker.get("kind") != "run" or marker.get("version") != 1 or not hmac.compare_digest(marker.get("token", ""), auth["run_token"]): fail()
    lock_fd = os.open(LOCK, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=run_fd)
    try:
        lock_info = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.geteuid() or stat.S_IMODE(lock_info.st_mode) != 0o600: fail()
        try:
            raw_lock = os.read(lock_fd, 1025)
            if len(raw_lock) > 1024: fail()
            lock = json.loads(raw_lock.decode("ascii"))
            boot = open("/proc/sys/kernel/random/boot_id", "rt", encoding="ascii").read(64).strip()
        except Exception: fail()
        if (not isinstance(lock, dict) or set(lock) != {"boot_id","deadline_monotonic_ns","token"} or
            not isinstance(lock.get("deadline_monotonic_ns"), int) or isinstance(lock.get("deadline_monotonic_ns"), bool) or
            not isinstance(lock.get("boot_id"), str) or not hmac.compare_digest(lock.get("token", ""), auth["lock_token"]) or
            not hmac.compare_digest(lock["boot_id"], auth["lock_boot_id"]) or lock["deadline_monotonic_ns"] != auth["lock_deadline_monotonic_ns"] or
            not hmac.compare_digest(boot, lock["boot_id"]) or time.monotonic_ns() >= lock["deadline_monotonic_ns"]): fail()
    finally: os.close(lock_fd)
    work_fd = root(auth["workdir"], "work", auth["work_token"], auth["work_identity"])
    try:
        no_nested_mounts(work_fd)
        root_dev = os.fstat(work_fd).st_dev
        seen = [0]
        def scan(fd):
            with os.scandir(os.dup(fd)) as children:
                for child in children:
                    seen[0] += 1
                    if seen[0] > 100000: fail()
                    item = child.stat(follow_symlinks=False)
                    if not (stat.S_ISREG(item.st_mode) or stat.S_ISDIR(item.st_mode)) or item.st_dev != root_dev: fail()
                    if stat.S_ISDIR(item.st_mode):
                        next_fd = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                        try: scan(next_fd)
                        finally: os.close(next_fd)
        scan(work_fd)
        args = sys.argv[1:]
        if args != EXPECTED_PREFIX + [auth["workdir"] + "/"]: fail()
        args[-1] = "."
        os.unlink(AUTH, dir_fd=run_fd)
        os.unlink(sys.argv[0])
        os.fchdir(work_fd)
        os.execve("/usr/bin/rsync", ["/usr/bin/rsync", *args], {"LANG":"C","LC_ALL":"C","PATH":"/usr/bin:/bin"})
    finally: os.close(work_fd)
finally: os.close(run_fd)
""" % (run_dir, auth_name)

@register_action("source_prepare_receiver")
def source_prepare_receiver(payload):
    data = _require_object(payload, {"workdir", "run_dir", "model_path", "drafter_path", "work_token", "run_token", "entries", "lock_token", "receiver_nonce"})
    paths = _root_payload({key: data[key] for key in ("workdir", "run_dir", "model_path", "drafter_path", "work_token", "run_token")}, require_tokens=True)
    if (not isinstance(data["lock_token"], str) or len(data["lock_token"]) != 64 or
        not isinstance(data["receiver_nonce"], str) or len(data["receiver_nonce"]) != 32 or
        any(character not in "0123456789abcdef" for character in data["receiver_nonce"])):
        _fail("unsafe_lock")
    work_fd, run_fd, work_identity, run_identity = _source_open(paths)
    try:
        _source_safe_tree(work_fd)
        lock_fd, _ = _open_regular(LOCK_NAME, dir_fd=run_fd)
        try:
            lock_state = _lock_state(lock_fd)
            if (not hmac.compare_digest(lock_state["token"], data["lock_token"]) or
                    not hmac.compare_digest(lock_state["boot_id"], _boot_id()) or
                    time.monotonic_ns() >= lock_state["deadline_monotonic_ns"]):
                _fail("unsafe_lock")
            # Descriptor-validate the private runtime files after each
            # destructive-tree check, directly before receiver creation.
            _source_validate_runtime_paths(paths, work_fd, run_fd)
            lock_state = _lock_state(lock_fd)
            if (not hmac.compare_digest(lock_state["token"], data["lock_token"]) or
                    not hmac.compare_digest(lock_state["boot_id"], _boot_id()) or
                    time.monotonic_ns() >= lock_state["deadline_monotonic_ns"]):
                _fail("unsafe_lock")
        finally:
            os.close(lock_fd)
        suffix = data["receiver_nonce"]
        auth_name = ".targetctl-source-receiver-" + suffix + ".json"
        receiver_name = ".targetctl-source-receiver-" + suffix + ".py"
        auth = json.dumps({"workdir": paths["workdir"], "work_token": paths["work_token"], "run_token": paths["run_token"], "work_identity": work_identity, "run_identity": run_identity, "lock_token": data["lock_token"], "lock_boot_id": lock_state["boot_id"], "lock_deadline_monotonic_ns": lock_state["deadline_monotonic_ns"]}, sort_keys=True, separators=(",", ":")).encode("ascii")
        created = []
        try:
            for name, content, mode in ((auth_name, auth, 0o600), (receiver_name, _source_receiver_program(paths["run_dir"], auth_name).encode("ascii"), 0o700)):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=run_fd)
                created.append(name)
                try:
                    view = memoryview(content)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            raise OSError
                        view = view[written:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(run_fd)
        except BaseException:
            for name in reversed(created):
                try:
                    os.unlink(name, dir_fd=run_fd)
                except OSError:
                    pass
            try:
                os.fsync(run_fd)
            except OSError:
                pass
            raise
        return {"receiver": paths["run_dir"] + "/" + receiver_name, "work": work_identity, "run": run_identity}
    finally:
        os.close(work_fd); os.close(run_fd)

@register_action("source_cleanup_receiver")
def source_cleanup_receiver(payload):
    data = _require_object(payload, {"run_dir", "run_token", "receiver"})
    name = data["receiver"]
    prefix = data["run_dir"] + "/.targetctl-source-receiver-"
    if not isinstance(name, str) or not name.startswith(prefix) or not name.endswith(".py"):
        _fail("invalid_payload")
    suffix = name[len(prefix):-3]
    if len(suffix) != 32 or any(character not in "0123456789abcdef" for character in suffix):
        _fail("invalid_payload")
    run_fd = _open_root(_canonical(_validate_absolute_path(data["run_dir"])))
    try:
        _root_identity(run_fd, "run", data["run_token"])
        stem = ".targetctl-source-receiver-" + suffix
        for leaf in (stem + ".py", stem + ".json"):
            try: os.unlink(leaf, dir_fd=run_fd)
            except FileNotFoundError: pass
            except OSError: _fail("unsafe_state")
        os.fsync(run_fd)
        return {"cleaned": True}
    finally: os.close(run_fd)

@register_action("source_preflight")
def source_preflight(payload):
    data, paths = _source_roots(payload)
    work_fd, run_fd, work_identity, run_identity = _source_open(paths)
    try:
        _assert_pinned_root(work_fd, work_identity)
        _assert_pinned_root(run_fd, run_identity)
        _source_safe_tree(work_fd)
        _source_validate_runtime_paths(paths, work_fd, run_fd)
        _read_marker(work_fd, "work", paths["work_token"])
        _read_marker(run_fd, "run", paths["run_token"])
        return {"work": work_identity, "run": run_identity}
    finally:
        os.close(work_fd)
        os.close(run_fd)

@register_action("source_verify")
def source_verify(payload):
    data, paths = _source_roots(payload)
    work_fd, run_fd, work_identity, run_identity = _source_open(paths)
    try:
        names = _source_entries(work_fd, data["entries"])
        hashed = []
        for name in names:
            parent_fd, leaf = _entry_parent(work_fd, name)
            try:
                item = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISREG(item.st_mode):
                    _fail("unexpected_entry")
                fd, before = _open_entry_regular(leaf, dir_fd=parent_fd)
                try:
                    digest = hashlib.sha256(); size = 0
                    while True:
                        block = os.read(fd, 1024 * 1024)
                        if not block: break
                        size += len(block); digest.update(block)
                    after = os.fstat(fd)
                finally:
                    os.close(fd)
                if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size) or size != after.st_size:
                    _fail("entry_changed")
                hashed.append((name, "file", int(bool(after.st_mode & stat.S_IXUSR)), size, digest.digest()))
            finally:
                os.close(parent_fd)
        _assert_pinned_root(work_fd, work_identity)
        _assert_pinned_root(run_fd, run_identity)
        _read_marker(work_fd, "work", paths["work_token"])
        _read_marker(run_fd, "run", paths["run_token"])
        return {"entry_count": len(hashed), "sha256": _frame_hash(hashed), "work": work_identity, "run": run_identity}
    finally:
        os.close(work_fd)
        os.close(run_fd)

@register_action("source_write_state")
def source_write_state(payload):
    data = _require_object(payload, {"run_dir", "run_token", "snapshot_id", "applied_tree_hash", "dirty"})
    if not isinstance(data["snapshot_id"], str) or not isinstance(data["applied_tree_hash"], str) or not isinstance(data["dirty"], bool) or not all(len(data[key]) == 64 and all(c in "0123456789abcdef" for c in data[key]) for key in ("snapshot_id", "applied_tree_hash")):
        _fail("invalid_payload")
    run_fd = _open_root(_canonical(_validate_absolute_path(data["run_dir"])))
    try:
        identity = _root_identity(run_fd, "run", data["run_token"])
        raw = json.dumps({"schema_version": 1, "snapshot_id": data["snapshot_id"], "applied_tree_hash": data["applied_tree_hash"], "dirty": data["dirty"]}, sort_keys=True, separators=(",", ":")).encode("ascii")
        temporary = ".source-state-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=run_fd)
        try:
            os.write(fd, raw); os.fsync(fd)
        finally:
            os.close(fd)
        try:
            existing = os.stat("source.json", dir_fd=run_fd, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode) or existing.st_uid != os.geteuid() or stat.S_IMODE(existing.st_mode) != 0o600: _fail("unsafe_state")
        except FileNotFoundError:
            pass
        os.replace(temporary, "source.json", src_dir_fd=run_fd, dst_dir_fd=run_fd)
        os.fsync(run_fd)
        _assert_pinned_root(run_fd, identity)
        _read_marker(run_fd, "run", data["run_token"])
        return {"stored": True}
    finally:
        os.close(run_fd)
'''

_EXTENSION_ERRORS = frozenset({"source_lifecycle", "unexpected_entry", "unsafe_mount", "unsafe_runtime_path"})


def _remote_payload(config: Any, state: Mapping[str, Any], entries: Sequence[SourceEntry]) -> dict[str, Any]:
    return {
        "workdir": config.workdir,
        "run_dir": config.run_dir,
        "model_path": config.model_path,
        "drafter_path": config.drafter_path,
        "work_token": state["work_token"],
        "run_token": state["run_token"],
        "entries": [entry.path for entry in entries],
    }


def _expect_root_identities(result: Any, state: Mapping[str, Any]) -> None:
    if not isinstance(result, Mapping) or _identity(result.get("work")) != _identity(state["work_identity"]) or _identity(result.get("run")) != _identity(state["run_identity"]):
        raise _error("root_identity_changed", "target root identity changed")


def sync_source(config: Any, transport: LocalTransport | SSHTransport, *, snapshot: SourceSnapshot | None = None) -> SyncResult:
    """Verify local source or perform the guarded two-step remote synchronization."""
    if hasattr(config, "validate_for"):
        config.validate_for("sync")
    root = Path(config.source_root)
    source = snapshot if snapshot is not None else build_snapshot(root)
    if not isinstance(source, SourceSnapshot):
        raise _error("invalid_snapshot", "source snapshot is invalid")
    if getattr(config, "mode", None) == "local":
        if not isinstance(transport, LocalTransport):
            raise _error("transport_invalid", "source synchronization transport is invalid")
        return SyncResult(source, False, verify_applied_tree(root, source))
    if getattr(config, "mode", None) != "ssh" or not isinstance(transport, SSHTransport):
        raise _error("transport_invalid", "source synchronization transport is invalid")
    state = _load_capabilities(root, config.name)
    initialized_now = False
    if state is None:
        initialized = transport.run_helper("initialize_roots", {"workdir": config.workdir, "run_dir": config.run_dir, "model_path": config.model_path, "drafter_path": config.drafter_path}, allowed_error_codes={"marker_exists", "unmarked_populated_root", "root_create_failed", "symlink_path", "path_overlap", "unsafe_root"})
        if not isinstance(initialized, Mapping):
            raise _error("initialization_failed", "target roots could not be initialized")
        _store_capabilities(root, config.name, initialized)
        state = _load_capabilities(root, config.name)
        if state is None:
            raise _error("initialization_failed", "target roots could not be initialized")
        initialized_now = True
    payload = _remote_payload(config, state, source.entries)
    inspected = transport.run_helper("inspect_roots", {key: payload[key] for key in ("workdir", "run_dir", "model_path", "drafter_path", "work_token", "run_token")}, allowed_error_codes={"marker_mismatch", "unsafe_root", "unsafe_state", "missing_path", "path_overlap"})
    _expect_root_identities(inspected, state)
    preflight = transport.run_helper("source_preflight", payload, extension_source=_SOURCE_EXTENSION, allowed_error_codes=_EXTENSION_ERRORS | {"marker_mismatch", "unsafe_root", "unsafe_state", "missing_path", "path_overlap"})
    _expect_root_identities(preflight, state)
    lock = transport.run_helper("acquire_lock", {"run_dir": config.run_dir, "run_token": state["run_token"], "lease_seconds": SOURCE_LOCK_LEASE_SECONDS}, allowed_error_codes={"lock_busy", "lock_failed", "unsafe_lock", "invalid_lease", "marker_mismatch", "unsafe_root"})
    if not isinstance(lock, Mapping) or not isinstance(lock.get("lock_token"), str):
        raise _error("lock_failed", "target synchronization lock could not be acquired")
    primary: BaseException | None = None
    stage: Path | None = None
    receiver_nonce = secrets.token_hex(16)
    receiver = config.run_dir + "/.targetctl-source-receiver-" + receiver_nonce + ".py"
    try:
        preflight = transport.run_helper("source_preflight", payload, extension_source=_SOURCE_EXTENSION, allowed_error_codes=_EXTENSION_ERRORS | {"marker_mismatch", "unsafe_root", "unsafe_state", "missing_path", "path_overlap"})
        _expect_root_identities(preflight, state)
        verify_applied_tree(root, source)
        stage, filter_path = _stage_snapshot(root, source, root)
        prepared = transport.run_helper("source_prepare_receiver", {**payload, "lock_token": lock["lock_token"], "receiver_nonce": receiver_nonce}, extension_source=_SOURCE_EXTENSION, allowed_error_codes=_EXTENSION_ERRORS | {"marker_mismatch", "unsafe_root", "unsafe_state", "unsafe_lock", "unsafe_mount", "missing_path", "path_overlap"})
        _expect_root_identities(prepared, state)
        if not isinstance(prepared, Mapping) or prepared.get("receiver") != receiver:
            raise _error("receiver_prepare_failed", "target source receiver could not be prepared")
        transport.guarded_rsync(stage, config.workdir, receiver=receiver, filter_file=filter_path)
        verified = transport.run_helper("source_verify", payload, extension_source=_SOURCE_EXTENSION, allowed_error_codes=_EXTENSION_ERRORS | {"entry_changed", "marker_mismatch", "unsafe_entry", "unsafe_root", "unsafe_state", "missing_path", "path_overlap"})
        _expect_root_identities(verified, state)
        if not isinstance(verified, Mapping) or verified.get("sha256") != source.applied_tree_hash or verified.get("entry_count") != len(source.entries):
            raise _error("applied_hash_mismatch", "target source contents do not match the snapshot")
        transport.run_helper("source_write_state", {"run_dir": config.run_dir, "run_token": state["run_token"], "snapshot_id": source.snapshot_id, "applied_tree_hash": source.applied_tree_hash, "dirty": source.dirty}, extension_source=_SOURCE_EXTENSION, allowed_error_codes={"unsafe_state", "marker_mismatch", "unsafe_root", "missing_path"})
        final_roots = transport.run_helper("inspect_roots", {key: payload[key] for key in ("workdir", "run_dir", "model_path", "drafter_path", "work_token", "run_token")}, allowed_error_codes={"marker_mismatch", "unsafe_root", "unsafe_state", "missing_path", "path_overlap"})
        _expect_root_identities(final_roots, state)
        return SyncResult(source, initialized_now, source.applied_tree_hash)
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_error: BaseException | None = None
        try:
            transport.run_helper("source_cleanup_receiver", {"run_dir": config.run_dir, "run_token": state["run_token"], "receiver": receiver}, extension_source=_SOURCE_EXTENSION, allowed_error_codes={"marker_mismatch", "unsafe_root", "unsafe_state", "missing_path"})
        except BaseException as error:
            cleanup_error = error
        if stage is not None:
            try:
                shutil.rmtree(stage)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
        try:
            transport.run_helper("release_lock", {"run_dir": config.run_dir, "run_token": state["run_token"], "lock_token": lock["lock_token"]}, allowed_error_codes={"lock_token_mismatch", "lock_release_failed", "unsafe_lock", "marker_mismatch", "unsafe_root"})
        except BaseException:
            if primary is None:
                raise _error("lock_release_failed", "target synchronization lock could not be released") from None
        if cleanup_error is not None and primary is None:
            raise _error("staging_cleanup_failed", "source synchronization temporary data could not be removed") from None


sync = sync_source
