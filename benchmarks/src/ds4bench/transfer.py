from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from .artifacts import MAX_RESULT_BYTES, RESULT_FILE_LIMITS, RESULT_FILES
from .stats import canonical_json_bytes

SCHEMA_VERSION = 1
RUNTIME_FILES = frozenset({"ds4bench.pyz", "licenses.json"})
RUNTIME_MANIFEST_NAME = "runtime-manifest.json"
RESULT_MANIFEST_NAME = "result-manifest.json"
MAX_RUNTIME_FILES = 512
MAX_RESULT_FILES = 16
MAX_RUNTIME_FILE_BYTES = 8 * 1024 * 1024
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_AGGREGATE_DOMAIN = b"ds4bench-transfer-aggregate-v1\x00"
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_PATH_COMPONENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MANIFEST_FIELDS = frozenset(
    {"schema_version", "kind", "run_id", "entries", "aggregate_sha256", "lock_sha256"}
)
_ENTRY_FIELDS = frozenset({"path", "size", "sha256"})


class TransferError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class TransferEntry:
    path: str
    size: int
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class TransferSidecar:
    path: Path
    sha256: str
    manifest: dict[str, object]


@dataclass(frozen=True, slots=True)
class PromotionResult:
    path: Path
    promoted: bool
    manifest_sha256: str


def sha256_file(path: Path | str) -> str:
    payload_path = Path(path)
    parent_fd = _open_directory(payload_path.parent, "file_parent")
    try:
        _, digest = _hash_regular_at(parent_fd, payload_path.name, MAX_RESULT_BYTES)
    finally:
        os.close(parent_fd)
    return digest


def framed_aggregate_sha256(
    entries: Iterable[TransferEntry | Mapping[str, object]],
) -> str:
    checked: list[TransferEntry] = []
    for value in entries:
        if isinstance(value, TransferEntry):
            entry = value
        elif isinstance(value, Mapping) and set(value) == _ENTRY_FIELDS:
            path = _safe_payload_path(value["path"])
            size = _bounded_size(value["size"], "entry_size")
            digest = _sha256(value["sha256"], "entry_sha256")
            entry = TransferEntry(path=path, size=size, sha256=digest)
        else:
            raise TransferError("entry_fields")
        _safe_payload_path(entry.path)
        _bounded_size(entry.size, "entry_size")
        _sha256(entry.sha256, "entry_sha256")
        checked.append(entry)
    if [entry.path for entry in checked] != sorted(entry.path for entry in checked):
        raise TransferError("entries_not_sorted")
    if len({entry.path for entry in checked}) != len(checked):
        raise TransferError("duplicate_entry_path")

    digest = hashlib.sha256()
    digest.update(_AGGREGATE_DOMAIN)
    digest.update(len(checked).to_bytes(4, "big"))
    for entry in checked:
        encoded_path = entry.path.encode("ascii")
        digest.update(len(encoded_path).to_bytes(2, "big"))
        digest.update(encoded_path)
        digest.update(entry.size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(entry.sha256))
    return digest.hexdigest()


def validate_transfer_manifest(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _MANIFEST_FIELDS:
        raise TransferError("manifest_fields")
    if isinstance(value["schema_version"], bool) or value["schema_version"] != SCHEMA_VERSION:
        raise TransferError("manifest_schema_version")
    kind = value["kind"]
    if kind not in {"runtime", "result"}:
        raise TransferError("manifest_kind")
    run_id = value["run_id"]
    if not isinstance(run_id, str) or _ID.fullmatch(run_id) is None:
        raise TransferError("manifest_run_id")
    lock_sha256 = _sha256(value["lock_sha256"], "lock_sha256")
    raw_entries = value["entries"]
    if not isinstance(raw_entries, list):
        raise TransferError("manifest_entries")

    entries: list[TransferEntry] = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict) or set(raw_entry) != _ENTRY_FIELDS:
            raise TransferError("entry_fields")
        entries.append(
            TransferEntry(
                path=_safe_payload_path(raw_entry["path"]),
                size=_bounded_size(raw_entry["size"], "entry_size"),
                sha256=_sha256(raw_entry["sha256"], "entry_sha256"),
            )
        )
    paths = [entry.path for entry in entries]
    if paths != sorted(paths):
        raise TransferError("entries_not_sorted")
    if len(paths) != len(set(paths)):
        raise TransferError("duplicate_entry_path")

    expected_files, file_count_limit, aggregate_limit = _kind_contract(kind)
    if len(entries) > file_count_limit:
        raise TransferError("file_count_limit")
    if frozenset(paths) != expected_files:
        raise TransferError(f"{kind}_file_set")
    total = 0
    for entry in entries:
        limit = _file_limit(kind, entry.path)
        if entry.size > limit:
            raise TransferError(f"file_size_limit:{entry.path}")
        total += entry.size
        if total > aggregate_limit:
            raise TransferError("aggregate_size_limit")

    aggregate = _sha256(value["aggregate_sha256"], "aggregate_sha256")
    if aggregate != framed_aggregate_sha256(entries):
        raise TransferError("aggregate_sha256_mismatch")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "run_id": run_id,
        "entries": [entry.as_dict() for entry in entries],
        "aggregate_sha256": aggregate,
        "lock_sha256": lock_sha256,
    }


def create_transfer_manifest(
    payload_root: Path | str,
    *,
    kind: str,
    run_id: str,
    lock_sha256: str,
) -> dict[str, object]:
    if kind not in {"runtime", "result"}:
        raise TransferError("manifest_kind")
    if not isinstance(run_id, str) or _ID.fullmatch(run_id) is None:
        raise TransferError("manifest_run_id")
    checked_lock = _sha256(lock_sha256, "lock_sha256")
    root_fd = _open_directory(Path(payload_root), "payload_root")
    try:
        entries = _collect_payload_fd(root_fd, kind)
    finally:
        os.close(root_fd)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "run_id": run_id,
        "entries": [entry.as_dict() for entry in entries],
        "aggregate_sha256": framed_aggregate_sha256(entries),
        "lock_sha256": checked_lock,
    }
    return validate_transfer_manifest(manifest)


def write_transfer_manifest(
    payload_root: Path | str,
    sidecar_path: Path | str,
    *,
    kind: str,
    run_id: str,
    lock_sha256: str,
) -> TransferSidecar:
    payload = _absolute(Path(payload_root))
    sidecar = _absolute(Path(sidecar_path))
    if sidecar == payload or payload in sidecar.parents:
        raise TransferError("sidecar_inside_payload")
    manifest = create_transfer_manifest(
        payload,
        kind=kind,
        run_id=run_id,
        lock_sha256=lock_sha256,
    )
    encoded = canonical_json_bytes(manifest)
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise TransferError("manifest_size_limit")
    digest = hashlib.sha256(encoded).hexdigest()
    _write_atomic_equal(sidecar, encoded)
    return TransferSidecar(path=sidecar, sha256=digest, manifest=manifest)


def load_transfer_manifest(
    sidecar_path: Path | str,
    expected_manifest_sha256: str,
) -> dict[str, object]:
    expected = _sha256(expected_manifest_sha256, "expected_manifest_sha256")
    sidecar = Path(sidecar_path)
    parent_fd = _open_directory(sidecar.parent, "sidecar_parent")
    try:
        encoded = _read_regular_at(
            parent_fd,
            sidecar.name,
            MAX_MANIFEST_BYTES,
            "sidecar",
        )
    finally:
        os.close(parent_fd)
    if hashlib.sha256(encoded).hexdigest() != expected:
        raise TransferError("sidecar_sha256_mismatch")
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransferError("sidecar_json") from error
    if canonical_json_bytes(value) != encoded:
        raise TransferError("sidecar_not_canonical")
    return validate_transfer_manifest(value)


def verify_transfer(
    payload_root: Path | str,
    sidecar_path: Path | str,
    expected_manifest_sha256: str,
    *,
    expected_kind: str | None = None,
    expected_run_id: str | None = None,
    expected_lock_sha256: str | None = None,
) -> dict[str, object]:
    manifest = load_transfer_manifest(sidecar_path, expected_manifest_sha256)
    _validate_expected_identity(
        manifest,
        expected_kind=expected_kind,
        expected_run_id=expected_run_id,
        expected_lock_sha256=expected_lock_sha256,
    )
    root_fd = _open_directory(Path(payload_root), "payload_root")
    try:
        _verify_payload_fd(root_fd, manifest)
    finally:
        os.close(root_fd)
    return manifest


def promote_verified_payload(
    staging_root: Path | str,
    destination_root: Path | str,
    sidecar_path: Path | str,
    expected_manifest_sha256: str,
    *,
    expected_kind: str | None = None,
    expected_run_id: str | None = None,
    expected_lock_sha256: str | None = None,
) -> PromotionResult:
    staging = _absolute(Path(staging_root))
    destination = _absolute(Path(destination_root))
    if staging == destination:
        raise TransferError("promotion_same_path")
    if staging.parent != destination.parent:
        raise TransferError("promotion_cross_directory")
    _safe_component(staging.name, "staging_name")
    _safe_component(destination.name, "destination_name")
    sidecar = _absolute(Path(sidecar_path))
    if sidecar == staging or staging in sidecar.parents:
        raise TransferError("sidecar_inside_payload")

    manifest = load_transfer_manifest(sidecar, expected_manifest_sha256)
    _validate_expected_identity(
        manifest,
        expected_kind=expected_kind,
        expected_run_id=expected_run_id,
        expected_lock_sha256=expected_lock_sha256,
    )

    parent_fd = _open_directory(staging.parent, "promotion_parent")
    lock_name = f".ds4bench-promote-{destination.name}.lock"
    lock_fd: int | None = None
    staging_fd: int | None = None
    try:
        lock_fd = _create_lock_at(parent_fd, lock_name)
        staging_fd = _open_directory_at(parent_fd, staging.name, "staging_root")
        _verify_payload_fd(staging_fd, manifest)
        staging_stat = os.fstat(staging_fd)
        try:
            destination_stat = os.stat(
                destination.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            destination_stat = None

        if destination_stat is not None:
            if not stat.S_ISDIR(destination_stat.st_mode):
                raise TransferError("destination_not_directory")
            destination_fd = _open_directory_at(
                parent_fd,
                destination.name,
                "destination_root",
            )
            try:
                _verify_payload_fd(destination_fd, manifest)
            finally:
                os.close(destination_fd)
            _remove_payload_at(parent_fd, staging.name, staging_fd, manifest)
            os.close(staging_fd)
            staging_fd = None
            _fsync_fd(parent_fd)
            return PromotionResult(
                path=destination,
                promoted=False,
                manifest_sha256=expected_manifest_sha256,
            )

        current = os.stat(staging.name, dir_fd=parent_fd, follow_symlinks=False)
        if _stat_identity(current) != _stat_identity(staging_stat):
            raise TransferError("staging_root_changed")
        os.rename(
            staging.name,
            destination.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        _fsync_fd(parent_fd)
        os.close(staging_fd)
        staging_fd = None
        return PromotionResult(
            path=destination,
            promoted=True,
            manifest_sha256=expected_manifest_sha256,
        )
    finally:
        if staging_fd is not None:
            os.close(staging_fd)
        if lock_fd is not None:
            os.close(lock_fd)
            try:
                os.unlink(lock_name, dir_fd=parent_fd)
                _fsync_fd(parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _collect_payload_fd(root_fd: int, kind: str) -> list[TransferEntry]:
    expected_files, file_count_limit, aggregate_limit = _kind_contract(kind)
    try:
        names = os.listdir(root_fd)
    except OSError as error:
        raise TransferError("payload_unreadable") from error
    if len(names) > file_count_limit:
        raise TransferError("file_count_limit")
    if any(not isinstance(name, str) or _PATH_COMPONENT.fullmatch(name) is None for name in names):
        raise TransferError("unsafe_payload_path")
    if frozenset(names) != expected_files:
        raise TransferError(f"{kind}_file_set")

    entries: list[TransferEntry] = []
    total = 0
    for name in sorted(names):
        size, digest = _hash_regular_at(root_fd, name, _file_limit(kind, name))
        total += size
        if total > aggregate_limit:
            raise TransferError("aggregate_size_limit")
        entries.append(TransferEntry(path=name, size=size, sha256=digest))
    return entries


def _verify_payload_fd(root_fd: int, manifest: Mapping[str, object]) -> None:
    kind = manifest["kind"]
    if not isinstance(kind, str):
        raise TransferError("manifest_kind")
    actual = _collect_payload_fd(root_fd, kind)
    expected = manifest["entries"]
    if [entry.as_dict() for entry in actual] != expected:
        raise TransferError("payload_manifest_mismatch")
    if framed_aggregate_sha256(actual) != manifest["aggregate_sha256"]:
        raise TransferError("payload_aggregate_mismatch")


def _validate_expected_identity(
    manifest: Mapping[str, object],
    *,
    expected_kind: str | None,
    expected_run_id: str | None,
    expected_lock_sha256: str | None,
) -> None:
    if expected_kind is not None and manifest["kind"] != expected_kind:
        raise TransferError("unexpected_manifest_kind")
    if expected_run_id is not None and manifest["run_id"] != expected_run_id:
        raise TransferError("unexpected_manifest_run_id")
    if expected_lock_sha256 is not None:
        checked = _sha256(expected_lock_sha256, "expected_lock_sha256")
        if manifest["lock_sha256"] != checked:
            raise TransferError("unexpected_lock_sha256")


def _kind_contract(kind: str) -> tuple[frozenset[str], int, int]:
    if kind == "runtime":
        return RUNTIME_FILES, MAX_RUNTIME_FILES, MAX_RUNTIME_BYTES
    if kind == "result":
        return RESULT_FILES, MAX_RESULT_FILES, MAX_RESULT_BYTES
    raise TransferError("manifest_kind")


def _file_limit(kind: str, path: str) -> int:
    if kind == "runtime":
        return MAX_RUNTIME_FILE_BYTES
    if kind == "result":
        try:
            return RESULT_FILE_LIMITS[path]
        except KeyError as error:
            raise TransferError("result_file_set") from error
    raise TransferError("manifest_kind")


def _safe_payload_path(value: object) -> str:
    if not isinstance(value, str):
        raise TransferError("unsafe_payload_path")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as error:
        raise TransferError("unsafe_payload_path") from error
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "//" in value
        or any(component in {"", ".", ".."} for component in value.split("/"))
        or any(_PATH_COMPONENT.fullmatch(component) is None for component in value.split("/"))
    ):
        raise TransferError("unsafe_payload_path")
    return value


def _safe_component(value: str, field: str) -> str:
    if _PATH_COMPONENT.fullmatch(value) is None or value in {".", ".."}:
        raise TransferError(f"unsafe_{field}")
    return value


def _safe_internal_component(value: str, field: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
        or len(value.encode("utf-8")) > 255
    ):
        raise TransferError(f"unsafe_{field}")
    return value


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise TransferError(f"invalid_{field}")
    return value


def _bounded_size(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
        raise TransferError(f"invalid_{field}")
    return value


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _open_directory(path: Path, field: str) -> int:
    absolute = _absolute(path)
    try:
        before = os.lstat(absolute)
    except OSError as error:
        raise TransferError(f"invalid_{field}") from error
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise TransferError(f"invalid_{field}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise TransferError(f"invalid_{field}") from error
    after = os.fstat(descriptor)
    if _stat_identity(before) != _stat_identity(after) or after.st_uid != os.getuid():
        os.close(descriptor)
        raise TransferError(f"invalid_{field}")
    return descriptor


def _open_directory_at(parent_fd: int, name: str, field: str) -> int:
    _safe_component(name, field)
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise TransferError(f"invalid_{field}") from error
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise TransferError(f"invalid_{field}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise TransferError(f"invalid_{field}") from error
    after = os.fstat(descriptor)
    if _stat_identity(before) != _stat_identity(after) or after.st_uid != os.getuid():
        os.close(descriptor)
        raise TransferError(f"invalid_{field}")
    return descriptor


def _hash_regular_at(root_fd: int, name: str, limit: int) -> tuple[int, str]:
    _safe_component(name, "payload_path")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        _validate_regular_stat(before, before, name, limit)
        descriptor = os.open(name, flags, dir_fd=root_fd)
    except OSError as error:
        raise TransferError(f"invalid_payload_file:{name}") from error
    try:
        opened = os.fstat(descriptor)
        _validate_regular_stat(before, opened, name, limit)
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, min(_HASH_CHUNK_BYTES, limit + 1 - observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > limit:
                raise TransferError(f"file_size_limit:{name}")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _stat_identity(opened, mutable=True) != _stat_identity(after, mutable=True):
            raise TransferError(f"payload_file_changed:{name}")
        if observed != opened.st_size:
            raise TransferError(f"payload_file_changed:{name}")
        return observed, digest.hexdigest()
    finally:
        os.close(descriptor)


def _read_regular_at(parent_fd: int, name: str, limit: int, field: str) -> bytes:
    _safe_component(name, field)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_regular_stat(before, before, name, limit)
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise TransferError(f"invalid_{field}") from error
    try:
        opened = os.fstat(descriptor)
        _validate_regular_stat(before, opened, name, limit)
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(_HASH_CHUNK_BYTES, limit + 1 - observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > limit:
                raise TransferError(f"{field}_size_limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if _stat_identity(opened, mutable=True) != _stat_identity(after, mutable=True):
            raise TransferError(f"{field}_changed")
        if observed != opened.st_size:
            raise TransferError(f"{field}_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_regular_stat(
    before: os.stat_result,
    opened: os.stat_result,
    name: str,
    limit: int,
) -> None:
    if _stat_identity(before) != _stat_identity(opened):
        raise TransferError(f"payload_file_changed:{name}")
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
        raise TransferError(f"invalid_payload_file:{name}")
    if opened.st_uid != os.getuid():
        raise TransferError(f"invalid_payload_owner:{name}")
    if opened.st_size > limit:
        raise TransferError(f"file_size_limit:{name}")


def _stat_identity(value: os.stat_result, *, mutable: bool = False) -> tuple[int, ...]:
    base = (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink)
    if mutable:
        return base + (value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    return base


def _write_atomic_equal(path: Path, payload: bytes) -> None:
    _safe_component(path.name, "sidecar_name")
    parent_fd = _open_directory(path.parent, "sidecar_parent")
    lock_name = f".{path.name}.lock"
    lock_fd: int | None = None
    temp_name = f".{path.name}.{os.getpid()}.tmp"
    temp_fd: int | None = None
    try:
        lock_fd = _create_lock_at(parent_fd, lock_name)
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            existing = _read_regular_at(parent_fd, path.name, MAX_MANIFEST_BYTES, "sidecar")
            if existing != payload:
                raise TransferError("sidecar_exists_different")
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        except OSError as error:
            raise TransferError("sidecar_temp_exists") from error
        _write_all(temp_fd, payload)
        os.fsync(temp_fd)
        os.fchmod(temp_fd, 0o644)
        os.close(temp_fd)
        temp_fd = None
        os.rename(temp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        _fsync_fd(parent_fd)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        if lock_fd is not None:
            os.close(lock_fd)
            try:
                os.unlink(lock_name, dir_fd=parent_fd)
                _fsync_fd(parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _create_lock_at(parent_fd: int, name: str) -> int:
    _safe_internal_component(name, "lock_name")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    except FileExistsError as error:
        raise TransferError("promotion_busy") from error
    except OSError as error:
        raise TransferError("lock_create_failed") from error
    os.fsync(descriptor)
    _fsync_fd(parent_fd)
    return descriptor


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise TransferError("short_write")
        view = view[written:]


def _remove_payload_at(
    parent_fd: int,
    name: str,
    root_fd: int,
    manifest: Mapping[str, object],
) -> None:
    entries = manifest["entries"]
    if not isinstance(entries, list):
        raise TransferError("manifest_entries")
    for entry in entries:
        if not isinstance(entry, dict):
            raise TransferError("manifest_entries")
        os.unlink(entry["path"], dir_fd=root_fd)
    os.rmdir(name, dir_fd=parent_fd)


def _fsync_fd(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise TransferError("fsync_failed") from error
