"""Private-safe primitives shared by the target controller.

This module deliberately turns all malformed external input into stable, generic
``TargetError`` instances.  Callers can report those errors without accidentally
including configuration or target-owned values in logs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = 1
PROTOCOL_VERSION = 1


class TargetError(Exception):
    """An error whose public text is explicitly safe to show to an operator."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: str, safe_message: str) -> None:
        self.code = code
        self.safe_message = safe_message
        super().__init__(f"{code}: {safe_message}")


def _error(code: str, message: str) -> TargetError:
    return TargetError(code, message)


def _normalise_json(value: Any) -> Any:
    """Accept only JSON values and reject non-finite or non-string-key objects."""

    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise _error("json_invalid", "JSON value is invalid")
        return value
    if isinstance(value, (list, tuple)):
        return [_normalise_json(item) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise _error("json_invalid", "JSON object is invalid")
            result[key] = _normalise_json(item)
        return result
    raise _error("json_invalid", "JSON value is invalid")


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON for a strictly JSON-compatible value."""

    try:
        return json.dumps(
            _normalise_json(value),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except TargetError:
        raise
    except (TypeError, ValueError, UnicodeError):
        raise _error("json_invalid", "JSON value is invalid") from None


def length_frame(*parts: bytes | bytearray | memoryview | str) -> bytes:
    """Encode a sequence unambiguously using eight-byte big-endian lengths."""

    framed = bytearray()
    for part in parts:
        if isinstance(part, str):
            raw = part.encode("utf-8")
        elif isinstance(part, (bytes, bytearray, memoryview)):
            raw = bytes(part)
        else:
            raise _error("hash_input_invalid", "hash input is invalid")
        framed.extend(len(raw).to_bytes(8, "big"))
        framed.extend(raw)
    return bytes(framed)


def sha256_framed(*parts: bytes | bytearray | memoryview | str) -> str:
    """Return the SHA-256 hex digest of a length-framed sequence."""

    return hashlib.sha256(length_frame(*parts)).hexdigest()


def record_id_for(value: Any) -> str:
    """Create a domain-separated deterministic record identifier.

    A record's stored ``record_id`` field, if present, is intentionally excluded
    so the ID can be recomputed from its remaining canonical content.
    """

    normalised = _normalise_json(value)
    if isinstance(normalised, dict):
        normalised = dict(normalised)
        normalised.pop("record_id", None)
    return sha256_framed("targetctl.record.v1", canonical_json_bytes(normalised))

# Short, explicit aliases used by record-producing modules.
hash_framed = sha256_framed
record_id = record_id_for


@dataclass(frozen=True, slots=True)
class RecordBase:
    """The common, privacy-safe envelope used by later artifact records."""

    schema: int
    record_id: str
    created_at: str
    operation: str
    target_name: str
    parent_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "record_id": self.record_id,
            "created_at": self.created_at,
            "operation": self.operation,
            "target_name": self.target_name,
            "parent_ids": list(self.parent_ids),
        }


def validate_object_keys(
    value: Any,
    *,
    allowed: Iterable[str],
    required: Iterable[str] = (),
) -> dict[str, Any]:
    """Check a JSON object has exactly permitted keys without naming bad input."""

    if not isinstance(value, dict):
        raise _error("schema_invalid", "object schema is invalid")
    allowed_set = frozenset(allowed)
    required_set = frozenset(required)
    if not required_set.issubset(allowed_set):
        raise _error("schema_invalid", "object schema is invalid")
    keys = frozenset(value)
    if not keys.issubset(allowed_set) or not required_set.issubset(keys):
        raise _error("schema_fields_invalid", "object fields are invalid")
    return value


def _open_parent_dir(path: Path) -> tuple[int, str]:
    """Open the parent through non-symlink directory components."""

    if path.name in ("", ".", ".."):
        raise _error("json_path_invalid", "JSON path is invalid")
    parent = path.parent
    fd = -1
    try:
        if parent.is_absolute():
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            parts = parent.parts[1:]
        else:
            fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            parts = parent.parts
        for component in parts:
            if component in ("", "."):
                continue
            if component == "..":
                raise _error("json_path_invalid", "JSON path is invalid")
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
        return fd, path.name
    except TargetError:
        if fd >= 0:
            os.close(fd)
        raise
    except OSError:
        if fd >= 0:
            os.close(fd)
        raise _error("json_path_invalid", "JSON path is unavailable") from None


def _check_existing_regular(dir_fd: int, name: str) -> None:
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise _error("json_path_invalid", "JSON path is unavailable") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise _error("json_path_unsafe", "JSON destination is unsafe")


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _error("json_invalid", "JSON object is invalid")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except TargetError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _error("json_invalid", "JSON document is invalid") from None
    if not isinstance(parsed, dict):
        raise _error("json_invalid", "JSON document is invalid")
    return _normalise_json(parsed)


def read_json_file(
    path: str | os.PathLike[str],
    *,
    allowed_keys: Iterable[str] | None = None,
    required_keys: Iterable[str] = (),
    max_bytes: int = 1_048_576,
) -> dict[str, Any]:
    """Read a bounded regular JSON object without following its final symlink."""

    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise _error("json_limit_invalid", "JSON size limit is invalid")
    required_tuple = tuple(required_keys)
    dir_fd, name = _open_parent_dir(Path(path))
    try:
        _check_existing_regular(dir_fd, name)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError:
            raise _error("json_read_failed", "JSON document is unavailable") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise _error("json_path_unsafe", "JSON source is unsafe")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(fd, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)
    if len(raw) > max_bytes:
        raise _error("json_too_large", "JSON document exceeds its size limit")
    value = _strict_json_object(raw)
    if allowed_keys is not None:
        validate_object_keys(value, allowed=allowed_keys, required=required_tuple)
    elif required_tuple:
        validate_object_keys(value, allowed=value.keys(), required=required_tuple)
    return value


def write_json_atomic(
    path: str | os.PathLike[str],
    value: Any,
    *,
    allowed_keys: Iterable[str] | None = None,
    required_keys: Iterable[str] = (),
    mode: int = 0o600,
) -> None:
    """Atomically replace a regular JSON file through a no-follow parent path."""

    if not isinstance(mode, int) or mode & ~0o777:
        raise _error("json_mode_invalid", "JSON mode is invalid")
    required_tuple = tuple(required_keys)
    normalised = _normalise_json(value)
    if not isinstance(normalised, dict):
        raise _error("json_invalid", "JSON document is invalid")
    if allowed_keys is not None:
        validate_object_keys(normalised, allowed=allowed_keys, required=required_tuple)
    elif required_tuple:
        validate_object_keys(normalised, allowed=normalised.keys(), required=required_tuple)
    payload = canonical_json_bytes(normalised) + b"\n"
    dir_fd, name = _open_parent_dir(Path(path))
    temp_name: str | None = None
    temp_fd: int | None = None
    try:
        _check_existing_regular(dir_fd, name)
        # The directory descriptor avoids a check-then-use path traversal.
        for _ in range(128):
            candidate = f".targetctl-{secrets.token_hex(16)}.json.tmp"
            try:
                temp_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    mode,
                    dir_fd=dir_fd,
                )
                temp_name = candidate
                break
            except FileExistsError:
                continue
        if temp_fd is None:
            raise _error("json_write_failed", "JSON document could not be written")
        os.fchmod(temp_fd, mode)
        view = memoryview(payload)
        while view:
            written = os.write(temp_fd, view)
            view = view[written:]
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None
        # Rename replaces the symlink itself rather than following it.  The
        # pre-check above additionally rejects a symlink destination outright.
        _check_existing_regular(dir_fd, name)
        os.replace(temp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except TargetError:
        raise
    except OSError:
        raise _error("json_write_failed", "JSON document could not be written") from None
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        os.close(dir_fd)
