from __future__ import annotations

import asyncio
import base64
import binascii
import json
import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Iterable, Mapping
from urllib.parse import quote, quote_plus

MAX_CANARY_BYTES = 4096
_REDACTION_LABEL = re.compile(r"\A[a-z][a-z0-9_-]{0,31}\Z")
_ERROR_CODE = re.compile(r"\A[a-z][a-z0-9_-]{0,63}\Z")

ERROR_CLASSES = frozenset(
    {
        "configuration",
        "scenario",
        "transport",
        "http",
        "timeout",
        "protocol",
        "cancelled",
        "harness",
        "cleanup",
        "incomplete",
        "unknown",
    }
)


class RedactionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ErrorRecord:
    error_class: str
    code: str

    def as_dict(self) -> dict[str, str]:
        return {"class": self.error_class, "code": self.code}


@dataclass(frozen=True, slots=True)
class CanarySet:
    """Explicit sensitive literals and their encoded representations."""

    replacements: tuple[tuple[str, str], ...]
    max_literal_length: int

    @classmethod
    def create(
        cls,
        *,
        lan_ip: str | None = None,
        lan_url: str | None = None,
        private_paths: Iterable[str | PurePath] = (),
        values: Iterable[tuple[str, str]] = (),
    ) -> CanarySet:
        labelled: list[tuple[str, str]] = []
        if lan_ip is not None:
            labelled.append(("lan-ip", lan_ip))
        if lan_url is not None:
            labelled.append(("lan-url", lan_url))
        labelled.extend(("private-path", str(path)) for path in private_paths)
        labelled.extend(values)

        variants: dict[str, str] = {}
        max_length = 0
        for label, value in labelled:
            if not isinstance(label, str) or _REDACTION_LABEL.fullmatch(label) is None:
                raise RedactionError("invalid_canary_label")
            if not isinstance(value, str) or not value or "\x00" in value:
                raise RedactionError("invalid_canary_value")
            raw = value.encode("utf-8")
            if len(raw) > MAX_CANARY_BYTES:
                raise RedactionError("canary_too_large")
            for variant in _encoded_variants(value):
                if variant:
                    variants.setdefault(variant, label)
                    max_length = max(max_length, len(variant.encode("utf-8")))

        # Longest-first keeps an IP nested in a URL from exposing the rest of
        # that URL through an earlier, shorter replacement.
        replacements = tuple(
            sorted(variants.items(), key=lambda item: (-len(item[0]), item[0], item[1]))
        )
        return cls(replacements=replacements, max_literal_length=max_length)

    def redact(self, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError("text must be str")
        result = text
        for literal, label in self.replacements:
            result = result.replace(literal, f"[REDACTED:{label}]")
        return result


def _encoded_variants(value: str) -> frozenset[str]:
    raw = value.encode("utf-8")
    variants = {
        value,
        quote(value, safe=""),
        quote_plus(value, safe=""),
        json.dumps(value, ensure_ascii=True)[1:-1],
        base64.b64encode(raw).decode("ascii"),
        base64.urlsafe_b64encode(raw).decode("ascii"),
        base64.b64encode(raw).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        binascii.hexlify(raw).decode("ascii"),
    }
    variants.update(
        variant.upper() for variant in tuple(variants) if "%" in variant
    )
    return frozenset(variants)


def redact_text(text: str, canaries: CanarySet, *, max_bytes: int) -> tuple[str, bool]:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("invalid_max_bytes")
    encoded = canaries.redact(text).encode("utf-8")
    if len(encoded) <= max_bytes:
        return encoded.decode("utf-8"), False
    retained = encoded[:max_bytes]
    while retained:
        try:
            return retained.decode("utf-8"), True
        except UnicodeDecodeError as error:
            retained = retained[: error.start]
    return "", True


def redact_structure(
    value: object,
    canaries: CanarySet,
    *,
    max_string_bytes: int = 65536,
) -> object:
    """Redact JSON values without stringifying exceptions or foreign objects."""

    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact_text(value, canaries, max_bytes=max_string_bytes)[0]
    if isinstance(value, (list, tuple)):
        return [
            redact_structure(item, canaries, max_string_bytes=max_string_bytes)
            for item in value
        ]
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise RedactionError("non_string_mapping_key")
            redacted_key = redact_text(key, canaries, max_bytes=max_string_bytes)[0]
            if redacted_key in output:
                raise RedactionError("redacted_key_collision")
            output[redacted_key] = redact_structure(
                item, canaries, max_string_bytes=max_string_bytes
            )
        return output
    raise RedactionError("non_json_value")


def error_record(
    error: BaseException | type[BaseException],
    *,
    code: str,
    phase: str | None = None,
) -> dict[str, str]:
    """Map an exception by type only; its message is never read or copied."""

    if not isinstance(code, str) or _ERROR_CODE.fullmatch(code) is None:
        raise RedactionError("invalid_error_code")
    error_type = error if isinstance(error, type) else type(error)
    if not issubclass(error_type, BaseException):
        raise TypeError("error must be an exception or exception type")

    if issubclass(error_type, asyncio.CancelledError):
        error_class = "cancelled"
    elif issubclass(error_type, TimeoutError):
        error_class = "timeout"
    elif issubclass(error_type, (ConnectionError, BrokenPipeError)):
        error_class = "transport"
    elif issubclass(error_type, (UnicodeError, json.JSONDecodeError)):
        error_class = "protocol"
    elif issubclass(error_type, (ValueError, TypeError, KeyError)):
        error_class = "configuration"
    else:
        error_class = "unknown"

    if phase is not None:
        if phase not in ERROR_CLASSES:
            raise RedactionError("invalid_error_phase")
        error_class = phase
    return ErrorRecord(error_class=error_class, code=code).as_dict()


def validate_error_record(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"class", "code"}:
        raise RedactionError("invalid_error_record")
    error_class = value.get("class")
    code = value.get("code")
    if error_class not in ERROR_CLASSES:
        raise RedactionError("invalid_error_class")
    if not isinstance(code, str) or _ERROR_CODE.fullmatch(code) is None:
        raise RedactionError("invalid_error_code")
    return {"class": error_class, "code": code}


class BoundedRedactedLog:
    """Bounded, chunk-boundary-safe producer-side log redaction."""

    __slots__ = ("_canaries", "_max_bytes", "_retained", "_total_bytes")

    def __init__(self, canaries: CanarySet, *, max_bytes: int) -> None:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            raise ValueError("invalid_max_bytes")
        self._canaries = canaries
        self._max_bytes = max_bytes
        self._retained = bytearray()
        self._total_bytes = 0

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    def write(self, chunk: str | bytes) -> None:
        if isinstance(chunk, str):
            payload = chunk.encode("utf-8", errors="replace")
        elif isinstance(chunk, bytes):
            payload = chunk
        else:
            raise TypeError("log chunk must be str or bytes")
        self._total_bytes += len(payload)
        source_ceiling = self._max_bytes + self._canaries.max_literal_length
        if len(self._retained) < source_ceiling:
            remaining = source_ceiling - len(self._retained)
            self._retained.extend(payload[:remaining])

    def finish(self) -> tuple[bytes, dict[str, int | bool | None]]:
        source = self._retained.decode("utf-8", errors="replace")
        text, redaction_truncated = redact_text(
            source, self._canaries, max_bytes=self._max_bytes
        )
        payload = text.encode("utf-8")
        truncated = redaction_truncated or self._total_bytes > len(self._retained)
        return payload, {
            "retained_bytes": len(payload),
            "truncated": truncated,
            "total_bytes": self._total_bytes,
        }
