"""Incremental, bounded parsing for UTF-8 server-sent events."""

from __future__ import annotations

import codecs
from dataclasses import dataclass


DEFAULT_MAX_EVENT_BYTES = 1 << 20
DEFAULT_MAX_BODY_BYTES = 64 << 20


class SSEError(ValueError):
    """A bounded, input-independent SSE failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SSEEvent:
    """One event dispatched by an SSE blank line."""

    data: str
    event: str = "message"
    id: str | None = None
    retry: int | None = None


class SSEParser:
    """Parse arbitrary byte chunks using a strict incremental UTF-8 decoder.

    Event and body limits count content-decoded response bytes.  An event is
    dispatched only by an LF or CRLF blank line; EOF never silently completes a
    partial event.
    """

    __slots__ = (
        "_body_bytes",
        "_data_lines",
        "_decoder",
        "_event_bytes",
        "_event_id",
        "_event_name",
        "_failed",
        "_finished",
        "_last_event_id",
        "_line_parts",
        "_max_body_bytes",
        "_max_event_bytes",
        "_retry",
    )

    def __init__(
        self,
        *,
        max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ) -> None:
        if (
            isinstance(max_event_bytes, bool)
            or not isinstance(max_event_bytes, int)
            or max_event_bytes <= 0
        ):
            raise ValueError("max_event_bytes")
        if (
            isinstance(max_body_bytes, bool)
            or not isinstance(max_body_bytes, int)
            or max_body_bytes <= 0
        ):
            raise ValueError("max_body_bytes")
        if max_event_bytes > max_body_bytes:
            raise ValueError("max_event_bytes")

        self._max_event_bytes = max_event_bytes
        self._max_body_bytes = max_body_bytes
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
        self._body_bytes = 0
        self._event_bytes = 0
        self._line_parts: list[str] = []
        self._data_lines: list[str] = []
        self._event_name: str | None = None
        self._event_id: str | None = None
        self._last_event_id: str | None = None
        self._retry: int | None = None
        self._finished = False
        self._failed = False

    @property
    def body_bytes(self) -> int:
        return self._body_bytes

    def feed(self, chunk: bytes) -> tuple[SSEEvent, ...]:
        """Consume one bytes object and return every newly dispatched event."""

        if self._failed:
            raise SSEError("parser_failed")
        if self._finished:
            raise SSEError("parser_finished")
        if not isinstance(chunk, bytes):
            raise TypeError("chunk must be bytes")
        if not chunk:
            return ()

        self._body_bytes += len(chunk)
        if self._body_bytes > self._max_body_bytes:
            self._raise("body_too_large")

        try:
            text = self._decoder.decode(chunk, final=False)
        except UnicodeDecodeError:
            self._raise("invalid_utf8")

        events = self._process_text(text)
        pending, _ = self._decoder.getstate()
        if self._event_bytes + len(pending) > self._max_event_bytes:
            self._raise("event_too_large")
        return tuple(events)

    def finalize(self) -> tuple[SSEEvent, ...]:
        """Validate EOF and reject any event lacking its terminating blank line."""

        if self._failed:
            raise SSEError("parser_failed")
        if self._finished:
            return ()
        try:
            text = self._decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            self._raise("invalid_utf8")
        events = self._process_text(text)
        if self._line_parts or self._event_bytes or self._has_event_fields():
            self._raise("unterminated_event")
        self._finished = True
        return tuple(events)

    def _process_text(self, text: str) -> list[SSEEvent]:
        events: list[SSEEvent] = []
        start = 0
        while True:
            newline = text.find("\n", start)
            if newline < 0:
                tail = text[start:]
                if tail:
                    self._add_event_bytes(len(tail.encode("utf-8")))
                    self._line_parts.append(tail)
                return events

            part = text[start:newline]
            self._add_event_bytes(len(part.encode("utf-8")) + 1)
            self._line_parts.append(part)
            line = "".join(self._line_parts)
            self._line_parts.clear()
            if line.endswith("\r"):
                line = line[:-1]
            event = self._process_line(line)
            if event is not None:
                events.append(event)
            start = newline + 1

    def _process_line(self, line: str) -> SSEEvent | None:
        if line == "":
            event = self._dispatch()
            self._event_bytes = 0
            return event
        if line.startswith(":"):
            return None

        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "data":
            self._data_lines.append(value)
        elif field == "event":
            self._event_name = value
        elif field == "id" and "\x00" not in value:
            self._event_id = value
        elif (
            field == "retry"
            and value.isascii()
            and value.isdigit()
            and len(value) <= 19
        ):
            self._retry = int(value)
        return None

    def _dispatch(self) -> SSEEvent | None:
        if not self._data_lines:
            self._reset_event_fields()
            return None

        if self._event_id is not None:
            self._last_event_id = self._event_id
        event = SSEEvent(
            data="\n".join(self._data_lines),
            event=self._event_name or "message",
            id=self._last_event_id,
            retry=self._retry,
        )
        self._reset_event_fields()
        return event

    def _reset_event_fields(self) -> None:
        self._data_lines.clear()
        self._event_name = None
        self._event_id = None
        self._retry = None

    def _has_event_fields(self) -> bool:
        return bool(
            self._data_lines
            or self._event_name is not None
            or self._event_id is not None
            or self._retry is not None
        )

    def _add_event_bytes(self, count: int) -> None:
        self._event_bytes += count
        if self._event_bytes > self._max_event_bytes:
            self._raise("event_too_large")

    def _raise(self, code: str) -> None:
        self._failed = True
        raise SSEError(code)
