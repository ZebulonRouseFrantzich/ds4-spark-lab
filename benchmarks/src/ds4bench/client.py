"""Bounded asynchronous OpenAI chat streaming client."""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from .schema import Deadlines, Sampling, ScenarioRequest
from .sse import DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_EVENT_BYTES, SSEError, SSEParser
from .stats import (
    ERROR_CLASS_SET,
    FINISH_CLASSES,
    SCHEMA_VERSION,
    validate_request_sample,
)


DEFAULT_MAX_ERROR_BODY_BYTES = 16 * 1024
TIMING_GRANULARITY = "body_chunk"

ERROR_CLASSES = ERROR_CLASS_SET


@dataclass(frozen=True, slots=True)
class RequestSample:
    """The exact terminal raw record for one scheduled request."""

    schema_version: int
    scenario_run_id: str
    request_id: str
    repetition: int
    scheduled_offset_ns: int
    send_ns: int | None
    http_accept_ns: int | None
    first_byte_ns: int | None
    first_model_token_ns: int | None
    token_event_timestamps_ns: tuple[int, ...]
    itl_ns: tuple[int, ...]
    completion_ns: int | None
    status_code: int | None
    retry_count: int
    retry_after: str | None
    finish_class: str
    error_class: str | None
    redacted_error_body: str | None
    prompt_tokens: int | None
    generated_tokens: int | None
    output_budget_kind: str
    output_budget_value: int | None
    timing_granularity: str

    def to_dict(self) -> dict[str, object]:
        """Return a stats-validated canonical request representation."""

        value: dict[str, object] = {
            "schema_version": self.schema_version,
            "scenario_run_id": self.scenario_run_id,
            "request_id": self.request_id,
            "repetition": self.repetition,
            "scheduled_offset_ns": self.scheduled_offset_ns,
            "send_ns": self.send_ns,
            "http_accept_ns": self.http_accept_ns,
            "first_byte_ns": self.first_byte_ns,
            "first_model_token_ns": self.first_model_token_ns,
            "token_event_timestamps_ns": list(self.token_event_timestamps_ns),
            "itl_ns": list(self.itl_ns),
            "completion_ns": self.completion_ns,
            "status_code": self.status_code,
            "retry_count": self.retry_count,
            "retry_after": self.retry_after,
            "finish_class": self.finish_class,
            "error_class": self.error_class,
            "redacted_error_body": self.redacted_error_body,
            "prompt_tokens": self.prompt_tokens,
            "generated_tokens": self.generated_tokens,
            "output_budget_kind": self.output_budget_kind,
            "output_budget_value": self.output_budget_value,
            "timing_granularity": self.timing_granularity,
        }
        return validate_request_sample(value)


class RequestCancelled(asyncio.CancelledError):
    """Propagated cancellation carrying the request's terminal sample."""

    __slots__ = ("sample",)

    def __init__(self, sample: RequestSample) -> None:
        self.sample = sample
        super().__init__("request_cancelled")


class OpenAIChatClient:
    """One shared connection pool sized for a scenario's concurrency."""

    __slots__ = (
        "_closed",
        "_endpoint",
        "_http",
        "_max_body_bytes",
        "_max_error_body_bytes",
        "_max_event_bytes",
        "_overall_seconds",
        "pool_capacity",
    )

    def __init__(
        self,
        endpoint: str,
        *,
        concurrency: int,
        deadlines: Deadlines,
        headers: Mapping[str, str] | None = None,
        max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        max_error_body_bytes: int = DEFAULT_MAX_ERROR_BODY_BYTES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not isinstance(endpoint, str) or not endpoint:
            raise ValueError("endpoint")
        if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency < 1:
            raise ValueError("concurrency")
        connect_seconds = _positive_deadline(deadlines.connect_seconds, "connect_seconds")
        read_seconds = _positive_deadline(deadlines.read_seconds, "read_seconds")
        self._overall_seconds = _positive_deadline(
            deadlines.overall_seconds, "overall_seconds"
        )
        for value, field in (
            (max_event_bytes, "max_event_bytes"),
            (max_body_bytes, "max_body_bytes"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(field)
        if max_event_bytes > max_body_bytes:
            raise ValueError("max_event_bytes")
        if (
            isinstance(max_error_body_bytes, bool)
            or not isinstance(max_error_body_bytes, int)
            or max_error_body_bytes < 1
            or max_error_body_bytes > max_body_bytes
        ):
            raise ValueError("max_error_body_bytes")

        timeout = httpx.Timeout(
            connect=connect_seconds,
            read=read_seconds,
            write=connect_seconds,
            pool=connect_seconds,
        )
        limits = httpx.Limits(
            max_connections=concurrency,
            max_keepalive_connections=concurrency,
        )
        self._http = httpx.AsyncClient(
            headers=dict(headers) if headers is not None else None,
            limits=limits,
            timeout=timeout,
            transport=transport,
            trust_env=False,
        )
        self._endpoint = endpoint
        self.pool_capacity = concurrency
        self._max_event_bytes = max_event_bytes
        self._max_body_bytes = max_body_bytes
        self._max_error_body_bytes = max_error_body_bytes
        self._closed = False

    async def __aenter__(self) -> OpenAIChatClient:
        if self._closed:
            raise RuntimeError("client_closed")
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            await self._http.aclose()


@dataclass(slots=True)
class _SampleState:
    request: ScenarioRequest
    scenario_run_id: str
    repetition: int
    send_ns: int
    http_accept_ns: int | None = None
    first_byte_ns: int | None = None
    status_code: int | None = None
    retry_after: str | None = None
    prompt_tokens: int | None = None
    generated_tokens: int | None = None
    finish_reason: str | None = None
    token_timestamps: list[int] | None = None

    def __post_init__(self) -> None:
        self.token_timestamps = []

    def terminal(
        self,
        *,
        clock: Callable[[], int],
        finish_class: str,
        error_class: str | None,
        redacted_error_body: str | None = None,
    ) -> RequestSample:
        timestamps = tuple(self.token_timestamps or ())
        return RequestSample(
            schema_version=SCHEMA_VERSION,
            scenario_run_id=self.scenario_run_id,
            request_id=self.request.id,
            repetition=self.repetition,
            scheduled_offset_ns=self.request.start_offset_ms * 1_000_000,
            send_ns=self.send_ns,
            http_accept_ns=self.http_accept_ns,
            first_byte_ns=self.first_byte_ns,
            first_model_token_ns=timestamps[0] if timestamps else None,
            token_event_timestamps_ns=timestamps,
            itl_ns=tuple(b - a for a, b in zip(timestamps, timestamps[1:])),
            completion_ns=clock(),
            status_code=self.status_code,
            retry_count=0,
            retry_after=self.retry_after,
            finish_class=finish_class,
            error_class=error_class,
            redacted_error_body=redacted_error_body,
            prompt_tokens=self.prompt_tokens,
            generated_tokens=self.generated_tokens,
            output_budget_kind=self.request.output_budget.kind,
            output_budget_value=self.request.output_budget.tokens,
            timing_granularity=TIMING_GRANULARITY,
        )


class _ModelEventError(ValueError):
    pass


async def run_request(
    client: OpenAIChatClient,
    request: ScenarioRequest,
    *,
    scenario_run_id: str,
    repetition: int,
    prompt: str,
    model: str,
    sampling: Sampling,
    clock_domain: str,
    clock: Callable[[], int] = time.monotonic_ns,
    on_first_model_token: Callable[[int], None] | None = None,
) -> RequestSample:
    """Run one request, mapping every terminal path except cancellation to a sample.

    ``clock_domain`` is required and validated for the run metadata that owns
    the raw timestamps. External cancellation closes the streaming response
    through httpx's context manager and propagates as
    :class:`RequestCancelled`, which carries the cancellation sample for the
    owning runner.
    """

    _validate_pattern(scenario_run_id, "scenario_run_id", _ID_RE)
    _validate_pattern(clock_domain, "clock_domain", _CLOCK_DOMAIN_RE)
    if isinstance(repetition, bool) or not isinstance(repetition, int) or repetition < 0:
        raise ValueError("repetition")
    if not isinstance(prompt, str):
        raise ValueError("prompt")
    if not isinstance(model, str) or not model:
        raise ValueError("model")
    if on_first_model_token is not None and not callable(on_first_model_token):
        raise ValueError("on_first_model_token")
    if client._closed:
        raise RuntimeError("client_closed")

    payload: dict[str, object] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": sampling.temperature,
        "top_p": sampling.top_p,
        "seed": sampling.seed,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    if request.output_budget.kind == "explicit":
        payload["max_tokens"] = request.output_budget.tokens

    state = _SampleState(
        request=request,
        scenario_run_id=scenario_run_id,
        repetition=repetition,
        send_ns=clock(),
    )
    parser = SSEParser(
        max_event_bytes=client._max_event_bytes,
        max_body_bytes=client._max_body_bytes,
    )
    first_model_token_callback_scheduled = False

    try:
        async with asyncio.timeout(client._overall_seconds):
            async with client._http.stream(
                "POST", client._endpoint, json=payload
            ) as response:
                state.http_accept_ns = clock()
                state.status_code = response.status_code
                state.retry_after = _safe_retry_after(response.headers.get("retry-after"))

                if not 200 <= response.status_code < 300:
                    body = await _read_error_body(
                        response,
                        state=state,
                        clock=clock,
                        limit=client._max_error_body_bytes,
                    )
                    return state.terminal(
                        clock=clock,
                        finish_class="error",
                        error_class="http_error",
                        redacted_error_body=body,
                    )

                done = False
                async for chunk in response.aiter_bytes():
                    if not chunk:
                        continue
                    chunk_ns = clock()
                    if state.first_byte_ns is None:
                        state.first_byte_ns = chunk_ns
                    events = parser.feed(chunk)
                    for index, event in enumerate(events):
                        if event.data == "[DONE]":
                            if index != len(events) - 1:
                                raise SSEError("data_after_done")
                            done = True
                            break
                        observed_first_token = _consume_model_event(
                            event.data, state=state, timestamp_ns=chunk_ns
                        )
                        if (
                            observed_first_token
                            and not first_model_token_callback_scheduled
                            and on_first_model_token is not None
                        ):
                            _schedule_first_model_token_callback(
                                on_first_model_token, chunk_ns
                            )
                            first_model_token_callback_scheduled = True
                    if done:
                        # ``feed`` decodes the entire yielded chunk. Finalize now
                        # so a terminal marker cannot hide a partial UTF-8
                        # codepoint or an unterminated trailing event.
                        parser.finalize()
                        break

                if not done:
                    eof_ns = clock()
                    events = parser.finalize()
                    for index, event in enumerate(events):
                        if event.data == "[DONE]":
                            if index != len(events) - 1:
                                raise SSEError("data_after_done")
                            done = True
                            break
                        observed_first_token = _consume_model_event(
                            event.data, state=state, timestamp_ns=eof_ns
                        )
                        if (
                            observed_first_token
                            and not first_model_token_callback_scheduled
                            and on_first_model_token is not None
                        ):
                            _schedule_first_model_token_callback(
                                on_first_model_token, eof_ns
                            )
                            first_model_token_callback_scheduled = True
                if not done:
                    return state.terminal(
                        clock=clock,
                        finish_class="incomplete",
                        error_class=None,
                    )

                finish_class = _finish_class(state.finish_reason)
                if finish_class is None:
                    return state.terminal(
                        clock=clock, finish_class="error", error_class="malformed_sse"
                    )
                usage_error = (
                    "usage_unavailable"
                    if state.prompt_tokens is None or state.generated_tokens is None
                    else None
                )
                return state.terminal(
                    clock=clock,
                    finish_class=finish_class,
                    error_class=usage_error,
                )
    except asyncio.CancelledError:
        sample = state.terminal(
            clock=clock,
            finish_class="cancelled",
            error_class="cancelled",
        )
        raise RequestCancelled(sample) from None
    except TimeoutError:
        return state.terminal(
            clock=clock, finish_class="error", error_class="overall_timeout"
        )
    except httpx.ConnectTimeout:
        return state.terminal(
            clock=clock, finish_class="error", error_class="connect_timeout"
        )
    except httpx.ReadTimeout:
        return state.terminal(
            clock=clock, finish_class="error", error_class="read_timeout"
        )
    except (httpx.WriteTimeout, httpx.PoolTimeout):
        return state.terminal(
            clock=clock, finish_class="error", error_class="connection_error"
        )
    except (httpx.ConnectError, httpx.ReadError, httpx.WriteError):
        return state.terminal(
            clock=clock, finish_class="error", error_class="connection_error"
        )
    except httpx.ProtocolError:
        return state.terminal(
            clock=clock, finish_class="error", error_class="protocol_error"
        )
    except SSEError as exc:
        if exc.code == "invalid_utf8":
            error_class = "invalid_utf8"
        elif exc.code in {"body_too_large", "event_too_large"}:
            error_class = "body_too_large"
        else:
            error_class = "malformed_sse"
        return state.terminal(
            clock=clock, finish_class="error", error_class=error_class
        )
    except (json.JSONDecodeError, _ModelEventError):
        return state.terminal(
            clock=clock, finish_class="error", error_class="malformed_sse"
        )
    except Exception:
        return state.terminal(
            clock=clock, finish_class="error", error_class="protocol_error"
        )


async def settle_request(
    client: OpenAIChatClient,
    request: ScenarioRequest,
    *,
    scenario_run_id: str,
    repetition: int,
    prompt: str,
    model: str,
    sampling: Sampling,
    clock_domain: str,
    clock: Callable[[], int] = time.monotonic_ns,
    on_first_model_token: Callable[[int], None] | None = None,
) -> RequestSample:
    """Always settle cancellation to the one terminal sample carried with it."""

    try:
        return await run_request(
            client,
            request,
            scenario_run_id=scenario_run_id,
            repetition=repetition,
            prompt=prompt,
            model=model,
            sampling=sampling,
            clock_domain=clock_domain,
            clock=clock,
            on_first_model_token=on_first_model_token,
        )
    except RequestCancelled as exc:
        return exc.sample


async def _read_error_body(
    response: httpx.Response,
    *,
    state: _SampleState,
    clock: Callable[[], int],
    limit: int,
) -> str:
    collected = bytearray()
    truncated = False
    async for chunk in response.aiter_bytes():
        if not chunk:
            continue
        if state.first_byte_ns is None:
            state.first_byte_ns = clock()
        remaining = limit - len(collected)
        if remaining > 0:
            collected.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
            break
    return redact_error_body(bytes(collected), limit=limit, truncated=truncated)


def _consume_model_event(
    data: str, *, state: _SampleState, timestamp_ns: int
) -> bool:
    had_model_token = bool(state.token_timestamps)
    parsed = json.loads(data)
    if not isinstance(parsed, dict):
        raise _ModelEventError

    choices = parsed.get("choices")
    if choices is not None:
        if not isinstance(choices, list):
            raise _ModelEventError
        for choice in choices:
            if not isinstance(choice, dict):
                raise _ModelEventError
            delta = choice.get("delta")
            if delta is not None:
                if not isinstance(delta, dict):
                    raise _ModelEventError
                if _is_model_delta(delta):
                    assert state.token_timestamps is not None
                    state.token_timestamps.append(timestamp_ns)
            finish = choice.get("finish_reason")
            if finish is not None:
                if not isinstance(finish, str):
                    raise _ModelEventError
                if state.finish_reason is not None and state.finish_reason != finish:
                    raise _ModelEventError
                state.finish_reason = finish

    usage = parsed.get("usage")
    if usage is not None:
        if not isinstance(usage, dict):
            raise _ModelEventError
        prompt_tokens = _usage_count(usage, "prompt_tokens")
        completion_tokens = _usage_count(usage, "completion_tokens")
        if prompt_tokens is not None:
            if (
                state.prompt_tokens is not None
                and state.prompt_tokens != prompt_tokens
            ):
                raise _ModelEventError
            state.prompt_tokens = prompt_tokens
        if completion_tokens is not None:
            if (
                state.generated_tokens is not None
                and state.generated_tokens != completion_tokens
            ):
                raise _ModelEventError
            state.generated_tokens = completion_tokens
    return not had_model_token and bool(state.token_timestamps)


def _schedule_first_model_token_callback(
    callback: Callable[[int], None], timestamp_ns: int
) -> None:
    """Queue a failure-isolated observer without awaiting it in the stream."""

    asyncio.get_running_loop().call_soon(
        _invoke_first_model_token_callback, callback, timestamp_ns
    )


def _invoke_first_model_token_callback(
    callback: Callable[[int], None], timestamp_ns: int
) -> None:
    try:
        callback(timestamp_ns)
    except Exception:
        # Observability must never change or terminate the measured request.
        pass


def _is_model_delta(delta: dict[str, Any]) -> bool:
    observed = False
    for field in ("content", "reasoning_content"):
        value = delta.get(field)
        if value is not None and not isinstance(value, str):
            raise _ModelEventError
        observed = observed or bool(value)

    function_call = delta.get("function_call")
    if function_call is not None:
        if not isinstance(function_call, dict):
            raise _ModelEventError
        for field in ("name", "arguments"):
            value = function_call.get(field)
            if value is not None and not isinstance(value, str):
                raise _ModelEventError
        observed = observed or bool(function_call)

    tool_calls = delta.get("tool_calls")
    if tool_calls is None:
        return observed
    if not isinstance(tool_calls, list):
        raise _ModelEventError
    observed = observed or bool(tool_calls)
    for tool_call in tool_calls:
        if not isinstance(tool_call, dict):
            raise _ModelEventError
        function = tool_call.get("function")
        if function is None:
            continue
        if not isinstance(function, dict):
            raise _ModelEventError
        for field in ("name", "arguments"):
            value = function.get(field)
            if value is not None and not isinstance(value, str):
                raise _ModelEventError
    return observed


def _usage_count(usage: dict[str, Any], field: str) -> int | None:
    value = usage.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _ModelEventError
    return value


def _finish_class(reason: str | None) -> str | None:
    if reason in {"stop", "length", "tool_calls", "content_filter"}:
        return reason
    return None


def _positive_deadline(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(field)
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ValueError(field)
    return result


def _validate_pattern(
    value: object, field: str, pattern: re.Pattern[str]
) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(field)


def _safe_retry_after(value: str | None) -> str | None:
    if value is None or not value.isascii():
        return None
    if value.isdigit() and 1 <= len(value) <= 10:
        return value
    if _HTTP_DATE_RE.fullmatch(value) is not None:
        return value
    return None


_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_CLOCK_DOMAIN_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z", re.ASCII)


_HTTP_DATE_RE = re.compile(
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-3][0-9] "
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"[0-9]{4} [0-2][0-9]:[0-5][0-9]:[0-6][0-9] GMT"
)
_URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>]+")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_VALUE_RE = re.compile(
    r"(?i)([\"']?(?:authorization|api[-_]?key|access[-_]?token|token|password|secret)"
    r"[\"']?\s*[:=]\s*)(?:\"[^\"\r\n]*(?:\"|$)|'[^'\r\n]*(?:'|$)|[^\s,;}]+)"
)
_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?!/)[^\s\"'<>:,;}]+")
_IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")


def redact_error_body(body: bytes, *, limit: int, truncated: bool = False) -> str:
    """Decode, redact, and byte-bound an endpoint-native error body."""

    text = body.decode("utf-8", errors="replace")
    text = _URL_RE.sub("[REDACTED_URL]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _SECRET_VALUE_RE.sub(
        lambda match: f'{match.group(1)}"[REDACTED]"', text
    )
    text = _ABSOLUTE_PATH_RE.sub("[REDACTED_PATH]", text)
    text = _IPV4_RE.sub("[REDACTED_ADDRESS]", text)
    marker = "[TRUNCATED]" if truncated else ""
    return _bounded_utf8(text, limit=limit, marker=marker)


def _bounded_utf8(text: str, *, limit: int, marker: str) -> str:
    encoded = text.encode("utf-8")
    marker_bytes = marker.encode("ascii")
    if len(encoded) + len(marker_bytes) <= limit:
        return text + marker
    content_limit = max(0, limit - len(marker_bytes))
    bounded = encoded[:content_limit].decode("utf-8", errors="ignore")
    return bounded + marker_bytes[: limit - len(bounded.encode("utf-8"))].decode("ascii")
