"""Frozen DS4 server metrics parsing and bounded telemetry collection."""

from __future__ import annotations

import asyncio
import math
import re
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping

import httpx

from .stats import SCHEMA_VERSION, TELEMETRY_METRICS, validate_telemetry

# These selectors are the complete subset of the frozen server's /metrics
# surface that has an honest representation in the result telemetry schema.
# Missing entries in this map are intentionally emitted as unavailable rather
# than inferred from neighboring counters.
_FROZEN_SERIES: dict[str, tuple[str, str]] = {
    "speculative_proposals_total": ("ds4_spec_drafts_total", "counter"),
    "speculative_accepted_tokens_total": ("ds4_spec_hits_total", "counter"),
    "quench_events_total": ("ds4_spec_quench_total", "counter"),
    "banks_live": ("ds4_banks_live", "gauge"),
    "prefill_tokens_total": (
        'ds4_tokens_prefilled_total{kind="computed"}',
        "counter",
    ),
    "generated_tokens_total": ("ds4_tokens_decoded_total", "counter"),
}
SERVER_METRICS = tuple(TELEMETRY_METRICS["server_metrics"])
_COUNTER_METRICS = frozenset(
    metric for metric, (_, kind) in _FROZEN_SERIES.items() if kind == "counter"
)
_SELECTOR_TO_METRIC = {selector: metric for metric, (selector, _) in _FROZEN_SERIES.items()}
_NUMBER_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_MAX_METRICS_BYTES = 1024 * 1024
_MAX_METRICS_LINES = 4096
_MAX_PERIODIC_RECORDS = 100_000


class MetricsError(ValueError):
    """A bounded failure while parsing or collecting frozen metrics."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class MetricsSnapshot:
    """One scrape, with only fixed allowlisted series retained."""

    timestamp_ns: int
    values: Mapping[str, float]
    scrape_available: bool = True

    def __post_init__(self) -> None:
        if (
            isinstance(self.timestamp_ns, bool)
            or not isinstance(self.timestamp_ns, int)
            or self.timestamp_ns < 0
        ):
            raise MetricsError("invalid_timestamp")
        if not isinstance(self.scrape_available, bool):
            raise MetricsError("invalid_scrape_status")
        checked: dict[str, int | float] = {}
        for metric, value in self.values.items():
            if metric not in _FROZEN_SERIES:
                raise MetricsError("unknown_metric")
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0
            ):
                raise MetricsError("invalid_metric_value")
            checked[metric] = value
        if not self.scrape_available and checked:
            raise MetricsError("unavailable_scrape_has_values")
        object.__setattr__(self, "values", MappingProxyType(checked))


@dataclass(frozen=True, slots=True)
class MetricsDelta:
    """Before/after counter deltas and the final value of allowlisted gauges."""

    timestamp_ns: int
    values: Mapping[str, float | None]

    def __post_init__(self) -> None:
        checked: dict[str, int | float | None] = {}
        if (
            isinstance(self.timestamp_ns, bool)
            or not isinstance(self.timestamp_ns, int)
            or self.timestamp_ns < 0
        ):
            raise MetricsError("invalid_timestamp")
        if set(self.values) != set(SERVER_METRICS):
            raise MetricsError("delta_metric_set")
        for metric in SERVER_METRICS:
            value = self.values[metric]
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0
            ):
                raise MetricsError("invalid_delta_value")
            checked[metric] = value
        object.__setattr__(self, "values", MappingProxyType(checked))


def parse_server_metrics(
    payload: str | bytes,
    *,
    timestamp_ns: int | None = None,
) -> MetricsSnapshot:
    """Parse only fixed, unlabeled or exactly-labeled frozen DS4 series."""

    if isinstance(payload, bytes):
        if len(payload) > _MAX_METRICS_BYTES:
            raise MetricsError("metrics_body_too_large")
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise MetricsError("metrics_invalid_utf8") from error
    elif isinstance(payload, str):
        if len(payload.encode("utf-8")) > _MAX_METRICS_BYTES:
            raise MetricsError("metrics_body_too_large")
        text = payload
    else:
        raise MetricsError("metrics_body_type")

    lines = text.splitlines()
    if len(lines) > _MAX_METRICS_LINES:
        raise MetricsError("metrics_too_many_lines")
    values: dict[str, int] = {}
    selected_names = frozenset(
        selector.partition("{")[0] for selector in _SELECTOR_TO_METRIC
    )
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        selector = fields[0]
        metric_name = selector.partition("{")[0]
        metric = _SELECTOR_TO_METRIC.get(selector)
        if metric is None:
            # A differently labeled known metric is not one of the frozen
            # selectors and must never be collapsed into an allowlisted row.
            if metric_name in selected_names and selector in selected_names:
                if len(fields) != 2:
                    raise MetricsError("malformed_selected_series")
            continue
        if len(fields) != 2 or _NUMBER_RE.fullmatch(fields[1]) is None:
            raise MetricsError("malformed_selected_series")
        value = int(fields[1])
        if metric in values:
            raise MetricsError("duplicate_selected_series")
        values[metric] = value

    observed_ns = time.monotonic_ns() if timestamp_ns is None else timestamp_ns
    return MetricsSnapshot(observed_ns, values)


def counter_deltas(before: MetricsSnapshot, after: MetricsSnapshot) -> MetricsDelta:
    """Compute nonnegative frozen counter deltas; resets remain unavailable."""

    if after.timestamp_ns < before.timestamp_ns:
        raise MetricsError("snapshot_order")
    values: dict[str, float | None] = {}
    for metric in SERVER_METRICS:
        if metric not in _FROZEN_SERIES:
            values[metric] = None
            continue
        after_value = after.values.get(metric) if after.scrape_available else None
        if metric not in _COUNTER_METRICS:
            values[metric] = after_value
            continue
        before_value = before.values.get(metric) if before.scrape_available else None
        if before_value is None or after_value is None or after_value < before_value:
            values[metric] = None
        else:
            values[metric] = after_value - before_value
    return MetricsDelta(after.timestamp_ns, values)


def snapshot_telemetry(
    snapshot: MetricsSnapshot,
    *,
    run_id: str,
    clock_domain: str,
) -> tuple[dict[str, object], ...]:
    """Represent one bounded periodic scrape, including honest unavailable rows."""

    values: Mapping[str, float | None] = {
        metric: snapshot.values.get(metric) if snapshot.scrape_available else None
        for metric in SERVER_METRICS
    }
    return _telemetry_records(
        values,
        timestamp_ns=snapshot.timestamp_ns,
        run_id=run_id,
        clock_domain=clock_domain,
    )


def delta_telemetry(
    delta: MetricsDelta,
    *,
    run_id: str,
    clock_domain: str,
) -> tuple[dict[str, object], ...]:
    """Represent before/after deltas without filling absent internal signals."""

    return _telemetry_records(
        delta.values,
        timestamp_ns=delta.timestamp_ns,
        run_id=run_id,
        clock_domain=clock_domain,
    )


def observed_execution(delta: MetricsDelta) -> dict[str, object]:
    """Build the exact metadata observation from counters actually exposed."""

    proposals = delta.values["speculative_proposals_total"]
    accepted = delta.values["speculative_accepted_tokens_total"]
    quench = delta.values["quench_events_total"]
    if proposals is None and accepted is None and quench is None:
        return {
            "status": "unavailable",
            "reason": "not_exposed_by_frozen_source",
        }
    return {
        "status": "available",
        "source": "metrics_delta",
        "speculative_steps": None,
        "plain_steps": None,
        "proposals": proposals,
        "verification_width_mean": None,
        "accepted_tokens": accepted,
        "quench_events": quench,
    }


def _telemetry_records(
    values: Mapping[str, float | None],
    *,
    timestamp_ns: int,
    run_id: str,
    clock_domain: str,
) -> tuple[dict[str, object], ...]:
    records: list[dict[str, object]] = []
    for metric in SERVER_METRICS:
        value = values.get(metric)
        item: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "timestamp_ns": timestamp_ns,
            "clock_domain": clock_domain,
            "source": "server_metrics",
            "metric": metric,
            "status": "available" if value is not None else "unavailable",
            "value": value,
            "unit": TELEMETRY_METRICS["server_metrics"][metric],
        }
        records.append(validate_telemetry(item, expected_run_id=run_id))
    return tuple(records)


class ServerMetricsSampler:
    """HTTP sampler whose periodic output is finite and schema-valid."""

    __slots__ = (
        "_client",
        "_clock",
        "_clock_domain",
        "_closed",
        "_interval_seconds",
        "_max_samples",
        "_metrics_url",
        "_owns_client",
        "_run_id",
    )

    def __init__(
        self,
        metrics_url: str,
        *,
        run_id: str,
        clock_domain: str,
        interval_seconds: float = 1.0,
        max_samples: int = 1024,
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if not isinstance(metrics_url, str) or not metrics_url:
            raise MetricsError("invalid_metrics_url")
        if (
            isinstance(interval_seconds, bool)
            or not isinstance(interval_seconds, (int, float))
            or not math.isfinite(float(interval_seconds))
            or float(interval_seconds) <= 0
        ):
            raise MetricsError("invalid_interval")
        maximum = _MAX_PERIODIC_RECORDS // len(SERVER_METRICS)
        if (
            isinstance(max_samples, bool)
            or not isinstance(max_samples, int)
            or not 1 <= max_samples <= maximum
        ):
            raise MetricsError("invalid_max_samples")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or float(timeout_seconds) <= 0
        ):
            raise MetricsError("invalid_timeout")
        if not callable(clock):
            raise MetricsError("invalid_clock")
        # Validate identity without retaining a fabricated telemetry item.
        _telemetry_records(
            {metric: None for metric in SERVER_METRICS},
            timestamp_ns=0,
            run_id=run_id,
            clock_domain=clock_domain,
        )
        self._metrics_url = metrics_url
        self._run_id = run_id
        self._clock_domain = clock_domain
        self._interval_seconds = float(interval_seconds)
        self._max_samples = max_samples
        self._clock = clock
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(float(timeout_seconds)), trust_env=False
        )
        self._closed = False

    async def __aenter__(self) -> ServerMetricsSampler:
        if self._closed:
            raise MetricsError("sampler_closed")
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            if self._owns_client:
                await self._client.aclose()

    async def snapshot(self) -> MetricsSnapshot:
        if self._closed:
            raise MetricsError("sampler_closed")
        timestamp_ns = self._clock()
        try:
            async with self._client.stream("GET", self._metrics_url) as response:
                if response.status_code != 200:
                    return MetricsSnapshot(
                        self._clock(), {}, scrape_available=False
                    )
                collected = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(collected) + len(chunk) > _MAX_METRICS_BYTES:
                        return MetricsSnapshot(
                            self._clock(), {}, scrape_available=False
                        )
                    collected.extend(chunk)
            timestamp_ns = self._clock()
            return parse_server_metrics(bytes(collected), timestamp_ns=timestamp_ns)
        except (httpx.HTTPError, MetricsError, UnicodeError):
            return MetricsSnapshot(timestamp_ns, {}, scrape_available=False)

    async def periodic(
        self, stop: asyncio.Event
    ) -> tuple[dict[str, object], ...]:
        if not isinstance(stop, asyncio.Event):
            raise MetricsError("invalid_stop_event")
        records: list[dict[str, object]] = []
        for _ in range(self._max_samples):
            if stop.is_set():
                break
            snapshot = await self.snapshot()
            records.extend(
                snapshot_telemetry(
                    snapshot,
                    run_id=self._run_id,
                    clock_domain=self._clock_domain,
                )
            )
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._interval_seconds)
            except TimeoutError:
                continue
            break
        return tuple(records)


__all__ = [
    "MetricsDelta",
    "MetricsError",
    "MetricsSnapshot",
    "SERVER_METRICS",
    "ServerMetricsSampler",
    "counter_deltas",
    "delta_telemetry",
    "observed_execution",
    "parse_server_metrics",
    "snapshot_telemetry",
]
