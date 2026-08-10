from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
RAW_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "scenario_run_id",
        "request_id",
        "repetition",
        "scheduled_offset_ns",
        "send_ns",
        "http_accept_ns",
        "first_byte_ns",
        "first_model_token_ns",
        "token_event_timestamps_ns",
        "itl_ns",
        "completion_ns",
        "status_code",
        "retry_count",
        "retry_after",
        "finish_class",
        "error_class",
        "redacted_error_body",
        "prompt_tokens",
        "generated_tokens",
        "output_budget_kind",
        "output_budget_value",
        "timing_granularity",
    }
)
FINISH_CLASSES = frozenset(
    {"stop", "length", "tool_calls", "content_filter", "error", "incomplete", "cancelled"}
)
COMPLETED_FINISH_CLASSES = frozenset({"stop", "length", "tool_calls", "content_filter"})
ERROR_CLASSES = (
    "http_error",
    "connect_timeout",
    "read_timeout",
    "overall_timeout",
    "connection_error",
    "protocol_error",
    "malformed_sse",
    "invalid_utf8",
    "body_too_large",
    "missing_done",
    "cancelled",
    "usage_unavailable",
)
ERROR_CLASS_SET = frozenset(ERROR_CLASSES)
FAILURE_CLASSES = (*ERROR_CLASSES, "incomplete")
TELEMETRY_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "timestamp_ns",
        "clock_domain",
        "source",
        "metric",
        "status",
        "value",
        "unit",
    }
)
TELEMETRY_METRICS: dict[str, dict[str, str]] = {
    "server_metrics": {
        "speculative_steps_total": "count",
        "plain_steps_total": "count",
        "speculative_proposals_total": "tokens",
        "speculative_accepted_tokens_total": "tokens",
        "verification_width": "tokens",
        "quench_events_total": "count",
        "banks_live": "count",
        "graph_speculative_steps_total": "count",
        "graph_plain_steps_total": "count",
        "prefill_tokens_total": "tokens",
        "generated_tokens_total": "tokens",
    },
    "nvidia_smi": {
        "gpu_temperature": "celsius",
        "gpu_power": "watts",
        "gpu_memory_used": "bytes",
        "gpu_memory_total": "bytes",
        "gpu_utilization": "percent",
        "gpu_clock": "megahertz",
    },
}
_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_CLOCK = re.compile(r"\A[a-z][a-z0-9_-]{0,63}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


class StatisticsError(ValueError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise StatisticsError("non_canonical_json_value") from error


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def nearest_rank(values: Sequence[int | float], percentile: int | float) -> int | float | None:
    if not values:
        return None
    if isinstance(percentile, bool) or not isinstance(percentile, (int, float)):
        raise StatisticsError("invalid_percentile")
    if not math.isfinite(float(percentile)) or percentile <= 0 or percentile > 100:
        raise StatisticsError("invalid_percentile")
    checked = [_finite_number(value, "invalid_quantile_value") for value in values]
    ordered = sorted(checked)
    rank = max(1, math.ceil((float(percentile) / 100.0) * len(ordered)))
    return ordered[rank - 1]


def distribution(values: Sequence[int | float], *, total: int) -> dict[str, int | float | None]:
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise StatisticsError("invalid_distribution_total")
    checked = [_finite_number(value, "invalid_distribution_value") for value in values]
    ordered = sorted(checked)
    if not ordered:
        return {
            "median": None,
            "p50": None,
            "p95": None,
            "p99": None,
            "max": None,
            "count": 0,
            "total": total,
        }
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        median: int | float = ordered[midpoint]
    else:
        median = (ordered[midpoint - 1] + ordered[midpoint]) / 2
    return {
        "median": median,
        "p50": nearest_rank(ordered, 50),
        "p95": nearest_rank(ordered, 95),
        "p99": nearest_rank(ordered, 99),
        "max": ordered[-1],
        "count": len(ordered),
        "total": total,
    }


def validate_request_sample(value: object) -> dict[str, object]:
    sample = _exact_dict(value, RAW_REQUEST_FIELDS, "request_sample_fields")
    if sample["schema_version"] != SCHEMA_VERSION:
        raise StatisticsError("request_schema_version")
    _bounded_id(sample["scenario_run_id"], "scenario_run_id")
    _bounded_id(sample["request_id"], "request_id")
    _nonnegative_int(sample["repetition"], "repetition")
    _nonnegative_int(sample["scheduled_offset_ns"], "scheduled_offset_ns")
    for field in (
        "send_ns",
        "http_accept_ns",
        "first_byte_ns",
        "first_model_token_ns",
        "completion_ns",
    ):
        _optional_nonnegative_int(sample[field], field)
    timestamps = _int_list(sample["token_event_timestamps_ns"], "token_event_timestamps_ns")
    itls = _int_list(sample["itl_ns"], "itl_ns")
    if timestamps != sorted(timestamps):
        raise StatisticsError("nonmonotonic_token_timestamps")
    if len(itls) != max(0, len(timestamps) - 1):
        raise StatisticsError("itl_timestamp_count")
    if itls != [
        later - earlier
        for earlier, later in zip(timestamps, timestamps[1:])
    ]:
        raise StatisticsError("itl_timestamp_mismatch")
    first_model_token_ns = sample["first_model_token_ns"]
    if first_model_token_ns != (timestamps[0] if timestamps else None):
        raise StatisticsError("first_model_token_mismatch")
    send_ns = sample["send_ns"]
    observed_sequence = [
        sample["http_accept_ns"],
        sample["first_byte_ns"],
        first_model_token_ns,
        sample["completion_ns"],
    ]
    previous = send_ns
    for current in observed_sequence:
        if isinstance(current, int):
            if not isinstance(previous, int) or current < previous:
                raise StatisticsError("nonmonotonic_request_timestamps")
            previous = current
    if timestamps and (
        not isinstance(sample["first_byte_ns"], int)
        or not isinstance(sample["completion_ns"], int)
        or timestamps[-1] > sample["completion_ns"]
    ):
        raise StatisticsError("token_timestamp_bounds")
    if send_ns is None and (
        any(item is not None for item in observed_sequence)
        or timestamps
        or itls
    ):
        raise StatisticsError("timing_without_send")
    status_code = sample["status_code"]
    if status_code is not None and (
        not isinstance(status_code, int)
        or isinstance(status_code, bool)
        or status_code < 100
        or status_code > 599
    ):
        raise StatisticsError("invalid_status_code")
    if (status_code is None) != (sample["http_accept_ns"] is None):
        raise StatisticsError("http_accept_status_mismatch")
    if sample["first_byte_ns"] is not None and sample["http_accept_ns"] is None:
        raise StatisticsError("first_byte_without_http_accept")
    if sample["retry_count"] != 0:
        raise StatisticsError("automatic_retries_forbidden")
    retry_after = sample["retry_after"]
    if retry_after is not None and (
        not isinstance(retry_after, str)
        or not retry_after.isascii()
        or len(retry_after.encode("ascii")) > 256
    ):
        raise StatisticsError("invalid_retry_after")
    finish_class = sample["finish_class"]
    if finish_class not in FINISH_CLASSES:
        raise StatisticsError("invalid_finish_class")
    error_class = sample["error_class"]
    if error_class is not None and error_class not in ERROR_CLASS_SET:
        raise StatisticsError("invalid_error_class")
    if finish_class in COMPLETED_FINISH_CLASSES and error_class not in {
        None,
        "usage_unavailable",
    }:
        raise StatisticsError("completed_with_error")
    if finish_class == "incomplete" and error_class is not None:
        raise StatisticsError("incomplete_has_error_class")
    if finish_class == "cancelled" and error_class != "cancelled":
        raise StatisticsError("cancelled_error_class")
    if finish_class == "error" and (
        error_class is None or error_class in {"cancelled", "usage_unavailable"}
    ):
        raise StatisticsError("missing_error_class")
    if finish_class in COMPLETED_FINISH_CLASSES and sample["completion_ns"] is None:
        raise StatisticsError("completed_without_completion")
    body = sample["redacted_error_body"]
    if body is not None and (
        not isinstance(body, str) or len(body.encode("utf-8")) > 65536
    ):
        raise StatisticsError("invalid_redacted_error_body")
    _optional_nonnegative_int(sample["prompt_tokens"], "prompt_tokens")
    _optional_nonnegative_int(sample["generated_tokens"], "generated_tokens")
    budget_kind = sample["output_budget_kind"]
    budget_value = sample["output_budget_value"]
    if budget_kind == "explicit":
        if _positive_int(budget_value, "output_budget_value") is None:
            raise AssertionError("unreachable")
    elif budget_kind == "omitted":
        if budget_value is not None:
            raise StatisticsError("omitted_budget_has_value")
    else:
        raise StatisticsError("invalid_output_budget_kind")
    timing = sample["timing_granularity"]
    if timing not in {"body_chunk", "unavailable"}:
        raise StatisticsError("invalid_timing_granularity")
    if (timing == "unavailable") != (send_ns is None):
        raise StatisticsError("timing_granularity_mismatch")
    return sample


def validate_telemetry(value: object, *, expected_run_id: str | None = None) -> dict[str, object]:
    item = _exact_dict(value, TELEMETRY_FIELDS, "telemetry_fields")
    if item["schema_version"] != SCHEMA_VERSION:
        raise StatisticsError("telemetry_schema_version")
    run_id = _bounded_id(item["run_id"], "telemetry_run_id")
    if expected_run_id is not None and run_id != expected_run_id:
        raise StatisticsError("telemetry_run_id_mismatch")
    _nonnegative_int(item["timestamp_ns"], "telemetry_timestamp_ns")
    if not isinstance(item["clock_domain"], str) or _CLOCK.fullmatch(item["clock_domain"]) is None:
        raise StatisticsError("invalid_telemetry_clock")
    source = item["source"]
    if source not in TELEMETRY_METRICS:
        raise StatisticsError("invalid_telemetry_source")
    metric = item["metric"]
    if metric not in TELEMETRY_METRICS[source]:
        raise StatisticsError("invalid_telemetry_metric")
    if item["unit"] != TELEMETRY_METRICS[source][metric]:
        raise StatisticsError("invalid_telemetry_unit")
    if item["status"] == "available":
        _finite_number(item["value"], "invalid_telemetry_value")
    elif item["status"] == "unavailable":
        if item["value"] is not None:
            raise StatisticsError("unavailable_telemetry_has_value")
    else:
        raise StatisticsError("invalid_telemetry_status")
    return item


def compute_summary(
    metadata: Mapping[str, object],
    scenario: Mapping[str, object],
    requests: Iterable[Mapping[str, object]],
    telemetry: Iterable[Mapping[str, object]],
    *,
    requests_sha256: str,
    telemetry_sha256: str,
) -> dict[str, object]:
    run_id = _bounded_id(metadata.get("run_id"), "run_id")
    scenario_id = metadata.get("scenario_id")
    if scenario_id not in {"S1", "S2", "S3", "S5A", "S5B"}:
        raise StatisticsError("invalid_scenario_id")
    if scenario.get("id") != scenario_id:
        raise StatisticsError("scenario_id_mismatch")
    vantage = metadata.get("vantage")
    if vantage not in {"controller_lan", "target_local"}:
        raise StatisticsError("invalid_vantage")
    if scenario.get("vantage") != vantage:
        raise StatisticsError("vantage_mismatch")
    if metadata.get("result_state") not in {"success", "failed"}:
        raise StatisticsError("invalid_result_state")
    if _SHA256.fullmatch(requests_sha256) is None or _SHA256.fullmatch(telemetry_sha256) is None:
        raise StatisticsError("invalid_raw_hash")

    raw = [validate_request_sample(dict(item)) for item in requests]
    samples = [item for item in raw if item["scenario_run_id"] == run_id]
    if len(samples) != len(raw):
        raise StatisticsError("request_run_id_mismatch")
    telemetry_items = [
        validate_telemetry(dict(item), expected_run_id=run_id) for item in telemetry
    ]
    total = len(samples)
    completed = [item for item in samples if item["finish_class"] in COMPLETED_FINISH_CLASSES]
    incomplete = [item for item in samples if item["finish_class"] == "incomplete"]
    failed = [
        item for item in samples if item["finish_class"] in {"error", "cancelled"}
    ]

    ttft_values = [
        item["first_model_token_ns"] - item["send_ns"]
        for item in completed
        if isinstance(item["first_model_token_ns"], int) and isinstance(item["send_ns"], int)
    ]
    completion_values = [
        item["completion_ns"] - item["send_ns"]
        for item in completed
        if isinstance(item["completion_ns"], int) and isinstance(item["send_ns"], int)
    ]
    itl_values = [itl for item in completed for itl in item["itl_ns"]]
    itl_covered = sum(1 for item in completed if item["itl_ns"])
    wall_duration_ns = _wall_duration_ns(samples)

    generated_sum = _available_sum(samples, "generated_tokens")
    prompt_sum = _available_sum(samples, "prompt_tokens")
    throughput = {
        "generated_tokens_per_second": _per_second(generated_sum, wall_duration_ns),
        "prompt_tokens_observed_per_second": _per_second(prompt_sum, wall_duration_ns),
        "completed_requests_per_second": _per_second(len(completed), wall_duration_ns),
        "scheduled_requests_per_second": _per_second(total, wall_duration_ns),
    }
    failures = {failure_class: 0 for failure_class in FAILURE_CLASSES}
    for item in samples:
        failure_class = item["error_class"]
        if isinstance(failure_class, str):
            failures[failure_class] += 1
        elif item["finish_class"] == "incomplete":
            failures["incomplete"] += 1

    latency = {
        "ttft_ns": distribution(ttft_values, total=total),
        "itl_ns": distribution(itl_values, total=total),
        "completion_ns": distribution(completion_values, total=total),
    }
    counts = {
        "scheduled": total,
        "completed": len(completed),
        "failed": len(failed),
        "incomplete": len(incomplete),
        "retry_responses": sum(1 for item in samples if item["retry_after"] is not None),
        "latency": {
            "ttft": {"completed": len(ttft_values), "total": total},
            "itl": {"completed": itl_covered, "total": total},
            "completion": {"completed": len(completion_values), "total": total},
        },
    }
    scenario_metrics = _scenario_metrics(
        scenario_id, scenario, samples, telemetry_items, wall_duration_ns
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "scenario_id": scenario_id,
        "vantage": vantage,
        "result_state": metadata["result_state"],
        "raw_inputs": {
            "requests_jsonl_sha256": requests_sha256,
            "telemetry_jsonl_sha256": telemetry_sha256,
        },
        "counts": counts,
        "wall_duration_ns": wall_duration_ns,
        "throughput": throughput,
        "latency": latency,
        "failures": failures,
        "scenario_metrics": scenario_metrics,
        "configured_policy": metadata.get("configured_policy"),
        "observed_execution": metadata.get("observed_execution"),
    }


def render_summary_markdown(summary: Mapping[str, object]) -> bytes:
    """Canonical rendering: the canonical summary JSON is the sole input."""

    canonical = canonical_json_bytes(dict(summary)).decode("utf-8").rstrip("\n")
    return (
        "# ds4bench result summary\n\n"
        f"- Run: `{summary['run_id']}`\n"
        f"- Scenario: `{summary['scenario_id']}`\n"
        f"- Vantage: `{summary['vantage']}`\n"
        f"- State: `{summary['result_state']}`\n\n"
        "## Canonical summary\n\n"
        "```json\n"
        f"{canonical}\n"
        "```\n"
    ).encode("utf-8")


def _scenario_metrics(
    scenario_id: str,
    scenario: Mapping[str, object],
    samples: Sequence[dict[str, object]],
    telemetry: Sequence[dict[str, object]],
    wall_duration_ns: int,
) -> dict[str, object]:
    if scenario_id == "S1":
        rates: list[float] = []
        for item in samples:
            if item["finish_class"] not in COMPLETED_FINISH_CLASSES:
                continue
            generated = item["generated_tokens"]
            send_ns = item["send_ns"]
            completion_ns = item["completion_ns"]
            if (
                isinstance(generated, int)
                and isinstance(send_ns, int)
                and isinstance(completion_ns, int)
                and completion_ns > send_ns
            ):
                rates.append(generated * 1_000_000_000 / (completion_ns - send_ns))
        fairness = None
        if rates and sum(rate * rate for rate in rates) > 0:
            fairness = sum(rates) ** 2 / (len(rates) * sum(rate * rate for rate in rates))
        return {
            "kind": "S1",
            "completed_request_generated_tokens_per_second": distribution(
                rates, total=len(samples)
            ),
            "jain_fairness": fairness,
            "gpu_memory_peak_bytes": _telemetry_max(
                telemetry, "nvidia_smi", "gpu_memory_used"
            ),
            "banks_live_max": _telemetry_max(
                telemetry, "server_metrics", "banks_live"
            ),
        }
    if scenario_id == "S2":
        waits = [
            item["first_model_token_ns"] - item["send_ns"]
            for item in samples
            if item["finish_class"] in COMPLETED_FINISH_CLASSES
            and isinstance(item["first_model_token_ns"], int)
            and isinstance(item["send_ns"], int)
        ]
        completed_samples = [
            item for item in samples if item["finish_class"] in COMPLETED_FINISH_CLASSES
        ]
        completed_tokens = _available_sum(completed_samples, "generated_tokens")
        return {
            "kind": "S2",
            "workflow_duration_ns": wall_duration_ns,
            "completed_generated_token_goodput_per_second": _per_second(
                completed_tokens, wall_duration_ns
            ),
            "waiting_proxy_ns": distribution(waits, total=len(samples)),
        }
    if scenario_id == "S3":
        return _s3_metrics(scenario, samples)
    return _s5_metrics(scenario_id, scenario, samples)


def _s3_metrics(
    scenario: Mapping[str, object], samples: Sequence[dict[str, object]]
) -> dict[str, object]:
    request_specs = scenario.get("requests")
    if not isinstance(request_specs, list):
        raise StatisticsError("invalid_s3_requests")
    injected_ids = [
        item.get("id")
        for item in request_specs
        if isinstance(item, dict) and item.get("trigger") is not None
    ]
    if len(injected_ids) != 1:
        raise StatisticsError("invalid_s3_injection")
    injected = next((item for item in samples if item["request_id"] == injected_ids[0]), None)
    if injected is None or not isinstance(injected["send_ns"], int):
        return {
            "kind": "S3",
            "injection_ns": None,
            "injected_first_model_token_ns": None,
            "injected_completion_ns": None,
            "active_itl_before_ns": distribution([], total=len(samples)),
            "active_itl_during_ns": distribution([], total=len(samples)),
            "active_itl_after_ns": distribution([], total=len(samples)),
        }
    injection_ns = injected["send_ns"]
    injected_first = injected["first_model_token_ns"]
    before: list[int] = []
    during: list[int] = []
    after: list[int] = []
    for item in samples:
        if item is injected:
            continue
        first = item["first_model_token_ns"]
        completion = item["completion_ns"]
        if not isinstance(first, int) or first >= injection_ns:
            continue
        if isinstance(completion, int) and completion <= injection_ns:
            continue
        timestamps = item["token_event_timestamps_ns"]
        itls = item["itl_ns"]
        event_ends = timestamps[-len(itls) :] if itls else []
        for itl, event_end in zip(itls, event_ends, strict=True):
            if event_end < injection_ns:
                before.append(itl)
            elif isinstance(injected_first, int) and event_end < injected_first:
                during.append(itl)
            elif isinstance(injected_first, int):
                after.append(itl)
    total = max(0, len(samples) - 1)
    return {
        "kind": "S3",
        "injection_ns": injection_ns,
        "injected_first_model_token_ns": injected_first,
        "injected_completion_ns": injected["completion_ns"],
        "active_itl_before_ns": distribution(before, total=total),
        "active_itl_during_ns": distribution(during, total=total),
        "active_itl_after_ns": distribution(after, total=total),
    }


def _s5_metrics(
    scenario_id: str,
    scenario: Mapping[str, object],
    samples: Sequence[dict[str, object]],
) -> dict[str, object]:
    server = scenario.get("server")
    if not isinstance(server, dict):
        raise StatisticsError("invalid_s5_server")
    expected_kind = "explicit" if scenario_id == "S5A" else "omitted"
    configured_tokens = 512 if scenario_id == "S5A" else server.get("default_output_tokens")
    generated_values = [
        item["generated_tokens"] for item in samples if item["generated_tokens"] is not None
    ]
    generated_available = len(generated_values) == len(samples)
    outcome_counts = {finish: 0 for finish in sorted(FINISH_CLASSES)}
    for item in samples:
        outcome_counts[item["finish_class"]] += 1
    return {
        "kind": "S5",
        "variant": scenario_id,
        "output_budget": {
            "request_kind": expected_kind,
            "configured_tokens": configured_tokens,
        },
        "outcomes": outcome_counts,
        "usage": {
            "status": "available" if generated_available else "unavailable",
            "generated_tokens": sum(generated_values) if generated_available else None,
            "available_requests": len(generated_values),
            "total_requests": len(samples),
        },
    }


def _telemetry_max(
    telemetry: Sequence[dict[str, object]], source: str, metric: str
) -> dict[str, object]:
    values = [
        item["value"]
        for item in telemetry
        if item["source"] == source
        and item["metric"] == metric
        and item["status"] == "available"
    ]
    if not values:
        return {"status": "unavailable", "value": None}
    return {"status": "available", "value": max(values)}


def _wall_duration_ns(samples: Sequence[dict[str, object]]) -> int:
    sent = [item for item in samples if isinstance(item["send_ns"], int)]
    if not sent:
        return 0
    bases = [item["send_ns"] - item["scheduled_offset_ns"] for item in sent]
    start = min(bases)
    observed_ends: list[int] = []
    for item in samples:
        for field in (
            "completion_ns",
            "first_model_token_ns",
            "first_byte_ns",
            "http_accept_ns",
            "send_ns",
        ):
            value = item[field]
            if isinstance(value, int):
                observed_ends.append(value)
                break
        timestamps = item["token_event_timestamps_ns"]
        if timestamps:
            observed_ends.append(timestamps[-1])
    planned_end = start + max(item["scheduled_offset_ns"] for item in samples)
    return max(0, max([planned_end, *observed_ends]) - start)


def _available_sum(samples: Sequence[dict[str, object]], field: str) -> int | None:
    values = [item[field] for item in samples]
    if any(value is None for value in values):
        return None
    return sum(values)


def _per_second(value: int | float | None, duration_ns: int) -> float | None:
    if value is None or duration_ns <= 0:
        return None
    return value * 1_000_000_000 / duration_ns


def load_jsonl(path: Path, *, max_lines: int, max_bytes: int) -> list[dict[str, object]]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise StatisticsError("raw_input_unreadable") from error
    if size > max_bytes:
        raise StatisticsError("raw_input_too_large")
    output: list[dict[str, object]] = []
    with path.open("rb") as stream:
        for line_number, line in enumerate(stream, start=1):
            if line_number > max_lines:
                raise StatisticsError("raw_input_too_many_lines")
            if not line.endswith(b"\n") or not line.strip():
                raise StatisticsError("invalid_jsonl_framing")
            try:
                value = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise StatisticsError("invalid_jsonl") from error
            if canonical_json_bytes(value) != line:
                raise StatisticsError("noncanonical_jsonl")
            if not isinstance(value, dict):
                raise StatisticsError("jsonl_record_not_object")
            output.append(value)
    return output


def _exact_dict(value: object, fields: frozenset[str], code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise StatisticsError(code)
    return value


def _bounded_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise StatisticsError(f"invalid_{field}")
    return value


def _finite_number(value: object, code: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise StatisticsError(code)
    if not math.isfinite(float(value)):
        raise StatisticsError(code)
    return value


def _positive_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise StatisticsError(f"invalid_{field}")
    return value


def _nonnegative_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StatisticsError(f"invalid_{field}")
    return value


def _optional_nonnegative_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    return _nonnegative_int(value, field)


def _int_list(value: object, field: str) -> list[int]:
    if not isinstance(value, list):
        raise StatisticsError(f"invalid_{field}")
    return [_nonnegative_int(item, field) for item in value]
