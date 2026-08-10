from __future__ import annotations

import json
import math
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Mapping

from .redaction import (
    BoundedRedactedLog,
    CanarySet,
    RedactionError,
    redact_text,
    validate_error_record,
)
from .stats import (
    COMPLETED_FINISH_CLASSES,
    RAW_REQUEST_FIELDS,
    SCHEMA_VERSION,
    StatisticsError,
    canonical_json_bytes,
    compute_summary,
    load_jsonl,
    render_summary_markdown,
    sha256_bytes,
    validate_request_sample,
    validate_telemetry,
)

RESULT_FILES = frozenset(
    {
        "metadata.json",
        "scenario.json",
        "source-manifest.json",
        "requests.jsonl",
        "server.log",
        "client.log",
        "telemetry.jsonl",
        "summary.json",
        "summary.md",
    }
)
RESULT_FILE_LIMITS = {
    "requests.jsonl": 128 * 1024 * 1024,
    "telemetry.jsonl": 64 * 1024 * 1024,
    "server.log": 1024 * 1024,
    "client.log": 1024 * 1024,
    "metadata.json": 8 * 1024 * 1024,
    "scenario.json": 8 * 1024 * 1024,
    "source-manifest.json": 8 * 1024 * 1024,
    "summary.json": 8 * 1024 * 1024,
    "summary.md": 8 * 1024 * 1024,
}
MAX_RESULT_BYTES = 256 * 1024 * 1024
MAX_TELEMETRY_LINES = 100_000
_METADATA_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "result_state",
        "scenario_id",
        "scenario_sha256",
        "prompt_manifest_sha256",
        "source_manifest_sha256",
        "vantage",
        "clock_domain",
        "started_utc",
        "completed_utc",
        "configured_policy",
        "observed_execution",
        "network",
        "warmup_repetitions",
        "measured_repetitions",
        "pairing",
        "runtime_bundle",
        "logs",
        "primary_error",
        "cleanup_error",
    }
)
_WRITER_FIELDS = frozenset(
    {
        "result_state",
        "scenario_sha256",
        "source_manifest_sha256",
        "completed_utc",
        "logs",
        "primary_error",
        "cleanup_error",
    }
)
_SCENARIO_FIELDS = frozenset(
    {
        "version",
        "id",
        "description",
        "vantage",
        "server",
        "prompts",
        "requests",
        "schedule",
        "sampling",
        "warmup_repetitions",
        "measured_repetitions",
        "deadlines",
        "preconditions",
    }
)
_SOURCE_FIELDS = frozenset(
    {
        "schema_version",
        "lab",
        "engine",
        "integration",
        "userspace",
        "controller",
        "target",
        "build",
        "weights",
    }
)
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SAFE_TEXT = re.compile(r"\A[\x20-\x7e]{1,256}\Z")
_UTC_TIME = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")


class ArtifactError(ValueError):
    pass


class ResultWriter:
    """Staging-first exact result-bundle producer.

    One result is one case/repetition, so scheduled request IDs are unique within
    the writer. Raw samples are appended as they settle and the raw streams are
    fsynced before summary computation starts.
    """

    def __init__(
        self,
        root: Path | str,
        metadata: Mapping[str, object],
        normalized_scenario: Mapping[str, object],
        source_manifest: Mapping[str, object],
        scheduled_ids: Iterable[str],
        *,
        canaries: CanarySet | None = None,
        log_limit_bytes: int = 1024 * 1024,
    ) -> None:
        self._root = Path(root)
        if (
            not isinstance(log_limit_bytes, int)
            or isinstance(log_limit_bytes, bool)
            or not 1 <= log_limit_bytes <= RESULT_FILE_LIMITS["server.log"]
        ):
            raise ArtifactError("invalid_log_limit")
        self._metadata_input = dict(metadata)
        self._scenario = dict(normalized_scenario)
        self._source_manifest = dict(source_manifest)
        validate_normalized_scenario(self._scenario)
        validate_source_manifest(self._source_manifest)
        self._run_id = _bounded_id(self._metadata_input.get("run_id"), "run_id")
        if self._scenario.get("id") != self._metadata_input.get("scenario_id"):
            raise ArtifactError("scenario_id_mismatch")
        if self._scenario.get("vantage") != self._metadata_input.get("vantage"):
            raise ArtifactError("vantage_mismatch")
        self._scheduled = tuple(scheduled_ids)
        if not self._scheduled or len(set(self._scheduled)) != len(self._scheduled):
            raise ArtifactError("invalid_scheduled_ids")
        scenario_requests = {
            item["id"]: item for item in self._scenario["requests"]
        }
        if any(
            not isinstance(request_id, str)
            or request_id not in scenario_requests
            for request_id in self._scheduled
        ):
            raise ArtifactError("unknown_scheduled_id")
        scheduled_set = set(self._scheduled)
        if not any(
            set(case["request_ids"]) == scheduled_set
            for case in self._scenario["schedule"]["case_matrix"]
        ):
            raise ArtifactError("scheduled_ids_do_not_form_case")
        self._request_specs = scenario_requests
        self._settled: set[str] = set()
        self._telemetry_lines = 0
        self._finalized = False
        self._logs_set = False
        self._canaries = canaries or CanarySet.create()
        self._log_limit = log_limit_bytes
        self._server_log = BoundedRedactedLog(
            self._canaries, max_bytes=log_limit_bytes
        )
        self._client_log = BoundedRedactedLog(
            self._canaries, max_bytes=log_limit_bytes
        )
        self._server_total_override: int | None = None
        self._client_total_override: int | None = None

        self._root.mkdir(parents=True, exist_ok=True)
        if self._root.is_symlink() or not self._root.is_dir():
            raise ArtifactError("unsafe_result_root")
        self._final_path = self._root / self._run_id
        self._staging_path = self._root / f".{self._run_id}.staging-{os.getpid()}"
        if self._final_path.exists() or self._staging_path.exists():
            raise ArtifactError("result_path_exists")
        self._staging_path.mkdir(mode=0o700)

        scenario_bytes = canonical_json_bytes(self._scenario)
        source_bytes = canonical_json_bytes(self._source_manifest)
        _write_fsynced(self._staging_path / "scenario.json", scenario_bytes)
        _write_fsynced(self._staging_path / "source-manifest.json", source_bytes)
        self._scenario_sha256 = sha256_bytes(scenario_bytes)
        self._source_sha256 = sha256_bytes(source_bytes)
        self._validate_metadata_input()
        self._requests_stream = _open_raw(self._staging_path / "requests.jsonl")
        self._telemetry_stream = _open_raw(self._staging_path / "telemetry.jsonl")

    @property
    def staging_path(self) -> Path:
        return self._staging_path

    @property
    def scheduled_ids(self) -> tuple[str, ...]:
        return self._scheduled

    def append_sample(self, sample: Mapping[str, object]) -> None:
        self._ensure_open()
        checked = validate_request_sample(dict(sample))
        error_body = checked["redacted_error_body"]
        if isinstance(error_body, str):
            checked["redacted_error_body"] = redact_text(
                error_body, self._canaries, max_bytes=65536
            )[0]
        request_id = checked["request_id"]
        if checked["scenario_run_id"] != self._run_id:
            raise ArtifactError("sample_run_id_mismatch")
        if request_id not in self._scheduled:
            raise ArtifactError("unscheduled_request")
        if request_id in self._settled:
            raise ArtifactError("duplicate_request_settlement")
        spec = self._request_specs[request_id]
        if checked["scheduled_offset_ns"] != spec["start_offset_ms"] * 1_000_000:
            raise ArtifactError("scheduled_offset_mismatch")
        budget = spec["output_budget"]
        if checked["output_budget_kind"] != budget["kind"]:
            raise ArtifactError("output_budget_kind_mismatch")
        expected_value = budget.get("tokens")
        if checked["output_budget_value"] != expected_value:
            raise ArtifactError("output_budget_value_mismatch")
        pairing = self._metadata_input.get("pairing")
        expected_repetition = pairing.get("repetition") if isinstance(pairing, dict) else None
        if expected_repetition is not None and checked["repetition"] != expected_repetition:
            raise ArtifactError("sample_repetition_mismatch")
        self._requests_stream.write(canonical_json_bytes(checked))
        self._requests_stream.flush()
        self._settled.add(request_id)

    def append_telemetry(self, item: Mapping[str, object]) -> None:
        self._ensure_open()
        if self._telemetry_lines >= MAX_TELEMETRY_LINES:
            raise ArtifactError("too_many_telemetry_records")
        checked = validate_telemetry(dict(item), expected_run_id=self._run_id)
        if checked["clock_domain"] != self._metadata_input["clock_domain"]:
            raise ArtifactError("telemetry_clock_domain_mismatch")
        payload = canonical_json_bytes(checked)
        if (
            self._telemetry_stream.tell() + len(payload)
            > RESULT_FILE_LIMITS["telemetry.jsonl"]
        ):
            raise ArtifactError("telemetry_too_large")
        self._telemetry_stream.write(payload)
        self._telemetry_stream.flush()
        self._telemetry_lines += 1

    def set_logs(
        self,
        server: str | bytes,
        client: str | bytes,
        *,
        server_total_bytes: int | None = None,
        client_total_bytes: int | None = None,
    ) -> None:
        self._ensure_open()
        if self._logs_set:
            raise ArtifactError("logs_already_set")
        self._server_log.write(server)
        self._client_log.write(client)
        self._server_total_override = _validate_total_override(
            server_total_bytes, self._server_log.total_bytes
        )
        self._client_total_override = _validate_total_override(
            client_total_bytes, self._client_log.total_bytes
        )
        self._logs_set = True

    def finalize(
        self,
        primary_error: Mapping[str, object] | None = None,
        cleanup_error: Mapping[str, object] | None = None,
    ) -> Path:
        self._ensure_open()
        try:
            primary = validate_error_record(
                dict(primary_error) if primary_error is not None else None
            )
            cleanup = validate_error_record(
                dict(cleanup_error) if cleanup_error is not None else None
            )
        except RedactionError as error:
            raise ArtifactError("invalid_result_error") from error

        missing = [item for item in self._scheduled if item not in self._settled]
        if missing and primary is None:
            primary = {"class": "incomplete", "code": "missing_settlement"}
        for request_id in missing:
            sample = self._incomplete_sample(request_id)
            self._requests_stream.write(canonical_json_bytes(sample))
            self._settled.add(request_id)

        _flush_fsync_close(self._requests_stream)
        _flush_fsync_close(self._telemetry_stream)
        requests_path = self._staging_path / "requests.jsonl"
        telemetry_path = self._staging_path / "telemetry.jsonl"
        if requests_path.stat().st_size > RESULT_FILE_LIMITS["requests.jsonl"]:
            raise ArtifactError("requests_too_large")

        server_bytes, server_meta = self._server_log.finish()
        client_bytes, client_meta = self._client_log.finish()
        _apply_total_override(server_meta, self._server_total_override)
        _apply_total_override(client_meta, self._client_total_override)
        _write_fsynced(self._staging_path / "server.log", server_bytes)
        _write_fsynced(self._staging_path / "client.log", client_bytes)
        server_meta["sha256"] = sha256_bytes(server_bytes)
        client_meta["sha256"] = sha256_bytes(client_bytes)

        requests_bytes = requests_path.read_bytes()
        telemetry_bytes = telemetry_path.read_bytes()
        request_items = load_jsonl(
            requests_path,
            max_lines=len(self._scheduled),
            max_bytes=RESULT_FILE_LIMITS["requests.jsonl"],
        )
        telemetry_items = load_jsonl(
            telemetry_path,
            max_lines=MAX_TELEMETRY_LINES,
            max_bytes=RESULT_FILE_LIMITS["telemetry.jsonl"],
        )
        result_state = _expected_result_state(
            request_items,
            primary_error=primary,
            cleanup_error=cleanup,
        )
        metadata = self._materialize_metadata(
            result_state=result_state,
            server_log=server_meta,
            client_log=client_meta,
            primary_error=primary,
            cleanup_error=cleanup,
        )

        # This call is intentionally after both raw streams are closed and
        # fsynced. Tests may hook compute_summary to enforce the ordering.
        summary = compute_summary(
            metadata,
            self._scenario,
            request_items,
            telemetry_items,
            requests_sha256=sha256_bytes(requests_bytes),
            telemetry_sha256=sha256_bytes(telemetry_bytes),
        )
        _write_fsynced(
            self._staging_path / "summary.json", canonical_json_bytes(summary)
        )
        _write_fsynced(
            self._staging_path / "summary.md", render_summary_markdown(summary)
        )
        _write_fsynced(
            self._staging_path / "metadata.json", canonical_json_bytes(metadata)
        )
        _fsync_directory(self._staging_path)
        _validate_exact_files(self._staging_path)
        os.replace(self._staging_path, self._final_path)
        _fsync_directory(self._root)
        self._finalized = True
        return self._final_path

    def _incomplete_sample(self, request_id: str) -> dict[str, object]:
        spec = self._request_specs[request_id]
        pairing = self._metadata_input["pairing"]
        repetition = pairing["repetition"] if pairing["repetition"] is not None else 0
        budget = spec["output_budget"]
        return validate_request_sample(
            {
                "schema_version": SCHEMA_VERSION,
                "scenario_run_id": self._run_id,
                "request_id": request_id,
                "repetition": repetition,
                "scheduled_offset_ns": spec["start_offset_ms"] * 1_000_000,
                "send_ns": None,
                "http_accept_ns": None,
                "first_byte_ns": None,
                "first_model_token_ns": None,
                "token_event_timestamps_ns": [],
                "itl_ns": [],
                "completion_ns": None,
                "status_code": None,
                "retry_count": 0,
                "retry_after": None,
                "finish_class": "incomplete",
                "error_class": None,
                "redacted_error_body": None,
                "prompt_tokens": None,
                "generated_tokens": None,
                "output_budget_kind": budget["kind"],
                "output_budget_value": budget.get("tokens"),
                "timing_granularity": "unavailable",
            }
        )

    def _validate_metadata_input(self) -> None:
        keys = set(self._metadata_input)
        if keys - _METADATA_FIELDS or not (_METADATA_FIELDS - _WRITER_FIELDS) <= keys:
            raise ArtifactError("metadata_fields")
        if self._metadata_input.get("schema_version") != SCHEMA_VERSION:
            raise ArtifactError("metadata_schema_version")
        if self._metadata_input.get("scenario_id") not in {"S1", "S2", "S3", "S5A", "S5B"}:
            raise ArtifactError("metadata_scenario_id")
        if self._metadata_input.get("vantage") not in {"controller_lan", "target_local"}:
            raise ArtifactError("metadata_vantage")
        if not _is_safe_text(self._metadata_input.get("clock_domain")):
            raise ArtifactError("metadata_clock_domain")
        _utc_time(self._metadata_input.get("started_utc"), "started_utc")
        _sha256(self._metadata_input.get("prompt_manifest_sha256"), "prompt_manifest")
        if "scenario_sha256" in self._metadata_input and self._metadata_input["scenario_sha256"] != self._scenario_sha256:
            raise ArtifactError("scenario_hash_mismatch")
        if "source_manifest_sha256" in self._metadata_input and self._metadata_input["source_manifest_sha256"] != self._source_sha256:
            raise ArtifactError("source_hash_mismatch")
        _configured_policy(self._metadata_input.get("configured_policy"))
        if self._metadata_input["configured_policy"] != self._scenario["server"]:
            raise ArtifactError("configured_policy_scenario_mismatch")
        if self._metadata_input["warmup_repetitions"] != self._scenario["warmup_repetitions"]:
            raise ArtifactError("warmup_repetitions_mismatch")
        if self._metadata_input["measured_repetitions"] != self._scenario["measured_repetitions"]:
            raise ArtifactError("measured_repetitions_mismatch")
        _observed_execution(self._metadata_input.get("observed_execution"))
        _network(self._metadata_input.get("network"), self._metadata_input["vantage"])
        _nonnegative_int(self._metadata_input.get("warmup_repetitions"), "warmup_repetitions")
        _positive_int(self._metadata_input.get("measured_repetitions"), "measured_repetitions")
        _pairing(self._metadata_input.get("pairing"))
        _runtime_bundle(self._metadata_input.get("runtime_bundle"), self._metadata_input["vantage"])

    def _materialize_metadata(
        self,
        *,
        result_state: str,
        server_log: dict[str, object],
        client_log: dict[str, object],
        primary_error: dict[str, str] | None,
        cleanup_error: dict[str, str] | None,
    ) -> dict[str, object]:
        metadata = {
            key: value
            for key, value in self._metadata_input.items()
            if key not in _WRITER_FIELDS
        }
        metadata.update(
            {
                "result_state": result_state,
                "scenario_sha256": self._scenario_sha256,
                "source_manifest_sha256": self._source_sha256,
                "completed_utc": datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                "logs": {"server": server_log, "client": client_log},
                "primary_error": primary_error,
                "cleanup_error": cleanup_error,
            }
        )
        validate_metadata(metadata)
        return metadata

    def _ensure_open(self) -> None:
        if self._finalized:
            raise ArtifactError("result_already_finalized")


def verify_result(path: Path | str) -> dict[str, object]:
    result_path = Path(path)
    _validate_exact_files(result_path)
    aggregate_size = 0
    for name in RESULT_FILES:
        entry = result_path / name
        info = entry.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ArtifactError("unsafe_result_file")
        if info.st_size > RESULT_FILE_LIMITS[name]:
            raise ArtifactError("result_file_too_large")
        aggregate_size += info.st_size
    if aggregate_size > MAX_RESULT_BYTES:
        raise ArtifactError("result_aggregate_too_large")

    metadata = _load_canonical_object(result_path / "metadata.json")
    scenario = _load_canonical_object(result_path / "scenario.json")
    source = _load_canonical_object(result_path / "source-manifest.json")
    stored_summary = _load_canonical_object(result_path / "summary.json")
    validate_metadata(metadata)
    validate_normalized_scenario(scenario)
    validate_source_manifest(source)
    if metadata["scenario_id"] != scenario["id"]:
        raise ArtifactError("metadata_scenario_mismatch")
    if metadata["vantage"] != scenario["vantage"]:
        raise ArtifactError("metadata_vantage_mismatch")
    if metadata["configured_policy"] != scenario["server"]:
        raise ArtifactError("metadata_policy_mismatch")
    if metadata["warmup_repetitions"] != scenario["warmup_repetitions"]:
        raise ArtifactError("metadata_warmup_mismatch")
    if metadata["measured_repetitions"] != scenario["measured_repetitions"]:
        raise ArtifactError("metadata_repetitions_mismatch")

    scenario_bytes = (result_path / "scenario.json").read_bytes()
    source_bytes = (result_path / "source-manifest.json").read_bytes()
    if metadata["scenario_sha256"] != sha256_bytes(scenario_bytes):
        raise ArtifactError("scenario_tampered")
    if metadata["source_manifest_sha256"] != sha256_bytes(source_bytes):
        raise ArtifactError("source_manifest_tampered")
    for log_name, metadata_name in (("server.log", "server"), ("client.log", "client")):
        payload = (result_path / log_name).read_bytes()
        log_meta = metadata["logs"][metadata_name]
        if log_meta["sha256"] != sha256_bytes(payload) or log_meta["retained_bytes"] != len(payload):
            raise ArtifactError("log_tampered")

    requests_path = result_path / "requests.jsonl"
    telemetry_path = result_path / "telemetry.jsonl"
    request_items = load_jsonl(
        requests_path,
        max_lines=1_000_000,
        max_bytes=RESULT_FILE_LIMITS["requests.jsonl"],
    )
    request_items = _validate_result_samples(metadata, scenario, request_items)
    telemetry_items = load_jsonl(
        telemetry_path,
        max_lines=MAX_TELEMETRY_LINES,
        max_bytes=RESULT_FILE_LIMITS["telemetry.jsonl"],
    )
    if any(
        item.get("clock_domain") != metadata["clock_domain"]
        for item in telemetry_items
    ):
        raise ArtifactError("telemetry_clock_domain_mismatch")
    expected_state = _expected_result_state(
        request_items,
        primary_error=metadata["primary_error"],
        cleanup_error=metadata["cleanup_error"],
    )
    if metadata["result_state"] != expected_state:
        raise ArtifactError("result_state_mismatch")
    requests_bytes = requests_path.read_bytes()
    telemetry_bytes = telemetry_path.read_bytes()
    recomputed = compute_summary(
        metadata,
        scenario,
        request_items,
        telemetry_items,
        requests_sha256=sha256_bytes(requests_bytes),
        telemetry_sha256=sha256_bytes(telemetry_bytes),
    )
    if canonical_json_bytes(recomputed) != (result_path / "summary.json").read_bytes():
        raise ArtifactError("summary_mismatch")
    if render_summary_markdown(recomputed) != (result_path / "summary.md").read_bytes():
        raise ArtifactError("summary_markdown_mismatch")
    if stored_summary != recomputed:
        raise ArtifactError("summary_object_mismatch")
    return recomputed


def _validate_result_samples(
    metadata: Mapping[str, object],
    scenario: Mapping[str, object],
    samples: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    request_specs = {
        item["id"]: item
        for item in scenario["requests"]
    }
    checked_samples: list[dict[str, object]] = []
    seen: set[str] = set()
    expected_repetition = metadata["pairing"]["repetition"]
    for raw_sample in samples:
        try:
            sample = validate_request_sample(dict(raw_sample))
        except StatisticsError as error:
            raise ArtifactError("invalid_request_record") from error
        request_id = sample["request_id"]
        if sample["scenario_run_id"] != metadata["run_id"]:
            raise ArtifactError("request_run_id_mismatch")
        if request_id in seen:
            raise ArtifactError("duplicate_request_record")
        spec = request_specs.get(request_id)
        if spec is None:
            raise ArtifactError("unknown_request_record")
        if sample["scheduled_offset_ns"] != spec["start_offset_ms"] * 1_000_000:
            raise ArtifactError("request_scheduled_offset_mismatch")
        budget = spec["output_budget"]
        if (
            sample["output_budget_kind"] != budget["kind"]
            or sample["output_budget_value"] != budget.get("tokens")
        ):
            raise ArtifactError("request_output_budget_mismatch")
        if (
            expected_repetition is not None
            and sample["repetition"] != expected_repetition
        ):
            raise ArtifactError("request_repetition_mismatch")
        seen.add(request_id)
        checked_samples.append(sample)
    if not any(
        set(case["request_ids"]) == seen
        for case in scenario["schedule"]["case_matrix"]
    ):
        raise ArtifactError("request_set_not_scenario_case")
    return checked_samples


def _expected_result_state(
    samples: Iterable[Mapping[str, object]],
    *,
    primary_error: object,
    cleanup_error: object,
) -> str:
    failed_sample = any(
        item["finish_class"] not in COMPLETED_FINISH_CLASSES
        for item in samples
    )
    return (
        "failed"
        if primary_error is not None or cleanup_error is not None or failed_sample
        else "success"
    )




def validate_metadata(value: object) -> dict[str, object]:
    metadata = _exact_dict(value, _METADATA_FIELDS, "metadata_fields")
    if metadata["schema_version"] != SCHEMA_VERSION:
        raise ArtifactError("metadata_schema_version")
    _bounded_id(metadata["run_id"], "run_id")
    if metadata["result_state"] not in {"success", "failed"}:
        raise ArtifactError("metadata_result_state")
    if metadata["scenario_id"] not in {"S1", "S2", "S3", "S5A", "S5B"}:
        raise ArtifactError("metadata_scenario_id")
    _sha256(metadata["scenario_sha256"], "scenario_sha256")
    _sha256(metadata["prompt_manifest_sha256"], "prompt_manifest_sha256")
    _sha256(metadata["source_manifest_sha256"], "source_manifest_sha256")
    if metadata["vantage"] not in {"controller_lan", "target_local"}:
        raise ArtifactError("metadata_vantage")
    if not _is_safe_text(metadata["clock_domain"]):
        raise ArtifactError("metadata_clock_domain")
    _utc_time(metadata["started_utc"], "started_utc")
    _utc_time(metadata["completed_utc"], "completed_utc")
    _configured_policy(metadata["configured_policy"])
    _observed_execution(metadata["observed_execution"])
    _network(metadata["network"], metadata["vantage"])
    _nonnegative_int(metadata["warmup_repetitions"], "warmup_repetitions")
    _positive_int(metadata["measured_repetitions"], "measured_repetitions")
    _pairing(metadata["pairing"])
    _runtime_bundle(metadata["runtime_bundle"], metadata["vantage"])
    logs = _exact_dict(metadata["logs"], frozenset({"server", "client"}), "logs_fields")
    _log_metadata(logs["server"])
    _log_metadata(logs["client"])
    try:
        validate_error_record(metadata["primary_error"])
        validate_error_record(metadata["cleanup_error"])
    except RedactionError as error:
        raise ArtifactError("invalid_metadata_error") from error
    return metadata


def validate_normalized_scenario(value: object) -> dict[str, object]:
    """Validate the exact plain-dictionary output of schema.normalize_scenario."""

    scenario = _exact_dict(value, _SCENARIO_FIELDS, "scenario_fields")
    if scenario["version"] != SCHEMA_VERSION:
        raise ArtifactError("scenario_version")
    scenario_id = scenario["id"]
    if scenario_id not in {"S1", "S2", "S3", "S5A", "S5B"}:
        raise ArtifactError("scenario_id")
    description = scenario["description"]
    if type(description) is not str or not description or len(description) > 2_048:
        raise ArtifactError("scenario_description")
    vantage = scenario["vantage"]
    if vantage not in {"controller_lan", "target_local"}:
        raise ArtifactError("scenario_vantage")
    policy = _configured_policy(scenario["server"])
    if policy["decode_policy"] == "plain" and not (
        scenario_id == "S1" and vantage == "target_local"
    ):
        raise ArtifactError("plain_policy_scope")

    prompts = scenario["prompts"]
    if type(prompts) is not list or not 1 <= len(prompts) <= 64:
        raise ArtifactError("scenario_prompts")
    prompt_by_id: dict[str, dict[str, object]] = {}
    prompt_paths: set[str] = set()
    for prompt in prompts:
        item = _exact_dict(
            prompt,
            frozenset({"id", "path", "sha256", "token_count", "license"}),
            "prompt_fields",
        )
        prompt_id = _bounded_id(item["id"], "prompt_id")
        if prompt_id in prompt_by_id:
            raise ArtifactError("duplicate_prompt_id")
        path = item["path"]
        if (
            type(path) is not str
            or not path.isascii()
            or len(path) > 512
            or "\\" in path
        ):
            raise ArtifactError("prompt_path")
        parsed_path = PurePosixPath(path)
        if (
            parsed_path.is_absolute()
            or tuple(parsed_path.parts[:3])
            != ("benchmarks", "prompts", "artifacts")
            or len(parsed_path.parts) <= 3
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or parsed_path.as_posix() != path
            or path in prompt_paths
        ):
            raise ArtifactError("prompt_path")
        prompt_paths.add(path)
        _sha256(item["sha256"], "prompt_sha256")
        _bounded_int(
            item["token_count"],
            "prompt_token_count",
            minimum=1,
            maximum=524_288,
        )
        license_name = item["license"]
        if (
            type(license_name) is not str
            or not license_name
            or len(license_name) > 128
        ):
            raise ArtifactError("prompt_license")
        prompt_by_id[prompt_id] = item

    requests = scenario["requests"]
    if type(requests) is not list or not 1 <= len(requests) <= 256:
        raise ArtifactError("scenario_requests")
    request_by_id: dict[str, dict[str, object]] = {}
    for request in requests:
        item = _exact_dict(
            request,
            frozenset(
                {"id", "prompt_id", "start_offset_ms", "trigger", "output_budget"}
            ),
            "scenario_request_fields",
        )
        request_id = _bounded_id(item["id"], "scenario_request_id")
        prompt_id = _bounded_id(item["prompt_id"], "scenario_prompt_id")
        if request_id in request_by_id or prompt_id not in prompt_by_id:
            raise ArtifactError("scenario_request_reference")
        _bounded_int(
            item["start_offset_ms"],
            "start_offset_ms",
            minimum=0,
            maximum=86_400_000,
        )
        if item["trigger"] is not None:
            trigger = _exact_dict(
                item["trigger"],
                frozenset({"kind", "minimum_requests"}),
                "trigger_fields",
            )
            if trigger["kind"] != "active_decode":
                raise ArtifactError("trigger_kind")
            _bounded_int(
                trigger["minimum_requests"],
                "minimum_requests",
                minimum=1,
                maximum=63,
            )
        budget = item["output_budget"]
        if type(budget) is not dict or budget.get("kind") not in {
            "explicit",
            "omitted",
        }:
            raise ArtifactError("output_budget")
        if budget["kind"] == "explicit":
            if set(budget) != {"kind", "tokens"}:
                raise ArtifactError("output_budget_fields")
            tokens = _bounded_int(
                budget["tokens"],
                "output_budget_tokens",
                minimum=1,
                maximum=393_216,
            )
            if prompt_by_id[prompt_id]["token_count"] + tokens > policy["context_tokens"]:
                raise ArtifactError("impossible_token_budget")
            if scenario_id == "S5B":
                raise ArtifactError("s5b_explicit_budget")
        else:
            if set(budget) != {"kind"}:
                raise ArtifactError("output_budget_fields")
            if scenario_id != "S5B":
                raise ArtifactError("omitted_budget_scope")
        request_by_id[request_id] = item

    schedule = _exact_dict(
        scenario["schedule"],
        frozenset({"kind", "case_matrix"}),
        "schedule_fields",
    )
    if schedule["kind"] not in {"offsets", "active_decode_injection"}:
        raise ArtifactError("schedule_kind")
    cases = schedule["case_matrix"]
    if type(cases) is not list or not 1 <= len(cases) <= 64:
        raise ArtifactError("schedule_cases")
    case_ids: set[str] = set()
    request_sets: set[tuple[str, ...]] = set()
    scheduled_ids: set[str] = set()
    for case in cases:
        item = _exact_dict(
            case, frozenset({"id", "request_ids"}), "case_fields"
        )
        case_id = _bounded_id(item["id"], "case_id")
        raw_request_ids = item["request_ids"]
        if (
            case_id in case_ids
            or type(raw_request_ids) is not list
            or not 1 <= len(raw_request_ids) <= 64
        ):
            raise ArtifactError("case_identity")
        checked_ids = tuple(
            _bounded_id(request_id, "case_request_id")
            for request_id in raw_request_ids
        )
        if (
            len(set(checked_ids)) != len(checked_ids)
            or any(request_id not in request_by_id for request_id in checked_ids)
            or checked_ids in request_sets
        ):
            raise ArtifactError("case_request_reference")
        case_ids.add(case_id)
        request_sets.add(checked_ids)
        scheduled_ids.update(checked_ids)
    if scheduled_ids != set(request_by_id):
        raise ArtifactError("unscheduled_scenario_request")
    if {item["prompt_id"] for item in request_by_id.values()} != set(prompt_by_id):
        raise ArtifactError("unused_scenario_prompt")

    sampling = _exact_dict(
        scenario["sampling"],
        frozenset({"temperature", "top_p", "seed"}),
        "sampling_fields",
    )
    if (
        type(sampling["temperature"]) is not float
        or sampling["temperature"] != 0.0
        or type(sampling["top_p"]) is not float
        or sampling["top_p"] != 1.0
        or type(sampling["seed"]) is not int
        or sampling["seed"] != 0
    ):
        raise ArtifactError("sampling_values")
    _bounded_int(
        scenario["warmup_repetitions"],
        "warmup_repetitions",
        minimum=1,
        maximum=100,
    )
    _bounded_int(
        scenario["measured_repetitions"],
        "measured_repetitions",
        minimum=1,
        maximum=100,
    )
    deadlines = _exact_dict(
        scenario["deadlines"],
        frozenset(
            {"connect_seconds", "read_seconds", "overall_seconds", "server_seconds"}
        ),
        "deadline_fields",
    )
    for key, number in deadlines.items():
        if (
            type(number) is not float
            or not math.isfinite(number)
            or not 0.0 < number <= 86_400.0
        ):
            raise ArtifactError(f"invalid_{key}")
    if any(
        deadlines[field] > deadlines["overall_seconds"]
        for field in ("connect_seconds", "read_seconds", "server_seconds")
    ):
        raise ArtifactError("invalid_deadline_order")
    preconditions = _exact_dict(
        scenario["preconditions"],
        frozenset(
            {
                "server_restart_each_repetition",
                "cache_state",
                "warmup_server_is_separate",
                "cooldown_seconds",
                "prompt_reuse",
            }
        ),
        "precondition_fields",
    )
    if (
        type(preconditions["server_restart_each_repetition"]) is not bool
        or type(preconditions["warmup_server_is_separate"]) is not bool
    ):
        raise ArtifactError("precondition_boolean")
    if (
        preconditions["cache_state"] not in {"cold", "warm"}
        or preconditions["prompt_reuse"] not in {"forbid", "allow"}
    ):
        raise ArtifactError("precondition_enum")
    cooldown = preconditions["cooldown_seconds"]
    if (
        type(cooldown) is not float
        or not math.isfinite(cooldown)
        or not 0.0 <= cooldown <= 3_600.0
    ):
        raise ArtifactError("invalid_cooldown_seconds")
    if preconditions["cache_state"] == "cold" and (
        not preconditions["server_restart_each_repetition"]
        or not preconditions["warmup_server_is_separate"]
    ):
        raise ArtifactError("invalid_cold_preconditions")

    triggered = [
        item for item in request_by_id.values() if item["trigger"] is not None
    ]
    if scenario_id == "S1":
        if schedule["kind"] != "offsets" or triggered:
            raise ArtifactError("invalid_s1_schedule")
        matrix: set[tuple[str, int]] = set()
        matrix_prompt_ids: set[str] = set()
        for case in cases:
            case_request_ids = case["request_ids"]
            concurrency = len(case_request_ids)
            case_prompt_ids = {
                request_by_id[request_id]["prompt_id"]
                for request_id in case_request_ids
            }
            if concurrency not in {1, 2, 4, 8, 12, 16} or len(case_prompt_ids) != 1:
                raise ArtifactError("invalid_s1_matrix")
            prompt_id = next(iter(case_prompt_ids))
            if (prompt_id, concurrency) in matrix:
                raise ArtifactError("invalid_s1_matrix")
            matrix.add((prompt_id, concurrency))
            matrix_prompt_ids.add(prompt_id)
        expected_matrix = {
            (prompt_id, concurrency)
            for prompt_id in matrix_prompt_ids
            for concurrency in (1, 2, 4, 8, 12, 16)
        }
        if (
            len(matrix_prompt_ids) != 2
            or len(cases) != 12
            or matrix != expected_matrix
            or len({item["token_count"] for item in prompts}) != 2
        ):
            raise ArtifactError("invalid_s1_matrix")
    elif scenario_id == "S2":
        roles = ("planner", "coder", "reviewer", "advisor")
        if (
            schedule["kind"] != "offsets"
            or triggered
            or set(request_by_id) != set(roles)
            or len(cases) != 1
            or set(cases[0]["request_ids"]) != set(roles)
        ):
            raise ArtifactError("invalid_s2")
        offsets = [request_by_id[role]["start_offset_ms"] for role in roles]
        role_prompts = {
            role: request_by_id[role]["prompt_id"]
            for role in roles
        }
        prompt_counts = {
            prompt_id: item["token_count"]
            for prompt_id, item in prompt_by_id.items()
        }
        if (
            offsets[0] != 0
            or offsets != sorted(offsets)
            or len(set(role_prompts.values())) != 4
            or not (
                prompt_counts[role_prompts["planner"]]
                > prompt_counts[role_prompts["coder"]]
                > prompt_counts[role_prompts["advisor"]]
                > prompt_counts[role_prompts["reviewer"]]
            )
        ):
            raise ArtifactError("invalid_s2")
    elif scenario_id == "S3":
        if schedule["kind"] != "active_decode_injection" or len(triggered) != 1:
            raise ArtifactError("invalid_s3")
        injection = triggered[0]
        for case in cases:
            if (
                injection["id"] not in case["request_ids"]
                or len(case["request_ids"]) - 1
                < injection["trigger"]["minimum_requests"]
            ):
                raise ArtifactError("invalid_s3")
    else:
        if schedule["kind"] != "offsets" or triggered:
            raise ArtifactError("invalid_s5")
        if scenario_id == "S5A":
            if any(
                item["output_budget"] != {"kind": "explicit", "tokens": 512}
                for item in request_by_id.values()
            ):
                raise ArtifactError("invalid_s5a")
        elif any(
            prompt_by_id[item["prompt_id"]]["token_count"]
            + policy["default_output_tokens"]
            <= policy["context_tokens"]
            for item in request_by_id.values()
        ):
            raise ArtifactError("invalid_s5b")
    return scenario


def validate_source_manifest(value: object) -> dict[str, object]:
    manifest = _exact_dict(value, _SOURCE_FIELDS, "source_manifest_fields")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ArtifactError("source_manifest_version")
    _repository(manifest["lab"], lab=True)
    _repository(manifest["engine"], lab=False)
    _repository(manifest["integration"], lab=False)
    userspace = _exact_dict(manifest["userspace"], frozenset({"flake_lock_sha256", "nixpkgs_revision", "python_version", "uv_version"}), "userspace_fields")
    _sha256(userspace["flake_lock_sha256"], "flake_lock_sha256")
    _bounded_commit(userspace["nixpkgs_revision"], "nixpkgs_revision")
    for field in ("python_version", "uv_version"):
        if not _is_safe_text(userspace[field]):
            raise ArtifactError(f"invalid_{field}")
    controller = _exact_dict(manifest["controller"], frozenset({"os", "kernel", "arch"}), "controller_fields")
    if any(not _is_safe_text(controller[field]) for field in controller):
        raise ArtifactError("controller_value")
    target_fields = frozenset({"os", "kernel", "arch", "hardware_vendor", "hardware_model", "soc", "gpu", "compute_capability", "firmware", "driver", "cuda", "nvcc", "c_compiler", "cpp_compiler", "clock_sync"})
    target = _exact_dict(manifest["target"], target_fields, "target_fields")
    for field in target_fields:
        _availability(target[field], field)
    build = _exact_dict(manifest["build"], frozenset({"build_id", "binary_sha256", "source_snapshot_id"}), "build_fields")
    _bounded_id(build["build_id"], "build_id")
    _sha256(build["binary_sha256"], "binary_sha256")
    _bounded_id(build["source_snapshot_id"], "build_source_snapshot_id")
    weights = _exact_dict(manifest["weights"], frozenset({"model_sha256", "drafter_sha256"}), "weights_fields")
    _sha256(weights["model_sha256"], "model_sha256")
    _sha256(weights["drafter_sha256"], "drafter_sha256")
    return manifest


def _configured_policy(value: object) -> dict[str, object]:
    fields = frozenset(
        {
            "context_tokens",
            "default_output_tokens",
            "decode_policy",
            "dspark_max_nlive",
            "terminal_yield_quench",
            "speculative_overrides",
        }
    )
    policy = _exact_dict(value, fields, "configured_policy_fields")
    _bounded_int(
        policy["context_tokens"],
        "context_tokens",
        minimum=1,
        maximum=524_288,
    )
    if policy["default_output_tokens"] != 393_216:
        raise ArtifactError("default_output_tokens")
    if policy["decode_policy"] not in {"shipped", "plain"}:
        raise ArtifactError("decode_policy")
    if policy["dspark_max_nlive"] != 1:
        raise ArtifactError("dspark_max_nlive")
    if policy["terminal_yield_quench"] is not True:
        raise ArtifactError("terminal_yield_quench")
    overrides = _exact_dict(
        policy["speculative_overrides"],
        frozenset(
            {
                "shadow_guard",
                "shadow_alpha",
                "shadow_min_evidence",
                "shadow_budget",
                "shadow_credit_cap",
            }
        ),
        "speculative_override_fields",
    )
    if any(item is not None for item in overrides.values()):
        raise ArtifactError("speculative_override_value")
    return policy


def _observed_execution(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("status") not in {"available", "unavailable"}:
        raise ArtifactError("observed_execution")
    if value["status"] == "unavailable":
        if set(value) != {"status", "reason"} or value["reason"] != "not_exposed_by_frozen_source":
            raise ArtifactError("observed_execution_unavailable")
        return value
    fields = frozenset({"status", "source", "speculative_steps", "plain_steps", "proposals", "verification_width_mean", "accepted_tokens", "quench_events"})
    observed = _exact_dict(value, fields, "observed_execution_fields")
    if observed["source"] != "metrics_delta":
        raise ArtifactError("observed_execution_source")
    for field in fields - {"status", "source"}:
        item = observed[field]
        if item is not None and (
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(float(item))
            or float(item) < 0
        ):
            raise ArtifactError("observed_execution_value")
    return observed


def _network(value: object, vantage: object) -> dict[str, object]:
    network = _exact_dict(value, frozenset({"path", "http_version", "tls", "link_speed_mbps", "mtu_bytes"}), "network_fields")
    expected_path = "direct_private_lan" if vantage == "controller_lan" else "target_loopback"
    if network["path"] != expected_path or network["tls"] is not False:
        raise ArtifactError("network_path")
    if not _is_safe_text(network["http_version"]):
        raise ArtifactError("http_version")
    if network["link_speed_mbps"] is not None:
        _bounded_int(
            network["link_speed_mbps"],
            "link_speed_mbps",
            minimum=1,
            maximum=100_000_000,
        )
    if network["mtu_bytes"] is not None:
        _bounded_int(
            network["mtu_bytes"],
            "mtu_bytes",
            minimum=1,
            maximum=1_048_576,
        )
    return network


def _pairing(value: object) -> dict[str, object]:
    pairing = _exact_dict(value, frozenset({"pair_id", "block_id", "order", "repetition"}), "pairing_fields")
    for field in ("pair_id", "block_id", "order"):
        if pairing[field] is not None:
            _bounded_id(pairing[field], field)
    if pairing["repetition"] is not None:
        _bounded_int(
            pairing["repetition"],
            "pairing_repetition",
            minimum=0,
            maximum=99,
        )
    return pairing


def _runtime_bundle(value: object, vantage: object) -> dict[str, object] | None:
    if vantage == "controller_lan":
        if value is not None:
            raise ArtifactError("controller_runtime_bundle")
        return None
    bundle = _exact_dict(value, frozenset({"bundle_sha256", "manifest_sha256", "lock_sha256"}), "runtime_bundle_fields")
    for field in bundle:
        _sha256(bundle[field], field)
    return bundle


def _log_metadata(value: object) -> dict[str, object]:
    item = _exact_dict(value, frozenset({"sha256", "retained_bytes", "truncated", "total_bytes"}), "log_metadata_fields")
    _sha256(item["sha256"], "log_sha256")
    _bounded_int(
        item["retained_bytes"],
        "retained_bytes",
        minimum=0,
        maximum=1024 * 1024,
    )
    if not isinstance(item["truncated"], bool):
        raise ArtifactError("log_truncated")
    if item["total_bytes"] is not None:
        _nonnegative_int(item["total_bytes"], "log_total_bytes")
        if item["total_bytes"] < item["retained_bytes"]:
            raise ArtifactError("log_total_less_than_retained")
    return item


def _repository(value: object, *, lab: bool) -> dict[str, object]:
    fields = {"url", "commit", "clean"}
    if lab:
        fields.update({"source_snapshot_id", "applied_tree_hash"})
    repo = _exact_dict(value, frozenset(fields), "repository_fields")
    url = repo["url"]
    if not isinstance(url, str) or not url.startswith("https://") or len(url) > 512 or "@" in url.split("//", 1)[1].split("/", 1)[0]:
        raise ArtifactError("repository_url")
    _bounded_commit(repo["commit"], "repository_commit")
    if not isinstance(repo["clean"], bool):
        raise ArtifactError("repository_clean")
    if lab:
        _bounded_id(repo["source_snapshot_id"], "source_snapshot_id")
        _sha256(repo["applied_tree_hash"], "applied_tree_hash")
    return repo


def _availability(value: object, field: str) -> dict[str, object]:
    item = _exact_dict(value, frozenset({"status", "value"}), f"{field}_availability_fields")
    if item["status"] == "available":
        if not _is_safe_text(item["value"]):
            raise ArtifactError(f"invalid_{field}")
    elif item["status"] == "unavailable":
        if item["value"] is not None:
            raise ArtifactError(f"unavailable_{field}_value")
    else:
        raise ArtifactError(f"invalid_{field}_status")
    return item


def _load_canonical_object(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArtifactError("invalid_json_file") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise ArtifactError("noncanonical_json_file")
    return value


def _validate_exact_files(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ArtifactError("invalid_result_directory")
    try:
        actual = {entry.name for entry in path.iterdir()}
    except OSError as error:
        raise ArtifactError("result_directory_unreadable") from error
    if actual != RESULT_FILES:
        raise ArtifactError("result_file_set")


def _open_raw(path: Path) -> BinaryIO:
    return path.open("xb", buffering=0)


def _write_fsynced(path: Path, payload: bytes) -> None:
    with path.open("xb", buffering=0) as stream:
        stream.write(payload)
        os.fsync(stream.fileno())


def _flush_fsync_close(stream: BinaryIO) -> None:
    stream.flush()
    os.fsync(stream.fileno())
    stream.close()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_total_override(value: int | None, observed: int) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < observed:
        raise ArtifactError("invalid_log_total_bytes")
    return value


def _apply_total_override(metadata: dict[str, object], value: int | None) -> None:
    if value is not None:
        metadata["total_bytes"] = value
        if value > metadata["retained_bytes"]:
            metadata["truncated"] = True


def _exact_dict(value: object, fields: frozenset[str], code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ArtifactError(code)
    return value


def _bounded_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ArtifactError(f"invalid_{field}")
    return value


def _bounded_commit(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or re.fullmatch(r"[0-9a-f]+", value) is None
    ):
        raise ArtifactError(f"invalid_{field}")
    return value


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ArtifactError(f"invalid_{field}")
    return value


def _is_safe_text(value: object) -> bool:
    return isinstance(value, str) and _SAFE_TEXT.fullmatch(value) is not None


def _utc_time(value: object, field: str) -> str:
    if not isinstance(value, str) or _UTC_TIME.fullmatch(value) is None:
        raise ArtifactError(f"invalid_{field}")
    return value


def _positive_int(value: object, field: str) -> int:
    return _bounded_int(value, field, minimum=1, maximum=2**63 - 1)


def _bounded_int(
    value: object,
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise ArtifactError(f"invalid_{field}")
    return value


def _nonnegative_int(value: object, field: str) -> int:
    return _bounded_int(value, field, minimum=0, maximum=2**63 - 1)
