from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Iterable, Mapping

from .artifacts import (
    ArtifactError,
    validate_metadata,
    validate_normalized_scenario,
    validate_source_manifest,
    verify_result,
)

ALLOWED_DIFFERENCES = frozenset({"policy", "engine-source"})
_POLICY_FIELDS = frozenset(
    {
        "decode_policy",
        "dspark_max_nlive",
        "terminal_yield_quench",
        "speculative_overrides",
    }
)


class ComparisonError(ValueError):
    pass


def compare_results(
    baseline_path: Path | str,
    candidate_path: Path | str,
    *,
    allow_differences: Iterable[str] = (),
) -> dict[str, object]:
    allowed_list = list(allow_differences)
    if any(item not in ALLOWED_DIFFERENCES for item in allowed_list):
        raise ComparisonError("invalid_allowed_difference")
    allowed = frozenset(allowed_list)

    baseline_summary = verify_result(baseline_path)
    candidate_summary = verify_result(candidate_path)
    baseline = _load_identity_documents(Path(baseline_path))
    candidate = _load_identity_documents(Path(candidate_path))
    _require_identity(baseline, candidate, allowed)

    return {
        "schema_version": 1,
        "baseline_run_id": baseline["metadata"]["run_id"],
        "candidate_run_id": candidate["metadata"]["run_id"],
        "allowed_differences": sorted(allowed),
        "pairing": {
            "baseline": baseline["metadata"]["pairing"],
            "candidate": candidate["metadata"]["pairing"],
        },
        "baseline": baseline_summary,
        "candidate": candidate_summary,
        "deltas": _summary_deltas(baseline_summary, candidate_summary),
    }


def _load_identity_documents(path: Path) -> dict[str, dict[str, object]]:
    try:
        metadata = json.loads((path / "metadata.json").read_bytes())
        scenario = json.loads((path / "scenario.json").read_bytes())
        source = json.loads((path / "source-manifest.json").read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ComparisonError("identity_unreadable") from error
    try:
        validate_metadata(metadata)
        validate_normalized_scenario(scenario)
        validate_source_manifest(source)
    except ArtifactError as error:
        raise ComparisonError("identity_invalid") from error
    return {"metadata": metadata, "scenario": scenario, "source": source}


def _require_identity(
    baseline: Mapping[str, dict[str, object]],
    candidate: Mapping[str, dict[str, object]],
    allowed: frozenset[str],
) -> None:
    left_metadata = baseline["metadata"]
    right_metadata = candidate["metadata"]
    if left_metadata["vantage"] != right_metadata["vantage"]:
        raise ComparisonError("vantage_mismatch")
    if left_metadata["network"] != right_metadata["network"]:
        raise ComparisonError("network_mismatch")

    metadata_identity_fields = (
        "schema_version",
        "scenario_id",
        "vantage",
        "clock_domain",
        "prompt_manifest_sha256",
        "network",
        "warmup_repetitions",
        "measured_repetitions",
        "runtime_bundle",
    )
    for field in metadata_identity_fields:
        if left_metadata[field] != right_metadata[field]:
            raise ComparisonError(f"metadata_identity_mismatch:{field}")

    left_pairing = left_metadata["pairing"]
    right_pairing = right_metadata["pairing"]
    for field in ("pair_id", "block_id", "repetition"):
        if left_pairing[field] != right_pairing[field]:
            raise ComparisonError(f"pairing_mismatch:{field}")

    left_scenario = copy.deepcopy(baseline["scenario"])
    right_scenario = copy.deepcopy(candidate["scenario"])
    left_policy = copy.deepcopy(left_metadata["configured_policy"])
    right_policy = copy.deepcopy(right_metadata["configured_policy"])
    if "policy" in allowed:
        for field in _POLICY_FIELDS:
            left_scenario["server"].pop(field)
            right_scenario["server"].pop(field)
            left_policy.pop(field)
            right_policy.pop(field)
    else:
        if left_metadata["scenario_sha256"] != right_metadata["scenario_sha256"]:
            raise ComparisonError("scenario_hash_mismatch")
    if left_scenario != right_scenario:
        raise ComparisonError("scenario_identity_mismatch")
    if left_policy != right_policy:
        raise ComparisonError("configured_policy_mismatch")

    left_source = copy.deepcopy(baseline["source"])
    right_source = copy.deepcopy(candidate["source"])
    if "engine-source" in allowed:
        left_source["engine"].pop("commit")
        right_source["engine"].pop("commit")
        for field in ("build_id", "binary_sha256", "source_snapshot_id"):
            left_source["build"].pop(field)
            right_source["build"].pop(field)
    else:
        if left_metadata["source_manifest_sha256"] != right_metadata["source_manifest_sha256"]:
            raise ComparisonError("source_manifest_hash_mismatch")
    if left_source != right_source:
        raise ComparisonError("source_identity_mismatch")


def _summary_deltas(
    baseline: Mapping[str, object], candidate: Mapping[str, object]
) -> dict[str, object]:
    return {
        "wall_duration_ns": _numeric_delta(
            baseline["wall_duration_ns"], candidate["wall_duration_ns"]
        ),
        "throughput": {
            key: _numeric_delta(baseline["throughput"][key], candidate["throughput"][key])
            for key in sorted(baseline["throughput"])
        },
        "latency": {
            family: {
                statistic: _numeric_delta(
                    baseline["latency"][family][statistic],
                    candidate["latency"][family][statistic],
                )
                for statistic in ("median", "p50", "p95", "p99", "max")
            }
            for family in sorted(baseline["latency"])
        },
    }


def _numeric_delta(baseline: object, candidate: object) -> int | float | None:
    if (
        baseline is None
        or candidate is None
        or isinstance(baseline, bool)
        or isinstance(candidate, bool)
        or not isinstance(baseline, (int, float))
        or not isinstance(candidate, (int, float))
    ):
        return None
    return candidate - baseline
