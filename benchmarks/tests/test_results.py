from __future__ import annotations

import base64
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

import ds4bench.artifacts as artifact_module
from ds4bench.artifacts import (
    ArtifactError,
    RESULT_FILES,
    ResultWriter,
    validate_normalized_scenario,
    verify_result,
)
from ds4bench.client import RequestSample
from ds4bench.compare import ComparisonError, compare_results
from ds4bench.redaction import (
    BoundedRedactedLog,
    CanarySet,
    RedactionError,
    error_record,
    redact_structure,
)
from ds4bench.stats import (
    StatisticsError,
    canonical_json_bytes,
    compute_summary,
    distribution,
    nearest_rank,
    validate_request_sample,
)

_HASH = "a" * 64


def _scenario(*, vantage: str = "controller_lan", policy: str = "shipped") -> dict[str, object]:
    server = {
        "context_tokens": 262144,
        "default_output_tokens": 393216,
        "decode_policy": policy,
        "dspark_max_nlive": 1,
        "terminal_yield_quench": True,
        "speculative_overrides": {
            "shadow_guard": None,
            "shadow_alpha": None,
            "shadow_min_evidence": None,
            "shadow_budget": None,
            "shadow_credit_cap": None,
        },
    }
    return {
        "version": 1,
        "id": "S5A",
        "description": "bounded result fixture",
        "vantage": vantage,
        "server": server,
        "prompts": [
            {
                "id": "long",
                "path": "benchmarks/prompts/artifacts/long.txt",
                "sha256": "b" * 64,
                "token_count": 1000,
                "license": "CC0-1.0",
            }
        ],
        "requests": [
            {
                "id": "request-1",
                "prompt_id": "long",
                "start_offset_ms": 0,
                "trigger": None,
                "output_budget": {"kind": "explicit", "tokens": 512},
            },
            {
                "id": "request-2",
                "prompt_id": "long",
                "start_offset_ms": 0,
                "trigger": None,
                "output_budget": {"kind": "explicit", "tokens": 512},
            },
        ],
        "schedule": {
            "kind": "offsets",
            "case_matrix": [
                {"id": "one", "request_ids": ["request-1"]},
                {"id": "two", "request_ids": ["request-1", "request-2"]},
            ],
        },
        "sampling": {"temperature": 0.0, "top_p": 1.0, "seed": 0},
        "warmup_repetitions": 1,
        "measured_repetitions": 5,
        "deadlines": {
            "connect_seconds": 1.0,
            "read_seconds": 2.0,
            "overall_seconds": 5.0,
            "server_seconds": 4.0,
        },
        "preconditions": {
            "server_restart_each_repetition": True,
            "cache_state": "cold",
            "warmup_server_is_separate": True,
            "cooldown_seconds": 0.0,
            "prompt_reuse": "allow",
        },
    }

def _policy_scenario(policy: str) -> dict[str, object]:
    scenario = _scenario(vantage="target_local", policy=policy)
    scenario["id"] = "S1"
    scenario["description"] = "paired policy result fixture"
    scenario["prompts"] = [
        {
            "id": "short",
            "path": "benchmarks/prompts/artifacts/short.txt",
            "sha256": "b" * 64,
            "token_count": 1_000,
            "license": "CC0-1.0",
        },
        {
            "id": "long",
            "path": "benchmarks/prompts/artifacts/long.txt",
            "sha256": "c" * 64,
            "token_count": 32_000,
            "license": "CC0-1.0",
        },
    ]
    scenario["requests"] = [
        {
            "id": "request-1",
            "prompt_id": "short",
            "start_offset_ms": 0,
            "trigger": None,
            "output_budget": {"kind": "explicit", "tokens": 128},
        },
        {
            "id": "request-2",
            "prompt_id": "long",
            "start_offset_ms": 0,
            "trigger": None,
            "output_budget": {"kind": "explicit", "tokens": 128},
        },
    ]
    scenario["schedule"] = {
        "kind": "offsets",
        "case_matrix": [
            {"id": "short-c1", "request_ids": ["request-1"]},
            {"id": "long-c1", "request_ids": ["request-2"]},
        ],
    }
    return scenario


def _source(*, engine_commit: str = "2" * 40, build_id: str = "build-a") -> dict[str, object]:
    available = lambda value: {"status": "available", "value": value}
    target = {
        "os": available("Linux"),
        "kernel": available("kernel"),
        "arch": available("aarch64"),
        "hardware_vendor": available("NVIDIA"),
        "hardware_model": available("DGX Spark"),
        "soc": available("GB10"),
        "gpu": available("SM121"),
        "compute_capability": available("12.1"),
        "firmware": {"status": "unavailable", "value": None},
        "driver": available("driver"),
        "cuda": available("cuda"),
        "nvcc": available("nvcc"),
        "c_compiler": available("cc"),
        "cpp_compiler": available("cxx"),
        "clock_sync": available("synchronized"),
    }
    return {
        "schema_version": 1,
        "lab": {
            "url": "https://example.invalid/lab.git",
            "commit": "1" * 40,
            "clean": True,
            "source_snapshot_id": "snapshot-a",
            "applied_tree_hash": "1" * 64,
        },
        "engine": {
            "url": "https://example.invalid/engine.git",
            "commit": engine_commit,
            "clean": True,
        },
        "integration": {
            "url": "https://example.invalid/integration.git",
            "commit": "3" * 40,
            "clean": True,
        },
        "userspace": {
            "flake_lock_sha256": "4" * 64,
            "nixpkgs_revision": "5" * 40,
            "python_version": "3.12.3",
            "uv_version": "0.8.0",
        },
        "controller": {"os": "Linux", "kernel": "kernel", "arch": "x86_64"},
        "target": target,
        "build": {
            "build_id": build_id,
            "binary_sha256": ("6" if build_id == "build-a" else "7") * 64,
            "source_snapshot_id": "snapshot-a" if build_id == "build-a" else "snapshot-b",
        },
        "weights": {"model_sha256": "8" * 64, "drafter_sha256": "9" * 64},
    }


def _metadata(
    run_id: str,
    scenario: dict[str, object],
    *,
    network_speed: int | None = 1000,
    order: str = "A",
) -> dict[str, object]:
    vantage = scenario["vantage"]
    runtime = None
    if vantage == "target_local":
        runtime = {
            "bundle_sha256": "a" * 64,
            "manifest_sha256": "b" * 64,
            "lock_sha256": "c" * 64,
        }
    return {
        "schema_version": 1,
        "run_id": run_id,
        "scenario_id": scenario["id"],
        "prompt_manifest_sha256": "d" * 64,
        "vantage": vantage,
        "clock_domain": "controller_monotonic",
        "started_utc": "2026-08-10T00:00:00Z",
        "configured_policy": copy.deepcopy(scenario["server"]),
        "observed_execution": {
            "status": "unavailable",
            "reason": "not_exposed_by_frozen_source",
        },
        "network": {
            "path": "direct_private_lan" if vantage == "controller_lan" else "target_loopback",
            "http_version": "HTTP/1.1",
            "tls": False,
            "link_speed_mbps": network_speed,
            "mtu_bytes": 1500,
        },
        "warmup_repetitions": scenario["warmup_repetitions"],
        "measured_repetitions": scenario["measured_repetitions"],
        "pairing": {
            "pair_id": "pair-a",
            "block_id": "block-a",
            "order": order,
            "repetition": 0,
        },
        "runtime_bundle": runtime,
    }


def _sample(
    run_id: str,
    request_id: str = "request-1",
    *,
    finish_class: str = "stop",
    error_class: str | None = None,
    generated_tokens: int | None = 2,
    start_ns: int = 1_000_000_000,
) -> dict[str, object]:
    successful = finish_class in {"stop", "length", "tool_calls", "content_filter"}
    return {
        "schema_version": 1,
        "scenario_run_id": run_id,
        "request_id": request_id,
        "repetition": 0,
        "scheduled_offset_ns": 0,
        "send_ns": start_ns,
        "http_accept_ns": start_ns + 10,
        "first_byte_ns": start_ns + 20,
        "first_model_token_ns": start_ns + 100 if successful else None,
        "token_event_timestamps_ns": [start_ns + 100, start_ns + 200] if successful else [],
        "itl_ns": [100] if successful else [],
        "completion_ns": start_ns + 1_000_000_000,
        "status_code": 200 if successful else 500,
        "retry_count": 0,
        "retry_after": None,
        "finish_class": finish_class,
        "error_class": error_class,
        "redacted_error_body": None,
        "prompt_tokens": 100,
        "generated_tokens": generated_tokens,
        "output_budget_kind": "explicit",
        "output_budget_value": 512,
        "timing_granularity": "body_chunk",
    }


def _telemetry(run_id: str, *, value: float = 100.0) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "timestamp_ns": 1,
        "clock_domain": "controller_monotonic",
        "source": "nvidia_smi",
        "metric": "gpu_memory_used",
        "status": "available",
        "value": value,
        "unit": "bytes",
    }


def _write_result(
    root: Path,
    run_id: str,
    *,
    scenario: dict[str, object] | None = None,
    source: dict[str, object] | None = None,
    metadata: dict[str, object] | None = None,
    samples: list[dict[str, object]] | None = None,
) -> Path:
    scenario = copy.deepcopy(scenario or _scenario())
    source = copy.deepcopy(source or _source())
    metadata = copy.deepcopy(metadata or _metadata(run_id, scenario))
    if samples is None:
        sample = _sample(run_id)
        request = next(
            item for item in scenario["requests"] if item["id"] == sample["request_id"]
        )
        budget = request["output_budget"]
        sample["output_budget_kind"] = budget["kind"]
        sample["output_budget_value"] = budget.get("tokens")
        samples = [sample]
    writer = ResultWriter(root, metadata, scenario, source, [item["request_id"] for item in samples])
    for sample in samples:
        writer.append_sample(sample)
    writer.append_telemetry(_telemetry(run_id))
    writer.set_logs("server clean\n", "client clean\n")
    return writer.finalize()


class RedactionTests(unittest.TestCase):
    def test_explicit_plain_and_encoded_canaries_are_removed_across_chunks(self) -> None:
        lan_ip = "192.168.44.23"
        lan_url = f"http://{lan_ip}:8080"
        private_path = "/home/operator/private model"
        canaries = CanarySet.create(
            lan_ip=lan_ip,
            lan_url=lan_url,
            private_paths=[private_path],
        )
        encoded = " ".join(
            (
                lan_url,
                quote(lan_url, safe=""),
                base64.b64encode(lan_url.encode()).decode(),
                private_path,
                private_path.encode().hex(),
            )
        )
        log = BoundedRedactedLog(canaries, max_bytes=4096)
        midpoint = encoded.index(lan_ip) + 4
        log.write(encoded[:midpoint])
        log.write(encoded[midpoint:])
        payload, metadata = log.finish()
        retained = payload.decode()
        self.assertNotIn(lan_ip, retained)
        self.assertNotIn(lan_url, retained)
        self.assertNotIn(private_path, retained)
        self.assertNotIn(quote(lan_url, safe=""), retained)
        self.assertIn("[REDACTED:lan-url]", retained)
        self.assertFalse(metadata["truncated"])

    def test_exception_messages_are_never_structured_or_copied(self) -> None:
        secret = "private-exception-message"
        record = error_record(RuntimeError(secret), code="request_failed")
        self.assertNotIn(secret, json.dumps(record))
        with self.assertRaises(RedactionError):
            redact_structure(RuntimeError(secret), CanarySet.create())

    def test_multibyte_canary_crossing_log_ceiling_is_not_partially_exposed(self) -> None:
        canaries = CanarySet.create(values=[("secret", "密密密")])
        log = BoundedRedactedLog(canaries, max_bytes=2)
        log.write("x密密密tail")
        payload, metadata = log.finish()
        self.assertNotIn("密", payload.decode())
        self.assertTrue(metadata["truncated"])


class StatisticsTests(unittest.TestCase):
    def test_nearest_rank_boundaries_and_even_median_are_deterministic(self) -> None:
        self.assertEqual(nearest_rank([5, 1, 4, 3, 2], 50), 3)
        self.assertEqual(nearest_rank([5, 1, 4, 3, 2], 95), 5)
        self.assertEqual(nearest_rank([5, 1, 4, 3, 2], 99), 5)
        result = distribution([4, 1, 3, 2], total=7)
        self.assertEqual(result["median"], 2.5)
        self.assertEqual(result["p50"], 2)
        self.assertEqual(result["total"], 7)

    def test_request_sample_to_dict_is_the_raw_validator_contract(self) -> None:
        expected = _sample("run-client-contract")
        constructor = dict(expected)
        constructor["token_event_timestamps_ns"] = tuple(
            constructor["token_event_timestamps_ns"]
        )
        constructor["itl_ns"] = tuple(constructor["itl_ns"])
        sample = RequestSample(**constructor)
        self.assertEqual(sample.to_dict(), expected)
        self.assertEqual(validate_request_sample(sample.to_dict()), expected)

    def test_normalized_scenario_types_and_plain_policy_scope_are_exact(self) -> None:
        scenario = _scenario()
        self.assertIs(validate_normalized_scenario(scenario), scenario)
        non_normalized = copy.deepcopy(scenario)
        non_normalized["preconditions"]["cooldown_seconds"] = 0
        with self.assertRaises(ArtifactError):
            validate_normalized_scenario(non_normalized)
        invalid_plain = _scenario(policy="plain")
        with self.assertRaises(ArtifactError):
            validate_normalized_scenario(invalid_plain)

    def test_normalized_s1_matrix_depends_on_measurement_vantage(self) -> None:
        for policy in ("shipped", "plain"):
            with self.subTest(policy=policy):
                scenario = _policy_scenario(policy)
                self.assertIs(validate_normalized_scenario(scenario), scenario)

        extra_concurrency = _policy_scenario("shipped")
        extra_concurrency["requests"].append(
            {
                "id": "request-3",
                "prompt_id": "short",
                "start_offset_ms": 0,
                "trigger": None,
                "output_budget": {"kind": "explicit", "tokens": 128},
            }
        )
        extra_concurrency["schedule"]["case_matrix"].append(
            {"id": "short-c2", "request_ids": ["request-1", "request-3"]}
        )
        with self.assertRaisesRegex(ArtifactError, "invalid_s1_matrix"):
            validate_normalized_scenario(extra_concurrency)

        controller_minimal = _policy_scenario("shipped")
        controller_minimal["vantage"] = "controller_lan"
        with self.assertRaisesRegex(ArtifactError, "invalid_s1_matrix"):
            validate_normalized_scenario(controller_minimal)

    def test_all_scheduled_denominators_and_unavailable_values_survive(self) -> None:
        scenario = _scenario()
        metadata = _metadata("run-stats", scenario)
        metadata.update(
            {
                "result_state": "failed",
                "scenario_sha256": _HASH,
                "source_manifest_sha256": _HASH,
                "completed_utc": "2026-08-10T00:00:01Z",
                "logs": {
                    "server": {"sha256": _HASH, "retained_bytes": 0, "truncated": False, "total_bytes": 0},
                    "client": {"sha256": _HASH, "retained_bytes": 0, "truncated": False, "total_bytes": 0},
                },
                "primary_error": None,
                "cleanup_error": None,
            }
        )
        incomplete = _sample("run-stats", "request-2")
        incomplete.update(
            {
                "send_ns": None,
                "http_accept_ns": None,
                "first_byte_ns": None,
                "first_model_token_ns": None,
                "token_event_timestamps_ns": [],
                "itl_ns": [],
                "completion_ns": None,
                "status_code": None,
                "finish_class": "incomplete",
                "error_class": None,
                "prompt_tokens": None,
                "generated_tokens": None,
                "timing_granularity": "unavailable",
            }
        )
        summary = compute_summary(
            metadata,
            scenario,
            [_sample("run-stats"), incomplete],
            [],
            requests_sha256=_HASH,
            telemetry_sha256=_HASH,
        )
        self.assertEqual(summary["counts"]["scheduled"], 2)
        self.assertEqual(summary["counts"]["completed"], 1)
        self.assertEqual(summary["latency"]["completion_ns"]["total"], 2)
        self.assertEqual(summary["counts"]["latency"]["completion"], {"completed": 1, "total": 2})
        self.assertEqual(summary["throughput"]["completed_requests_per_second"], 1.0)
        self.assertEqual(summary["throughput"]["scheduled_requests_per_second"], 2.0)
        self.assertIsNone(summary["throughput"]["generated_tokens_per_second"])
        self.assertIsNone(summary["scenario_metrics"]["usage"]["generated_tokens"])
        self.assertEqual(summary["failures"]["incomplete"], 1)


class ResultWriterTests(unittest.TestCase):
    def test_raw_stream_is_closed_and_present_before_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario = _scenario()
            writer = ResultWriter(root, _metadata("run-order", scenario), scenario, _source(), ["request-1"])
            writer.append_sample(_sample("run-order"))
            writer.set_logs("", "")
            original = artifact_module.compute_summary
            observed: list[bool] = []

            def checking_summary(*args: object, **kwargs: object) -> dict[str, object]:
                observed.append(
                    writer._requests_stream.closed
                    and (writer.staging_path / "requests.jsonl").read_bytes().endswith(b"\n")
                    and not (writer.staging_path / "summary.json").exists()
                )
                return original(*args, **kwargs)

            with patch.object(artifact_module, "compute_summary", side_effect=checking_summary):
                result = writer.finalize()
            self.assertEqual(observed, [True])
            self.assertEqual({item.name for item in result.iterdir()}, RESULT_FILES)

    def test_duplicate_settlement_is_rejected_and_missing_is_materialized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario = _scenario()
            duplicate = ResultWriter(root, _metadata("run-duplicate", scenario), scenario, _source(), ["request-1"])
            duplicate.append_sample(_sample("run-duplicate"))
            with self.assertRaisesRegex(ArtifactError, "duplicate_request_settlement"):
                duplicate.append_sample(_sample("run-duplicate"))
            duplicate.set_logs("", "")
            duplicate.finalize()

            missing = ResultWriter(root, _metadata("run-missing", scenario), scenario, _source(), ["request-1", "request-2"])
            missing.append_sample(_sample("run-missing"))
            missing.set_logs("", "")
            path = missing.finalize()
            records = [json.loads(line) for line in (path / "requests.jsonl").read_text().splitlines()]
            self.assertEqual(len(records), 2)
            self.assertEqual(records[1]["request_id"], "request-2")
            self.assertEqual(records[1]["finish_class"], "incomplete")
            self.assertIsNone(records[1]["error_class"])
            metadata = json.loads((path / "metadata.json").read_bytes())
            self.assertEqual(metadata["result_state"], "failed")
            self.assertEqual(metadata["primary_error"], {"class": "incomplete", "code": "missing_settlement"})

    def test_failure_bundle_is_promoted_and_cleanup_error_is_secondary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario = _scenario()
            writer = ResultWriter(
                root,
                _metadata("run-failure", scenario),
                scenario,
                _source(),
                ["request-1"],
                canaries=CanarySet.create(private_paths=["/private/model"]),
                log_limit_bytes=12,
            )
            writer.append_sample(
                _sample(
                    "run-failure",
                    finish_class="error",
                    error_class="http_error",
                    generated_tokens=None,
                )
            )
            writer.set_logs("/private/model and trailing", "client")
            path = writer.finalize(
                primary_error={"class": "http", "code": "request_failed"},
                cleanup_error={"class": "cleanup", "code": "stop_failed"},
            )
            self.assertTrue(path.is_dir())
            metadata = json.loads((path / "metadata.json").read_bytes())
            self.assertEqual(metadata["result_state"], "failed")
            self.assertEqual(metadata["primary_error"]["code"], "request_failed")
            self.assertEqual(metadata["cleanup_error"]["code"], "stop_failed")
            self.assertTrue(metadata["logs"]["server"]["truncated"])
            self.assertNotIn("/private/model", (path / "server.log").read_text())
            verify_result(path)

    def test_verify_reproduces_summary_bytes_and_detects_all_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = _write_result(root, "run-verify")
            before = (original / "summary.json").read_bytes()
            first = verify_result(original)
            second = verify_result(original)
            self.assertEqual(first, second)
            self.assertEqual((original / "summary.json").read_bytes(), before)

            requests_copy = root / "tamper-requests"
            shutil.copytree(original, requests_copy)
            with (requests_copy / "requests.jsonl").open("ab") as stream:
                stream.write(b" ")
            with self.assertRaises((ArtifactError, StatisticsError)):
                verify_result(requests_copy)

            offset_copy = root / "tamper-offset"
            shutil.copytree(original, offset_copy)
            request = json.loads((offset_copy / "requests.jsonl").read_bytes())
            request["scheduled_offset_ns"] = 1
            (offset_copy / "requests.jsonl").write_bytes(canonical_json_bytes(request))
            with self.assertRaises(ArtifactError):
                verify_result(offset_copy)

            telemetry_copy = root / "tamper-telemetry"
            shutil.copytree(original, telemetry_copy)
            with (telemetry_copy / "telemetry.jsonl").open("ab") as stream:
                stream.write(canonical_json_bytes(_telemetry("run-verify", value=101.0)))
            with self.assertRaises((ArtifactError, StatisticsError)):
                verify_result(telemetry_copy)

            extra_copy = root / "extra-file"
            shutil.copytree(original, extra_copy)
            (extra_copy / "unexpected.txt").write_text("unexpected")
            with self.assertRaisesRegex(ArtifactError, "result_file_set"):
                verify_result(extra_copy)

            missing_copy = root / "missing-file"
            shutil.copytree(original, missing_copy)
            (missing_copy / "summary.md").unlink()
            with self.assertRaisesRegex(ArtifactError, "result_file_set"):
                verify_result(missing_copy)


class ComparisonTests(unittest.TestCase):
    def test_policy_and_engine_source_are_the_only_allowed_identity_differences(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline_scenario = _policy_scenario("shipped")
            baseline = _write_result(
                root,
                "run-base",
                scenario=baseline_scenario,
                metadata=_metadata("run-base", baseline_scenario),
            )

            policy_scenario = _policy_scenario("plain")
            policy = _write_result(
                root,
                "run-policy",
                scenario=policy_scenario,
                metadata=_metadata("run-policy", policy_scenario, order="B"),
            )
            with self.assertRaises(ComparisonError):
                compare_results(baseline, policy)
            comparison = compare_results(
                baseline, policy, allow_differences=["policy", "policy"]
            )
            self.assertEqual(comparison["allowed_differences"], ["policy"])
            self.assertEqual(comparison["pairing"]["baseline"]["order"], "A")
            self.assertEqual(comparison["pairing"]["candidate"]["order"], "B")

            engine_source = _source(engine_commit="e" * 40, build_id="build-b")
            engine = _write_result(
                root,
                "run-engine",
                scenario=baseline_scenario,
                source=engine_source,
                metadata=_metadata("run-engine", baseline_scenario),
            )
            compare_results(baseline, engine, allow_differences=["engine-source"])
            with self.assertRaises(ComparisonError):
                compare_results(baseline, engine, allow_differences=["policy"])

            changed_network_scenario = _policy_scenario("plain")
            changed_network = _write_result(
                root,
                "run-network",
                scenario=changed_network_scenario,
                metadata=_metadata("run-network", changed_network_scenario, network_speed=2500),
            )
            with self.assertRaisesRegex(ComparisonError, "network_mismatch"):
                compare_results(
                    baseline,
                    changed_network,
                    allow_differences=["policy", "engine-source"],
                )

    def test_controller_lan_and_target_local_results_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lan = _write_result(root, "run-lan")
            local_scenario = _scenario(vantage="target_local")
            local = _write_result(
                root,
                "run-local",
                scenario=local_scenario,
                metadata=_metadata("run-local", local_scenario),
            )
            with self.assertRaisesRegex(ComparisonError, "vantage_mismatch"):
                compare_results(
                    lan,
                    local,
                    allow_differences=["policy", "engine-source"],
                )

    def test_unknown_allowed_difference_is_rejected(self) -> None:
        with self.assertRaisesRegex(ComparisonError, "invalid_allowed_difference"):
            compare_results("missing-a", "missing-b", allow_differences=["hardware"])


if __name__ == "__main__":
    unittest.main()
