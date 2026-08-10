from __future__ import annotations

from dataclasses import replace
import base64
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from benchmarks.src.ds4bench.schema import ScenarioError
from benchmarks.src.ds4bench.stats import canonical_json_bytes
from scripts.targetctl.benchmark import (
    BASELINE_OPERATIONS,
    CHUNK_BYTES,
    SCENARIOS,
    PreparedBenchmark,
    StageFile,
    _download_target,
    _inspect_file,
    _metadata,
    _plan,
    _source_manifest,
    _stage,
    _stage_manifest,
    execute_benchmark,
    prepare_benchmark,
    run_baseline,
    run_paired_s1_controls,
    run_repetition,
    run_scenario,
    structured_benchmark_result,
)
from scripts.targetctl.common import TargetError
from scripts.targetctl.doctor import DOCTOR_TOOLS, DoctorResult
from scripts.targetctl.lifecycle import RuntimeInputs


class _RecordingTransport:
    def __init__(self, *, committed: bool = False, tamper: bool = False) -> None:
        self.committed = committed
        self.tamper = tamper
        self.calls: list[tuple[str, dict[str, object]]] = []

    def run_helper(self, action, payload, **_kwargs):
        self.calls.append((action, dict(payload)))
        if action == "benchmark_stage_begin":
            return {"status": "committed" if self.committed else "ready"}
        if action == "benchmark_stage_chunk":
            if self.tamper:
                return {"offset": payload["offset"], "size": 0}
            content = base64.b64decode(payload["content_b64"], validate=True)
            return {"offset": payload["offset"], "size": len(content)}
        if action == "benchmark_stage_commit":
            return {"status": "committed"}
        raise AssertionError(action)


def _scenario(vantage: str = "controller_lan") -> SimpleNamespace:
    return SimpleNamespace(
        id="S1",
        vantage=vantage,
        prompts=(),
        warmup_repetitions=1,
        measured_repetitions=2,
        deadlines=SimpleNamespace(server_seconds=5.0),
        preconditions=SimpleNamespace(cooldown_seconds=0.0),
        schedule=SimpleNamespace(case_matrix=(SimpleNamespace(id="c1"),)),
    )


def _prepared(root: Path, transport=None, vantage: str = "controller_lan") -> PreparedBenchmark:
    root.mkdir(parents=True, exist_ok=True)
    runtime_dir = root / "runtime"
    runtime_dir.mkdir()
    payload_dir = runtime_dir / "payload"
    payload_dir.mkdir()
    bundle = payload_dir / "ds4bench.pyz"
    licenses = payload_dir / "licenses.json"
    runtime_manifest = runtime_dir / "runtime-manifest.json"
    bundle.write_bytes(b"bundle")
    licenses.write_bytes(b"licenses")
    runtime_manifest.write_bytes(b"manifest")
    prompt_manifest = root / "benchmarks" / "prompts" / "manifest.json"
    prompt_manifest.parent.mkdir(parents=True)
    prompt_manifest.write_bytes(b"{}")
    portable = SimpleNamespace(
        bundle_path=bundle,
        licenses_path=licenses,
        manifest_path=runtime_manifest,
        bundle_sha256=hashlib.sha256(b"bundle").hexdigest(),
        licenses_sha256=hashlib.sha256(b"licenses").hexdigest(),
        manifest_sha256=hashlib.sha256(b"manifest").hexdigest(),
        lock_sha256="a" * 64,
    )
    config = SimpleNamespace(
        name="spark",
        mode="ssh",
        run_dir="/srv/lab/targetctl/run",
        source_root=root,
        lan_api_base_url="http://192.168.1.20:8000",
        lan_bind_host="192.168.1.20",
    )
    runtime = SimpleNamespace(run_token="b" * 64, port=8000)
    normalized = {
        "server": {
            "context_tokens": 32768,
            "default_output_tokens": 393216,
            "decode_policy": "shipped",
            "dspark_max_nlive": 1,
            "terminal_yield_quench": True,
            "speculative_overrides": {"shadow_guard": None, "shadow_alpha": None, "shadow_min_evidence": None, "shadow_budget": None, "shadow_credit_cap": None},
        }
    }
    return PreparedBenchmark(
        root,
        config,
        transport or _RecordingTransport(),
        SimpleNamespace(),
        {"build_id": "c" * 64},
        runtime,
        root / "benchmarks/scenarios/s1.json",
        _scenario(vantage),
        normalized,
        portable,
        {},
        hashlib.sha256(b"{}").hexdigest(),
        root / "results",
    )


class StageTransferContracts(unittest.TestCase):
    def test_manifest_framing_and_chunk_boundaries_are_bounded(self) -> None:
        content = b"x" * (CHUNK_BYTES + 1)
        manifest = _stage_manifest("b-abc", (StageFile("file.bin", len(content), hashlib.sha256(content).hexdigest(), content=content),))
        self.assertEqual(manifest["entries"][0]["size"], CHUNK_BYTES + 1)
        self.assertRegex(manifest["aggregate_sha256"], r"^[0-9a-f]{64}$")

    def test_stage_uses_multiple_chunks_and_exact_idempotent_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared = _prepared(root)
            large = prepared.portable.bundle_path
            large.write_bytes(b"x" * (CHUNK_BYTES + 1))
            prepared.portable.bundle_sha256 = hashlib.sha256(large.read_bytes()).hexdigest()
            metadata = {"schema_version": 1}
            _stage(prepared, "b-abc", metadata)
            actions = [action for action, _payload in prepared.transport.calls]
            self.assertGreaterEqual(actions.count("benchmark_stage_chunk"), 2)
            self.assertEqual(actions[-1], "benchmark_stage_commit")

            committed = _RecordingTransport(committed=True)
            prepared = _prepared(root / "second", committed)
            _stage(prepared, "b-def", metadata)
            self.assertEqual([action for action, _ in committed.calls], ["benchmark_stage_begin"])

    def test_tampered_chunk_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prepared = _prepared(Path(temporary), _RecordingTransport(tamper=True))
            with self.assertRaisesRegex(TargetError, "benchmark_chunk_invalid"):
                _stage(prepared, "b-abc", {"schema_version": 1})

    def test_symlink_and_hardlink_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"content")
            symlink = root / "link"
            symlink.symlink_to(source)
            with self.assertRaisesRegex(TargetError, "benchmark_input_invalid"):
                _inspect_file(symlink, 100)
            hardlink = root / "hardlink"
            os.link(source, hardlink)
            with self.assertRaisesRegex(TargetError, "benchmark_input_invalid"):
                _inspect_file(source, 100)

    def test_result_download_streams_above_helper_response_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prepared = _prepared(Path(temporary))
            prepared.result_root.mkdir()
            content = b"z" * (CHUNK_BYTES * 3 + 17)
            entry = {"path": "requests.jsonl", "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            manifest = {"schema_version": 1, "kind": "result", "run_id": "b-abc", "entries": [entry], "aggregate_sha256": "c" * 64, "lock_sha256": "a" * 64}
            manifest_sha = hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
            offsets: list[int] = []

            def helper(_prepared, action, payload, timeout=30.0):
                del timeout
                if action == "benchmark_result_prepare":
                    return {"manifest": manifest, "manifest_sha256": manifest_sha}
                self.assertEqual(action, "benchmark_result_chunk")
                offset, length = payload["offset"], payload["length"]
                offsets.append(offset)
                chunk = content[offset : offset + length]
                return {"content_b64": base64.b64encode(chunk).decode("ascii"), "offset": offset, "size": len(chunk), "chunk_sha256": hashlib.sha256(chunk).hexdigest(), "eof": offset + len(chunk) == len(content)}

            promotion = SimpleNamespace(path=prepared.result_root / "b-abc")
            with patch("scripts.targetctl.benchmark._helper", side_effect=helper), patch("scripts.targetctl.benchmark.validate_transfer_manifest", return_value=manifest), patch("scripts.targetctl.benchmark.promote_verified_payload", return_value=promotion), patch("scripts.targetctl.benchmark.verify_result"):
                result = _download_target(prepared, "b-abc")
            self.assertEqual(result, promotion.path)
            self.assertEqual(offsets, [0, CHUNK_BYTES, CHUNK_BYTES * 2, CHUNK_BYTES * 3])

class PreflightContracts(unittest.TestCase):
    def test_scenario_validation_precedes_target_config_and_serve(self) -> None:
        with patch(
            "scripts.targetctl.benchmark.load_scenario",
            side_effect=ScenarioError("invalid_json"),
        ), patch("scripts.targetctl.workflow.load_operational_target") as config, patch(
            "scripts.targetctl.benchmark.serve"
        ) as launched:
            with self.assertRaisesRegex(TargetError, "benchmark_scenario_invalid"):
                prepare_benchmark(".", "spark", Path("benchmarks/scenarios/s1.json"))
        config.assert_not_called()
        launched.assert_not_called()

    def test_prepared_scenario_derives_lease_from_server_and_startup_horizons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario = _scenario()
            scenario.deadlines = SimpleNamespace(server_seconds=7000.0)
            config = SimpleNamespace(
                name="spark",
                mode="ssh",
                source_root=root,
                validate_for=lambda _operation: None,
            )
            source = SimpleNamespace(as_dict=lambda: {"snapshot_id": "source"})
            build = {"build_id": "c" * 64}
            runtime = RuntimeInputs(
                model_path="/models/model",
                drafter_path="/models/drafter",
                source_snapshot_id="a" * 64,
                applied_tree_hash="b" * 64,
                build_id="c" * 64,
                port=8000,
                startup_timeout=120.0,
            )
            portable = SimpleNamespace(
                payload_dir=root / "payload",
                manifest_path=root / "runtime-manifest.json",
                manifest_sha256="d" * 64,
                aggregate_sha256="e" * 64,
                lock_sha256="f" * 64,
            )
            with (
                patch("scripts.targetctl.workflow._root", return_value=root),
                patch("scripts.targetctl.benchmark.load_scenario", return_value=scenario),
                patch("scripts.targetctl.benchmark.normalize_scenario", return_value={}),
                patch("scripts.targetctl.workflow.load_operational_target", return_value=config),
                patch("scripts.targetctl.benchmark.select_transport", return_value=SimpleNamespace()),
                patch("scripts.targetctl.workflow._ready", return_value=(source, build)),
                patch("scripts.targetctl.workflow.build_snapshot", return_value=source),
                patch("scripts.targetctl.workflow._verify_current_binary"),
                patch("scripts.targetctl.workflow._runtime", return_value=runtime),
                patch("scripts.targetctl.benchmark.build_runtime_bundle", return_value=portable),
                patch("scripts.targetctl.benchmark.verify_transfer"),
                patch(
                    "scripts.targetctl.benchmark.doctor",
                    return_value=SimpleNamespace(status="succeeded"),
                ),
                patch("scripts.targetctl.benchmark._source_manifest", return_value={}),
                patch(
                    "scripts.targetctl.benchmark._inspect_file",
                    return_value=(2, "1" * 64, ()),
                ),
            ):
                prepared = prepare_benchmark(
                    root,
                    "spark",
                    Path("benchmarks/scenarios/s1.json"),
                )

            self.assertIsNot(prepared.runtime, runtime)
            self.assertEqual(runtime.lease_seconds, 300)
            self.assertEqual(prepared.runtime.lease_seconds, 7150)

    def test_impossible_scenario_horizon_fails_before_doctor_or_serve(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario = _scenario()
            scenario.deadlines = SimpleNamespace(server_seconds=7036.0)
            config = SimpleNamespace(
                name="spark",
                mode="ssh",
                source_root=root,
                validate_for=lambda _operation: None,
            )
            source = SimpleNamespace(as_dict=lambda: {"snapshot_id": "source"})
            build = {"build_id": "c" * 64}
            runtime = RuntimeInputs(
                model_path="/models/model",
                drafter_path="/models/drafter",
                source_snapshot_id="a" * 64,
                applied_tree_hash="b" * 64,
                build_id="c" * 64,
                port=8000,
                startup_timeout=120.0,
            )
            with (
                patch("scripts.targetctl.workflow._root", return_value=root),
                patch("scripts.targetctl.benchmark.load_scenario", return_value=scenario),
                patch("scripts.targetctl.benchmark.normalize_scenario", return_value={}),
                patch("scripts.targetctl.workflow.load_operational_target", return_value=config),
                patch("scripts.targetctl.benchmark.select_transport", return_value=SimpleNamespace()),
                patch("scripts.targetctl.workflow._ready", return_value=(source, build)),
                patch("scripts.targetctl.workflow.build_snapshot", return_value=source),
                patch("scripts.targetctl.workflow._verify_current_binary"),
                patch("scripts.targetctl.workflow._runtime", return_value=runtime),
                patch("scripts.targetctl.benchmark.build_runtime_bundle") as bundled,
                patch("scripts.targetctl.benchmark.doctor") as checked,
                patch("scripts.targetctl.benchmark.serve") as launched,
            ):
                with self.assertRaises(TargetError) as caught:
                    prepare_benchmark(
                        root,
                        "spark",
                        Path("benchmarks/scenarios/s1.json"),
                    )

            self.assertEqual(caught.exception.code, "benchmark_scenario_invalid")
            bundled.assert_not_called()
            checked.assert_not_called()
            launched.assert_not_called()


class OperationRoutingContracts(unittest.TestCase):
    def _paired_prepared(
        self,
        root: Path,
    ) -> tuple[PreparedBenchmark, PreparedBenchmark]:
        shipped = _prepared(root / "shipped", vantage="target_local")
        plain = _prepared(root / "plain", vantage="target_local")
        cases = (
            SimpleNamespace(id="short-c1"),
            SimpleNamespace(id="medium-c1"),
        )
        shipped_scenario = _scenario("target_local")
        shipped_scenario.measured_repetitions = 5
        shipped_scenario.schedule.case_matrix = cases
        plain_scenario = _scenario("target_local")
        plain_scenario.measured_repetitions = 5
        plain_scenario.schedule.case_matrix = cases
        server = dict(shipped.normalized["server"])
        return (
            replace(
                shipped,
                scenario=shipped_scenario,
                normalized={
                    "description": "shipped control",
                    "server": {**server, "decode_policy": "shipped"},
                },
            ),
            replace(
                plain,
                scenario=plain_scenario,
                normalized={
                    "description": "plain control",
                    "server": {**server, "decode_policy": "plain"},
                },
            ),
        )

    def test_paired_controls_run_warmups_then_ab_ba_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            shipped, plain = self._paired_prepared(Path(temporary))
            calls: list[tuple[str, str, int, bool, object]] = []

            def repeated(prepared, case_id, repetition, *, retain, pairing=None):
                label = "shipped" if prepared is shipped else "plain"
                calls.append((label, case_id, repetition, retain, pairing))
                if not retain:
                    return None
                return prepared.result_root / f"{case_id}-r{repetition}"

            with patch(
                "scripts.targetctl.benchmark.prepare_benchmark",
                side_effect=(shipped, plain),
            ), patch(
                "scripts.targetctl.benchmark.run_repetition",
                side_effect=repeated,
            ):
                result = run_paired_s1_controls(".", "spark")

        expected: list[tuple[str, str, int, bool]] = [
            ("shipped", "short-c1", 0, False),
            ("plain", "short-c1", 0, False),
            ("shipped", "medium-c1", 0, False),
            ("plain", "medium-c1", 0, False),
        ]
        for case_id in ("short-c1", "medium-c1"):
            for repetition in range(5):
                labels = (
                    ("shipped", "plain")
                    if repetition % 2 == 0
                    else ("plain", "shipped")
                )
                expected.extend(
                    (label, case_id, repetition, True) for label in labels
                )
        self.assertEqual([entry[:4] for entry in calls], expected)
        self.assertTrue(all(entry[4] is None for entry in calls[:4]))

        measured = calls[4:]
        for case_id in ("short-c1", "medium-c1"):
            blocks: dict[int, str] = {}
            for repetition in range(5):
                pair = [
                    entry
                    for entry in measured
                    if entry[1:3] == (case_id, repetition)
                ]
                self.assertEqual(len(pair), 2)
                metadata = [entry[4] for entry in pair]
                self.assertEqual(metadata[0]["pair_id"], metadata[1]["pair_id"])
                self.assertEqual(metadata[0]["block_id"], metadata[1]["block_id"])
                self.assertEqual(
                    {entry[0]: entry[4]["order"] for entry in pair},
                    {"shipped": "A", "plain": "B"},
                )
                self.assertEqual(
                    {entry[4]["repetition"] for entry in pair},
                    {repetition},
                )
                blocks[repetition] = metadata[0]["block_id"]
            self.assertEqual(blocks[0], blocks[1])
            self.assertEqual(blocks[2], blocks[3])
            self.assertNotEqual(blocks[1], blocks[2])

        expected_artifacts = {
            label: [
                f"results/{case_id}-r{repetition}"
                for case_id in ("short-c1", "medium-c1")
                for repetition in range(5)
            ]
            for label in ("shipped", "plain")
        }
        self.assertEqual(result["artifacts"], expected_artifacts)
        self.assertEqual(
            result["alternation"],
            {
                "A": "shipped",
                "B": "plain",
                "even_repetition": "AB",
                "odd_repetition": "BA",
            },
        )
        self.assertEqual(
            result["measured_results"],
            {"shipped": 10, "plain": 10},
        )

    def test_paired_controls_fail_closed_on_scenario_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            shipped, plain = self._paired_prepared(Path(temporary))
            plain = replace(
                plain,
                normalized={
                    **plain.normalized,
                    "measured_repetitions": 6,
                },
            )
            with patch(
                "scripts.targetctl.benchmark.prepare_benchmark",
                side_effect=(shipped, plain),
            ), patch(
                "scripts.targetctl.benchmark.run_repetition",
            ) as repeated:
                with self.assertRaises(TargetError) as caught:
                    run_paired_s1_controls(".", "spark")
        self.assertEqual(
            caught.exception.code,
            "benchmark_paired_scenario_mismatch",
        )
        repeated.assert_not_called()

    def test_paired_operation_routes_to_alternating_runner(self) -> None:
        with patch(
            "scripts.targetctl.benchmark.run_paired_s1_controls",
            return_value={"status": "succeeded"},
        ) as paired:
            result = execute_benchmark(".", "spark", "bench-s1-local-paired")
        paired.assert_called_once_with(".", "spark")
        self.assertEqual(result, {"status": "succeeded"})

    def test_local_smoke_uses_shipped_control_and_first_case_only(self) -> None:
        with patch("scripts.targetctl.benchmark.run_scenario", return_value={"status": "succeeded"}) as dispatched:
            execute_benchmark(".", "spark", "bench-smoke-local")
        dispatched.assert_called_once_with(".", "spark", "bench-smoke-local", smoke=True)

        scenario = _scenario("target_local")
        scenario.schedule.case_matrix = (SimpleNamespace(id="first"), SimpleNamespace(id="second"))
        self.assertEqual(_plan(scenario, True), (("first", 0, True),))

    def test_target_local_controls_use_their_scenario_and_result_path(self) -> None:
        for operation in ("bench-s1-local-shipped", "bench-s1-local-plain"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                prepared = _prepared(root, vantage="target_local")
                promoted = prepared.result_root / f"{operation}-result"
                with patch("scripts.targetctl.benchmark.prepare_benchmark", return_value=prepared) as preflight, patch(
                    "scripts.targetctl.benchmark._plan",
                    return_value=(("c1", 0, True),),
                ), patch("scripts.targetctl.benchmark.run_repetition", return_value=promoted) as repeated:
                    result = run_scenario(root, "spark", operation)
                preflight.assert_called_once_with(root, "spark", SCENARIOS[operation])
                repeated.assert_called_once_with(prepared, "c1", 0, retain=True)
                self.assertEqual(result["vantage"], "target_local")
                self.assertEqual(result["artifacts"], [promoted.relative_to(root).as_posix()])

    def test_baseline_runs_primary_family_then_paired_local_controls(self) -> None:
        expected = (
            "bench-s1",
            "bench-s2",
            "bench-s3",
            "bench-s5a",
            "bench-s5b",
            "bench-s1-local-paired",
        )
        self.assertEqual(BASELINE_OPERATIONS, expected)
        dispatched: list[str] = []

        def scenario(_root, _target, operation):
            dispatched.append(operation)
            return {"operation": operation}

        def paired(_root, _target):
            dispatched.append("bench-s1-local-paired")
            return {"operation": "bench-s1-local-paired"}

        with patch(
            "scripts.targetctl.benchmark.run_scenario",
            side_effect=scenario,
        ), patch(
            "scripts.targetctl.benchmark.run_paired_s1_controls",
            side_effect=paired,
        ):
            result = run_baseline(".", "spark")
        self.assertEqual(dispatched, list(expected))
        self.assertEqual(
            result["scenarios"],
            [{"operation": operation} for operation in expected],
        )




class WorkflowDispatchContracts(unittest.TestCase):
    def _cleanup(self):
        return SimpleNamespace(status="succeeded", server_log_sha256=None)

    def _common_patches(self, prepared: PreparedBenchmark):
        return (
            patch("scripts.targetctl.benchmark._stage"),
            patch("scripts.targetctl.workflow._store_pending_run"),
            patch("scripts.targetctl.workflow._clear_pending_run"),
            patch("scripts.targetctl.benchmark.launch_profile_from_scenario", return_value=SimpleNamespace()),
            patch("scripts.targetctl.benchmark.serve"),
            patch("scripts.targetctl.benchmark.cleanup", return_value=self._cleanup()),
            patch("scripts.targetctl.benchmark._remove_report"),
            patch("scripts.targetctl.benchmark._remove_stage"),
        )

    def test_lan_dispatch_uses_private_bind_but_never_serializes_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prepared = _prepared(Path(temporary), vantage="controller_lan")
            prepared.result_root.mkdir()
            with self._common_patches(prepared)[0] as stage, self._common_patches(prepared)[1], self._common_patches(prepared)[2], self._common_patches(prepared)[3], patch("scripts.targetctl.benchmark.serve") as launched, patch("scripts.targetctl.benchmark.cleanup", return_value=self._cleanup()), patch("scripts.targetctl.benchmark._remove_report"), patch("scripts.targetctl.benchmark._remove_stage"), patch("scripts.targetctl.benchmark._run_controller", return_value=Path(temporary) / "raw"), patch("scripts.targetctl.benchmark.logs", return_value=b"safe\n"), patch("scripts.targetctl.benchmark._promote_controller", return_value=prepared.result_root / "b-result"):
                result = run_repetition(prepared, "c1", 0, retain=True)
            self.assertIsNotNone(result)
            self.assertEqual(launched.call_args.kwargs["bind_host"], "192.168.1.20")
            metadata = stage.call_args.args[2]
            self.assertNotIn("192.168.1.20", json.dumps(metadata))
            self.assertEqual(metadata["network"]["path"], "direct_private_lan")

    def test_target_local_dispatch_uses_portable_helper_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prepared = _prepared(Path(temporary), vantage="target_local")
            prepared.result_root.mkdir()
            pairing = {
                "pair_id": "pair-control-0",
                "block_id": "block-control-0",
                "order": "A",
                "repetition": 0,
            }
            with patch("scripts.targetctl.benchmark._stage") as stage, patch("scripts.targetctl.workflow._store_pending_run"), patch("scripts.targetctl.workflow._clear_pending_run"), patch("scripts.targetctl.benchmark.launch_profile_from_scenario", return_value=SimpleNamespace()), patch("scripts.targetctl.benchmark.serve") as launched, patch("scripts.targetctl.benchmark.cleanup", return_value=self._cleanup()), patch("scripts.targetctl.benchmark._remove_report"), patch("scripts.targetctl.benchmark._remove_stage"), patch("scripts.targetctl.benchmark._run_target") as target_client, patch("scripts.targetctl.benchmark._helper", return_value={"status": "verified"}), patch("scripts.targetctl.benchmark._download_target", return_value=prepared.result_root / "b-result"), patch("scripts.targetctl.benchmark.time.sleep") as cooled:
                result = run_repetition(
                    prepared,
                    "c1",
                    0,
                    retain=True,
                    pairing=pairing,
                )
            self.assertIsNotNone(result)
            self.assertIsNone(launched.call_args.kwargs["bind_host"])
            target_client.assert_called_once()
            cooled.assert_not_called()
            self.assertEqual(stage.call_args.args[2]["pairing"], pairing)
            metadata = _metadata(prepared, "b-abc", 0, pairing=pairing)
            self.assertEqual(metadata["network"]["path"], "target_loopback")
            self.assertIsNotNone(metadata["runtime_bundle"])
            self.assertEqual(metadata["pairing"], pairing)

    def test_failure_cools_down_after_server_report_and_stage_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prepared = _prepared(Path(temporary), vantage="controller_lan")
            prepared.scenario.preconditions.cooldown_seconds = 2.5
            events: list[str] = []

            def event(name):
                def record(*_args, **_kwargs):
                    events.append(name)
                    if name == "server":
                        return self._cleanup()
                    return None

                return record

            with patch("scripts.targetctl.benchmark._stage"), patch("scripts.targetctl.workflow._store_pending_run"), patch("scripts.targetctl.workflow._clear_pending_run"), patch("scripts.targetctl.benchmark.launch_profile_from_scenario", return_value=SimpleNamespace()), patch("scripts.targetctl.benchmark.serve"), patch("scripts.targetctl.benchmark._run_controller", side_effect=RuntimeError("client failed")), patch("scripts.targetctl.benchmark.cleanup", side_effect=event("server")), patch("scripts.targetctl.benchmark._remove_report", side_effect=event("report")), patch("scripts.targetctl.benchmark._remove_stage", side_effect=event("stage")), patch("scripts.targetctl.benchmark.time.sleep", side_effect=event("cooldown")) as cooled:
                with self.assertRaises(TargetError) as caught:
                    run_repetition(prepared, "c1", 0, retain=True)
            self.assertEqual(caught.exception.code, "benchmark_execution_failed")
            self.assertEqual(events, ["server", "report", "stage", "cooldown"])
            cooled.assert_called_once_with(2.5)

    def test_scenario_failure_is_fixed_and_private_safe(self) -> None:
        canary = "/private/scenario/location"
        with patch("scripts.targetctl.benchmark.execute_benchmark", side_effect=TargetError("benchmark_scenario_invalid", canary)):
            result = structured_benchmark_result(".", "spark", "bench-s1")
        self.assertEqual(result["error"], "benchmark_scenario_invalid")
        self.assertNotIn(canary, json.dumps(result))


class IdentityContracts(unittest.TestCase):
    def test_source_manifest_keeps_exact_public_identity_without_private_values(self) -> None:
        repositories = (
            SimpleNamespace(name="lab", head="a" * 40, dirty=False),
            SimpleNamespace(name="engine", head="b" * 40, dirty=False),
            SimpleNamespace(name="integration", head="c" * 40, dirty=False),
        )
        source = SimpleNamespace(repositories=repositories, dirty=False, snapshot_id="snapshot", applied_tree_hash="d" * 64)
        public = {
            "repositories": [
                {"identity": "lab", "commit": "a" * 40, "clean": True},
                {"identity": "engine/ds4", "commit": "b" * 40, "clean": True},
                {"identity": "spark/ds4-on-spark", "commit": "c" * 40, "clean": True},
            ],
            "flake_lock_hash": "e" * 64,
            "nixpkgs_revision": "f" * 40,
            "system": {"os": "Linux", "kernel": "6.1", "arch": "x86_64"},
        }
        doctor = DoctorResult("succeeded", None, "Linux", "6.1", "aarch64", tuple((name, "1.0", "/private/tool") for name, _ in DOCTOR_TOOLS), ("GB10", "sm_121"), 1, 1, True, "1" * 64, "2" * 64)
        with patch("scripts.targetctl.benchmark.controller_provenance", return_value=public), patch("scripts.targetctl.benchmark._uv_version", return_value="0.8.0"):
            manifest = _source_manifest(Path("."), source, {"build_id": "build", "binary_sha256": "3" * 64}, doctor)
        encoded = json.dumps(manifest, sort_keys=True)
        self.assertNotIn("/private", encoded)
        self.assertEqual(manifest["weights"], {"model_sha256": "1" * 64, "drafter_sha256": "2" * 64})
        self.assertEqual(manifest["build"]["binary_sha256"], "3" * 64)
        self.assertEqual(manifest["target"]["clock_sync"], {"status": "available", "value": "synchronized"})


if __name__ == "__main__":
    unittest.main()
