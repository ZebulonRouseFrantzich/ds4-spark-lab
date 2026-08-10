from __future__ import annotations

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
    CHUNK_BYTES,
    PreparedBenchmark,
    StageFile,
    _download_target,
    _inspect_file,
    _metadata,
    _source_manifest,
    _stage,
    _stage_manifest,
    prepare_benchmark,
    run_repetition,
    structured_benchmark_result,
)
from scripts.targetctl.common import TargetError
from scripts.targetctl.doctor import DOCTOR_TOOLS, DoctorResult


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
            with patch("scripts.targetctl.benchmark._stage"), patch("scripts.targetctl.workflow._store_pending_run"), patch("scripts.targetctl.workflow._clear_pending_run"), patch("scripts.targetctl.benchmark.launch_profile_from_scenario", return_value=SimpleNamespace()), patch("scripts.targetctl.benchmark.serve") as launched, patch("scripts.targetctl.benchmark.cleanup", return_value=self._cleanup()), patch("scripts.targetctl.benchmark._remove_report"), patch("scripts.targetctl.benchmark._remove_stage"), patch("scripts.targetctl.benchmark._run_target") as target_client, patch("scripts.targetctl.benchmark._helper", return_value={"status": "verified"}), patch("scripts.targetctl.benchmark._download_target", return_value=prepared.result_root / "b-result"):
                result = run_repetition(prepared, "c1", 0, retain=True)
            self.assertIsNotNone(result)
            self.assertIsNone(launched.call_args.kwargs["bind_host"])
            target_client.assert_called_once()
            metadata = _metadata(prepared, "b-abc", 0)
            self.assertEqual(metadata["network"]["path"], "target_loopback")
            self.assertIsNotNone(metadata["runtime_bundle"])

    def test_interruption_always_cleans_server_stage_and_pending_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prepared = _prepared(Path(temporary), vantage="controller_lan")
            with patch("scripts.targetctl.benchmark._stage"), patch("scripts.targetctl.workflow._store_pending_run"), patch("scripts.targetctl.workflow._clear_pending_run") as cleared, patch("scripts.targetctl.benchmark.launch_profile_from_scenario", return_value=SimpleNamespace()), patch("scripts.targetctl.benchmark.serve"), patch("scripts.targetctl.benchmark._run_controller", side_effect=KeyboardInterrupt), patch("scripts.targetctl.benchmark.cleanup", return_value=self._cleanup()) as stopped, patch("scripts.targetctl.benchmark._remove_report"), patch("scripts.targetctl.benchmark._remove_stage") as removed:
                with self.assertRaises(KeyboardInterrupt):
                    run_repetition(prepared, "c1", 0, retain=True)
            stopped.assert_called_once()
            removed.assert_called_once()
            cleared.assert_called_once()

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
