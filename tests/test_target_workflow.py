from __future__ import annotations

import base64
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts.targetctl.common import TargetError
from scripts.targetctl.source import _is_excluded
from scripts.targetctl.workflow import DEFAULT_LOCAL_PORT, load_operational_target, structured_result


class TargetWorkflowContracts(unittest.TestCase):
    def _config(self, root: Path, mode: int = 0o600) -> Path:
        path = root / "targets" / "targets.toml"
        path.parent.mkdir(mode=0o700)
        path.write_text('schema_version = 1\n[local]\nname = "local"\nmode = "local"\n', encoding="utf-8")
        os.chmod(path, mode)
        return path

    def test_operational_config_is_private_and_source_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._config(root)
            self.assertEqual(load_operational_target(root, "local").name, "local")
            self.assertTrue(_is_excluded("targets/targets.toml"))
            self.assertTrue(_is_excluded("targets/.state/local.workflow-v1.json"))

    def test_symlink_and_permissive_config_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._config(root, 0o644)
            with self.assertRaisesRegex(TargetError, "config_private_invalid"):
                load_operational_target(root, "local")
            os.chmod(path, 0o600)
            replacement = root / "replacement.toml"
            replacement.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(replacement)
            with self.assertRaisesRegex(TargetError, "config_private_invalid"):
                load_operational_target(root, "local")

    def test_missing_state_is_structured_and_private_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._config(root)
            result = structured_result(root, "local", "status")
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["error"], "workflow_state_missing")
            self.assertNotIn("targets.toml", str(result))

    def test_recipes_delegate_with_quoted_target(self) -> None:
        text = Path("Justfile").read_text(encoding="utf-8")
        for operation in ("doctor", "sync", "build", "serve", "status", "logs", "stop", "smoke", "cleanup", "bundle"):
            self.assertIn(f"scripts.targetctl {operation} --target {{{{ quote(target) }}}}", text)
        self.assertEqual(DEFAULT_LOCAL_PORT, 8000)


class StructuredWorkflowBoundaryTests(unittest.TestCase):
    def test_unexpected_exception_is_private_safe(self) -> None:
        canary = "/private/model-canary.gguf"
        with patch("scripts.targetctl.workflow.execute", side_effect=RuntimeError(canary)):
            result = structured_result(".", "local", "doctor")
        self.assertEqual(result, {"schema": 1, "operation": "doctor", "target": "local", "status": "failed", "error": "internal_error"})
        self.assertNotIn(canary, str(result))

    def test_interrupt_is_private_safe(self) -> None:
        with patch("scripts.targetctl.workflow.execute", side_effect=KeyboardInterrupt):
            result = structured_result(".", "local", "doctor")
        self.assertEqual(result, {"schema": 1, "operation": "doctor", "target": "local", "status": "failed", "error": "interrupted"})


class WorkflowBundleEvidenceTests(unittest.TestCase):
    def test_local_bundle_promotes_and_validates_real_evidence(self) -> None:
        from scripts.targetctl.artifacts import validate_bundle_index
        from scripts.targetctl.build import BuildResult
        from scripts.targetctl.config import TargetConfig
        from scripts.targetctl.doctor import DOCTOR_TOOLS, DoctorResult
        from scripts.targetctl.lifecycle import CleanupResult, RunResult, SmokeResult
        from scripts.targetctl.source import RepositoryState, SourceEntry, SourceSnapshot, SyncResult
        from scripts.targetctl.common import canonical_json_bytes
        from scripts.targetctl.artifacts import _SOURCE_EXCLUSIONS
        from scripts.targetctl.workflow import run_bundle

        entry = {"path": "src/test.py", "type": "file", "executable": 0, "size": 1, "sha256": "f" * 64, "origin": "tracked"}
        tree = __import__("hashlib").sha256(b"targetctl-entry-hash-v1\0")
        for field in (b"src/test.py", b"file", b"0", b"1", bytes.fromhex("f" * 64)):
            tree.update(len(field).to_bytes(8, "big")); tree.update(field)
        applied = tree.hexdigest()
        repos = [
            {"name": "lab", "head": "a" * 40, "pinned_head": None, "dirty": False, "status_sha256": "a" * 64, "tracked_diff_sha256": "a" * 64},
            {"name": "engine", "head": "b" * 40, "pinned_head": "b" * 40, "dirty": False, "status_sha256": "b" * 64, "tracked_diff_sha256": "b" * 64},
            {"name": "integration", "head": "c" * 40, "pinned_head": "c" * 40, "dirty": False, "status_sha256": "c" * 64, "tracked_diff_sha256": "c" * 64},
        ]
        snapshot_id = __import__("hashlib").sha256(b"targetctl-source-snapshot-v1\0" + canonical_json_bytes({"schema_version": 1, "exclusion_policy_version": 1, "exclusions": list(_SOURCE_EXCLUSIONS), "repositories": repos, "entries": [entry], "applied_tree_hash": applied})).hexdigest()
        source = SourceSnapshot(tuple(RepositoryState(**repo) for repo in repos), (SourceEntry("src/test.py", 0, 1, "f" * 64, "tracked"),), False, applied, snapshot_id)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "runtime"
            run_dir.mkdir(mode=0o700)
            build_log = b"[REDACTED]\n"
            server_log = b"[REDACTED]\n"
            (run_dir / "build.log").write_bytes(build_log)
            (run_dir / "server.log").write_bytes(server_log)
            os.chmod(run_dir / "build.log", 0o600)
            os.chmod(run_dir / "server.log", 0o600)
            build_hash = __import__("hashlib").sha256(build_log).hexdigest()
            server_hash = __import__("hashlib").sha256(server_log).hexdigest()
            config = TargetConfig(name="local", mode="local", run_dir=str(run_dir), source_root=root)
            provenance = {
                "repositories": [
                    {"identity": "lab", "commit": source.repositories[0].head, "clean": not source.repositories[0].dirty},
                    {"identity": "engine/ds4", "commit": source.repositories[1].head, "gitlink": source.repositories[1].pinned_head, "clean": not source.repositories[1].dirty},
                    {"identity": "spark/ds4-on-spark", "commit": source.repositories[2].head, "gitlink": source.repositories[2].pinned_head, "clean": not source.repositories[2].dirty},
                ],
                "flake_lock_hash": "a" * 64, "nixpkgs_revision": "a" * 40,
                "system": {"os": "Linux", "kernel": "6.1.0", "arch": "x86_64"},
                "tools": {"git": "1.0", "nix": "unavailable", "python": "1.0"},
            }
            doctor = DoctorResult("succeeded", None, "Linux", "6.1.0", "x86_64", tuple((name, "1.0", path) for name, path in DOCTOR_TOOLS), ("GB10", "sm_121"), 1, 1, True, "b" * 64, "c" * 64)
            built = BuildResult("succeeded", None, source.snapshot_id, source.applied_tree_hash, "d" * 64, "e" * 64, "make-cuda-spark", "1.0", 1, "verified", build_hash, 0, 1)
            run = RunResult("run-aaaaaaaaaaaaaaaaaaaaaaaa", "running", 8000, source.snapshot_id, "d" * 64, "e" * 64, 11, 12, 13, 14)
            cleanup = CleanupResult(run.run_id, "stopped", "cleared", "cleared", "not_found", "cleared", server_hash, None)
            smoked = SmokeResult(run.run_id, "succeeded", None, 200, 200, "passed", "b" * 64, "c" * 64, 1, run, cleanup)
            old_env = {key: os.environ.get(key) for key in ("TARGETCTL_MODEL_PATH", "TARGETCTL_DRAFTER_PATH")}
            os.environ["TARGETCTL_MODEL_PATH"], os.environ["TARGETCTL_DRAFTER_PATH"] = "/private/model.gguf", "/private/drafter.gguf"
            try:
                with patch("scripts.targetctl.workflow.load_operational_target", return_value=config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.build_snapshot", return_value=source), patch("scripts.targetctl.workflow.controller_provenance", return_value=provenance), patch("scripts.targetctl.workflow.doctor", return_value=doctor), patch("scripts.targetctl.workflow.sync_source", return_value=SyncResult(source, True, source.applied_tree_hash)), patch("scripts.targetctl.workflow.build", return_value=built), patch("scripts.targetctl.workflow.smoke", return_value=smoked), patch("scripts.targetctl.workflow._verify_current_binary"):
                    result = run_bundle(root, "local")
            finally:
                for key, value in old_env.items():
                    if value is None: os.environ.pop(key, None)
                    else: os.environ[key] = value
            self.assertEqual(result["status"], "succeeded")
            bundle = root / result["artifact"]
            self.assertTrue(validate_bundle_index(bundle)["complete"])
            self.assertEqual(result["report_cleanup"]["status"], "succeeded")
            self.assertFalse((run_dir / "build.log").exists())
            self.assertFalse((run_dir / "server.log").exists())


class _WorkflowFixture:
    """Small factory for independently valid public workflow evidence."""

    def __init__(self, root: Path, *, ssh: bool = False) -> None:
        from scripts.targetctl.build import BuildResult
        from scripts.targetctl.config import TargetConfig
        from scripts.targetctl.doctor import DOCTOR_TOOLS, DoctorResult
        from scripts.targetctl.lifecycle import CleanupResult, RunResult, SmokeResult
        from scripts.targetctl.source import RepositoryState, SourceEntry, SourceSnapshot

        entry = {"path": "src/test.py", "type": "file", "executable": 0, "size": 1, "sha256": "f" * 64, "origin": "tracked"}
        tree = hashlib.sha256(b"targetctl-entry-hash-v1\0")
        for field in (b"src/test.py", b"file", b"0", b"1", bytes.fromhex("f" * 64)):
            tree.update(len(field).to_bytes(8, "big"))
            tree.update(field)
        applied = tree.hexdigest()
        repositories = [
            {"name": "lab", "head": "a" * 40, "pinned_head": None, "dirty": False, "status_sha256": "a" * 64, "tracked_diff_sha256": "a" * 64},
            {"name": "engine", "head": "b" * 40, "pinned_head": "b" * 40, "dirty": False, "status_sha256": "b" * 64, "tracked_diff_sha256": "b" * 64},
            {"name": "integration", "head": "c" * 40, "pinned_head": "c" * 40, "dirty": False, "status_sha256": "c" * 64, "tracked_diff_sha256": "c" * 64},
        ]
        from scripts.targetctl.artifacts import _SOURCE_EXCLUSIONS
        from scripts.targetctl.common import canonical_json_bytes
        snapshot_id = hashlib.sha256(b"targetctl-source-snapshot-v1\0" + canonical_json_bytes({"schema_version": 1, "exclusion_policy_version": 1, "exclusions": list(_SOURCE_EXCLUSIONS), "repositories": repositories, "entries": [entry], "applied_tree_hash": applied})).hexdigest()
        self.source = SourceSnapshot(tuple(RepositoryState(**item) for item in repositories), (SourceEntry("src/test.py", 0, 1, "f" * 64, "tracked"),), False, applied, snapshot_id)
        self.build_log, self.server_log = b"[REDACTED] build\n", b"[REDACTED] server\n"
        self.build_digest, self.server_digest = (hashlib.sha256(value).hexdigest() for value in (self.build_log, self.server_log))
        self.binary = b"binary"
        binary_digest = hashlib.sha256(self.binary).hexdigest()
        self.build = BuildResult("succeeded", None, self.source.snapshot_id, self.source.applied_tree_hash, "d" * 64, binary_digest, "make-cuda-spark", "1.0", len(self.binary), "verified", self.build_digest, 0, 1)
        self.doctor = DoctorResult("succeeded", None, "Linux", "6.1.0", "x86_64", tuple((name, "1.0", path) for name, path in DOCTOR_TOOLS), ("GB10", "sm_121"), 1, 1, True, "b" * 64, "c" * 64)
        self.provenance = {
            "repositories": [
                {"identity": "lab", "commit": "a" * 40, "clean": True},
                {"identity": "engine/ds4", "commit": "b" * 40, "gitlink": "b" * 40, "clean": True},
                {"identity": "spark/ds4-on-spark", "commit": "c" * 40, "gitlink": "c" * 40, "clean": True},
            ],
            "flake_lock_hash": "a" * 64, "nixpkgs_revision": "a" * 40,
            "system": {"os": "Linux", "kernel": "6.1.0", "arch": "x86_64"},
            "tools": {"git": "1.0", "nix": "unavailable", "python": "1.0"},
        }
        if ssh:
            self.config = TargetConfig("spark", "ssh", ssh_host="private-host", workdir="/lab/targetctl/work", run_dir="/lab/targetctl/run", api_base_url="http://127.0.0.1:8010", model_path="/private/model-canary.gguf", drafter_path="/private/drafter-canary.gguf", source_root=root)
        else:
            self.run_dir = root / "runtime"
            self.run_dir.mkdir(mode=0o700)
            self.config = TargetConfig("local", "local", run_dir=str(self.run_dir), source_root=root)

    def smoke(self, run_id: str):
        from scripts.targetctl.lifecycle import CleanupResult, RunResult, SmokeResult

        run = RunResult(run_id, "running", 8010 if self.config.mode == "ssh" else 8000, self.source.snapshot_id, self.build.build_id, self.build.binary_sha256, 11, 12, 13, 14)
        cleanup = CleanupResult(run_id, "succeeded", "cleared", "cleared", "not_found", "cleared", self.server_digest, None)
        return SmokeResult(run_id, "succeeded", None, 200, 200, "passed", "b" * 64, "c" * 64, 1, run, cleanup)

    def install_ready_state(self, root: Path) -> None:
        from scripts.targetctl.workflow import _save_build, _save_source

        _save_source(root, self.config.name, self.source)
        _save_build(root, self.config.name, self.source, self.build)

    def install_binary(self) -> None:
        path = Path(self.config.source_root) / "engine" / "ds4"
        path.mkdir(parents=True)
        binary = path / "ds4-server"
        binary.write_bytes(self.binary)
        os.chmod(binary, 0o700)


class _ReportTransport:
    def __init__(self, fixture: _WorkflowFixture, *, mismatch: bool = False) -> None:
        self.fixture, self.mismatch, self.calls = fixture, mismatch, []

    def run_helper(self, action, payload, **_kwargs):
        self.calls.append((action, payload))
        if action == "read_report":
            content = {"build.log": self.fixture.build_log, "server.log": self.fixture.server_log}[payload["name"]]
            return {"sha256": hashlib.sha256(content).hexdigest(), "content_b64": base64.b64encode(content).decode("ascii")}
        if action == "remove_reports":
            reports = payload["reports"]
            if self.mismatch:
                return {"reports": [{"name": "wrong.log", "result": "cleared"} for _ in reports]}
            return {"reports": [{"name": item["name"], "result": "cleared"} for item in reports]}
        raise AssertionError(f"unexpected helper action: {action}")


class WorkflowFinalCoverageTests(unittest.TestCase):
    def _bundle(self, root: Path, fixture: _WorkflowFixture, transport: _ReportTransport):
        from scripts.targetctl.source import SyncResult
        from scripts.targetctl.workflow import run_bundle

        with ExitStack() as stack:
            stack.enter_context(patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config))
            stack.enter_context(patch("scripts.targetctl.workflow.select_transport", return_value=transport))
            stack.enter_context(patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source))
            stack.enter_context(patch("scripts.targetctl.workflow.controller_provenance", return_value=fixture.provenance))
            stack.enter_context(patch("scripts.targetctl.workflow.doctor", return_value=fixture.doctor))
            stack.enter_context(patch("scripts.targetctl.workflow.sync_source", return_value=SyncResult(fixture.source, True, fixture.source.applied_tree_hash)))
            stack.enter_context(patch("scripts.targetctl.workflow.build", return_value=fixture.build))
            stack.enter_context(patch("scripts.targetctl.workflow.smoke", side_effect=lambda _config, _transport, _runtime, *, run_id: fixture.smoke(run_id)))
            stack.enter_context(patch("scripts.targetctl.source._load_capabilities", return_value={"work_token": "1" * 64, "run_token": "2" * 64}))
            return run_bundle(root, fixture.config.name)

    def test_ssh_bundle_uses_only_report_helpers_and_preserves_artifact_on_cleanup_mismatch(self) -> None:
        from scripts.targetctl.artifacts import validate_bundle_index

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root, ssh=True)
            transport = _ReportTransport(fixture)
            with patch("scripts.targetctl.workflow._read_stored_log", side_effect=AssertionError("controller opened a remote path")):
                result = self._bundle(root, fixture, transport)
            self.assertEqual(result["status"], "succeeded")
            self.assertEqual([action for action, _ in transport.calls], ["read_report", "read_report", "remove_reports"])
            self.assertEqual(
                transport.calls[-1][1]["reports"],
                [{"name": "build.log", "sha256": fixture.build_digest}, {"name": "server.log", "sha256": fixture.server_digest}],
            )
            self.assertTrue(validate_bundle_index(root / result["artifact"])["complete"])
            artifact_bytes = b"".join(path.read_bytes() for path in (root / result["artifact"]).rglob("*") if path.is_file())
            private = (fixture.config.ssh_host, fixture.config.workdir, fixture.config.run_dir, fixture.config.model_path, fixture.config.drafter_path)
            self.assertTrue(all(value not in str(result) and value.encode() not in artifact_bytes for value in private))
            mismatched = _ReportTransport(fixture, mismatch=True)
            with patch("scripts.targetctl.workflow._read_stored_log", side_effect=AssertionError("controller opened a remote path")):
                failed = self._bundle(root, fixture, mismatched)
            self.assertEqual((failed["status"], failed["error"], failed["report_cleanup"]["status"]), ("failed", "report_cleanup_failed", "failed"))
            self.assertTrue(validate_bundle_index(root / failed["artifact"])["complete"])
            failed_bytes = b"".join(path.read_bytes() for path in (root / failed["artifact"]).rglob("*") if path.is_file())
            self.assertTrue(all(value not in str(failed) and value.encode() not in failed_bytes for value in private))

    def test_stale_source_and_binary_reject_before_lifecycle(self) -> None:
        from scripts.targetctl.workflow import execute

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            transport = Mock()
            lifecycle = Mock()
            stale_source = fixture.source.__class__(fixture.source.repositories, fixture.source.entries, True, fixture.source.applied_tree_hash, fixture.source.snapshot_id)
            with patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport", return_value=transport), patch("scripts.targetctl.workflow.build_snapshot", return_value=stale_source), patch("scripts.targetctl.workflow.serve", lifecycle):
                with self.assertRaisesRegex(TargetError, "workflow_source_stale"):
                    execute(root, "local", "serve")
            self.assertFalse(lifecycle.called)

            fixture.install_binary()
            (root / "engine" / "ds4" / "ds4-server").write_bytes(b"stale!")
            with patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport", return_value=transport), patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source), patch("scripts.targetctl.workflow.serve", lifecycle):
                with self.assertRaisesRegex(TargetError, "workflow_binary_stale"):
                    execute(root, "local", "serve")
            self.assertFalse(lifecycle.called)

    def test_pending_run_survives_ambiguous_serve_and_requires_matching_cleanup(self) -> None:
        from scripts.targetctl.lifecycle import CleanupResult
        from scripts.targetctl.workflow import _pending_run, execute

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            fixture.install_binary()
            observed = []

            def ambiguous(*_args, run_id, **_kwargs):
                observed.append(run_id)
                self.assertEqual(_pending_run(root, "local"), run_id)
                raise TargetError("serve_ambiguous", "dispatch outcome is unavailable")

            environment = {"TARGETCTL_MODEL_PATH": "/private/model-canary.gguf", "TARGETCTL_DRAFTER_PATH": "/private/drafter-canary.gguf"}
            with patch.dict(os.environ, environment, clear=False), patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source), patch("scripts.targetctl.workflow.serve", side_effect=ambiguous):
                with self.assertRaisesRegex(TargetError, "serve_ambiguous"):
                    execute(root, "local", "serve")
            self.assertEqual(_pending_run(root, "local"), observed[0])

            wrong = CleanupResult("run-ffffffffffffffffffffffff", "succeeded", "cleared", "cleared", "not_found", "cleared")
            with patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.cleanup", return_value=wrong):
                execute(root, "local", "cleanup")
            self.assertEqual(_pending_run(root, "local"), observed[0])

            matching = CleanupResult(observed[0], "succeeded", "cleared", "cleared", "not_found", "cleared")
            with patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.cleanup", return_value=matching):
                execute(root, "local", "cleanup")
            self.assertIsNone(_pending_run(root, "local"))

    def test_identity_only_operations_and_cli_evidence_are_private_safe(self) -> None:
        from scripts.targetctl.lifecycle import CleanupResult, StatusResult
        from scripts.targetctl.workflow import execute

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            private = "/private/model-canary.gguf"
            with patch.dict(os.environ, {}, clear=True), patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.status", return_value=StatusResult(None, "stopped", False)), patch("scripts.targetctl.workflow.logs", return_value=b"[REDACTED]\n"), patch("scripts.targetctl.workflow.stop", return_value=CleanupResult(None, "succeeded", "cleared", "cleared", "not_found", "cleared")), patch("scripts.targetctl.workflow.cleanup", return_value=CleanupResult(None, "succeeded", "cleared", "cleared", "not_found", "cleared")):
                status = execute(root, "local", "status")
                logs = structured_result(root, "local", "logs")
                stop = execute(root, "local", "stop")
                cleanup = execute(root, "local", "cleanup")
            self.assertEqual(status, {"status": "succeeded", "run_id": None, "state": "stopped", "active": False})
            self.assertEqual(
                logs,
                {"schema": 1, "operation": "logs", "target": "local", "status": "succeeded", "content_b64": base64.b64encode(b"[REDACTED]\n").decode("ascii"), "log_sha256": hashlib.sha256(b"[REDACTED]\n").hexdigest(), "log_bytes": len(b"[REDACTED]\n")},
            )
            self.assertEqual((stop["status"], stop["process"], stop["socket"], stop["lock"], stop["temp"]), ("succeeded", "cleared", "cleared", "not_found", "cleared"))
            self.assertEqual((cleanup["status"], cleanup["process"], cleanup["socket"], cleanup["lock"], cleanup["temp"]), ("succeeded", "cleared", "cleared", "not_found", "cleared"))

            fixture.install_binary()

            def smoke_with_observed(_config, _transport, _runtime, *, run_id):
                return fixture.smoke(run_id)

            environment = {"TARGETCTL_MODEL_PATH": private, "TARGETCTL_DRAFTER_PATH": "/private/drafter-canary.gguf"}
            with patch.dict(os.environ, environment, clear=False), patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.doctor", return_value=fixture.doctor):
                doctor = structured_result(root, "local", "doctor")
            with patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source), patch("scripts.targetctl.workflow.build", return_value=fixture.build):
                built = structured_result(root, "local", "build")
            with patch.dict(os.environ, environment, clear=False), patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source), patch("scripts.targetctl.workflow.smoke", side_effect=smoke_with_observed):
                smoked = structured_result(root, "local", "smoke")
            self.assertEqual(doctor, {"schema": 1, "operation": "doctor", "target": "local", **fixture.doctor.controller_payload()})
            self.assertEqual(built, {"schema": 1, "operation": "build", "target": "local", **fixture.build.controller_payload()})
            self.assertEqual(set(smoked), {"schema", "operation", "target", "status", "smoke", "run", "cleanup"})
            observed = fixture.smoke(smoked["smoke"]["run_id"])
            self.assertEqual(smoked["smoke"], observed.controller_payload())
            self.assertEqual(smoked["run"], observed.run.controller_payload())
            self.assertEqual(smoked["cleanup"], observed.cleanup.controller_payload())
            state = (root / "targets" / ".state" / "local.workflow-v1.json").read_text(encoding="utf-8")
            self.assertTrue(all(value not in str((doctor, built, logs, smoked)) and value not in state for value in (private, "/private/drafter-canary.gguf")))
