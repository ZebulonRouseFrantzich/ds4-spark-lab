from __future__ import annotations

import base64
from contextlib import ExitStack
from dataclasses import replace
import json
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from scripts.targetctl.common import TargetError
from scripts.targetctl.redaction import StreamingRedactor, redaction_canaries
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
            self.assertTrue(_is_excluded("targets/.state/local.workflow-v2.json"))

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
    def test_remote_report_canaries_exclude_controller_only_ssh_alias(self) -> None:
        from scripts.targetctl.config import TargetConfig
        from scripts.targetctl.redaction import StreamingRedactor
        from scripts.targetctl.workflow import _private_canaries

        with tempfile.TemporaryDirectory() as temporary:
            config = TargetConfig(
                "spark",
                "ssh",
                ssh_host="spark",
                workdir="/lab/targetctl/work",
                run_dir="/lab/targetctl/run",
                api_base_url="http://127.0.0.1:8010",
                model_path="/models/releases/model.gguf",
                drafter_path="/models/releases/drafter.gguf",
                source_root=Path(temporary),
            )
            canaries = _private_canaries(config)
            self.assertNotIn(config.ssh_host, canaries)
            self.assertIn(config.workdir, canaries)
            redactor = StreamingRedactor(canaries, max_output=1024)
            text = (redactor.feed(b"make cuda-spark\n") + redactor.finalize()).encode("utf-8")
            self.assertEqual(text, b"make cuda-spark\n")

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

    def test_build_and_server_log_promotion_preserves_full_digest_at_finite_boundaries(self) -> None:
        from scripts.targetctl.artifacts import ArtifactBundle, MAX_TEXT_BYTES
        from scripts.targetctl.config import TargetConfig
        from scripts.targetctl.workflow import _promote_build_log, _promote_server_log

        def log_content(label: str, size: int) -> bytes:
            line = f"{label} safe artifact output\n".encode("utf-8")
            return line * (size // len(line)) + b"x" * (size % len(line))

        for size in (65_537, MAX_TEXT_BYTES):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run_dir = root / "runtime"
                run_dir.mkdir(mode=0o700)
                config = TargetConfig(name="local", mode="local", run_dir=str(run_dir), source_root=root)
                bundle = ArtifactBundle(root, "local", f"log-boundary-{size}")
                build_log = log_content("build", size)
                server_log = log_content("server", size)
                for name, content in (("build.log", build_log), ("server.log", server_log)):
                    path = run_dir / name
                    path.write_bytes(content)
                    os.chmod(path, 0o600)

                with patch.dict(
                    os.environ,
                    {
                        "TARGETCTL_MODEL_PATH": "/private/model.gguf",
                        "TARGETCTL_DRAFTER_PATH": "/private/drafter.gguf",
                    },
                    clear=False,
                ):
                    _promote_build_log(
                        bundle,
                        root,
                        "local",
                        hashlib.sha256(build_log).hexdigest(),
                        config,
                        None,
                    )
                    _promote_server_log(
                        bundle,
                        root,
                        "local",
                        hashlib.sha256(server_log).hexdigest(),
                        config,
                        None,
                    )

                promoted_build = (bundle._staging / "texts" / "build-log.txt").read_bytes()
                promoted_server = (bundle._staging / "texts" / "server-log.txt").read_bytes()
                self.assertEqual(promoted_build, build_log)
                self.assertEqual(promoted_server, server_log)
                self.assertEqual(hashlib.sha256(promoted_build).hexdigest(), hashlib.sha256(build_log).hexdigest())
                self.assertEqual(hashlib.sha256(promoted_server).hexdigest(), hashlib.sha256(server_log).hexdigest())

    def test_build_and_server_log_promotion_refuses_over_limit_inputs(self) -> None:
        from scripts.targetctl.artifacts import ArtifactBundle, MAX_TEXT_BYTES
        from scripts.targetctl.config import TargetConfig
        from scripts.targetctl.workflow import _promote_build_log, _promote_server_log

        for report_name in ("build", "server"):
            with self.subTest(report=report_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run_dir = root / "runtime"
                run_dir.mkdir(mode=0o700)
                content = b"x" * (MAX_TEXT_BYTES + 1)
                source = run_dir / f"{report_name}.log"
                source.write_bytes(content)
                os.chmod(source, 0o600)
                config = TargetConfig(name="local", mode="local", run_dir=str(run_dir), source_root=root)
                bundle = ArtifactBundle(root, "local", f"over-limit-{report_name}")

                with patch.dict(
                    os.environ,
                    {
                        "TARGETCTL_MODEL_PATH": "/private/model.gguf",
                        "TARGETCTL_DRAFTER_PATH": "/private/drafter.gguf",
                    },
                    clear=False,
                ), self.assertRaises(TargetError) as raised:
                    if report_name == "build":
                        _promote_build_log(
                            bundle,
                            root,
                            "local",
                            hashlib.sha256(content).hexdigest(),
                            config,
                            None,
                        )
                    else:
                        _promote_server_log(
                            bundle,
                            root,
                            "local",
                            hashlib.sha256(content).hexdigest(),
                            config,
                            None,
                        )

                self.assertEqual(raised.exception.code, "artifact_log_unavailable")
                self.assertFalse((bundle._staging / "texts" / f"{report_name}-log.txt").exists())


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
            self.config = TargetConfig("spark", "ssh", ssh_host="private-host", workdir="/lab/targetctl/work", run_dir="/lab/targetctl/run", api_base_url="http://127.0.0.1:8010", model_path="/home/private-user/models/releases/model-canary.gguf", drafter_path="/mnt/private-store/drafters/releases/drafter-canary.gguf", source_root=root)
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
        from scripts.targetctl.workflow import (
            _build_generation,
            _save_build,
            _save_source,
        )

        _save_source(root, self.config.name, self.source)
        generation = _build_generation(root, self.config.name, self.source)
        _save_build(
            root,
            self.config.name,
            self.source,
            self.build,
            expected_generation=generation,
        )

    def install_binary(self) -> None:
        path = Path(self.config.source_root) / "engine" / "ds4"
        path.mkdir(parents=True)
        binary = path / "ds4-server"
        binary.write_bytes(self.binary)
        os.chmod(binary, 0o700)


class _ReportTransport:
    def __init__(self, fixture: _WorkflowFixture, *, mismatch: bool = False, server_report: str = "valid") -> None:
        self.fixture, self.mismatch, self.server_report, self.calls = fixture, mismatch, server_report, []
        self.reports = {"build.log": fixture.build_log, "server.log": fixture.server_log}
        self.server_reads = 0
        if server_report == "absent":
            self.reports.pop("server.log")
        elif server_report == "mismatch":
            self.reports["server.log"] = b"[REDACTED] different server log\n"

    def run_helper(self, action, payload, **_kwargs):
        self.calls.append((action, payload))
        if action == "read_report":
            name = payload["name"]
            if name not in self.reports:
                raise TargetError("artifact_log_unavailable", "sanitized target report is unavailable")
            if name == "server.log":
                self.server_reads += 1
                if self.server_report == "changing" and self.server_reads == 2:
                    self.reports[name] = b"[REDACTED] changed during promotion\n"
            content = self.reports[name]
            return {"sha256": hashlib.sha256(content).hexdigest(), "content_b64": base64.b64encode(content).decode("ascii")}
        if action == "remove_reports":
            reports = payload["reports"]
            if self.mismatch:
                return {"reports": [{"name": "wrong.log", "result": "cleared"} for _ in reports]}
            outcomes = []
            for item in reports:
                content = self.reports.get(item["name"])
                if content is None or hashlib.sha256(content).hexdigest() != item["sha256"]:
                    result = "not_found"
                else:
                    del self.reports[item["name"]]
                    result = "cleared"
                outcomes.append({"name": item["name"], "result": result})
            return {"reports": outcomes}
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

    def test_sync_snapshot_round_trips_dot_and_underscore_tracked_paths_to_doctor(self) -> None:
        from scripts.targetctl.artifacts import _SOURCE_EXCLUSIONS
        from scripts.targetctl.common import canonical_json_bytes
        from scripts.targetctl.source import SourceEntry, SourceSnapshot, SyncResult

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            entries = tuple(
                SourceEntry(path, 0, 1, "f" * 64, "tracked")
                for path in (
                    ".envrc",
                    ".gitignore",
                    "_tooling/config.py",
                    "nested/.gitignore",
                    "scripts/targetctl/__main__.py",
                )
            )
            tree = hashlib.sha256(b"targetctl-entry-hash-v1\0")
            for entry in entries:
                for field in (
                    entry.path.encode("utf-8"),
                    b"file",
                    str(entry.executable).encode("ascii"),
                    str(entry.size).encode("ascii"),
                    bytes.fromhex(entry.sha256),
                ):
                    tree.update(len(field).to_bytes(8, "big"))
                    tree.update(field)
            applied = tree.hexdigest()
            identity = {
                "schema_version": 1,
                "exclusion_policy_version": 1,
                "exclusions": list(_SOURCE_EXCLUSIONS),
                "repositories": [item.as_dict() for item in fixture.source.repositories],
                "entries": [item.as_dict() for item in entries],
                "applied_tree_hash": applied,
            }
            snapshot_id = hashlib.sha256(
                b"targetctl-source-snapshot-v1\0" + canonical_json_bytes(identity)
            ).hexdigest()
            source = SourceSnapshot(
                fixture.source.repositories,
                entries,
                False,
                applied,
                snapshot_id,
            )
            transport = Mock()
            doctor_call = Mock(return_value=fixture.doctor)

            with ExitStack() as stack:
                stack.enter_context(
                    patch.dict(
                        os.environ,
                        {
                            "TARGETCTL_MODEL_PATH": "/private/model-canary.gguf",
                            "TARGETCTL_DRAFTER_PATH": "/private/drafter-canary.gguf",
                        },
                        clear=False,
                    )
                )
                stack.enter_context(
                    patch(
                        "scripts.targetctl.workflow.load_operational_target",
                        return_value=fixture.config,
                    )
                )
                stack.enter_context(
                    patch(
                        "scripts.targetctl.workflow.select_transport",
                        return_value=transport,
                    )
                )
                stack.enter_context(
                    patch(
                        "scripts.targetctl.workflow.sync_source",
                        return_value=SyncResult(source, True, source.applied_tree_hash),
                    )
                )
                stack.enter_context(
                    patch(
                        "scripts.targetctl.workflow.build_snapshot",
                        return_value=source,
                    )
                )
                stack.enter_context(
                    patch("scripts.targetctl.workflow.doctor", doctor_call)
                )
                synced = structured_result(root, "local", "sync")
                diagnosed = structured_result(root, "local", "doctor")

            self.assertEqual(
                synced,
                {
                    "schema": 1,
                    "operation": "sync",
                    "target": "local",
                    "status": "succeeded",
                    "snapshot_id": source.snapshot_id,
                    "applied_tree_hash": source.applied_tree_hash,
                    "initialized": True,
                },
            )
            self.assertEqual(
                diagnosed,
                {
                    "schema": 1,
                    "operation": "doctor",
                    "target": "local",
                    **fixture.doctor.controller_payload(),
                },
            )
            doctor_call.assert_called_once()
            self.assertEqual(doctor_call.call_args.kwargs["snapshot"], source)

    def test_ssh_bundle_uses_only_report_helpers_and_preserves_artifact_on_cleanup_mismatch(self) -> None:
        from scripts.targetctl.artifacts import validate_bundle_index

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root, ssh=True)
            private = redaction_canaries(
                (fixture.config.model_path, fixture.config.drafter_path),
                additional=(fixture.config.ssh_host, fixture.config.workdir, fixture.config.run_dir),
            )
            home_ancestor = "/home/private-user"
            producer = StreamingRedactor(private)
            fixture.server_log = (
                producer.feed(f"server ancestor-only {home_ancestor}\n") + producer.finalize()
            ).encode("utf-8")
            fixture.server_digest = hashlib.sha256(fixture.server_log).hexdigest()
            transport = _ReportTransport(fixture)
            with patch("scripts.targetctl.workflow._read_stored_log", side_effect=AssertionError("controller opened a remote path")):
                result = self._bundle(root, fixture, transport)
            self.assertEqual(result["status"], "succeeded")
            self.assertEqual([action for action, _ in transport.calls], ["read_report", "read_report", "read_report", "remove_reports"])
            self.assertEqual(
                transport.calls[-1][1]["reports"],
                [{"name": "build.log", "sha256": fixture.build_digest}, {"name": "server.log", "sha256": fixture.server_digest}],
            )
            self.assertEqual(transport.reports, {})
            self.assertTrue(validate_bundle_index(root / result["artifact"])["complete"])
            artifact_bytes = b"".join(path.read_bytes() for path in (root / result["artifact"]).rglob("*") if path.is_file())
            self.assertNotIn(home_ancestor.encode(), fixture.server_log)
            self.assertIn("/home/private-user", private)
            self.assertIn("/mnt/private-store", private)
            self.assertTrue(all(value not in str(result) and value.encode() not in artifact_bytes for value in private))
            mismatched = _ReportTransport(fixture, mismatch=True)
            with patch("scripts.targetctl.workflow._read_stored_log", side_effect=AssertionError("controller opened a remote path")):
                failed = self._bundle(root, fixture, mismatched)
            self.assertEqual((failed["status"], failed["error"], failed["report_cleanup"]["status"]), ("failed", "report_cleanup_failed", "failed"))
            self.assertTrue(validate_bundle_index(root / failed["artifact"])["complete"])
            failed_bytes = b"".join(path.read_bytes() for path in (root / failed["artifact"]).rglob("*") if path.is_file())
            self.assertTrue(all(value not in str(failed) and value.encode() not in failed_bytes for value in private))

    def test_failed_cleanup_promotes_digest_matching_server_log_and_rejects_bad_evidence(self) -> None:
        from scripts.targetctl.artifacts import validate_bundle_index

        def with_failed_cleanup(original_smoke, run_id: str):
            smoked = original_smoke(run_id)
            return replace(
                smoked,
                cleanup=replace(
                    smoked.cleanup,
                    status="failed",
                    process="unknown",
                    failure_class="command_failed",
                ),
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root, ssh=True)
            private = redaction_canaries(
                (fixture.config.model_path, fixture.config.drafter_path),
                additional=(fixture.config.ssh_host, fixture.config.workdir, fixture.config.run_dir),
            )
            non_home_ancestor = "/mnt/private-store"
            producer = StreamingRedactor(private)
            fixture.server_log = (
                producer.feed(f"failed cleanup ancestor-only {non_home_ancestor}\n")
                + producer.finalize()
            ).encode("utf-8")
            fixture.server_digest = hashlib.sha256(fixture.server_log).hexdigest()
            original_smoke = fixture.smoke
            fixture.smoke = lambda run_id: with_failed_cleanup(original_smoke, run_id)
            transport = _ReportTransport(fixture)
            result = self._bundle(root, fixture, transport)
            artifact = root / result["artifact"]
            cleanup_record = json.loads((artifact / "cleanup.json").read_text(encoding="utf-8"))["payload"]
            server_log = (artifact / "texts" / "server-log.txt").read_bytes()
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["report_cleanup"]["status"], "succeeded")
            self.assertEqual(
                transport.calls[-1],
                (
                    "remove_reports",
                    {
                        "run_dir": fixture.config.run_dir,
                        "run_token": "2" * 64,
                        "reports": [{"name": "build.log", "sha256": fixture.build_digest}],
                    },
                ),
            )
            self.assertNotIn("build.log", transport.reports)
            self.assertEqual(transport.reports["server.log"], fixture.server_log)
            self.assertEqual(cleanup_record["status"], "failed")
            self.assertEqual(cleanup_record["server_log_sha256"], fixture.server_digest)
            self.assertNotIn(non_home_ancestor.encode(), fixture.server_log)
            self.assertIn("/home/private-user", private)
            self.assertIn("/mnt/private-store", private)
            failed_artifact_bytes = b"".join(
                path.read_bytes() for path in artifact.rglob("*") if path.is_file()
            )
            for raw in private:
                self.assertNotIn(raw, str(result))
                self.assertNotIn(raw.encode(), server_log)
                self.assertNotIn(raw.encode(), failed_artifact_bytes)
            self.assertEqual(hashlib.sha256(server_log).hexdigest(), fixture.server_digest)
            self.assertTrue(validate_bundle_index(artifact)["complete"])

        for report, code in (
            ("absent", "artifact_log_unavailable"),
            ("mismatch", "artifact_log_mismatch"),
            ("changing", "artifact_log_mismatch"),
        ):
            with self.subTest(report=report), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture = _WorkflowFixture(root, ssh=True)
                original_smoke = fixture.smoke
                fixture.smoke = lambda run_id, original_smoke=original_smoke: with_failed_cleanup(original_smoke, run_id)
                transport = _ReportTransport(fixture, server_report=report)
                with self.assertRaises(TargetError) as raised:
                    self._bundle(root, fixture, transport)
                self.assertEqual(raised.exception.code, code)
                self.assertFalse(any(action == "remove_reports" for action, _ in transport.calls))
                self.assertEqual(transport.reports["build.log"], fixture.build_log)
                if report != "absent":
                    self.assertIn("server.log", transport.reports)
                artifact_root = root / "artifacts" / "phase-01-runs" / fixture.config.name
                self.assertFalse(artifact_root.exists() and any(artifact_root.iterdir()))

    def test_ssh_identity_runtime_uses_distinct_validated_target_paths(self) -> None:
        from scripts.targetctl.workflow import _status_runtime

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root, ssh=True)
            fixture.install_ready_state(root)
            capabilities = {"work_token": "1" * 64, "run_token": "2" * 64}
            with patch("scripts.targetctl.source._load_capabilities", return_value=capabilities):
                runtime = _status_runtime(root, "spark", fixture.config)
            self.assertEqual(runtime.model_path, fixture.config.model_path)
            self.assertEqual(runtime.drafter_path, fixture.config.drafter_path)
            self.assertNotEqual(runtime.model_path, runtime.drafter_path)

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

    def test_failed_bundle_keeps_exact_attempt_artifact_but_invalidates_prior_build(self) -> None:
        from scripts.targetctl.artifacts import validate_bundle_index
        from scripts.targetctl.build import BuildResult
        from scripts.targetctl.source import SyncResult
        from scripts.targetctl.workflow import _read_state, execute, run_bundle

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            fixture.install_binary()
            (fixture.run_dir / "build.log").write_bytes(fixture.build_log)
            os.chmod(fixture.run_dir / "build.log", 0o600)
            failed = BuildResult(
                "failed", "command_failed",
                fixture.source.snapshot_id, fixture.source.applied_tree_hash,
                None, None, "make-cuda-spark", None, None, None,
                fixture.build_digest, 2, 19,
            )
            lifecycle = Mock()

            environment = {
                "TARGETCTL_MODEL_PATH": "/private/model-canary.gguf",
                "TARGETCTL_DRAFTER_PATH": "/private/drafter-canary.gguf",
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config),
                patch("scripts.targetctl.workflow.select_transport", return_value=Mock()),
                patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source),
                patch("scripts.targetctl.workflow.controller_provenance", return_value=fixture.provenance),
                patch("scripts.targetctl.workflow.sync_source", return_value=SyncResult(fixture.source, True, fixture.source.applied_tree_hash)),
                patch("scripts.targetctl.workflow.doctor", return_value=fixture.doctor),
                patch("scripts.targetctl.workflow.build", return_value=failed),
                patch("scripts.targetctl.workflow.serve", lifecycle),
            ):
                bundled = run_bundle(root, "local")
                with self.assertRaisesRegex(TargetError, "workflow_state_invalid"):
                    execute(root, "local", "serve")

            artifact = root / bundled["artifact"]
            build_record = json.loads((artifact / "build.json").read_text(encoding="utf-8"))["payload"]
            self.assertEqual(bundled["status"], "failed")
            self.assertEqual(build_record, failed.controller_payload())
            self.assertTrue(validate_bundle_index(artifact)["complete"])
            self.assertIsNone(_read_state(root, "local", True)["build"])
            self.assertFalse(lifecycle.called)

    def test_execute_build_cas_rejects_save_after_identical_sync(self) -> None:
        from scripts.targetctl.source import SyncResult
        from scripts.targetctl.workflow import _read_state, execute

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            synchronized = SyncResult(
                fixture.source, True, fixture.source.applied_tree_hash,
            )
            build_committed = threading.Event()
            resume_build = threading.Event()
            errors: list[BaseException] = []

            def delayed_build(*_args, **_kwargs):
                build_committed.set()
                if not resume_build.wait(5):
                    raise AssertionError("build was not resumed")
                return fixture.build

            def run_build() -> None:
                try:
                    execute(root, "local", "build")
                except BaseException as error:
                    errors.append(error)

            with (
                patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config),
                patch("scripts.targetctl.workflow.select_transport"),
                patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source),
                patch("scripts.targetctl.workflow.sync_source", return_value=synchronized),
                patch("scripts.targetctl.workflow.build", side_effect=delayed_build),
            ):
                worker = threading.Thread(target=run_build)
                worker.start()
                try:
                    self.assertTrue(build_committed.wait(5))
                    result = execute(root, "local", "sync")
                finally:
                    resume_build.set()
                    worker.join(5)

            self.assertFalse(worker.is_alive())
            self.assertEqual(result["snapshot_id"], fixture.source.snapshot_id)
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], TargetError)
            self.assertEqual(errors[0].code, "workflow_source_stale")
            state = _read_state(root, "local", True)
            self.assertEqual(state["source"], fixture.source.as_dict())
            self.assertIsNone(state["build"])
            self.assertIsNone(state["pending"])

    def test_bundle_build_cas_rejects_save_after_identical_sync(self) -> None:
        from scripts.targetctl.source import SyncResult
        from scripts.targetctl.workflow import _read_state, execute, run_bundle

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            synchronized = SyncResult(
                fixture.source, True, fixture.source.applied_tree_hash,
            )
            build_committed = threading.Event()
            resume_build = threading.Event()
            errors: list[BaseException] = []

            def delayed_build(*_args, **_kwargs):
                build_committed.set()
                if not resume_build.wait(5):
                    raise AssertionError("bundle build was not resumed")
                return fixture.build

            def run() -> None:
                try:
                    run_bundle(root, "local")
                except BaseException as error:
                    errors.append(error)

            with (
                patch.dict(
                    os.environ,
                    {
                        "TARGETCTL_MODEL_PATH": "/private/model-canary.gguf",
                        "TARGETCTL_DRAFTER_PATH": "/private/drafter-canary.gguf",
                    },
                    clear=False,
                ),
                patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config),
                patch("scripts.targetctl.workflow.select_transport"),
                patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source),
                patch("scripts.targetctl.workflow.controller_provenance", return_value=fixture.provenance),
                patch("scripts.targetctl.workflow.sync_source", return_value=synchronized),
                patch("scripts.targetctl.workflow.doctor", return_value=fixture.doctor),
                patch("scripts.targetctl.workflow.build", side_effect=delayed_build),
            ):
                worker = threading.Thread(target=run)
                worker.start()
                try:
                    self.assertTrue(build_committed.wait(5))
                    execute(root, "local", "sync")
                finally:
                    resume_build.set()
                    worker.join(5)

            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], TargetError)
            self.assertEqual(errors[0].code, "workflow_source_stale")
            state = _read_state(root, "local", True)
            self.assertEqual(state["source"], fixture.source.as_dict())
            self.assertIsNone(state["build"])
            self.assertIsNone(state["pending"])

    def test_newer_post_sync_build_survives_delayed_old_save_until_next_sync(self) -> None:
        from scripts.targetctl.source import SyncResult
        from scripts.targetctl.workflow import (
            _build_generation,
            _read_state,
            _ready,
            _save_build,
            execute,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            old_generation = _build_generation(
                root, fixture.config.name, fixture.source,
            )
            newer = replace(fixture.build, build_id="e" * 64)
            synchronized = SyncResult(
                fixture.source, True, fixture.source.applied_tree_hash,
            )

            with (
                patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config),
                patch("scripts.targetctl.workflow.select_transport"),
                patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source),
                patch("scripts.targetctl.workflow.sync_source", return_value=synchronized),
                patch("scripts.targetctl.workflow.build", return_value=newer),
            ):
                execute(root, "local", "sync")
                built = execute(root, "local", "build")
                with self.assertRaisesRegex(TargetError, "workflow_source_stale"):
                    _save_build(
                        root,
                        fixture.config.name,
                        fixture.source,
                        fixture.build,
                        expected_generation=old_generation,
                    )
                source, current = _ready(root, "local")
                self.assertEqual(source, fixture.source)
                self.assertEqual(current["build_id"], newer.build_id)
                self.assertEqual(built["build_id"], newer.build_id)
                execute(root, "local", "sync")

            self.assertIsNone(_read_state(root, "local", True)["build"])

    def test_sync_interruption_releases_controller_lock_without_mutation(self) -> None:
        from scripts.targetctl.source import SyncResult
        from scripts.targetctl.workflow import _read_state, execute

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            before = _read_state(root, "local", True)
            synchronized = SyncResult(
                fixture.source, True, fixture.source.applied_tree_hash,
            )

            with (
                patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config),
                patch("scripts.targetctl.workflow.select_transport"),
            ):
                with patch("scripts.targetctl.workflow.sync_source", side_effect=KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        execute(root, "local", "sync")
                self.assertEqual(_read_state(root, "local", True), before)
                with patch("scripts.targetctl.workflow.sync_source", return_value=synchronized):
                    result = execute(root, "local", "sync")

            self.assertEqual(result["snapshot_id"], fixture.source.snapshot_id)
            self.assertIsNone(_read_state(root, "local", True)["build"])

    def test_sync_preflight_failure_preserves_existing_controller_state(self) -> None:
        from scripts.targetctl.workflow import (
            _read_state, _ready, _store_pending_run, execute,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            source, built = _ready(root, "local")
            _store_pending_run(
                root, "local", source, built,
                "run-existing-owner-0001",
            )
            before = _read_state(root, "local", True)
            synchronized = Mock()

            with (
                patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config),
                patch("scripts.targetctl.workflow.select_transport"),
                patch("scripts.targetctl.workflow.sync_source", synchronized),
            ):
                with self.assertRaisesRegex(TargetError, "workflow_run_pending"):
                    execute(root, "local", "sync")

            self.assertEqual(_read_state(root, "local", True), before)
            synchronized.assert_not_called()

    def test_pending_run_survives_ambiguous_serve_and_requires_matching_cleanup(self) -> None:
        from scripts.targetctl.lifecycle import CleanupResult
        from scripts.targetctl.workflow import _pending_run, _ready, _store_pending_run, execute

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

            source, built = _ready(root, "local")
            expired = "run-expired-owner-0001"
            _store_pending_run(root, "local", source, built, expired)
            absent = CleanupResult(None, "not_run", "not_found", "not_found", "not_found", "not_found")
            with patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.cleanup", return_value=absent):
                execute(root, "local", "cleanup")
            self.assertIsNone(_pending_run(root, "local"))

    def test_pending_run_cas_refuses_duplicate_owner(self) -> None:
        from scripts.targetctl.workflow import _pending_run, _ready, _store_pending_run

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            source, built = _ready(root, "local")
            barrier = threading.Barrier(2)
            errors: list[str] = []

            def store(run_id: str) -> None:
                barrier.wait()
                try:
                    _store_pending_run(root, "local", source, built, run_id)
                except TargetError as error:
                    errors.append(error.code)

            run_ids = ("run-aaaaaaaaaaaaaaaaaaaaaaaa", "run-bbbbbbbbbbbbbbbbbbbbbbbb")
            workers = [threading.Thread(target=store, args=(run_id,)) for run_id in run_ids]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
            self.assertEqual(len(errors), 1)
            self.assertIn(errors[0], {"workflow_run_pending", "workflow_busy"})
            self.assertIn(_pending_run(root, "local"), run_ids)

    def test_pre_dispatch_refusal_clears_only_new_pending_owner(self) -> None:
        from scripts.targetctl.workflow import _pending_run, execute

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            fixture.install_binary()
            observed: list[str] = []

            def refused(*_args, run_id: str, **_kwargs) -> None:
                observed.append(run_id)
                self.assertEqual(_pending_run(root, "local"), run_id)
                raise TargetError("serve_not_dispatched", "target server launch was refused")

            environment = {"TARGETCTL_MODEL_PATH": "/private/model-canary.gguf", "TARGETCTL_DRAFTER_PATH": "/private/drafter-canary.gguf"}
            with patch.dict(os.environ, environment, clear=False), patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source), patch("scripts.targetctl.workflow.serve", side_effect=refused):
                with self.assertRaisesRegex(TargetError, "serve_not_dispatched"):
                    execute(root, "local", "serve")
            self.assertEqual(len(observed), 1)
            self.assertIsNone(_pending_run(root, "local"))

    def test_smoke_pre_dispatch_refusal_clears_new_pending_owner(self) -> None:
        from scripts.targetctl.workflow import _pending_run, execute

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            fixture.install_binary()
            observed: list[str] = []

            def refused(*_args, run_id: str, **_kwargs) -> None:
                observed.append(run_id)
                self.assertEqual(_pending_run(root, "local"), run_id)
                raise TargetError("serve_not_dispatched", "target server launch was refused")

            environment = {"TARGETCTL_MODEL_PATH": "/private/model-canary.gguf", "TARGETCTL_DRAFTER_PATH": "/private/drafter-canary.gguf"}
            with patch.dict(os.environ, environment, clear=False), patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source), patch("scripts.targetctl.workflow.smoke", side_effect=refused):
                with self.assertRaisesRegex(TargetError, "serve_not_dispatched"):
                    execute(root, "local", "smoke")
            self.assertEqual(len(observed), 1)
            self.assertIsNone(_pending_run(root, "local"))

    def test_refusal_cas_does_not_clear_a_different_pending_owner(self) -> None:
        from scripts.targetctl.workflow import (
            _clear_new_pending_on_refusal, _pending_run, _ready,
            _store_pending_run,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            source, built = _ready(root, "local")
            replacement = "run-replacement-owner-0001"
            _store_pending_run(root, "local", source, built, replacement)

            _clear_new_pending_on_refusal(
                root,
                "local",
                "run-refused-owner-0001",
                TargetError("serve_not_dispatched", "target server launch was refused"),
            )
            self.assertEqual(_pending_run(root, "local"), replacement)

    def test_ambiguous_smoke_error_retains_pending_owner(self) -> None:
        from scripts.targetctl.workflow import _pending_run, execute

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _WorkflowFixture(root)
            fixture.install_ready_state(root)
            fixture.install_binary()
            observed: list[str] = []

            def ambiguous(*_args, run_id: str, **_kwargs) -> None:
                observed.append(run_id)
                raise TargetError("helper_timeout", "dispatch outcome is unavailable")

            environment = {"TARGETCTL_MODEL_PATH": "/private/model-canary.gguf", "TARGETCTL_DRAFTER_PATH": "/private/drafter-canary.gguf"}
            with patch.dict(os.environ, environment, clear=False), patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source), patch("scripts.targetctl.workflow.smoke", side_effect=ambiguous):
                with self.assertRaisesRegex(TargetError, "helper_timeout"):
                    execute(root, "local", "smoke")
            self.assertEqual(_pending_run(root, "local"), observed[0])

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
            with patch.dict(os.environ, environment, clear=False), patch("scripts.targetctl.workflow.load_operational_target", return_value=fixture.config), patch("scripts.targetctl.workflow.select_transport"), patch("scripts.targetctl.workflow.build_snapshot", return_value=fixture.source), patch("scripts.targetctl.workflow.doctor", return_value=fixture.doctor):
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
            state = (root / "targets" / ".state" / "local.workflow-v2.json").read_text(encoding="utf-8")
            self.assertTrue(all(value not in str((doctor, built, logs, smoked)) and value not in state for value in (private, "/private/drafter-canary.gguf")))
