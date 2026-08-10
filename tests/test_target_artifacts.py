from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from scripts.targetctl.artifacts import ArtifactBundle, MAX_SOURCE_FILE_BYTES, _validate_record_payload, controller_provenance, validate_bundle_index
from scripts.targetctl.common import TargetError, canonical_json_bytes, read_json_file
from scripts.targetctl import source as source_helper
from scripts.targetctl.remote import LAUNCH_PROFILE
from scripts.targetctl.redaction import StreamingRedactor


STAMP = "2026-08-08T12:34:56Z"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _snapshot(entries: int = 1, *, paths: tuple[str, ...] | None = None) -> dict[str, object]:
    repositories = [
        {"name": "lab", "head": "a" * 40, "pinned_head": None, "dirty": False, "status_sha256": "b" * 64, "tracked_diff_sha256": "c" * 64},
        {"name": "engine", "head": "d" * 40, "pinned_head": "e" * 40, "dirty": False, "status_sha256": "f" * 64, "tracked_diff_sha256": "0" * 64},
        {"name": "integration", "head": "1" * 40, "pinned_head": "2" * 40, "dirty": False, "status_sha256": "3" * 64, "tracked_diff_sha256": "4" * 64},
    ]
    if paths is None:
        paths = tuple(f"src/file-{index:06d}.py" for index in range(entries))
    inventory = [
        {"path": path, "type": "file", "executable": 0, "size": index, "sha256": _digest(f"entry-{index}"), "origin": "tracked"}
        for index, path in enumerate(paths)
    ]
    applied_tree_hash = source_helper._tree_hash(
        source_helper.SourceEntry(entry["path"], entry["executable"], entry["size"], entry["sha256"], entry["origin"])
        for entry in inventory
    )
    identity = {
        "schema_version": 1, "exclusion_policy_version": 1, "exclusions": list(source_helper._EXCLUDED_ROOTS),
        "repositories": repositories, "entries": inventory, "applied_tree_hash": applied_tree_hash,
    }
    snapshot_id = hashlib.sha256(b"targetctl-source-snapshot-v1\0" + canonical_json_bytes(identity)).hexdigest()
    return {
        "schema_version": 1, "exclusion_policy_version": 1, "repositories": repositories, "dirty": False,
        "entries": inventory, "applied_tree_hash": applied_tree_hash, "snapshot_id": snapshot_id,
    }


def _payload(name: str, *, build_log_sha256: str | None = None, server_log_sha256: str | None = None, entries: int = 1) -> dict[str, object]:
    snapshot = _snapshot(entries)
    snapshot_id, applied_hash, build_id, binary_hash, primary_hash, draft_hash = snapshot["snapshot_id"], snapshot["applied_tree_hash"], "7" * 64, "8" * 64, "9" * 64, "a" * 64
    if name == "controller":
        return {
            "provenance": {
                "repositories": [
                    {"identity": "lab", "commit": "a" * 40, "clean": True},
                    {"identity": "engine/ds4", "commit": "d" * 40, "gitlink": "e" * 40, "clean": True},
                    {"identity": "spark/ds4-on-spark", "commit": "1" * 40, "gitlink": "2" * 40, "clean": True},
                ],
                "flake_lock_hash": "d" * 64,
                "nixpkgs_revision": "e" * 40,
                "system": {"os": "Linux", "kernel": "1.2.3", "arch": "x86_64"},
                "tools": {"git": "1.2.3", "nix": "unavailable", "python": "3.14.0"},
            }
        }
    if name == "source":
        return {"snapshot": _snapshot(entries)}
    if name == "target-doctor":
        return {
            "status": "succeeded", "failure_class": None, "os": "Linux", "kernel": "6.12.0", "arch": "aarch64",
            "tools": [
                {"name": "nvidia-smi", "version": "570.1", "location": "/usr/bin/nvidia-smi"},
                {"name": "nvcc", "version": "12.8", "location": "/usr/local/cuda/bin/nvcc"},
                {"name": "gcc", "version": "14.2", "location": "/usr/bin/gcc"},
                {"name": "g++", "version": "14.2", "location": "/usr/bin/g++"},
                {"name": "make", "version": "4.4", "location": "/usr/bin/make"},
                {"name": "python3", "version": "3.13", "location": "/usr/bin/python3"},
                {"name": "git", "version": "2.47", "location": "/usr/bin/git"},
                {"name": "rsync", "version": "3.4", "location": "/usr/bin/rsync"},
                {"name": "cuobjdump", "version": "12.8", "location": "/usr/local/cuda/bin/cuobjdump"},
            ],
            "gpu": {"platform": "GB10", "compute_capability": "sm_121"},
            "memory_bytes": 1024, "disk_bytes": 1024, "time_sync": True,
            "primary_weight_sha256": primary_hash, "draft_weight_sha256": draft_hash,
            "nix": {"status": "matched", "version": "2.28.5"},
        }
    if name == "build":
        return {
            "status": "succeeded", "failure_class": None, "source_snapshot_id": snapshot_id, "source_applied_tree_hash": applied_hash,
            "build_id": build_id, "binary_sha256": binary_hash, "command": "make-cuda-spark", "version": "1.2.3",
            "binary_size": 1024, "sass": "verified", "build_log_sha256": build_log_sha256, "exit_code": 0, "duration_ns": 1000,
        }
    if name == "run":
        return {
            "status": "succeeded", "failure_class": None, "state": "stopped", "run_id": "run-1",
            "source_snapshot_id": snapshot_id, "build_id": build_id, "binary_sha256": binary_hash,
            "supervisor_pid": 100, "supervisor_start_ticks": 200, "child_pid": 101, "child_start_ticks": 201, "port": 8080,
            "launch_profile": dict(LAUNCH_PROFILE),
        }
    if name == "smoke":
        return {
            "status": "succeeded", "failure_class": None, "readiness_http": 200, "models_http": 200, "contract": "passed",
            "primary_weight_sha256": primary_hash, "draft_weight_sha256": draft_hash, "duration_ns": 1000,
        }
    return {
        "status": "succeeded", "failure_class": None, "process": "cleared", "socket": "not_found", "lock": "cleared", "temp": "cleared",
        "server_log_sha256": server_log_sha256,
    }


class ArtifactBundleTests(unittest.TestCase):
    def _bundle(self, root: Path, operation_id: str = "operation-1") -> ArtifactBundle:
        return ArtifactBundle(root, "spark", operation_id, operation="sync")

    def _complete(
        self,
        bundle: ArtifactBundle,
        *,
        entries: int = 1,
        overrides: dict[str, dict[str, object]] | None = None,
    ) -> None:
        build_source = bundle._repo_root / f"{bundle.operation_id}-build.log"
        server_source = bundle._repo_root / f"{bundle.operation_id}-server.log"
        build_source.write_text("build output\n", encoding="utf-8")
        server_source.write_text("server output\n", encoding="utf-8")
        bundle.promote_text("build-log", build_source, StreamingRedactor())
        bundle.promote_text("server-log", server_source, StreamingRedactor())
        build_hash = hashlib.sha256((bundle._staging / "texts" / "build-log.txt").read_bytes()).hexdigest()
        server_hash = hashlib.sha256((bundle._staging / "texts" / "server-log.txt").read_bytes()).hexdigest()
        for name in ("controller", "source", "target-doctor", "build", "run", "smoke", "cleanup"):
            payload = _payload(name, build_log_sha256=build_hash, server_log_sha256=server_hash, entries=entries)
            if overrides and name in overrides:
                payload.update(overrides[name])
            bundle.write_record(name, payload, created_at=STAMP)

    def test_parent_chain_and_incomplete_bundle_never_promote(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self._bundle(root)
            with self.assertRaises(TargetError) as raised:
                bundle.write_record("source", _payload("source"), created_at=STAMP)
            self.assertEqual(raised.exception.code, "artifact_parent_invalid")
            bundle.write_record("controller", _payload("controller"), created_at=STAMP)
            with self.assertRaises(TargetError) as raised:
                bundle.finalize()
            self.assertEqual(raised.exception.code, "artifact_incomplete")
            self.assertFalse((root / "artifacts" / "phase-01-runs" / "spark" / "operation-1").exists())

    def test_source_snapshot_paths_match_source_inventory_components(self) -> None:
        payload = {"snapshot": _snapshot(paths=(".envrc", "nested/.gitignore", "scripts/targetctl/__main__.py"))}

        self.assertEqual(_validate_record_payload("source", payload), payload)

    def test_source_snapshot_paths_reject_unsafe_components(self) -> None:
        unsafe_paths = (
            "",
            "/absolute.py",
            ".",
            "..",
            "nested//file.py",
            "nested/./file.py",
            "nested/../file.py",
            "nested\\file.py",
            "control\nfile.py",
            "a" * 129,
        )
        for path in unsafe_paths:
            with self.subTest(path=path):
                payload = {"snapshot": _snapshot(paths=(path,))}
                with self.assertRaises(TargetError) as raised:
                    _validate_record_payload("source", payload)
                self.assertEqual(raised.exception.code, "artifact_value_invalid")

    def test_duplicate_unknown_fields_and_private_fields_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self._bundle(Path(temporary))
            bundle.write_record("controller", _payload("controller"), created_at=STAMP)
            with self.assertRaises(TargetError) as raised:
                bundle.write_record("controller", _payload("controller"), created_at=STAMP)
            self.assertEqual(raised.exception.code, "artifact_record_invalid")
            with self.assertRaises(TargetError) as raised:
                bundle.write_record("not-a-record", {"kind": "x"}, created_at=STAMP)
            self.assertEqual(raised.exception.code, "artifact_record_invalid")
            for field in ("model_path", "target_address", "ssh_user", "credential"):
                with self.subTest(field=field):
                    other = self._bundle(Path(temporary), f"other-{field}")
                    with self.assertRaises(TargetError) as raised:
                        other.write_record("controller", {field: "private"}, created_at=STAMP)
                    self.assertEqual(raised.exception.code, "schema_fields_invalid")
            unsafe_value = self._bundle(Path(temporary), "unsafe-value")
            with self.assertRaises(TargetError) as raised:
                unsafe_value.write_record("controller", {"note": "/home/user/model.gguf"}, created_at=STAMP)
            self.assertEqual(raised.exception.code, "schema_fields_invalid")

    def test_ids_and_file_hashes_are_deterministic_and_index_is_sufficient(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self._bundle(root, "first")
            second = self._bundle(root, "second")
            self._complete(first, entries=6000)
            self._complete(second, entries=6000)
            first_path = root / first.finalize()
            second_path = root / second.finalize()
            first_index = read_json_file(first_path / "index.json")
            second_index = read_json_file(second_path / "index.json")
            self.assertEqual(first_index["record_ids"], second_index["record_ids"])
            self.assertEqual([item["name"] for item in first_index["files"]], [item["name"] for item in second_index["files"]])
            self.assertEqual(validate_bundle_index(first_path), first_index)
            self.assertEqual(set(first_index["record_ids"]), {"controller", "source", "target-doctor", "build", "run", "smoke", "cleanup"})
            for item in first_index["files"]:
                content = (first_path / item["name"]).read_bytes()
                self.assertEqual(len(content), item["size"])
                import hashlib
                self.assertEqual(hashlib.sha256(content).hexdigest(), item["sha256"])
            source = read_json_file(first_path / "source.json", max_bytes=MAX_SOURCE_FILE_BYTES)
            self.assertEqual(source["parent_ids"], [first_index["record_ids"]["controller"]])
            durations = [
                read_json_file(first_path / f"{name}.json", max_bytes=MAX_SOURCE_FILE_BYTES)["duration_ns"]
                for name in ("controller", "source", "target-doctor", "build", "run", "smoke", "cleanup")
            ]
            self.assertEqual(len(source["payload"]["snapshot"]["entries"]), 6000)
            self.assertEqual([repository["name"] for repository in source["payload"]["snapshot"]["repositories"]], ["lab", "engine", "integration"])
            self.assertEqual(durations, sorted(durations))
            self.assertEqual(stat.S_IMODE(first_path.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((first_path / "controller.json").stat().st_mode), 0o600)
            malformed_index = dict(first_index)
            malformed_index["unexpected"] = True
            (first_path / "index.json").write_text(json.dumps(malformed_index), encoding="utf-8")
            with self.assertRaises(TargetError):
                validate_bundle_index(first_path)
            (first_path / "index.json").write_text('{"schema":1,"schema":1}', encoding="utf-8")
            with self.assertRaises(TargetError):
                validate_bundle_index(first_path)

    def test_typed_records_reject_free_form_private_and_dishonest_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_bundle = self._bundle(root, "source-invalid")
            source_bundle.write_record("controller", _payload("controller"), created_at=STAMP)
            bad_source = _payload("source")
            bad_source["private_path"] = "/home/target/model.gguf"
            with self.assertRaises(TargetError):
                source_bundle.write_record("source", bad_source, created_at=STAMP)

            doctor_bundle = self._bundle(root, "doctor-invalid")
            doctor_bundle.write_record("controller", _payload("controller"), created_at=STAMP)
            doctor_bundle.write_record("source", _payload("source"), created_at=STAMP)
            bad_doctor = _payload("target-doctor")
            bad_doctor["tools"][1]["location"] = "/home/target/bin/nvcc"
            with self.assertRaises(TargetError):
                doctor_bundle.write_record("target-doctor", bad_doctor, created_at=STAMP)

            bundle = self._bundle(root, "typed-invalid")
            bundle.write_record("controller", _payload("controller"), created_at=STAMP)
            bundle.write_record("source", _payload("source"), created_at=STAMP)
            bundle.write_record("target-doctor", _payload("target-doctor"), created_at=STAMP)
            bad_build = _payload("build")
            with self.assertRaises(TargetError):
                bundle.write_record("build", bad_build, created_at=STAMP)
            failed_build = _payload("build")
            failed_build.update({"status": "failed", "failure_class": "command_failed", "source_snapshot_id": None, "source_applied_tree_hash": None, "build_id": None, "binary_sha256": None, "command": None, "version": None, "binary_size": None, "sass": None, "build_log_sha256": None, "exit_code": None, "duration_ns": None})
            bundle.write_record("build", failed_build, created_at=STAMP)
            bad_run = _payload("run")
            bad_run["state"] = "running"
            bad_run["child_pid"] = None
            bad_run["child_start_ticks"] = None
            with self.assertRaises(TargetError):
                bundle.write_record("run", bad_run, created_at=STAMP)
            failed_run = _payload("run")
            failed_run.update({"status": "failed", "failure_class": "command_failed", "state": "failed_startup", "source_snapshot_id": None, "build_id": None, "binary_sha256": None, "supervisor_pid": None, "supervisor_start_ticks": None, "child_pid": None, "child_start_ticks": None, "port": None})
            bundle.write_record("run", failed_run, created_at=STAMP)
            bad_smoke = _payload("smoke")
            bad_smoke["readiness_http"] = True
            with self.assertRaises(TargetError):
                bundle.write_record("smoke", bad_smoke, created_at=STAMP)
            not_run_smoke = _payload("smoke")
            not_run_smoke.update({"status": "not_run", "failure_class": None, "readiness_http": None, "models_http": None, "contract": "not_run", "primary_weight_sha256": None, "draft_weight_sha256": None, "duration_ns": None})
            bundle.write_record("smoke", not_run_smoke, created_at=STAMP)
            bad_cleanup = _payload("cleanup")
            bad_cleanup["process"] = True
            with self.assertRaises(TargetError):
                bundle.write_record("cleanup", bad_cleanup, created_at=STAMP)

    def test_build_attempt_evidence_has_dependency_safe_status_rules(self) -> None:
        command_failed = _payload("build", build_log_sha256="d" * 64)
        command_failed.update({
            "status": "failed", "failure_class": "command_failed", "build_id": None,
            "binary_sha256": None, "version": None, "binary_size": None, "sass": None,
            "exit_code": 2, "duration_ns": 42,
        })
        self.assertEqual(_validate_record_payload("build", command_failed)["exit_code"], 2)
        timed_out = dict(command_failed)
        timed_out.update({"failure_class": "timeout", "exit_code": None})
        self.assertIsNone(_validate_record_payload("build", timed_out)["exit_code"])
        preflight = dict(command_failed)
        preflight.update({
            "failure_class": "preflight", "command": None, "build_log_sha256": None,
            "exit_code": None, "duration_ns": None,
        })
        self.assertIsNone(_validate_record_payload("build", preflight)["command"])
        for key, value in (("duration_ns", None), ("build_log_sha256", None), ("exit_code", 0)):
            malformed = dict(command_failed)
            malformed[key] = value
            with self.subTest(key=key):
                with self.assertRaises(TargetError):
                    _validate_record_payload("build", malformed)

    def test_doctor_facts_require_the_exact_finite_tools_and_healthy_values(self) -> None:
        payload = _payload("target-doctor")
        self.assertEqual(
            [item["name"] for item in payload["tools"]],
            ["nvidia-smi", "nvcc", "gcc", "g++", "make", "python3", "git", "rsync", "cuobjdump"],
        )
        resolved = _payload("target-doctor")
        resolved["tools"][2]["location"] = "/usr/bin/gcc-14"
        resolved["tools"][3]["location"] = "/usr/bin/g++-14"
        resolved["tools"][5]["location"] = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-python3/bin/python3.13"
        validated = _validate_record_payload("target-doctor", resolved)
        self.assertEqual(validated["tools"][2]["location"], "/usr/bin/gcc-14")
        for unsafe in ("/tmp/gcc", "/home/target/gcc", "/usr/bin/../gcc", "/usr/bin/gcc name"):
            with self.subTest(location=unsafe):
                malformed = _payload("target-doctor")
                malformed["tools"][2]["location"] = unsafe
                with self.assertRaises(TargetError):
                    _validate_record_payload("target-doctor", malformed)
        for field, value in (("memory_bytes", 0), ("disk_bytes", 0), ("time_sync", False)):
            with self.subTest(field=field):
                malformed = _payload("target-doctor")
                malformed[field] = value
                with self.assertRaises(TargetError):
                    _validate_record_payload("target-doctor", malformed)

    def test_advertised_log_mismatch_or_missing_fails_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mismatch = self._bundle(root, "mismatch")
            self._complete(mismatch)
            (mismatch._staging / "texts" / "build-log.txt").write_text("tampered", encoding="utf-8")
            with self.assertRaises(TargetError) as raised:
                mismatch.finalize()
            self.assertEqual(raised.exception.code, "artifact_log_mismatch")
            missing = self._bundle(root, "missing")
            self._complete(missing)
            (missing._staging / "texts" / "server-log.txt").unlink()
            with self.assertRaises(TargetError) as raised:
                missing.finalize()
            self.assertEqual(raised.exception.code, "artifact_log_missing")

    def test_failed_cleanup_retains_advertised_server_log_evidence(self) -> None:
        failed_cleanup = {
            "status": "failed",
            "failure_class": "command_failed",
            "process": "unknown",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retained = self._bundle(root, "failed-cleanup-retained")
            self._complete(retained, overrides={"cleanup": failed_cleanup})
            live_server_log = root / f"{retained.operation_id}-server.log"
            live_server_log.write_text("live server continued\n", encoding="utf-8")
            retained_path = root / retained.finalize()
            retained_index = validate_bundle_index(retained_path)
            cleanup = read_json_file(retained_path / "cleanup.json")["payload"]
            server_log = (retained_path / "texts" / "server-log.txt").read_bytes()
            self.assertEqual(live_server_log.read_text(encoding="utf-8"), "live server continued\n")
            self.assertEqual(server_log, b"server output\n")
            self.assertEqual(cleanup["status"], "failed")
            self.assertEqual(hashlib.sha256(server_log).hexdigest(), cleanup["server_log_sha256"])
            self.assertTrue(retained_index["complete"])

            missing = self._bundle(root, "failed-cleanup-missing")
            self._complete(missing, overrides={"cleanup": failed_cleanup})
            (missing._staging / "texts" / "server-log.txt").unlink()
            with self.assertRaises(TargetError) as raised:
                missing.finalize()
            self.assertEqual(raised.exception.code, "artifact_log_missing")

            mismatch = self._bundle(root, "failed-cleanup-mismatch")
            self._complete(
                mismatch,
                overrides={
                    "cleanup": {
                        **failed_cleanup,
                        "server_log_sha256": "0" * 64,
                    }
                },
            )
            with self.assertRaises(TargetError) as raised:
                mismatch.finalize()
            self.assertEqual(raised.exception.code, "artifact_log_mismatch")

    def test_status_and_lifecycle_matrices_reject_contradictory_evidence(self) -> None:
        not_run_payloads = {
            "target-doctor": {
                "status": "not_run", "failure_class": None, "os": None, "kernel": None, "arch": None,
                "tools": [{"name": tool["name"], "version": None, "location": None} for tool in _payload("target-doctor")["tools"]],
                "gpu": None, "memory_bytes": None, "disk_bytes": None, "time_sync": None,
                "primary_weight_sha256": None, "draft_weight_sha256": None,
                "nix": {"status": "unavailable", "version": None},
            },
            "build": {
                "status": "not_run", "failure_class": None, "source_snapshot_id": None, "source_applied_tree_hash": None,
                "build_id": None, "binary_sha256": None, "command": None, "version": None, "binary_size": None,
                "sass": "not_run", "build_log_sha256": None, "exit_code": None, "duration_ns": None,
            },
            "run": {
                "status": "not_run", "failure_class": None, "state": None, "run_id": None, "source_snapshot_id": None,
                "build_id": None, "binary_sha256": None, "supervisor_pid": None, "supervisor_start_ticks": None,
                "child_pid": None, "child_start_ticks": None, "port": None,
                "launch_profile": None,
            },
            "smoke": {
                "status": "not_run", "failure_class": None, "readiness_http": None, "models_http": None,
                "contract": "not_run", "primary_weight_sha256": None, "draft_weight_sha256": None, "duration_ns": None,
            },
            "cleanup": {
                "status": "not_run", "failure_class": None, "process": "not_run", "socket": None,
                "lock": "not_run", "temp": None, "server_log_sha256": None,
            },
        }
        failed_doctor = {**_payload("target-doctor"), "status": "failed", "failure_class": "preflight"}
        failed_doctor["nix"] = {"status": "unavailable", "version": None}
        failed_payloads = {
            "target-doctor": failed_doctor,
            "build": {**_payload("build", build_log_sha256="d" * 64), "status": "failed", "failure_class": "command_failed", "build_id": None, "binary_sha256": None, "version": None, "binary_size": None, "sass": None, "exit_code": 2},
            "run": {**_payload("run"), "status": "failed", "failure_class": "command_failed", "state": "failed_startup", "run_id": None, "source_snapshot_id": None, "build_id": None, "binary_sha256": None, "supervisor_pid": None, "supervisor_start_ticks": None, "child_pid": None, "child_start_ticks": None, "port": None},
            "smoke": {**_payload("smoke"), "status": "failed", "failure_class": "contract_failed", "contract": "failed"},
            "cleanup": {**_payload("cleanup"), "status": "failed", "failure_class": "command_failed", "process": "unknown"},
        }
        for name, payload in not_run_payloads.items():
            with self.subTest(name=name, status="not_run"):
                self.assertEqual(_validate_record_payload(name, payload)["status"], "not_run")
        for name, payload in failed_payloads.items():
            with self.subTest(name=name, status="failed"):
                self.assertEqual(_validate_record_payload(name, payload)["status"], "failed")
        for name in not_run_payloads:
            contradictory = dict(not_run_payloads[name])
            contradictory["failure_class"] = "command_failed"
            with self.subTest(name=name, contradiction="not_run failure"):
                with self.assertRaises(TargetError):
                    _validate_record_payload(name, contradictory)
        contradictory_payloads = (
            ("target-doctor", {**not_run_payloads["target-doctor"], "os": "Linux"}),
            ("build", {**not_run_payloads["build"], "sass": "verified"}),
            ("build", {**_payload("build"), "sass": "missing"}),
            ("run", {**not_run_payloads["run"], "state": "failed_startup"}),
            ("run", {**_payload("run"), "child_pid": None, "child_start_ticks": None}),
            ("run", {**_payload("run"), "status": "failed", "failure_class": "command_failed"}),
            ("smoke", {**not_run_payloads["smoke"], "readiness_http": 200}),
            ("smoke", {**_payload("smoke"), "models_http": 500}),
            ("cleanup", {**not_run_payloads["cleanup"], "process": "cleared"}),
            ("cleanup", {**_payload("cleanup"), "socket": "unknown"}),
        )
        for name, payload in contradictory_payloads:
            with self.subTest(name=name, payload=payload):
                with self.assertRaises(TargetError):
                    _validate_record_payload(name, payload)

    def test_finalization_rejects_dependency_and_identity_mismatches(self) -> None:
        build_not_run = {
            "status": "not_run", "failure_class": None, "source_snapshot_id": None, "source_applied_tree_hash": None,
            "build_id": None, "binary_sha256": None, "command": None, "version": None, "binary_size": None,
            "sass": "not_run", "build_log_sha256": None, "exit_code": None, "duration_ns": None,
        }
        run_not_run = {
            "status": "not_run", "failure_class": None, "state": None, "run_id": None, "source_snapshot_id": None,
            "build_id": None, "binary_sha256": None, "supervisor_pid": None, "supervisor_start_ticks": None,
            "child_pid": None, "child_start_ticks": None, "port": None,
            "launch_profile": None,
        }
        doctor_not_run = {
            "status": "not_run",
            "failure_class": None,
            "os": None,
            "kernel": None,
            "arch": None,
            "tools": [
                {"name": tool["name"], "version": None, "location": None}
                for tool in _payload("target-doctor")["tools"]
            ],
            "gpu": None,
            "memory_bytes": None,
            "disk_bytes": None,
            "time_sync": None,
            "primary_weight_sha256": None,
            "draft_weight_sha256": None,
            "nix": {"status": "unavailable", "version": None},
        }
        smoke_not_run = {
            "status": "not_run",
            "failure_class": None,
            "readiness_http": None,
            "models_http": None,
            "contract": "not_run",
            "primary_weight_sha256": None,
            "draft_weight_sha256": None,
            "duration_ns": None,
        }
        controller_mismatch = json.loads(json.dumps(_payload("controller")))
        controller_mismatch["provenance"]["repositories"][1]["commit"] = "f" * 40
        attempted_failure = {"status": "failed", "failure_class": "command_failed", "build_id": None, "binary_sha256": None, "version": None, "binary_size": None, "sass": None, "exit_code": 2, "duration_ns": 1}
        cases = (
            ("doctor-failure", {"target-doctor": {"status": "failed", "failure_class": "preflight"}}),
            ("build-failure", {"build": attempted_failure}),
            ("build-not-run", {"build": build_not_run}),
            ("run-failure", {"run": {"status": "failed", "failure_class": "command_failed", "state": "failed_startup"}}),
            ("run-not-run", {"run": run_not_run}),
            ("build-source", {"build": {"source_snapshot_id": "b" * 64}}),
            ("run-binary", {"run": {"binary_sha256": "c" * 64}}),
            ("smoke-weight", {"smoke": {"primary_weight_sha256": "d" * 64}}),
            (
                "doctor-not-run-build-attempted",
                {
                    "target-doctor": doctor_not_run,
                    "build": attempted_failure,
                    "run": run_not_run,
                    "smoke": smoke_not_run,
                },
            ),
            ("controller-source", {"controller": controller_mismatch}),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for operation_id, overrides in cases:
                with self.subTest(operation_id=operation_id):
                    bundle = self._bundle(root, operation_id)
                    self._complete(bundle, overrides=overrides)
                    with self.assertRaises(TargetError) as raised:
                        bundle.finalize()
                    self.assertEqual(raised.exception.code, "artifact_record_invalid")

    def test_run_lifecycle_states_use_exact_status_vocabulary(self) -> None:
        for state in ("running", "stopped"):
            payload = _payload("run")
            payload["state"] = state
            self.assertEqual(_validate_record_payload("run", payload)["state"], state)
        for state in ("starting", "failed_startup", "stale_identity", "failed", "stale"):
            payload = _payload("run")
            payload["state"] = state
            with self.assertRaises(TargetError):
                _validate_record_payload("run", payload)

    def test_symlink_traversal_and_unsafe_text_inputs_fail(self) -> None:

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "secret.txt"
            source.write_text("safe", encoding="utf-8")
            link = root / "link.txt"
            link.symlink_to(source)
            bundle = self._bundle(root)
            with self.assertRaises(TargetError) as raised:
                bundle.promote_text("log", link, StreamingRedactor())
            self.assertEqual(raised.exception.code, "artifact_source_unsafe")
            with self.assertRaises(TargetError) as raised:
                ArtifactBundle(root, "../spark", "traversal")
            self.assertEqual(raised.exception.code, "artifact_name_invalid")
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(TargetError) as raised:
                bundle.promote_text("fifo", fifo, StreamingRedactor())
            self.assertEqual(raised.exception.code, "artifact_source_unsafe")

    def test_text_promotion_redacts_split_canaries_and_invalid_bytes(self) -> None:
        from scripts.targetctl.config import TargetConfig
        from scripts.targetctl.workflow import _private_canaries

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "raw.log"
            canary = (
                "/mnt/targetctl-private/models/drafter/"
                + "/".join(f"segment-{index:02d}-" + ("x" * 96) for index in range(6))
                + "/draft.gguf"
            )
            self.assertGreater(len(canary), 512)
            config = TargetConfig(
                "spark", "ssh", ssh_host="target-alias",
                workdir="/mnt/ds4-data/spark/work",
                run_dir="/mnt/ds4-data/spark/run",
                api_base_url="http://127.0.0.1:8080",
                model_path="/home/private-user/models/releases/model.gguf",
                drafter_path=canary, source_root=root,
            )
            config.validate_for("logs")
            private = _private_canaries(config)
            self.assertIn(canary, private)
            emitted_ancestor = str(Path(canary).parents[2])
            home_ancestor = "/home/private-user"
            self.assertIn(emitted_ancestor, private)
            self.assertIn("/mnt/targetctl-private", private)
            self.assertIn(home_ancestor, private)
            source.write_bytes(
                b"producer-prefix "
                + home_ancestor.encode()
                + b" middle "
                + emitted_ancestor.encode()
                + b" producer-suffix\x1b[31m red\x1b[0m\ninvalid:\xff\x00\n"
            )
            bundle = self._bundle(root)
            relative = bundle.promote_text(
                "server-log",
                source,
                StreamingRedactor(private),
                canaries=private,
                chunk_bytes=257,
            )
            self.assertEqual(relative, "artifacts/phase-01-runs/spark/operation-1/texts/server-log.txt")
            staged = bundle._staging / "texts" / "server-log.txt"
            content = staged.read_text(encoding="utf-8")
            for private_value in (home_ancestor, emitted_ancestor, "/mnt/targetctl-private"):
                self.assertNotIn(private_value, content)
            self.assertNotIn("\x1b", content)
            self.assertNotIn("\x00", content)
            self.assertIn("invalid:\ufffd", content)
            self.assertIn("producer-prefix [REDACTED] middle [REDACTED] producer-suffix", content)

    def test_streaming_redactor_enforces_utf8_byte_limits(self) -> None:
        redactor = StreamingRedactor(max_output=10)
        output = redactor.feed("ééééé\n") + redactor.finalize()
        self.assertLessEqual(len(output.encode("utf-8")), 10)
        self.assertTrue(output.encode("utf-8").decode("utf-8"))

    def test_oversized_text_is_rejected_without_retention(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "large.log"
            source.write_bytes(b"x" * 128)
            bundle = self._bundle(root)
            with self.assertRaises(TargetError) as raised:
                bundle.promote_text("large", source, StreamingRedactor(), max_bytes=64)
            self.assertEqual(raised.exception.code, "artifact_too_large")
            self.assertFalse((bundle._staging / "texts" / "large.txt").exists())


class ControllerProvenanceTests(unittest.TestCase):
    def _git(self, root: Path, *args: str) -> str:
        return subprocess.check_output(("git", "-C", os.fspath(root), *args), text=True).strip()

    def _commit(self, root: Path, file_name: str) -> str:
        (root / file_name).write_text(file_name, encoding="utf-8")
        self._git(root, "add", file_name)
        self._git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", file_name)
        return self._git(root, "rev-parse", "HEAD")

    def test_fake_workspace_provenance_contains_only_public_identities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "workspace"
            root.mkdir()
            self._git(root, "init")
            engine = temporary_root / "engine-source"
            spark = temporary_root / "spark-source"
            engine.mkdir()
            spark.mkdir()
            self._git(engine, "init")
            self._git(spark, "init")
            engine_commit = self._commit(engine, "engine.txt")
            spark_commit = self._commit(spark, "spark.txt")
            self._git(root, "-c", "protocol.file.allow=always", "submodule", "add", os.fspath(engine), "engine/ds4")
            self._git(root, "-c", "protocol.file.allow=always", "submodule", "add", os.fspath(spark), "spark/ds4-on-spark")
            (root / "flake.lock").write_text(
                json.dumps({"nodes": {"nixpkgs": {"locked": {"rev": "a" * 40}}}}), encoding="utf-8"
            )
            self._git(root, "add", "flake.lock")
            self._git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "workspace")
            provenance = controller_provenance(root)
            self.assertEqual(provenance["repositories"][1]["commit"], engine_commit)
            self.assertEqual(provenance["repositories"][2]["commit"], spark_commit)
            self.assertEqual(provenance["repositories"][1]["gitlink"], engine_commit)
            self.assertEqual(provenance["repositories"][2]["gitlink"], spark_commit)
            self.assertTrue(all(item["clean"] for item in provenance["repositories"]))
            encoded = json.dumps(provenance, sort_keys=True)
            self.assertNotIn(str(root), encoded)
            self.assertNotIn("example.invalid", encoded)
