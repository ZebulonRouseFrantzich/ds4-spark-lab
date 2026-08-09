from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from scripts.targetctl import build as build_module
from scripts.targetctl.build import BuildResult
from scripts.targetctl.transport import CommandResult
from scripts.targetctl.doctor import DOCTOR_TOOLS, DoctorResult, RuntimeInput


class DoctorBuildPayloadTests(unittest.TestCase):
    def test_doctor_payload_is_finite_and_contains_no_runtime_input(self) -> None:
        runtime = RuntimeInput("/private/model.gguf", "/private/drafter.gguf", 8123)
        result = DoctorResult(
            "succeeded", None, "Linux", "6.12.0", "aarch64",
            tuple((name, "1.2.3", location) for name, location in DOCTOR_TOOLS),
            ("GB10", "sm_121"), 1024, 2048, True,
            hashlib.sha256(b"model").hexdigest(), hashlib.sha256(b"draft").hexdigest(),
        )
        payload = result.controller_payload()
        self.assertEqual([item["name"] for item in payload["tools"]], [name for name, _ in DOCTOR_TOOLS])
        self.assertEqual(payload["gpu"], {"platform": "GB10", "compute_capability": "sm_121"})
        self.assertNotIn(runtime.model_path, repr(payload))
        self.assertNotIn(runtime.drafter_path, repr(payload))
        with self.assertRaises(AttributeError):
            result.status = "failed"  # type: ignore[misc]

    def test_build_payload_only_exposes_stable_identity(self) -> None:
        digest = "a" * 64
        result = BuildResult("succeeded", None, digest, digest, digest, digest, "make-cuda-spark", "1.2.3", 10, "verified", digest, 0, 123)
        self.assertEqual(result.controller_payload(), {
            "status": "succeeded", "failure_class": None,
            "source_snapshot_id": digest, "source_applied_tree_hash": digest,
            "build_id": digest, "binary_sha256": digest, "command": "make-cuda-spark",
            "version": "1.2.3", "binary_size": 10, "sass": "verified",
            "build_log_sha256": digest, "exit_code": 0, "duration_ns": 123,
        })
        with self.assertRaises(AttributeError):
            result.sass = "missing"  # type: ignore[misc]

    def test_local_attempt_results_retain_sanitized_evidence(self) -> None:
        snapshot = SimpleNamespace(snapshot_id="a" * 64, applied_tree_hash="b" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            run_dir.mkdir(mode=0o700)
            config = SimpleNamespace(
                source_root="/private/build-canary",
                local_run_dir=run_dir,
                model_path="/models/model-canary.gguf",
                drafter_path="/models/draft-canary.gguf",
            )
            failure = CommandResult(2, False, 17, b"compiler: /private/build-", b"canary\x1b[31m failed\n")
            timeout = CommandResult(-1, True, 19, b"timeout /private/build-", b"canary\n")
            with mock.patch.object(build_module, "verify_applied_tree"), mock.patch.object(build_module, "_sha256_regular", return_value=("c" * 64, 10)), mock.patch.object(build_module, "_version", return_value="1.2.3"), mock.patch.object(build_module, "_sass"):
                transport = mock.Mock()
                transport.run.return_value = failure
                nonzero = build_module._build_local(config, transport, snapshot, jobs=1)
                self.assertEqual((nonzero.status, nonzero.failure_class, nonzero.exit_code, nonzero.duration_ns), ("failed", "command_failed", 2, 17))
                log = (run_dir / "build.log").read_bytes()
                self.assertEqual(nonzero.build_log_sha256, hashlib.sha256(log).hexdigest())
                self.assertNotIn(b"/private/build-canary", log)
                self.assertNotIn(b"\x1b", log)
                transport.run.return_value = timeout
                timed_out = build_module._build_local(config, transport, snapshot, jobs=1)
                timeout_log = (run_dir / "build.log").read_bytes()
                self.assertEqual((timed_out.status, timed_out.failure_class, timed_out.exit_code, timed_out.duration_ns), ("failed", "timeout", None, 19))
                self.assertEqual(timed_out.build_log_sha256, hashlib.sha256(timeout_log).hexdigest())
                transport.run.return_value = CommandResult(0, False, 23, b"made\n", b"")
                succeeded = build_module._build_local(config, transport, snapshot, jobs=1)
            success_log = (run_dir / "build.log").read_bytes()
            self.assertEqual(succeeded.build_log_sha256, hashlib.sha256(success_log).hexdigest())
            self.assertEqual((succeeded.status, succeeded.exit_code, succeeded.duration_ns), ("succeeded", 0, 23))
            preflight = build_module._failed("build_jobs_invalid", snapshot)
            self.assertEqual((preflight.command, preflight.build_log_sha256, preflight.exit_code, preflight.duration_ns), (None, None, None, None))
            self.assertEqual((preflight.source_snapshot_id, preflight.source_applied_tree_hash), ("a" * 64, "b" * 64))

    def test_remote_redactor_removes_split_canaries_and_controls(self) -> None:
        namespace: dict[str, object] = {"HelperError": Exception, "_fail": lambda code: None}
        extension = build_module.REMOTE_REDACTION_EXTENSION + build_module.REMOTE_BUILD_EXTENSION.split("@register_action('target_build')", 1)[0]
        exec(extension, namespace)
        state = namespace["_targetctl_redactor"](("/private/build-canary",))  # type: ignore[operator]
        namespace["_targetctl_redact_feed"](state, b"error /private/build-")  # type: ignore[operator]
        namespace["_targetctl_redact_feed"](state, b"canary\x1b[31m printable\n", True)  # type: ignore[operator]
        output = bytes(state["out"])  # type: ignore[index]
        self.assertNotIn(b"/private/build-canary", output)
        self.assertNotIn(b"\x1b", output)
        self.assertIn(b"[REDACTED]", output)
        self.assertIn(b"printable", output)
        cutoff = namespace["_targetctl_redactor"](("/private/build-canary",))  # type: ignore[operator]
        namespace["_targetctl_redact_feed"](cutoff, b"x" * 4090 + b"/private/build-")  # type: ignore[operator]
        namespace["_targetctl_redact_feed"](cutoff, b"canary\n", True)  # type: ignore[operator]
        self.assertNotIn(b"/private/build-canary", bytes(cutoff["out"]))  # type: ignore[index]
        privacy = namespace["_targetctl_redactor"](())  # type: ignore[operator]
        namespace["_targetctl_redact_feed"](privacy, b"Bearer abcdefghijk token=xyzabcdefghi ghp_abcdefgh 192.168.1.9 ~alice/a \x1b]secret-payload", True)  # type: ignore[operator]
        private_output = bytes(privacy["out"])  # type: ignore[index]
        for value in (b"abcdefghijk", b"xyzabcdefghi", b"ghp_abcdefgh", b"192.168.1.9", b"~alice/a", b"secret-payload"):
            self.assertNotIn(value, private_output)
