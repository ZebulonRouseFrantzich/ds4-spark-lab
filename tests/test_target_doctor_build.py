from __future__ import annotations

import hashlib
import unittest

from scripts.targetctl.build import BuildResult
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
        result = BuildResult("succeeded", None, digest, digest, digest, digest, "make-cuda-spark", "1.2.3", 10, "verified", digest)
        self.assertEqual(result.controller_payload(), {
            "status": "succeeded", "failure_class": None,
            "source_snapshot_id": digest, "source_applied_tree_hash": digest,
            "build_id": digest, "binary_sha256": digest, "command": "make-cuda-spark",
            "version": "1.2.3", "binary_size": 10, "sass": "verified",
            "build_log_sha256": digest,
        })
        with self.assertRaises(AttributeError):
            result.sass = "missing"  # type: ignore[misc]
