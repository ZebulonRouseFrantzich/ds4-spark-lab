from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from types import SimpleNamespace

from scripts.targetctl.common import TargetError
from scripts.targetctl import remote
from scripts.targetctl.lifecycle import RuntimeInputs, logs, serve, status, stop
from scripts.targetctl.transport import LocalTransport


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / "work"
        self.run = self.root / "run"
        self.models = self.root / "models"
        self.models.mkdir()
        self.model = self.models / "primary.gguf"
        self.drafter = self.models / "draft.gguf"
        self.model.write_bytes(b"primary")
        self.drafter.write_bytes(b"draft")
        initialized = remote.initialize_roots({"workdir": str(self.work), "run_dir": str(self.run), "model_path": str(self.model), "drafter_path": str(self.drafter)})
        self.runtime = RuntimeInputs(str(self.model), str(self.drafter), "1" * 64, "2" * 64, "3" * 64, initialized["work"]["token"], initialized["run"]["token"], self._port())
        self.config = SimpleNamespace(mode="ssh", workdir=str(self.work), run_dir=str(self.run), validate_for=lambda operation: None)
        self.transport = LocalTransport()

    @staticmethod
    def _port() -> int:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]
        finally:
            probe.close()

    def test_invalid_runtime_input_is_rejected(self) -> None:
        with self.assertRaises(Exception):
            RuntimeInputs(str(self.model), str(self.drafter), "x", "2" * 64, "3" * 64, "4" * 64, "5" * 64, 1)

    def test_runtime_inputs_validate_paths_and_port(self) -> None:
        RuntimeInputs(str(self.model), str(self.drafter), "1" * 64, "2" * 64, "3" * 64, "4" * 64, "5" * 64, 8000)
        with self.assertRaises(TargetError):
            RuntimeInputs(str(self.model), str(self.drafter), "x", "2" * 64, "3" * 64, "4" * 64, "5" * 64, 0)
        with self.assertRaises(TargetError):
            RuntimeInputs(str(self.model), str(self.drafter), "x", "2" * 64, "3" * 64, "4" * 64, "5" * 64, 99999)

    def test_lifecycle_stop_without_run_returns_not_run(self) -> None:
        result = stop(self.config, self.transport, self.runtime)
        self.assertEqual(result.status, "not_run")
        self.assertIsNone(result.run_id)

    def test_lifecycle_status_without_run_returns_stopped(self) -> None:
        result = status(self.config, self.transport, self.runtime)
        self.assertEqual(result.state, "stopped")
        self.assertFalse(result.active)
