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

    def _server(self, body: bytes = b"Paris is the capital of France.") -> None:
        binary = self.work / "engine" / "ds4" / "ds4-server"
        binary.parent.mkdir(parents=True)
        binary.write_text(
            "#!/usr/bin/python3\n"
            "import argparse, json\n"
            "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
            "p=argparse.ArgumentParser(); p.add_argument('--cuda',action='store_true'); p.add_argument('-m'); p.add_argument('-c'); p.add_argument('--host'); p.add_argument('--port',type=int); a=p.parse_args()\n"
            "class H(BaseHTTPRequestHandler):\n"
            " def log_message(self,*x): pass\n"
            " def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b'{}')\n"
            " def do_POST(self): self.send_response(200); self.end_headers(); self.wfile.write(b'{\\\"choices\\\":[{\\\"message\\\":{\\\"content\\\":\\\"Paris\\\"}}]}')\n"
            "HTTPServer((a.host,a.port),H).serve_forever()\n",
            encoding="ascii",
        )
        build = self.run / "build.json"
        build.write_text(json.dumps({"schema_version": 1, "source_snapshot_id": "1" * 64, "source_applied_tree_hash": "2" * 64, "build_id": "3" * 64, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}), encoding="ascii")
        build.chmod(0o600)
        binary.chmod(0o700)

    def test_start_status_logs_stop_and_atomic_state(self) -> None:
        self._server()
        result = serve(self.config, self.transport, self.runtime, run_id="run-12345678")
        self.assertEqual(result.state, "running")
        self.assertTrue(status(self.config, self.transport, self.runtime).active)
        self.assertEqual(json.loads((self.run / "run.json").read_text(encoding="ascii"))["state"], "running")
        with self.assertRaises(TargetError) as error:
            serve(self.config, self.transport, self.runtime, run_id="run-12345679")
        self.assertEqual(error.exception.code, "run_active")
        self.assertEqual(stop(self.config, self.transport, self.runtime).status, "stopped")
        self.assertEqual(stop(self.config, self.transport, self.runtime).status, "not_run")
        self.assertEqual(json.loads((self.run / "run.json").read_text(encoding="ascii"))["state"], "stopped")

    def test_invalid_runtime_input_is_rejected(self) -> None:
        with self.assertRaises(Exception):
            RuntimeInputs(str(self.model), str(self.drafter), "x", "2" * 64, "3" * 64, "4" * 64, "5" * 64, 1)
