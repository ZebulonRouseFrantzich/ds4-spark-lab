from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest

from scripts.targetctl.common import TargetError
from scripts.targetctl import remote
from scripts.targetctl.lifecycle import RuntimeInputs, logs, serve, status, stop
from scripts.targetctl.transport import CommandResult, LocalTransport


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

    def _server(self) -> None:
        binary = self.work / "engine" / "ds4" / "ds4-server"
        binary.parent.mkdir(parents=True)
        binary.write_text(
            "#!/usr/bin/python3\n"
            "import socket, sys\n"
            "port = int(sys.argv[sys.argv.index('--port') + 1])\n"
            "listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "listener.bind(('127.0.0.1', port))\n"
            "listener.listen()\n"
            "while True: listener.accept()[0].close()\n",
            encoding="ascii",
        )
        build = self.run / "build.json"
        build.write_text(json.dumps({"schema_version": 1, "source_snapshot_id": "1" * 64, "source_applied_tree_hash": "2" * 64, "build_id": "3" * 64, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}), encoding="ascii")
        build.chmod(0o600)
        binary.chmod(0o700)

    def _in_process_helper_runner(self, argv: tuple[str, ...], program: bytes | None, timeout: float | None, cwd: str, env: dict[str, str], maximum: int) -> CommandResult:
        self.assertIsNotNone(program)
        assert program is not None
        self.helper_programs.append(program)
        source, _, invocation = program.rstrip().rpartition(b"\n")
        call = ast.parse(invocation.decode("ascii"), mode="exec").body[0].value
        assert isinstance(call, ast.Call)
        encoded_request = ast.literal_eval(call.args[0].args[0])
        request = base64.b64decode(encoded_request, validate=True)
        output = io.BytesIO()
        replacement_stdout = io.TextIOWrapper(output, encoding="ascii")
        original_stdout = sys.stdout
        original_environment = os.environ.copy()
        original_umask = os.umask(0o077)
        try:
            os.environ.clear()
            os.environ.update(env)
            sys.stdout = replacement_stdout
            namespace = {"__name__": "_lifecycle_test_helper_"}
            exec(compile(source, "<lifecycle-test-helper>", "exec"), namespace)
            namespace["run"](request)
            replacement_stdout.flush()
        finally:
            sys.stdout = original_stdout
            os.environ.clear()
            os.environ.update(original_environment)
            os.umask(original_umask)
            replacement_stdout.detach()
        return CommandResult(0, False, 0, output.getvalue(), b"")

    def test_start_status_logs_stop_and_atomic_state(self) -> None:
        self._server()
        self.helper_programs: list[bytes] = []
        transport = LocalTransport(runner=self._in_process_helper_runner)
        result = serve(self.config, transport, self.runtime, run_id="run-12345678")
        self.assertEqual(result.state, "running")
        self.assertTrue(self.helper_programs)
        self.assertTrue(status(self.config, transport, self.runtime).active)
        self.assertEqual(logs(self.config, transport, self.runtime), b"")
        self.assertEqual(json.loads((self.run / "run.json").read_text(encoding="ascii"))["state"], "running")
        with self.assertRaises(TargetError) as error:
            serve(self.config, transport, self.runtime, run_id="run-12345679")
        self.assertEqual(error.exception.code, "run_active")
        self.assertEqual(stop(self.config, transport, self.runtime).status, "stopped")
        self.assertEqual(stop(self.config, transport, self.runtime).status, "not_run")
        self.assertEqual(json.loads((self.run / "run.json").read_text(encoding="ascii"))["state"], "stopped")

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
