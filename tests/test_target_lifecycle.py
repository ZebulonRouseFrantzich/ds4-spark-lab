from __future__ import annotations

import hashlib
import json
import fcntl
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import threading
import unittest
from types import SimpleNamespace

from scripts.targetctl.common import TargetError
from scripts.targetctl import remote
from scripts.targetctl.redaction import redaction_canaries
from scripts.targetctl.lifecycle import (
    CleanupResult, FIXED_LAUNCH_PROFILE, LaunchProfile, RuntimeInputs, RunResult,
    SmokeResult, cleanup, launch_profile_from_scenario, logs, serve, smoke,
    status, stop,
)
from scripts.targetctl.transport import LocalTransport


def _write_server(path: Path, port: int, secrets: tuple[str, ...] = ()) -> None:
    """Write a tiny, silent loopback HTTP server. All output flushed immediately."""
    secrets_repr = repr(list(secrets))
    path.write_text(
        "import http.server, json, sys, os\n"
        "class H(http.server.BaseHTTPRequestHandler):\n"
        "  def do_GET(self):\n"
        "    if self.path == '/v1/models':\n"
        "      self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps({'data':[{'id':'ds4'}]}).encode()); return\n"
        "    self.send_response(404); self.end_headers()\n"
        "  def do_POST(self):\n"
        "    if self.path == '/v1/chat/completions':\n"
        "      body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))\n"
        "      expected={'model':'deepseek-v4-flash','messages':[{'role':'user','content':'What is the capital of France? Answer in one sentence.'}],'max_tokens':64,'stream':False}\n"
        "      if body != expected: self.send_response(400); self.end_headers(); return\n"
        "      self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps({'choices':[{'message':{'content':'Paris is the capital of France.'}}]}).encode()); return\n"
        "    self.send_response(404); self.end_headers()\n"
        "  def log_message(self, fmt, *args): pass\n"
        "s = http.server.HTTPServer(('127.0.0.1', " + str(port) + "), H)\n"
        + ("sys.stderr.write('SECRET_TOKEN_12345\\n'); sys.stderr.flush()\n" if secrets else "")
        + "s.serve_forever()\n",
        encoding="utf-8",
    )


def _write_server_with_secret(path: Path, port: int, secret: str) -> None:
    """Write a server that prints a secret to stdout."""
    path.write_text(
        "import http.server, json, sys, time\n"
        "class H(http.server.BaseHTTPRequestHandler):\n"
        "  def do_GET(self):\n"
        "    if self.path == '/v1/models':\n"
        "      self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps({'data':[{'id':'ds4'}]}).encode()); return\n"
        "    self.send_response(404); self.end_headers()\n"
        "  def log_message(self, fmt, *args): pass\n"
        "secret = " + repr(secret.encode("utf-8")) + "\n"
        "half = len(secret) // 2\n"
        "sys.stdout.buffer.write(b'producer-prefix ' + secret[:half]); sys.stdout.buffer.flush()\n"
        "time.sleep(0.1)\n"
        "sys.stdout.buffer.write(secret[half:] + b' producer-suffix\\n'); sys.stdout.buffer.flush()\n"
        "s = http.server.HTTPServer(('127.0.0.1', " + str(port) + "), H)\n"
        "s.serve_forever()\n",
        encoding="utf-8",
    )


def _write_build_json(run_dir: Path, work_dir: Path, binary_name: str) -> str:
    """Write build.json and server.log in run_dir with mode 0o600. Returns binary SHA256."""
    binary_path = work_dir / binary_name
    binary_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    build = {
        "schema_version": 1, "record_type": "build", "build_id": "3" * 64,
        "source_snapshot_id": "1" * 64, "source_applied_tree_hash": "2" * 64,
        "binary_sha256": binary_hash, "binary_size": binary_path.stat().st_size,
        "version": "1.0", "sass": "verified",
        "build_log_sha256": hashlib.sha256(b"").hexdigest(),
        "exit_code": 0, "duration_ns": 1,
    }
    for name, data in [("build.json", json.dumps(build).encode("ascii")), ("server.log", b"")]:
        fd = os.open(str(run_dir / name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
    return binary_hash


def _wait_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"Port {port} not reachable within {timeout}s")


def _busy_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    # intentionally leaked to keep the port occupied
    return port


def _maximum_remote_path(fill: str) -> str:
    path = "/" + "/".join([fill * 128] * 31 + [fill * 96])
    if len(path) != 4096:
        raise AssertionError("maximum path fixture must be exactly 4096 bytes")
    return path


class LifecycleTests(unittest.TestCase):
    """Focused tests proving the deterministic lifecycle with real tiny servers."""

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
        self._leaked_ports: list[int] = []

    def addCleanup(self, func, *args, **kwargs):  # noqa: N802 — matches unittest API
        super().addCleanup(func, *args, **kwargs)

    def tearDown(self) -> None:
        for p in self._leaked_ports:
            try:
                with socket.create_connection(("127.0.0.1", p), timeout=0.1):
                    pass
            except OSError:
                pass

    @staticmethod
    def _port() -> int:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]
        finally:
            probe.close()

    def _setup_work(self, binary_name: str = "server.py", port: int = 0) -> int:
        if port == 0:
            port = self._port()
        # Create fresh directories for initialize_roots (must be empty or pre-marked)
        self.work.mkdir(mode=0o700, exist_ok=True)
        self.run.mkdir(mode=0o700, exist_ok=True)
        # Initialize roots BEFORE placing non-marker files in workdir
        initialized = remote.initialize_roots({
            "workdir": str(self.work), "run_dir": str(self.run),
            "model_path": str(self.model), "drafter_path": str(self.drafter),
        })
        self.runtime = RuntimeInputs(
            str(self.model), str(self.drafter),
            "1" * 64, "2" * 64, "3" * 64,
            initialized["work"]["token"], initialized["run"]["token"], port,
            binary_path=binary_name,
        )
        self.config = SimpleNamespace(
            mode="ssh", workdir=str(self.work), run_dir=str(self.run),
            validate_for=lambda operation: None,
        )
        self.transport = LocalTransport()
        # Place the server binary in workdir AFTER roots are initialized
        server_path = self.work / binary_name
        _write_server(server_path, port)
        server_path.chmod(0o700)
        # Write build.json in run_dir with mode 0o600 (required by _open_regular)
        binary_hash = hashlib.sha256(server_path.read_bytes()).hexdigest()
        build = {
            "schema_version": 1,
            "record_type": "build",
            "build_id": "3" * 64,
            "source_snapshot_id": "1" * 64,
            "source_applied_tree_hash": "2" * 64,
            "binary_sha256": binary_hash,
            "binary_size": server_path.stat().st_size,
            "version": "1.0",
            "sass": "verified",
            "build_log_sha256": hashlib.sha256(b"").hexdigest(),
            "exit_code": 0,
            "duration_ns": 1,
        }
        fd = os.open(str(self.run / "build.json"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, json.dumps(build).encode("ascii"))
        finally:
            os.close(fd)
        fd = os.open(str(self.run / "server.log"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, b"")
        finally:
            os.close(fd)
        return port

    # ---- Basic validation -------------------------------------------------

    def test_invalid_runtime_input_is_rejected(self) -> None:
        with self.assertRaises(Exception):
            RuntimeInputs(
                str(self.model), str(self.drafter),
                "x", "2" * 64, "3" * 64, "4" * 64, "5" * 64, 1,
            )

    def test_runtime_inputs_validate_paths_and_port(self) -> None:
        RuntimeInputs(str(self.model), str(self.drafter), "1" * 64, "2" * 64, "3" * 64, "4" * 64, "5" * 64, 8000)
        with self.assertRaises(TargetError):
            RuntimeInputs(str(self.model), str(self.drafter), "x", "2" * 64, "3" * 64, "4" * 64, "5" * 64, 0)
        with self.assertRaises(TargetError):
            RuntimeInputs(str(self.model), str(self.drafter), "x", "2" * 64, "3" * 64, "4" * 64, "5" * 64, 99999)

    @staticmethod
    def _server_mapping(**changes):
        mapping = {
            "context_tokens": 32768,
            "default_output_tokens": 393216,
            "decode_policy": "shipped",
            "dspark_max_nlive": 1,
            "terminal_yield_quench": True,
            "speculative_overrides": {
                "shadow_guard": None,
                "shadow_alpha": None,
                "shadow_min_evidence": None,
                "shadow_budget": None,
                "shadow_credit_cap": None,
            },
        }
        mapping.update(changes)
        return mapping

    def test_launch_profile_from_scenario_is_exact_and_bounded(self) -> None:
        target_local = launch_profile_from_scenario(
            self._server_mapping(), "target_local"
        )
        self.assertEqual(target_local, FIXED_LAUNCH_PROFILE)
        controller = launch_profile_from_scenario(
            self._server_mapping(context_tokens=262144, decode_policy="plain"),
            "controller_lan",
        )
        self.assertEqual(
            controller.controller_payload(),
            {
                "schema_version": 2,
                "accelerator": "cuda",
                "context_tokens": 262144,
                "default_output_tokens": 393216,
                "bind": "private_lan",
                "continuation_mtp_mode": 2,
                "decode_policy": "plain",
                "dspark_max_nlive": 1,
                "terminal_yield_quench": True,
                "speculative_overrides": {
                    "shadow_guard": None,
                    "shadow_alpha": None,
                    "shadow_min_evidence": None,
                    "shadow_budget": None,
                    "shadow_credit_cap": None,
                },
            },
        )

    def test_launch_profiles_reject_unknown_values_and_overrides(self) -> None:
        invalid_mappings = (
            {**self._server_mapping(), "unknown": None},
            self._server_mapping(context_tokens=65536),
            self._server_mapping(default_output_tokens=1),
            self._server_mapping(decode_policy="automatic"),
            self._server_mapping(dspark_max_nlive=2),
            self._server_mapping(terminal_yield_quench=False),
            self._server_mapping(
                speculative_overrides={
                    **self._server_mapping()["speculative_overrides"],
                    "shadow_guard": 1,
                }
            ),
            self._server_mapping(
                speculative_overrides={
                    **self._server_mapping()["speculative_overrides"],
                    "unknown": None,
                }
            ),
        )
        for mapping in invalid_mappings:
            with self.subTest(mapping=mapping):
                with self.assertRaises(TargetError) as raised:
                    launch_profile_from_scenario(mapping, "target_local")
                self.assertEqual(raised.exception.code, "invalid_launch_profile")
        with self.assertRaises(TargetError):
            launch_profile_from_scenario(self._server_mapping(), "remote")
        with self.assertRaises(TargetError):
            LaunchProfile(bind="public")

    def test_shipped_and_plain_launch_evidence_is_exact(self) -> None:
        self._setup_work()
        expected_env = {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "DS4_CONT_MTP_MODE": "2",
            "DS4_CONT_DSPARK": "1",
            "DS4_DSPARK_MODEL": self.runtime.drafter_path,
            "DS4_DSPARK_MAX_NLIVE": "1",
            "DS4_DSPARK_QUENCH": "1",
        }
        shipped = serve(self.config, self.transport, self.runtime)
        try:
            launch = json.loads((self.run / "launch.json").read_bytes())
            self.assertEqual(launch["env"], expected_env)
            self.assertEqual(
                launch["argv"][-9:],
                [
                    "--cuda", "-m", self.runtime.model_path,
                    "-c", "32768", "--host", "127.0.0.1",
                    "--port", str(self.runtime.port),
                ],
            )
            self.assertEqual(
                launch["launch_profile"],
                FIXED_LAUNCH_PROFILE.controller_payload(),
            )
            self.assertEqual(shipped.launch_profile, FIXED_LAUNCH_PROFILE)
        finally:
            stop(self.config, self.transport, self.runtime, run_id=shipped.run_id)

        plain_profile = LaunchProfile(context_tokens=262144, decode_policy="plain")
        plain = serve(
            self.config,
            self.transport,
            self.runtime,
            launch_profile=plain_profile,
        )
        try:
            launch = json.loads((self.run / "launch.json").read_bytes())
            self.assertEqual(launch["env"], expected_env)
            self.assertEqual(
                launch["argv"][-10:],
                [
                    "--cuda", "-m", self.runtime.model_path,
                    "-c", "262144", "--host", "127.0.0.1",
                    "--port", str(self.runtime.port), "--no-spec",
                ],
            )
            self.assertEqual(
                launch["launch_profile"], plain_profile.controller_payload()
            )
            self.assertEqual(plain.launch_profile, plain_profile)
        finally:
            stop(self.config, self.transport, self.runtime, run_id=plain.run_id)

    def test_private_bind_pairing_and_result_redaction(self) -> None:
        self._setup_work()
        private_host = ".".join(("192", "168", "20", "30"))
        validations = []
        config = SimpleNamespace(
            mode="ssh",
            workdir=str(self.work),
            run_dir=str(self.run),
            lan_bind_host=private_host,
            validate_for=validations.append,
        )
        profile = launch_profile_from_scenario(
            self._server_mapping(), "controller_lan"
        )

        class CaptureTransport:
            def __init__(self):
                self.payload = None

            def run_helper(self, action, payload, **kwargs):
                self.payload = payload
                return {
                    "run_id": payload["run_id"],
                    "state": "running",
                    "port": payload["port"],
                    "binary_sha256": "a" * 64,
                    "supervisor_pid": 101,
                    "supervisor_start_ticks": 102,
                    "child_pid": 103,
                    "child_start_ticks": 104,
                    "launch_profile": payload["launch_profile"],
                }

        capture = CaptureTransport()
        result = serve(
            config,
            capture,
            self.runtime,
            launch_profile=profile,
            bind_host=private_host,
        )
        self.assertEqual(validations, ["serve", "benchmark"])
        self.assertEqual(capture.payload["bind_host"], private_host)
        self.assertEqual(capture.payload["launch_profile"]["bind"], "private_lan")
        self.assertNotIn(
            private_host,
            json.dumps(result.controller_payload(), sort_keys=True),
        )

        class UnknownProfileTransport(CaptureTransport):
            def run_helper(self, action, payload, **kwargs):
                value = super().run_helper(action, payload, **kwargs)
                value["launch_profile"] = {
                    **value["launch_profile"],
                    "unknown_override": None,
                }
                return value

        with self.assertRaises(TargetError):
            serve(
                config,
                UnknownProfileTransport(),
                self.runtime,
                launch_profile=profile,
                bind_host=private_host,
            )

        invalid_calls = (
            {"launch_profile": profile},
            {"launch_profile": profile, "bind_host": ".".join(("192", "168", "20", "31"))},
            {"launch_profile": FIXED_LAUNCH_PROFILE, "bind_host": private_host},
        )
        for arguments in invalid_calls:
            with self.subTest(arguments=arguments):
                with self.assertRaises(TargetError):
                    serve(config, CaptureTransport(), self.runtime, **arguments)

        local = SimpleNamespace(
            mode="local",
            source_root=self.work,
            local_run_dir=self.run,
            validate_for=lambda operation: None,
        )
        with self.assertRaises(TargetError):
            serve(
                local,
                CaptureTransport(),
                self.runtime,
                launch_profile=profile,
                bind_host=private_host,
            )
        with self.assertRaises(TargetError):
            serve(
                config,
                CaptureTransport(),
                self.runtime,
                launch_profile={"bind": "private_lan"},
                bind_host=private_host,
            )

    def test_single_maximum_path_launch_state_stays_bounded(self) -> None:
        self._setup_work()
        maximum_model = _maximum_remote_path("m")
        self.runtime = RuntimeInputs(
            maximum_model, self.runtime.drafter_path,
            self.runtime.source_snapshot_id, self.runtime.applied_tree_hash,
            self.runtime.build_id, self.runtime.work_token, self.runtime.run_token,
            self.runtime.port, binary_path=self.runtime.binary_path,
        )
        legacy_canaries = redaction_canaries(
            (maximum_model, self.runtime.drafter_path),
            additional=(str(self.work), str(self.run)),
        )
        self.assertGreater(sum(len(value.encode("ascii")) for value in legacy_canaries), 65_536)

        result = serve(self.config, self.transport, self.runtime)
        try:
            launch_bytes = (self.run / "launch.json").read_bytes()
            self.assertLessEqual(len(launch_bytes), 65_536)
            launch = json.loads(launch_bytes)
            self.assertEqual(
                set(launch),
                {
                    "argv", "drafter", "redaction_paths", "fixed_canaries",
                    "lease_seconds", "run_id", "launch_profile",
                    "env",
                },
            )
            self.assertEqual(
                launch["redaction_paths"],
                [maximum_model, self.runtime.drafter_path],
            )
            self.assertEqual(
                launch["fixed_canaries"],
                [str(self.work), str(self.run), "127.0.0.1"],
            )
            self.assertNotIn("secrets", launch)
        finally:
            stop(self.config, self.transport, self.runtime, run_id=result.run_id)

    def test_two_maximum_paths_fit_and_embedded_canaries_match(self) -> None:
        port = self._setup_work()
        maximum_model = _maximum_remote_path("m")
        maximum_drafter = _maximum_remote_path("d")
        self.runtime = RuntimeInputs(
            maximum_model, maximum_drafter,
            self.runtime.source_snapshot_id, self.runtime.applied_tree_hash,
            self.runtime.build_id, self.runtime.work_token, self.runtime.run_token,
            self.runtime.port, binary_path=self.runtime.binary_path,
        )

        contract_canaries = {str(self.work), str(self.run), "127.0.0.1"}
        for private_path in (maximum_model, maximum_drafter):
            components = private_path.split("/")[1:]
            contract_canaries.add(private_path)
            contract_canaries.add(components[-1])
            contract_canaries.update(
                "/" + "/".join(components[:depth])
                for depth in range(len(components) - 1, 1, -1)
            )
        expected_canaries = redaction_canaries(
            (maximum_model, maximum_drafter),
            additional=(str(self.work), str(self.run), "127.0.0.1"),
        )
        self.assertEqual(set(expected_canaries), contract_canaries)

        server_path = self.work / "server.py"
        emitted_canaries = "\n" + "\n".join(expected_canaries) + "\n"
        _write_server_with_secret(server_path, port, emitted_canaries)
        server_path.chmod(0o700)
        _write_build_json(self.run, self.work, "server.py")

        result = serve(self.config, self.transport, self.runtime)
        try:
            launch_bytes = (self.run / "launch.json").read_bytes()
            self.assertLessEqual(len(launch_bytes), 65_536)
            launch = json.loads(launch_bytes)
            self.assertEqual(
                launch["redaction_paths"],
                [maximum_model, maximum_drafter],
            )
            self.assertEqual(
                launch["fixed_canaries"],
                [str(self.work), str(self.run), "127.0.0.1"],
            )
            self.assertNotIn("secrets", launch)

            log_content = logs(self.config, self.transport, self.runtime)
            self.assertEqual(log_content.count(b"[REDACTED]"), len(expected_canaries))
            self.assertIn(b"producer-prefix \n", log_content)
            self.assertIn(b"\n producer-suffix", log_content)
            for private in contract_canaries:
                self.assertNotIn(private.encode("ascii"), log_content)
        finally:
            stop(self.config, self.transport, self.runtime, run_id=result.run_id)

    # ---- Stop / status without run (empty state) --------------------------

    def test_lifecycle_stop_without_run_returns_not_run(self) -> None:
        self._setup_work()
        result = stop(self.config, self.transport, self.runtime)
        self.assertEqual(result.status, "not_run")
        self.assertIsNone(result.run_id)

    def test_lifecycle_status_without_run_returns_stopped(self) -> None:
        self._setup_work()
        result = status(self.config, self.transport, self.runtime)
        self.assertEqual(result.state, "stopped")
        self.assertFalse(result.active)

    def test_local_runtime_needs_no_repository_tokens(self) -> None:
        self.work.mkdir(mode=0o700, exist_ok=True)
        self.run.mkdir(mode=0o700, exist_ok=True)
        port = self._port()
        server_path = self.work / "server.py"
        _write_server(server_path, port)
        server_path.chmod(0o700)
        config = SimpleNamespace(
            mode="local", source_root=self.work, local_run_dir=self.run,
            validate_for=lambda operation: None,
        )
        runtime = RuntimeInputs(
            str(self.model), str(self.drafter),
            "1" * 64, "2" * 64, "3" * 64, port=port,
        )
        binary_hash = _write_build_json(self.run, self.work, "server.py")
        result = stop(config, LocalTransport(), runtime)
        self.assertEqual(result.status, "not_run")

    # ---- controller_payload field contracts --------------------------------

    def test_cleanup_payload_has_only_expected_fields(self) -> None:
        payload = CleanupResult(
            None, "not_run", "not_run", "not_run", "not_found", "not_found",
            None, None,
        ).controller_payload()
        self.assertEqual(
            set(payload),
            {"run_id", "status", "failure_class", "process", "socket", "lock",
             "temp", "server_log_sha256"},
        )

    def test_smoke_result_payload_fields(self) -> None:
        payload = SmokeResult(
            "run-test", "succeeded", None, True, True, True,
            "a" * 64, "b" * 64, 1_000_000,
        ).controller_payload()
        self.assertEqual(
            set(payload),
            {"run_id", "status", "failure_class", "readiness_http", "models_http",
             "contract", "primary_weight_sha256", "draft_weight_sha256",
             "duration_ns"},
        )

    def test_run_result_payload_fields(self) -> None:
        payload = RunResult(
            "run-1", "running", 8080, "a" * 64, "b" * 64,
            "c" * 64, 123, 456, 789, 101112,
        ).controller_payload()
        self.assertEqual(
            set(payload),
            {"run_id", "state", "port", "source_snapshot_id", "build_id",
             "binary_sha256", "supervisor_pid", "supervisor_start_ticks",
             "child_pid", "child_start_ticks", "launch_profile"},
        )

    # ---- Full serve → status → logs → stop lifecycle ----------------------

    def test_full_serve_status_logs_stop(self) -> None:
        port = self._setup_work()
        # Serve
        result = serve(self.config, self.transport, self.runtime)
        self.assertEqual(result.state, "running")
        self.assertEqual(result.port, port)
        self.assertIsNotNone(result.binary_sha256)
        self.assertIsNotNone(result.supervisor_pid)
        self.assertGreater(result.supervisor_pid, 1)
        self.assertIsNotNone(result.supervisor_start_ticks)
        self.assertIsNotNone(result.child_pid)
        self.assertGreater(result.child_pid, 1)
        self.assertIsNotNone(result.child_start_ticks)
        # Status
        st = status(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(st.state, "running")
        self.assertTrue(st.active)
        self.assertEqual(st.run_id, result.run_id)
        # Logs
        log_content = logs(self.config, self.transport, self.runtime)
        self.assertIsInstance(log_content, bytes)
        # Stop
        cl = stop(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(cl.status, "succeeded")
        self.assertEqual(cl.process, "cleared")
        self.assertEqual(cl.socket, "cleared")
        self.assertIn(cl.lock, ("cleared", "not_found"))
        self.assertIn(cl.temp, ("cleared", "not_found"))
        self.assertIsNone(cl.failure_class)

    def test_cleanup_preserves_every_result_field(self) -> None:
        port = self._setup_work()
        result = serve(self.config, self.transport, self.runtime)
        cl = cleanup(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertIsInstance(cl.run_id, str)
        self.assertEqual(cl.status, "succeeded")
        self.assertIn(cl.process, ("cleared", "not_found"))
        self.assertIn(cl.socket, ("cleared", "not_found", "unknown"))
        self.assertIn(cl.lock, ("cleared", "not_found"))
        self.assertIn(cl.temp, ("cleared", "not_found"))
        self.assertIsNotNone(cl.server_log_sha256)

    # ---- Cleanup idempotency retains target-side evidence ------------------

    def test_double_stop_returns_original_evidence(self) -> None:
        self._setup_work()
        result = serve(self.config, self.transport, self.runtime)
        first = stop(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(first.status, "succeeded")
        second = stop(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(second.status, "succeeded")
        self.assertEqual(second.controller_payload(), first.controller_payload())

    def test_local_cleanup_retry_returns_original_evidence(self) -> None:
        self._setup_work()
        config = SimpleNamespace(
            mode="local", source_root=self.work, local_run_dir=self.run,
            validate_for=lambda operation: None,
        )
        result = serve(config, self.transport, self.runtime)
        first = cleanup(config, self.transport, self.runtime, run_id=result.run_id)
        second = cleanup(config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(first.status, "succeeded")
        self.assertEqual(second.controller_payload(), first.controller_payload())

    def test_cleanup_retry_after_response_loss_returns_persisted_evidence(self) -> None:
        self._setup_work()
        result = serve(self.config, self.transport, self.runtime)

        class DropFirstStopResponse:
            def __init__(self, transport: LocalTransport) -> None:
                self.transport = transport
                self.dropped = False

            def run_helper(self, action, payload, **kwargs):
                response = self.transport.run_helper(action, payload, **kwargs)
                if action == "lifecycle_stop" and not self.dropped:
                    self.dropped = True
                    raise TargetError("helper_timeout", "response was lost")
                return response

        dropped = DropFirstStopResponse(self.transport)
        with self.assertRaisesRegex(TargetError, "response was lost"):
            stop(self.config, dropped, self.runtime, run_id=result.run_id)
        retry = stop(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(retry.status, "succeeded")
        state = json.loads((self.run / "run.json").read_text(encoding="ascii"))
        self.assertTrue(state["cleanup_complete"])
        self.assertEqual(
            retry.controller_payload(),
            {
                "run_id": result.run_id, "status": "succeeded", "failure_class": None,
                **state["cleanup"],
            },
        )

    def test_concurrent_cleanup_calls_return_one_persisted_evidence(self) -> None:
        self._setup_work()
        result = serve(self.config, self.transport, self.runtime)
        gate = threading.Barrier(3)
        outcomes: list[CleanupResult] = []
        errors: list[BaseException] = []

        def invoke() -> None:
            try:
                gate.wait()
                outcomes.append(cleanup(self.config, self.transport, self.runtime, run_id=result.run_id))
            except BaseException as error:
                errors.append(error)

        workers = [threading.Thread(target=invoke) for _ in range(2)]
        for worker in workers:
            worker.start()
        gate.wait()
        for worker in workers:
            worker.join(30)
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(outcomes[0].controller_payload(), outcomes[1].controller_payload())

    # ---- Port conflict prevents serve -------------------------------------

    def test_occupied_port_blocks_serve(self) -> None:
        port = self._setup_work()
        # Occupy port with a real listener
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        blocker.bind(("127.0.0.1", port))
        blocker.listen(1)
        self.addCleanup(blocker.close)
        self._leaked_ports.append(port)
        self.runtime = RuntimeInputs(
            str(self.model), str(self.drafter),
            "1" * 64, "2" * 64, "3" * 64,
            self.runtime.work_token, self.runtime.run_token, port,
            binary_path="server.py", startup_timeout=3,
        )
        with self.assertRaises(TargetError) as ctx:
            serve(self.config, self.transport, self.runtime)
        self.assertIn(ctx.exception.code, ("startup_timeout", "startup_failed"))

    # ---- Startup failure (bad binary path) --------------------------------

    def test_bad_binary_path_is_not_dispatched(self) -> None:
        self._setup_work()
        self.config.workdir = "/nonexistent"
        with self.assertRaises(TargetError) as ctx:
            serve(self.config, self.transport, self.runtime)
        self.assertEqual(ctx.exception.code, "serve_not_dispatched")
        self.assertFalse((self.run / "run.json").exists())

    def test_build_binary_mismatch_is_not_dispatched_and_releases_lease(self) -> None:
        self._setup_work()
        build_path = self.run / "build.json"
        build = json.loads(build_path.read_text(encoding="ascii"))
        build["binary_sha256"] = "0" * 64
        build_path.write_text(json.dumps(build), encoding="ascii")
        build_path.chmod(0o600)

        with self.assertRaises(TargetError) as ctx:
            serve(self.config, self.transport, self.runtime, run_id="run-refused-build-0001")
        self.assertEqual(ctx.exception.code, "serve_not_dispatched")
        self.assertFalse((self.run / "run.json").exists())
        self.assertFalse((self.run / ".targetctl-operation-lock-v1").exists())

    def test_attempt_report_is_not_accepted_as_active_build_manifest(self) -> None:
        self._setup_work()
        build_path = self.run / "build.json"
        build = json.loads(build_path.read_text(encoding="ascii"))
        build.update({
            "record_type": "build-attempt",
            "attempt_id": "9" * 64,
            "status": "succeeded",
            "failure_class": None,
            "command": "make-cuda-spark",
        })
        build_path.write_text(json.dumps(build), encoding="ascii")
        build_path.chmod(0o600)

        with self.assertRaises(TargetError) as ctx:
            serve(self.config, self.transport, self.runtime, run_id="run-refused-attempt-0001")
        self.assertEqual(ctx.exception.code, "serve_not_dispatched")
        self.assertFalse((self.run / "run.json").exists())
        self.assertFalse((self.run / ".targetctl-operation-lock-v1").exists())

    def test_local_lock_contention_is_classified_before_helper_dispatch(self) -> None:
        self._setup_work()
        config = SimpleNamespace(
            mode="local", source_root=self.work, local_run_dir=self.run,
            validate_for=lambda operation: None,
        )
        calls: list[str] = []

        class RecordingTransport:
            def run_helper(self, action, payload, **kwargs):
                calls.append(action)
                raise AssertionError("helper must not be dispatched while the local lock is busy")

        lock_fd = os.open(
            self.run / ".targetctl-operation-lock-v1",
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
            0o600,
        )
        self.addCleanup(os.close, lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaises(TargetError) as ctx:
            serve(config, RecordingTransport(), self.runtime, run_id="run-local-busy-0001")
        self.assertEqual(ctx.exception.code, "serve_not_dispatched")
        self.assertEqual(calls, [])

    # ---- Server log hash matches actual content ---------------------------

    def test_server_log_hash_matches_content(self) -> None:
        self._setup_work()
        result = serve(self.config, self.transport, self.runtime)
        log_content = logs(self.config, self.transport, self.runtime)
        expected_hash = hashlib.sha256(log_content).hexdigest()
        cl = stop(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(cl.server_log_sha256, expected_hash)

    def test_serve_replaces_hardlinked_log_without_touching_canary(self) -> None:
        self._setup_work()
        canary = self.root / "outside-canary"
        canary_content = b"outside data must survive"
        canary.write_bytes(canary_content)
        canary.chmod(0o600)
        (self.run / "server.log").unlink()
        os.link(canary, self.run / "server.log")

        result = serve(self.config, self.transport, self.runtime)
        try:
            self.assertEqual(canary.read_bytes(), canary_content)
            self.assertNotEqual(
                (canary.stat().st_dev, canary.stat().st_ino),
                ((self.run / "server.log").stat().st_dev, (self.run / "server.log").stat().st_ino),
            )
            self.assertEqual((self.run / "server.log").stat().st_nlink, 1)
        finally:
            stop(self.config, self.transport, self.runtime, run_id=result.run_id)


    # ---- No orphan PGID after stop ----------------------------------------

    def test_no_orphan_pgid_after_stop(self) -> None:
        self._setup_work()
        result = serve(self.config, self.transport, self.runtime)
        child_pid = result.child_pid
        supervisor_pid = result.supervisor_pid
        cl = stop(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(cl.process, "cleared")
        # Both supervisor and child should be dead
        for pid in (supervisor_pid, child_pid):
            if pid and pid > 1:
                try:
                    os.kill(pid, 0)
                    self.fail(f"Process {pid} still alive after stop")
                except ProcessLookupError:
                    pass  # expected — process is gone
                except PermissionError:
                    self.fail(f"Process {pid} still alive (permission error)")

    # ---- State transitions: stopped → status shows stale ------------------

    def test_stale_identity_on_status_after_kill(self) -> None:
        self._setup_work()
        server_path = self.work / "server.py"
        server_path.write_text(
            server_path.read_text(encoding="utf-8").replace(
                "import http.server, json, sys, os\n",
                "import http.server, json, sys, os, signal, time\n"
                "if os.fork() == 0:\n"
                "  signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "  while True: time.sleep(1)\n",
            ),
            encoding="utf-8",
        )
        _write_build_json(self.run, self.work, "server.py")
        result = serve(self.config, self.transport, self.runtime)
        # Simulate an external SIGKILL of the supervisor; its independently
        # sessioned child, orphanable descendant group, and listener must be cleaned.
        supervisor_pid = result.supervisor_pid
        if supervisor_pid and supervisor_pid > 1:
            try:
                os.killpg(supervisor_pid, signal.SIGKILL)
            except OSError:
                pass
        time.sleep(0.5)
        st = status(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(st.state, "stale_identity")
        self.assertFalse(st.active)
        prior_log = (self.run / "server.log").read_bytes()
        with self.assertRaises(TargetError) as refused:
            serve(self.config, self.transport, self.runtime, run_id="run-replacement-0002")
        self.assertEqual(refused.exception.code, "serve_not_dispatched")
        state = json.loads((self.run / "run.json").read_text(encoding="ascii"))
        self.assertEqual(state["state"], "stale_identity")
        self.assertFalse(state["cleanup_complete"])
        self.assertEqual((self.run / "server.log").read_bytes(), prior_log)

        outcome = cleanup(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(outcome.status, "succeeded")
        self.assertNotIn("unknown", (outcome.process, outcome.socket, outcome.lock, outcome.temp))
        settled = json.loads((self.run / "run.json").read_text(encoding="ascii"))
        self.assertTrue(settled["cleanup_complete"])
        self.assertEqual(
            settled["cleanup"],
            {
                "process": outcome.process,
                "socket": outcome.socket,
                "lock": outcome.lock,
                "temp": outcome.temp,
                "server_log_sha256": outcome.server_log_sha256,
            },
        )
        self.assertEqual(
            cleanup(self.config, self.transport, self.runtime, run_id=result.run_id).controller_payload(),
            outcome.controller_payload(),
        )
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(probe.close)
        probe.bind(("127.0.0.1", self.runtime.port))


    def test_status_and_refused_serve_preserve_pre_spawn_starting_state(self) -> None:
        self._setup_work()
        binary_hash = hashlib.sha256((self.work / "server.py").read_bytes()).hexdigest()
        state = {
            "schema_version": 1, "run_id": "run-starting-0001", "state": "starting",
            "source_snapshot_id": "1" * 64, "applied_tree_hash": "2" * 64,
            "build_id": "3" * 64, "binary_sha256": binary_hash,
            "port": self.runtime.port, "launch_profile": FIXED_LAUNCH_PROFILE.controller_payload(),
            "supervisor_pid": None, "supervisor_start_ticks": None,
            "supervisor_cmdline_sha256": None, "child_pid": None,
            "child_start_ticks": None, "child_pgid": None,
            "child_cmdline_sha256": None, "listener_inode": None,
            "cleanup_complete": False, "cleanup": None,
        }
        state_path = self.run / "run.json"
        state_path.write_text(json.dumps(state), encoding="ascii")
        state_path.chmod(0o600)
        prior_state = state_path.read_bytes()
        prior_log = b"prior-server-log-must-survive"
        (self.run / "server.log").write_bytes(prior_log)
        (self.run / "server.log").chmod(0o600)

        observed = status(self.config, self.transport, self.runtime, run_id=state["run_id"])
        self.assertEqual(observed.state, "starting")
        self.assertFalse(observed.active)
        self.assertEqual(state_path.read_bytes(), prior_state)
        with self.assertRaises(TargetError) as refused:
            serve(self.config, self.transport, self.runtime, run_id="run-replacement-0001")
        self.assertEqual(refused.exception.code, "serve_not_dispatched")
        self.assertEqual(state_path.read_bytes(), prior_state)
        self.assertEqual((self.run / "server.log").read_bytes(), prior_log)
    # ---- Cross-chunk secret redaction in log ------------------------------

    def test_cross_chunk_non_home_ancestor_redaction(self) -> None:
        port = self._setup_work()
        server_path = self.work / "server.py"
        long_secret = (
            "/mnt/targetctl-private/models/drafter/"
            + "/".join(f"segment-{index:02d}-" + ("x" * 96) for index in range(6))
            + "/draft.gguf"
        )
        self.assertGreater(len(long_secret), 512)
        self.assertLessEqual(len(long_secret), 4096)
        self.runtime = RuntimeInputs(
            self.runtime.model_path, long_secret,
            self.runtime.source_snapshot_id, self.runtime.applied_tree_hash,
            self.runtime.build_id, self.runtime.work_token, self.runtime.run_token,
            self.runtime.port, binary_path=self.runtime.binary_path,
        )
        emitted_ancestor = str(Path(long_secret).parents[2])
        markers = ("\x1b[31m", "\x00", "\x85", "\x1b[0m")
        obfuscated_ancestor = "".join(
            character + (markers[index % len(markers)] if index + 1 < len(emitted_ancestor) else "")
            for index, character in enumerate(emitted_ancestor)
        )
        _write_server_with_secret(server_path, port, obfuscated_ancestor)
        server_path.chmod(0o700)
        _write_build_json(self.run, self.work, "server.py")
        result = serve(self.config, self.transport, self.runtime)
        time.sleep(0.3)
        log_content = logs(self.config, self.transport, self.runtime)
        self.assertIn(b"[REDACTED]", log_content)
        self.assertIn(b"producer-prefix [REDACTED] producer-suffix", log_content)
        for private in (emitted_ancestor, "/mnt/targetctl-private"):
            self.assertNotIn(private.encode(), log_content)
        stop(self.config, self.transport, self.runtime, run_id=result.run_id)

    # ---- Control bytes stripped from log -----------------------------------

    def test_control_bytes_stripped_from_log(self) -> None:
        port = self._setup_work()
        server_path = self.work / "server.py"
        # Write a server that prints control characters to stdout
        server_path.write_text(
            "import http.server, json, sys\n"
            "class H(http.server.BaseHTTPRequestHandler):\n"
            "  def do_GET(self):\n"
            "    if self.path == '/v1/models':\n"
            "      self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps({'data':[]}).encode()); return\n"
            "    self.send_response(404); self.end_headers()\n"
            "  def log_message(self, fmt, *args): pass\n"
            "sys.stdout.write('\\x00\\x01\\x02\\x03'); sys.stdout.flush()\n"
            "s = http.server.HTTPServer(('127.0.0.1', " + str(port) + "), H)\n"
            "s.serve_forever()\n",
            encoding="utf-8",
        )
        server_path.chmod(0o700)
        binary_hash = _write_build_json(self.run, self.work, "server.py")
        result = serve(self.config, self.transport, self.runtime)
        time.sleep(0.3)
        log_content = logs(self.config, self.transport, self.runtime)
        # No raw null bytes or other control chars should be in the log
        self.assertNotIn(b"\x00", log_content)
        stop(self.config, self.transport, self.runtime, run_id=result.run_id)

    # ---- Private temp files removed after stop ----------------------------

    def test_private_temp_files_removed(self) -> None:
        port = self._setup_work()
        result = serve(self.config, self.transport, self.runtime)
        # Supervisor and launch files should exist during run
        self.assertTrue((self.run / "launch.json").exists())
        self.assertTrue((self.run / "supervisor.py").exists())
        cl = stop(self.config, self.transport, self.runtime, run_id=result.run_id)
        # After stop, all temporary files should be gone
        self.assertFalse((self.run / "supervisor.py").exists())
        self.assertFalse((self.run / "launch.json").exists())
        self.assertFalse((self.run / "ack.json").exists())

    # ---- Smoke returns real evidence --------------------------------------

    def test_smoke_returns_real_evidence(self) -> None:
        port = self._setup_work()
        result = smoke(self.config, self.transport, self.runtime)
        self.assertEqual(result.status, "succeeded")
        self.assertIsNone(result.failure_class)
        self.assertEqual(result.readiness_http, 200)
        self.assertEqual(result.models_http, 200)
        self.assertEqual(result.contract, "passed")
        self.assertIsNotNone(result.primary_weight_sha256)
        self.assertEqual(len(result.primary_weight_sha256), 64)
        self.assertIsNotNone(result.draft_weight_sha256)
        self.assertEqual(len(result.draft_weight_sha256), 64)
        self.assertGreater(result.duration_ns, 0)
        self.assertIsInstance(result.run_id, str)

    # ---- Smoke run_id is preallocated and deterministic --------------------

    def test_smoke_preallocates_run_id(self) -> None:
        self._setup_work()
        result = smoke(self.config, self.transport, self.runtime, run_id="my-run-001")
        self.assertEqual(result.run_id, "my-run-001")

    def test_smoke_propagates_pre_dispatch_refusal_without_reconciliation(self) -> None:
        self._setup_work()
        active = serve(self.config, self.transport, self.runtime, run_id="run-active-smoke-0001")
        lease_path = self.run / ".targetctl-operation-lock-v1"
        lease_before = lease_path.read_bytes()

        with self.assertRaises(TargetError) as refused:
            smoke(self.config, self.transport, self.runtime, run_id="run-replacement-smoke-0001")
        self.assertEqual(refused.exception.code, "serve_not_dispatched")
        self.assertEqual(lease_path.read_bytes(), lease_before)
        current = status(self.config, self.transport, self.runtime, run_id=active.run_id)
        self.assertTrue(current.active)
        self.assertEqual(cleanup(self.config, self.transport, self.runtime, run_id=active.run_id).status, "succeeded")

    def test_cleanup_wrong_run_id_is_absent_without_mutating_current_run(self) -> None:
        self._setup_work()
        result = serve(self.config, self.transport, self.runtime)
        lease_path = self.run / ".targetctl-operation-lock-v1"
        lease_before = lease_path.read_bytes()
        absent = cleanup(self.config, self.transport, self.runtime, run_id="run-absent-0001")
        self.assertEqual(absent.status, "not_run")
        self.assertIsNone(absent.run_id)
        self.assertEqual(lease_path.read_bytes(), lease_before)
        current = json.loads((self.run / "run.json").read_text(encoding="ascii"))
        self.assertEqual(current["run_id"], result.run_id)
        self.assertFalse(current["cleanup_complete"])
        self.assertEqual(cleanup(self.config, self.transport, self.runtime, run_id=result.run_id).status, "succeeded")

    def test_cleanup_refuses_operation_lease_owned_by_another_run(self) -> None:
        self._setup_work()
        result = serve(self.config, self.transport, self.runtime)
        lease_path = self.run / ".targetctl-operation-lock-v1"
        lease = json.loads(lease_path.read_text(encoding="ascii"))
        lease["lifecycle_run_id"] = "run-different-0001"
        lease_path.write_text(
            json.dumps(lease, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )

        refused = cleanup(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(refused.status, "failed")
        self.assertEqual(refused.lock, "unknown")
        self.assertTrue(lease_path.exists())
        state = json.loads((self.run / "run.json").read_text(encoding="ascii"))
        self.assertFalse(state["cleanup_complete"])

    # ---- Status with wrong run_id returns stopped -------------------------

    def test_status_wrong_run_id_returns_stopped(self) -> None:
        port = self._setup_work()
        result = serve(self.config, self.transport, self.runtime)
        st = status(self.config, self.transport, self.runtime, run_id="nonexistent")
        self.assertEqual(st.state, "stopped")
        self.assertFalse(st.active)
        stop(self.config, self.transport, self.runtime, run_id=result.run_id)

    # ---- Serve fails on occupied port, cleanup still happens ---------------

    def test_occupied_port_cleanup_succeeds(self) -> None:
        port = self._setup_work()
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        blocker.bind(("127.0.0.1", port))
        blocker.listen(1)
        self.addCleanup(blocker.close)
        self._leaked_ports.append(port)
        self.runtime = RuntimeInputs(
            str(self.model), str(self.drafter),
            "1" * 64, "2" * 64, "3" * 64,
            self.runtime.work_token, self.runtime.run_token, port,
            binary_path="server.py", startup_timeout=3,
        )
        with self.assertRaises(TargetError):
            serve(self.config, self.transport, self.runtime)
        # Cleanup should succeed even after failed serve
        cl = stop(self.config, self.transport, self.runtime)
        self.assertEqual(cl.status, "succeeded")


    def test_child_popen_failure_releases_lock_and_private_files(self) -> None:
        self._setup_work(binary_name="broken-server")
        server_path = self.work / "broken-server"
        server_path.write_text("#!/definitely/not/an-interpreter\n", encoding="utf-8")
        server_path.chmod(0o700)
        _write_build_json(self.run, self.work, "broken-server")

        with self.assertRaises(TargetError) as ctx:
            serve(self.config, self.transport, self.runtime)
        self.assertEqual(ctx.exception.code, "startup_failed")
        time.sleep(0.1)

        self.assertFalse((self.run / ".targetctl-operation-lock-v1").exists())
        for name in ("launch.json", "ack.json", "supervisor.py"):
            self.assertFalse((self.run / name).exists())
        self.assertLessEqual((self.run / "server.log").stat().st_size, 1_048_576)
        outcome = stop(self.config, self.transport, self.runtime)
        self.assertEqual(outcome.status, "succeeded")
        self.assertIn(outcome.temp, ("cleared", "not_found"))
        self.assertIn(outcome.lock, ("cleared", "not_found"))
        self.assertIsNotNone(outcome.server_log_sha256)

    def test_noisy_server_log_is_bounded_and_stop_leaves_no_orphan(self) -> None:
        port = self._setup_work()
        server_path = self.work / "server.py"
        server_path.write_text(
            "import http.server, json, sys\n"
            "sys.stdout.write('x' * 2097152); sys.stdout.flush()\n"
            "class H(http.server.BaseHTTPRequestHandler):\n"
            "  def do_GET(self):\n"
            "    self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(json.dumps({'data':[]}).encode())\n"
            "  def log_message(self, fmt, *args): pass\n"
            "s = http.server.HTTPServer(('127.0.0.1', " + str(port) + "), H)\n"
            "s.serve_forever()\n",
            encoding="utf-8",
        )
        _write_build_json(self.run, self.work, "server.py")

        result = serve(self.config, self.transport, self.runtime)
        self.assertLessEqual(len(logs(self.config, self.transport, self.runtime)), 1_048_576)
        outcome = stop(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(outcome.status, "succeeded")
        self.assertIn(outcome.socket, ("cleared", "not_found"))
        self.assertIn(outcome.temp, ("cleared", "not_found"))
        for pid in (result.supervisor_pid, result.child_pid):
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        for name in ("launch.json", "ack.json", "supervisor.py"):
            self.assertFalse((self.run / name).exists())

    def test_failed_startup_cleanup_removes_private_files_and_reports_digest(self) -> None:
        port = self._setup_work()
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", port))
        blocker.listen(1)
        self.addCleanup(blocker.close)
        self.runtime = RuntimeInputs(
            str(self.model), str(self.drafter),
            "1" * 64, "2" * 64, "3" * 64,
            self.runtime.work_token, self.runtime.run_token, port,
            binary_path="server.py", startup_timeout=3,
        )

        with self.assertRaises(TargetError) as ctx:
            serve(self.config, self.transport, self.runtime)
        self.assertEqual(ctx.exception.code, "startup_failed")
        outcome = cleanup(self.config, self.transport, self.runtime)
        self.assertEqual(outcome.status, "succeeded")
        self.assertEqual(outcome.process, "not_found")
        self.assertEqual(outcome.socket, "not_found")
        self.assertIn(outcome.temp, ("cleared", "not_found"))
        self.assertIn(outcome.lock, ("cleared", "not_found"))
        self.assertIsNotNone(outcome.server_log_sha256)
        self.assertLessEqual((self.run / "server.log").stat().st_size, 1_048_576)
        for name in ("launch.json", "ack.json", "supervisor.py"):
            self.assertFalse((self.run / name).exists())

    def test_ambiguous_remote_serve_keeps_target_cleanup_lease(self) -> None:
        self._setup_work()
        calls: list[str] = []
        payloads: list[dict[str, object]] = []
        lease_path = self.run / ".targetctl-operation-lock-v1"

        class DropServeResponse:
            def __init__(self, transport: LocalTransport) -> None:
                self.transport = transport
                self.lease_token: str | None = None

            def run_helper(self, action, payload, **kwargs):
                calls.append(action)
                payloads.append(dict(payload))
                response = self.transport.run_helper(action, payload, **kwargs)
                if action == "lifecycle_serve":
                    self.lease_token = json.loads(lease_path.read_text(encoding="ascii"))["token"]
                    raise TargetError("helper_timeout", "target helper timed out")
                return response

        dropped = DropServeResponse(self.transport)
        identifier = "run-ambiguous-0001"
        with self.assertRaisesRegex(TargetError, "helper_timeout"):
            serve(self.config, dropped, self.runtime, run_id=identifier)
        self.assertEqual(calls, ["lifecycle_serve"])
        self.assertNotIn("lock_token", payloads[0])
        lease = json.loads(lease_path.read_text(encoding="ascii"))
        self.assertEqual(lease["lifecycle_run_id"], identifier)
        self.assertIsNotNone(dropped.lease_token)
        token = dropped.lease_token.encode("ascii")
        self.assertNotIn(token, (self.run / "run.json").read_bytes())
        self.assertNotIn(token, (self.run / "launch.json").read_bytes())

        first = cleanup(self.config, self.transport, self.runtime, run_id=identifier)
        self.assertEqual(first.status, "succeeded")
        self.assertFalse(lease_path.exists())
        retry = cleanup(self.config, self.transport, self.runtime, run_id=identifier)
        self.assertEqual(retry.controller_payload(), first.controller_payload())

    def test_silent_server_lease_expiry_converges(self) -> None:
        port = self._setup_work()
        self.runtime = RuntimeInputs(
            str(self.model), str(self.drafter), "1" * 64, "2" * 64, "3" * 64,
            self.runtime.work_token, self.runtime.run_token, port,
            binary_path="server.py", lease_seconds=1,
        )
        result = serve(self.config, self.transport, self.runtime)
        time.sleep(1.5)
        observed = status(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(observed.state, "stopped")
        self.assertFalse(observed.active)

    def test_hup_stops_owned_supervisor(self) -> None:
        self._setup_work()
        result = serve(self.config, self.transport, self.runtime)
        os.kill(result.supervisor_pid, signal.SIGHUP)
        time.sleep(0.3)
        observed = status(self.config, self.transport, self.runtime, run_id=result.run_id)
        self.assertEqual(observed.state, "stopped")
        self.assertFalse(observed.active)
