from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import socket
import sys
import time
import threading
from pathlib import Path
import shlex
import tempfile
import unittest
from types import SimpleNamespace
import warnings
from unittest import mock

from scripts.targetctl import remote
from scripts.targetctl.common import PROTOCOL_VERSION, TargetError
from scripts.targetctl.transport import (
    CommandResult,
    LocalTransport,
    MAX_HELPER_RESPONSE_METADATA_BYTES,
    MAX_HELPER_STDOUT_BYTES,
    MAX_PROCESS_OUTPUT_BYTES,
    SSHForward,
    SSHTransport,
    select_transport,
)


def roots(tmp_path: Path) -> dict[str, str]:
    model = tmp_path / "models" / "model.gguf"
    drafter = tmp_path / "models" / "draft.gguf"
    model.parent.mkdir(parents=True, exist_ok=True)
    model.write_bytes(b"m")
    drafter.write_bytes(b"d")
    return {
        "workdir": str(tmp_path / "work"),
        "run_dir": str(tmp_path / "run"),
        "model_path": str(model),
        "drafter_path": str(drafter),
    }


def initialized(tmp_path: Path) -> tuple[dict[str, str], dict[str, object]]:
    payload = roots(tmp_path)
    return payload, remote.initialize_roots(payload)


def successful_runner(captured: dict[str, object], *, bad_digest: bool = False, protocol_version: int = PROTOCOL_VERSION) -> mock.Mock:
    def runner(argv, input_bytes, timeout, cwd, env, cap):
        captured.update(argv=tuple(argv), program=input_bytes, timeout=timeout, cwd=cwd, env=dict(env), cap=cap)
        host_index = argv.index("--") + 1
        remote_shell_argv = shlex.split(argv[host_index + 1])
        helper_argv = shlex.split(remote_shell_argv[2].removeprefix("cd -- / && exec "))
        remote_environment = dict(argument.split("=", 1) for argument in helper_argv[2:-4])
        digest = remote_environment["TARGETCTL_HELPER_DIGEST"]
        if bad_digest:
            digest = "0" * 64
        response = {
            "protocol_version": protocol_version,
            "helper_sha256": digest,
            "ok": True,
            "result": {"registered": True},
        }
        return CommandResult(0, False, 1, json.dumps(response).encode("ascii"), b"")

    return mock.Mock(side_effect=runner)


class RemoteRootTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.tmp_path = Path(self._temporary_directory.name)

    def test_initialization_rejects_symlink_components_and_populated_roots(self) -> None:
        payload = roots(self.tmp_path)
        (self.tmp_path / "link").symlink_to(self.tmp_path / "missing")
        payload["workdir"] = str(self.tmp_path / "link" / "work")
        with self.assertRaises(remote.HelperError) as error:
            remote.initialize_roots(payload)
        self.assertEqual(error.exception.code, "symlink_path")

        payload = roots(self.tmp_path / "populated")
        workdir = Path(payload["workdir"])
        workdir.mkdir(parents=True, mode=0o700)
        workdir.chmod(0o700)
        (workdir / "foreign").write_text("x")
        with self.assertRaises(remote.HelperError) as error:
            remote.initialize_roots(payload)
        self.assertEqual(error.exception.code, "unmarked_populated_root")

    def test_marker_token_and_device_identity_are_verified(self) -> None:
        payload, state = initialized(self.tmp_path)
        work = state["work"]
        run = state["run"]
        checked = remote.inspect_roots({**payload, "work_token": work["token"], "run_token": run["token"]})
        self.assertEqual(checked["work"], work["identity"])
        self.assertEqual(checked["run"], run["identity"])
        with self.assertRaises(remote.HelperError) as error:
            remote.inspect_roots({**payload, "work_token": "0" * 64, "run_token": run["token"]})
        self.assertEqual(error.exception.code, "marker_mismatch")

    def test_lock_is_exclusive_and_requires_its_exact_token(self) -> None:
        payload, state = initialized(self.tmp_path)
        run_token = state["run"]["token"]
        first = remote.acquire_lock({"run_dir": payload["run_dir"], "run_token": run_token, "lease_seconds": 60})
        with self.assertRaises(remote.HelperError) as error:
            remote.acquire_lock({"run_dir": payload["run_dir"], "run_token": run_token, "lease_seconds": 60})
        self.assertEqual(error.exception.code, "lock_busy")
        with self.assertRaises(remote.HelperError) as error:
            remote.release_lock({"run_dir": payload["run_dir"], "run_token": run_token, "lock_token": "0" * 64})
        self.assertEqual(error.exception.code, "lock_token_mismatch")
        self.assertEqual(
            remote.release_lock({"run_dir": payload["run_dir"], "run_token": run_token, "lock_token": first["lock_token"]}),
            {"released": True},
        )
        self.assertIn("lock_token", remote.acquire_lock({"run_dir": payload["run_dir"], "run_token": run_token, "lease_seconds": 60}))

    def test_expired_lock_reclaims_only_owned_receiver_pairs_and_malformed_fails_closed(self) -> None:
        payload, state = initialized(self.tmp_path)
        run = Path(payload["run_dir"])
        run_token = state["run"]["token"]
        lock = run / remote.LOCK_NAME
        lock.write_text(json.dumps({"boot_id": remote._boot_id(), "deadline_monotonic_ns": time.monotonic_ns() - 1, "token": "a" * 64}), encoding="ascii")
        lock.chmod(0o600)
        nonce = "b" * 32
        receiver = run / f".targetctl-source-receiver-{nonce}"
        receiver.with_suffix(".py").write_text("#!/usr/bin/python3\n", encoding="ascii")
        receiver.with_suffix(".py").chmod(0o700)
        receiver.with_suffix(".json").write_text("{}", encoding="ascii")
        receiver.with_suffix(".json").chmod(0o600)
        canary = run / "canary"
        canary.write_text("keep", encoding="ascii")
        canary.chmod(0o600)
        recovered = remote.acquire_lock({"run_dir": payload["run_dir"], "run_token": run_token, "lease_seconds": 60})
        self.assertTrue(recovered["reclaimed"])
        self.assertEqual(recovered["stale_receiver_pairs_cleaned"], 1)
        self.assertTrue(canary.exists())
        self.assertFalse(receiver.with_suffix(".py").exists())
        self.assertFalse(receiver.with_suffix(".json").exists())
        remote.release_lock({"run_dir": payload["run_dir"], "run_token": run_token, "lock_token": recovered["lock_token"]})
        lock.write_text("not-json", encoding="ascii")
        lock.chmod(0o600)
        with self.assertRaises(remote.HelperError) as error:
            remote.acquire_lock({"run_dir": payload["run_dir"], "run_token": run_token, "lease_seconds": 60})
        self.assertEqual(error.exception.code, "unsafe_lock")

    def test_overlap_and_weak_or_symlink_reports_fail_closed(self) -> None:
        payload = roots(self.tmp_path)
        payload["run_dir"] = payload["workdir"] + "/nested"
        with self.assertRaises(remote.HelperError) as error:
            remote.initialize_roots(payload)
        self.assertEqual(error.exception.code, "path_overlap")

        payload, state = initialized(self.tmp_path)
        report = Path(payload["run_dir"]) / "doctor.json"
        report.write_bytes(b"{}")
        os.chmod(report, 0o644)
        with self.assertRaises(remote.HelperError) as error:
            remote.read_report({"run_dir": payload["run_dir"], "run_token": state["run"]["token"], "name": "doctor.json"})
        self.assertEqual(error.exception.code, "unsafe_state")
        report.unlink()
        report.symlink_to(Path(payload["run_dir"]) / remote._marker_name("run"))
        with self.assertRaises(remote.HelperError) as error:
            remote.read_report({"run_dir": payload["run_dir"], "run_token": state["run"]["token"], "name": "doctor.json"})
        self.assertEqual(error.exception.code, "unsafe_state")

    def test_entry_hash_rejects_paths_and_non_regular_entries(self) -> None:
        root = self.tmp_path / "tree"
        root.mkdir(mode=0o700)
        entry = root / "file.txt"
        entry.write_bytes(b"contents")
        self.assertEqual(remote.hash_entries({"root": str(root), "entries": ["file.txt"]})["entry_count"], 1)
        with self.assertRaises(remote.HelperError) as error:
            remote.hash_entries({"root": str(root), "entries": ["../file.txt"]})
        self.assertEqual(error.exception.code, "invalid_entry")
        (root / "directory").mkdir()
        with self.assertRaises(remote.HelperError) as error:
            remote.hash_entries({"root": str(root), "entries": ["directory"]})
        self.assertEqual(error.exception.code, "unsupported_entry")


class TransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.ssh_config = Path(self._temporary_directory.name) / "config"
        self.ssh_config.write_text("Host *\n", encoding="utf-8")
        self.ssh_config.chmod(0o600)

    def test_ssh_helper_uses_one_fixed_no_forwarding_command_and_round_trips_quoting(self) -> None:
        captured: dict[str, object] = {}
        transport = SSHTransport("spark_1.example", runner=successful_runner(captured), ssh_config=self.ssh_config)
        result = transport.run_helper(
            "extension",
            {"value": "quoted value"},
            extension_source='@register_action("extension")\ndef extension(payload):\n return {"registered": True}',
        )
        self.assertEqual(result, {"registered": True})

        argv = captured["argv"]
        self.assertEqual(argv[:3], ("ssh", "-F", str(self.ssh_config)))
        host_index = argv.index("--") + 1
        self.assertEqual(argv[host_index], "spark_1.example")
        self.assertEqual(len(argv), host_index + 2)
        ssh_options = {argv[index + 1] for index, argument in enumerate(argv[:-1]) if argument == "-o"}
        self.assertTrue(
            {
                "ForwardAgent=no",
                "IdentityAgent=none",
                "ForwardX11=no",
                "RequestTTY=no",
                "RemoteCommand=none",
                "ClearAllForwardings=yes",
                "ControlMaster=no",
            }.issubset(ssh_options)
        )
        # These options override any user-configured control socket: this client
        # cannot attach to an existing master or leave a persistent one behind.
        self.assertEqual(
            {option for option in ssh_options if option.startswith("Control")},
            {"ControlMaster=no", "ControlPath=none", "ControlPersist=no"},
        )

        # OpenSSH concatenates operands after the host with spaces before invoking
        # the remote shell.  Reconstruct that exact command rather than checking
        # unrelated substrings in the local argv.
        remote_text = " ".join(argv[host_index + 1 :])
        remote_shell_argv = shlex.split(remote_text)
        self.assertEqual(remote_shell_argv[:2], ["/bin/sh", "-c"])
        self.assertEqual(len(remote_shell_argv), 3)
        self.assertTrue(remote_shell_argv[2].startswith("cd -- / && exec "))
        helper_argv = shlex.split(remote_shell_argv[2].removeprefix("cd -- / && exec "))
        self.assertEqual(helper_argv[:2], ["/usr/bin/env", "-i"])
        self.assertEqual(helper_argv[-4:], ["/usr/bin/python3", "-I", "-S", "-"])
        self.assertTrue(any(argument.startswith("TARGETCTL_HELPER_DIGEST=") for argument in helper_argv))
        remote_environment = dict(argument.split("=", 1) for argument in helper_argv[2:-4])
        self.assertEqual(set(remote_environment), {"LANG", "LC_ALL", "PATH", "TARGETCTL_HELPER_DIGEST", "TARGETCTL_HELPER_DEFERRED"})
        self.assertEqual(remote_environment["LANG"], "C")
        self.assertEqual(remote_environment["LC_ALL"], "C")
        self.assertEqual(remote_environment["PATH"], "/usr/bin:/bin")
        self.assertEqual(remote_environment["TARGETCTL_HELPER_DEFERRED"], "1")
        self.assertNotIn("quoted value", remote_text)
        self.assertNotIn("extension", remote_text)
        self.assertIn(b"run(base64.b64decode", captured["program"])
        self.assertEqual(captured["cwd"], "/")
        self.assertEqual(captured["env"], {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})

    def test_select_transport_uses_only_a_validated_current_user_ssh_config(self) -> None:
        home = Path(self._temporary_directory.name) / "home"
        config = home / ".ssh" / "config"
        config.parent.mkdir(parents=True)
        config.write_text("Host *\n", encoding="utf-8")
        config.chmod(0o600)
        captured: dict[str, object] = {}

        with mock.patch("scripts.targetctl.transport.Path.home", return_value=home):
            transport = select_transport(SimpleNamespace(mode="ssh", ssh_host="spark"), runner=successful_runner(captured))
            transport.run_helper("handshake", {})
        self.assertEqual(captured["argv"][:3], ("ssh", "-F", str(config)))

        config.chmod(0o620)
        with mock.patch("scripts.targetctl.transport.Path.home", return_value=home):
            with self.assertRaises(TargetError) as error:
                select_transport(SimpleNamespace(mode="ssh", ssh_host="spark"))
        self.assertEqual(error.exception.code, "ssh_config_invalid")
        self.assertNotIn(str(config), str(error.exception))

        config.chmod(0o600)
        config.unlink()
        config.symlink_to(self.ssh_config)
        with mock.patch("scripts.targetctl.transport.Path.home", return_value=home):
            with self.assertRaises(TargetError) as error:
                select_transport(SimpleNamespace(mode="ssh", ssh_host="spark"))
        self.assertEqual(error.exception.code, "ssh_config_invalid")
        self.assertNotIn(str(config), str(error.exception))

        config.unlink()
        with mock.patch("scripts.targetctl.transport.Path.home", return_value=home):
            with self.assertRaises(TargetError) as error:
                select_transport(SimpleNamespace(mode="ssh", ssh_host="spark"))
        self.assertEqual(error.exception.code, "ssh_config_invalid")
        self.assertNotIn(str(config), str(error.exception))

    def test_rsync_uses_the_isolated_ssh_config(self) -> None:
        source = Path(self._temporary_directory.name) / "source"
        source.mkdir()
        captured: dict[str, object] = {}

        def runner(argv, input_bytes, timeout, cwd, env, cap):
            captured["argv"] = tuple(argv)
            return CommandResult(0, False, 1, b"", b"")

        SSHTransport("spark", runner=mock.Mock(side_effect=runner), ssh_config=self.ssh_config).guarded_rsync(
            source,
            "/remote-work",
            receiver="/usr/bin/rsync",
        )
        ssh_argv = shlex.split(captured["argv"][captured["argv"].index("-e") + 1])
        self.assertEqual(ssh_argv[:3], ["ssh", "-F", str(self.ssh_config)])
        self.assertIn("ControlPath=none", ssh_argv)
        self.assertIn("ControlPersist=no", ssh_argv)

    def test_ssh_rejects_aliases_and_keeps_request_strings_out_of_options_and_shell(self) -> None:
        for alias in ("-oProxyCommand=evil", "spark host", "spark;touch", "", "spärk"):
            with self.subTest(alias=alias):
                with self.assertRaises(TargetError) as error:
                    SSHTransport(alias)
                self.assertEqual(error.exception.code, "invalid_ssh_host")

        captured: dict[str, object] = {}
        SSHTransport("spark", runner=successful_runner(captured), ssh_config=self.ssh_config).run_helper(
            "'; touch /tmp/pwned; #",
            {"private": "$(touch /tmp/also-pwned)"},
        )
        argv = captured["argv"]
        host_index = argv.index("--") + 1
        remote_text = " ".join(argv[host_index + 1 :])
        self.assertNotIn("pwned", " ".join(argv))
        self.assertNotIn("private", " ".join(argv))
        self.assertNotIn("pwned", remote_text)
        self.assertNotIn("private", remote_text)
        self.assertEqual(argv[host_index], "spark")

    def test_extension_registers_before_the_deferred_helper_dispatch(self) -> None:
        extension = '@register_action("extension")\ndef extension(payload):\n    _require_object(payload, {"answer"})\n    return {"answer": payload["answer"]}\n'
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            result = LocalTransport().run_helper("extension", {"answer": 42}, extension_source=extension)
        self.assertEqual(result, {"answer": 42})
        self.assertFalse(any(issubclass(warning.category, ResourceWarning) for warning in caught))

    def test_private_payload_does_not_change_helper_digest_but_extension_does(self) -> None:
        captured: list[dict[str, object]] = []

        def runner(argv, input_bytes, timeout, cwd, env, cap):
            captured.append({"program": input_bytes, "digest": env["TARGETCTL_HELPER_DIGEST"]})
            response = {
                "protocol_version": PROTOCOL_VERSION,
                "helper_sha256": env["TARGETCTL_HELPER_DIGEST"],
                "ok": True,
                "result": {},
            }
            return CommandResult(0, False, 1, json.dumps(response).encode("ascii"), b"")

        transport = LocalTransport(runner=mock.Mock(side_effect=runner))
        extension = '@register_action("test")\ndef test(payload):\n return {}\n'
        transport.run_helper("test", {"private": "first-secret"}, extension_source=extension)
        transport.run_helper("test", {"private": "second-secret"}, extension_source=extension)
        transport.run_helper("test", {"private": "second-secret"}, extension_source=extension + "\n# changed\n")

        self.assertNotEqual(captured[0]["program"], captured[1]["program"])
        self.assertEqual(captured[0]["digest"], captured[1]["digest"])
        self.assertNotEqual(captured[1]["digest"], captured[2]["digest"])

    def test_helper_output_cap_is_enforced(self) -> None:
        def oversized(argv, input_bytes, timeout, cwd, env, cap):
            return CommandResult(0, False, 1, b"x" * (cap + 1), b"")

        with self.assertRaises(TargetError) as error:
            LocalTransport(
                runner=mock.Mock(side_effect=oversized),
            ).run_helper("handshake", {})
        self.assertEqual(error.exception.code, "helper_execution_failed")

    def test_base64_log_envelope_crosses_prior_cap_locally_and_over_ssh(self) -> None:
        report_envelope = {
            "protocol_version": PROTOCOL_VERSION,
            "helper_sha256": "0" * 64,
            "ok": True,
            "result": {"sha256": "0" * 64, "content_b64": ""},
        }
        report_metadata_bytes = len(json.dumps(
            report_envelope,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")) + 1
        self.assertEqual(
            report_metadata_bytes,
            MAX_HELPER_RESPONSE_METADATA_BYTES,
        )
        payload, state = initialized(Path(self._temporary_directory.name) / "large-report")
        run = Path(payload["run_dir"])
        report = run / "server.log"
        fake_ssh = Path(self._temporary_directory.name) / "ssh"
        fake_ssh.write_text(
            "#!/usr/bin/python3\n"
            "import os, sys\n"
            "separator = sys.argv.index('--')\n"
            "os.execv('/bin/sh', ['/bin/sh', '-c', sys.argv[separator + 2]])\n",
            encoding="ascii",
        )
        fake_ssh.chmod(0o700)
        transports = {
            "local": LocalTransport(),
            "ssh": SSHTransport(
                "spark",
                ssh_binary=str(fake_ssh),
                ssh_config=self.ssh_config,
            ),
        }

        for raw_size in (786_432, 1_048_576):
            content = (b"x\n" * ((raw_size + 1) // 2))[:raw_size]
            report.write_bytes(content)
            report.chmod(0o600)
            expected_envelope_size = (
                4 * ((raw_size + 2) // 3)
                + MAX_HELPER_RESPONSE_METADATA_BYTES
            )
            self.assertGreater(expected_envelope_size, MAX_PROCESS_OUTPUT_BYTES)
            self.assertLessEqual(expected_envelope_size, MAX_HELPER_STDOUT_BYTES)
            if raw_size == 1_048_576:
                self.assertEqual(expected_envelope_size, MAX_HELPER_STDOUT_BYTES)
            for mode, transport in transports.items():
                with self.subTest(mode=mode, raw_size=raw_size):
                    result = transport.run_helper(
                        "read_report",
                        {
                            "run_dir": payload["run_dir"],
                            "run_token": state["run"]["token"],
                            "name": "server.log",
                        },
                    )
                    decoded = base64.b64decode(result["content_b64"], validate=True)
                    self.assertEqual(decoded, content)
                    self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())

    def test_helper_envelope_one_byte_over_limit_terminates_and_fails_closed(self) -> None:
        empty_envelope = {
            "protocol_version": PROTOCOL_VERSION,
            "helper_sha256": "0" * 64,
            "ok": True,
            "result": {"padding": ""},
        }
        envelope_metadata_bytes = len(json.dumps(
            empty_envelope,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")) + 1
        padding_bytes = MAX_HELPER_STDOUT_BYTES + 1 - envelope_metadata_bytes
        extension = (
            '@register_action("oversized_envelope")\n'
            "def oversized_envelope(payload):\n"
            '    return {"padding": "x" * payload["padding_bytes"]}\n'
        )
        processes: list[subprocess.Popen[bytes]] = []
        real_popen = subprocess.Popen

        def record_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        with mock.patch(
            "scripts.targetctl.transport.subprocess.Popen",
            side_effect=record_process,
        ):
            with self.assertRaises(TargetError) as error:
                LocalTransport().run_helper(
                    "oversized_envelope",
                    {"padding_bytes": padding_bytes},
                    extension_source=extension,
                    timeout=5.0,
                )

        self.assertEqual(error.exception.code, "helper_execution_failed")
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertTrue(all(
            stream is None or stream.closed
            for stream in (processes[0].stdin, processes[0].stdout, processes[0].stderr)
        ))

    def test_helper_digest_protocol_and_output_fail_closed_without_command_text(self) -> None:
        captured: dict[str, object] = {}
        with self.assertRaises(TargetError) as error:
            SSHTransport("spark", runner=successful_runner(captured, bad_digest=True), ssh_config=self.ssh_config).run_helper("handshake", {})
        self.assertEqual(error.exception.code, "helper_integrity_failed")
        with self.assertRaises(TargetError) as error:
            SSHTransport("spark", runner=successful_runner({}, protocol_version=PROTOCOL_VERSION + 1), ssh_config=self.ssh_config).run_helper("handshake", {})
        self.assertEqual(error.exception.code, "helper_integrity_failed")

        def malformed(argv, input_bytes, timeout, cwd, env, cap):
            return CommandResult(0, False, 1, b"[]", b"")

        with self.assertRaises(TargetError) as error:
            LocalTransport(runner=mock.Mock(side_effect=malformed)).run_helper("handshake", {})
        self.assertEqual(error.exception.code, "invalid_helper_response")

        def hostile_runner(argv, input_bytes, timeout, cwd, env, cap):
            return CommandResult(255, False, 1, b"", b"ssh very-private-host.example rejected command")

        with self.assertRaises(TargetError) as error:
            SSHTransport("spark", runner=mock.Mock(side_effect=hostile_runner), ssh_config=self.ssh_config).run_helper("handshake", {})
        self.assertEqual(error.exception.code, "helper_execution_failed")
        self.assertNotIn("very-private-host", str(error.exception))

    def test_helper_error_codes_are_allowlisted_without_rendering_untrusted_values(self) -> None:
        secret = "very-private-helper-error"

        def error_runner(code: str, message: str = secret) -> mock.Mock:
            def runner(argv, input_bytes, timeout, cwd, env, cap):
                response = {
                    "protocol_version": PROTOCOL_VERSION,
                    "helper_sha256": env["TARGETCTL_HELPER_DIGEST"],
                    "ok": False,
                    "error": {"code": code, "message": message},
                }
                return CommandResult(0, False, 1, json.dumps(response).encode("ascii"), b"")

            return mock.Mock(side_effect=runner)

        for code in (f"rejected\n{secret}", f"\x1b[31m{secret}", secret, "x" * 65):
            with self.subTest(code=repr(code)):
                with self.assertRaises(TargetError) as error:
                    LocalTransport(runner=error_runner(code)).run_helper("handshake", {})
                self.assertEqual(error.exception.code, "invalid_helper_response")
                self.assertNotIn(secret, str(error.exception))
                self.assertNotIn(code, str(error.exception))

        with self.assertRaises(TargetError) as error:
            LocalTransport(runner=error_runner("invalid_payload")).run_helper("handshake", {})
        self.assertEqual(error.exception.code, "invalid_payload")
        self.assertNotIn(secret, str(error.exception))

        with self.assertRaises(TargetError) as error:
            LocalTransport(runner=error_runner("extension_rejected")).run_helper(
                "extension",
                {},
                extension_source='@register_action("extension")\ndef extension(payload):\n    return {}',
                allowed_error_codes={"extension_rejected"},
            )
        self.assertEqual(error.exception.code, "extension_rejected")
        self.assertNotIn(secret, str(error.exception))

    def test_transport_rejects_environment_outside_fixed_allowlist(self) -> None:
        with self.assertRaises(TargetError) as error:
            LocalTransport().run(("/usr/bin/true",), env={"AWS_SECRET_ACCESS_KEY": "private"})
        self.assertEqual(error.exception.code, "invalid_environment")
        self.assertNotIn("private", str(error.exception))

    def test_local_transport_drains_stdout_while_writing_near_limit_stdin(self) -> None:
        input_bytes = b"x" * (1024 * 1024 - 1)
        stdout_bytes = 2 * 1024 * 1024
        child = (
            "import sys\n"
            f"sys.stdout.buffer.write(b'o' * {stdout_bytes})\n"
            "sys.stdout.buffer.flush()\n"
            "request = sys.stdin.buffer.read()\n"
            "sys.stdout.buffer.write(str(len(request)).encode('ascii'))\n"
            "sys.stdout.buffer.flush()\n"
        )

        result = LocalTransport(max_output_bytes=stdout_bytes + 1024).run(
            (sys.executable, "-c", child),
            input_bytes=input_bytes,
            timeout=5.0,
        )

        self.assertFalse(result.timed_out)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout[:stdout_bytes], b"o" * stdout_bytes)
        self.assertEqual(result.stdout[stdout_bytes:], str(len(input_bytes)).encode("ascii"))
        self.assertEqual(result.stderr, b"")

    def test_local_transport_times_out_when_child_never_reads_stdin_and_closes_pipes(self) -> None:
        input_bytes = b"x" * (1024 * 1024 - 1)
        processes: list[subprocess.Popen[bytes]] = []
        real_popen = subprocess.Popen

        def record_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        child = "import time\ntime.sleep(60)\n"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            started = time.monotonic()
            with mock.patch("scripts.targetctl.transport.subprocess.Popen", side_effect=record_process):
                result = LocalTransport().run(
                    (sys.executable, "-c", child),
                    input_bytes=input_bytes,
                    timeout=0.25,
                )
            elapsed = time.monotonic() - started

        self.assertTrue(result.timed_out)
        self.assertEqual(result.exit_code, -1)
        self.assertLess(elapsed, 2.0)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertTrue(all(stream is None or stream.closed for stream in (processes[0].stdin, processes[0].stdout, processes[0].stderr)))
        self.assertFalse(any(issubclass(warning.category, ResourceWarning) for warning in caught))


class SSHForwardTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.ssh_config = Path(self._temporary_directory.name) / "config"
        self.ssh_config.write_text(
            "Host *\n"
            "  LocalForward 49101 127.0.0.1:49111\n"
            "  RemoteForward 49102 127.0.0.1:49112\n"
            "  DynamicForward 49103\n",
            encoding="utf-8",
        )
        self.ssh_config.chmod(0o600)

    def test_forward_uses_fixed_stdio_bridge_and_clears_configured_forwards(self) -> None:
        transport = SSHTransport("spark_1.example", ssh_binary="/usr/bin/ssh", ssh_config=self.ssh_config)
        argv = SSHForward(transport, target_port=43123).argv
        self.assertEqual(argv[:3], ("/usr/bin/ssh", "-F", str(self.ssh_config)))
        self.assertEqual(argv[-2:], ("--", "spark_1.example"))
        self.assertEqual(argv[argv.index("-W") + 1], "127.0.0.1:43123")
        self.assertEqual(argv.count("-W"), 1)
        self.assertFalse(any(flag in argv for flag in ("-L", "-R", "-D")))
        options = {argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "-o"}
        self.assertTrue(
            {
                "ForwardAgent=no",
                "ForwardX11=no",
                "RequestTTY=no",
                "RemoteCommand=none",
                "ControlMaster=no",
                "ClearAllForwardings=yes",
                "ConnectionAttempts=1",
            }.issubset(options)
        )
        self.assertNotIn("ClearAllForwardings=no", options)

    def test_bridge_serves_sequential_http_connections_and_reaps_on_interrupt(self) -> None:
        fake_ssh = Path(self._temporary_directory.name) / "ssh"
        fake_ssh.write_text(
            "#!/usr/bin/python3\n"
            "import os, socket, sys, threading\n"
            "destination = sys.argv[sys.argv.index('-W') + 1]\n"
            "host, raw_port = destination.rsplit(':', 1)\n"
            "connection = socket.create_connection((host, int(raw_port)), timeout=3)\n"
            "def upload():\n"
            "  try:\n"
            "    while True:\n"
            "      data = os.read(0, 16384)\n"
            "      if not data:\n"
            "        connection.shutdown(socket.SHUT_WR)\n"
            "        return\n"
            "      connection.sendall(data)\n"
            "  except OSError:\n"
            "    return\n"
            "threading.Thread(target=upload, daemon=True).start()\n"
            "try:\n"
            "  while True:\n"
            "    data = connection.recv(16384)\n"
            "    if not data:\n"
            "      break\n"
            "    view = memoryview(data)\n"
            "    while view:\n"
            "      view = view[os.write(1, view):]\n"
            "finally:\n"
            "  connection.close()\n",
            encoding="utf-8",
        )
        fake_ssh.chmod(0o700)
        requests: list[bytes] = []
        server_errors: list[BaseException] = []
        processes: list[subprocess.Popen[bytes]] = []
        real_popen = subprocess.Popen

        def record_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target:
            target.bind(("127.0.0.1", 0))
            target.listen(2)
            target.settimeout(4)
            target_port = int(target.getsockname()[1])

            def serve() -> None:
                try:
                    for _ in range(2):
                        connection, _ = target.accept()
                        with connection:
                            connection.settimeout(3)
                            request = bytearray()
                            while b"\r\n\r\n" not in request:
                                chunk = connection.recv(4096)
                                if not chunk:
                                    break
                                request.extend(chunk)
                            requests.append(bytes(request))
                            connection.sendall(
                                b"HTTP/1.0 200 OK\r\n"
                                b"Content-Length: 2\r\n"
                                b"Connection: close\r\n\r\nok"
                            )
                except BaseException as error:
                    server_errors.append(error)

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            transport = SSHTransport("spark_1.example", ssh_binary=str(fake_ssh), ssh_config=self.ssh_config)
            forward = SSHForward(transport, target_port=target_port, timeout=3)

            def request(path: str) -> bytes:
                with socket.create_connection(("127.0.0.1", forward.local_port), timeout=3) as client:
                    client.settimeout(3)
                    client.sendall(f"GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n".encode("ascii"))
                    response = bytearray()
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            return bytes(response)
                        response.extend(chunk)

            with self.assertRaises(KeyboardInterrupt):
                with mock.patch("scripts.targetctl.transport.subprocess.Popen", side_effect=record_process):
                    with forward:
                        bridge_port = forward.local_port
                        self.assertIn(b"\r\n\r\nok", request("/health"))
                        self.assertIn(b"\r\n\r\nok", request("/v1/models"))
                        raise KeyboardInterrupt
            server.join(timeout=4)

        self.assertFalse(server.is_alive())
        self.assertEqual(server_errors, [])
        self.assertEqual([item.split(b" ", 2)[1] for item in requests], [b"/health", b"/v1/models"])
        self.assertEqual(len(processes), 2)
        self.assertTrue(all(process.poll() is not None for process in processes))
        self.assertFalse(forward._workers)
        self.assertFalse(forward._processes)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", bridge_port)), 0)


if __name__ == "__main__":
    unittest.main()
