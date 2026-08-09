from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from scripts.targetctl import build as build_module
from scripts.targetctl import doctor as doctor_module
from scripts.targetctl.build import BuildResult
from scripts.targetctl.common import TargetError
from scripts.targetctl.transport import CommandResult, helper_source
from scripts.targetctl.doctor import DOCTOR_TOOLS, DoctorResult, RuntimeInput
from scripts.targetctl.source import SourceSnapshot


class DoctorBuildPayloadTests(unittest.TestCase):
    @staticmethod
    def _leader_exits_while_descendant_holds_pipes(pid_path: Path) -> tuple[str, ...]:
        program = (
            "import os,time\n"
            "child=os.fork()\n"
            "if child:\n"
            f" fd=os.open({str(pid_path)!r},os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)\n"
            " os.write(fd,str(child).encode('ascii'));os.close(fd);os._exit(0)\n"
            "time.sleep(60)\n"
        )
        return (sys.executable, "-c", program)

    def assert_process_not_running(self, pid: int) -> None:
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            try:
                state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()[0]
            except (FileNotFoundError, ProcessLookupError):
                return
            if state == "Z":
                return
            time.sleep(0.01)
        self.fail(f"descendant {pid} survived process-group termination")

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
        self.assertEqual(payload["nix"], {"status": "absent", "version": None})
        self.assertNotIn(runtime.model_path, repr(payload))
        self.assertNotIn(runtime.drafter_path, repr(payload))
        with self.assertRaises(AttributeError):
            result.status = "failed"  # type: ignore[misc]

    def test_nix_identity_matches_native_paths_and_versions(self) -> None:
        versions = {"nvcc": "12.8", "gcc": "14.2", "g++": "14.2"}
        tools = tuple((name, versions.get(name, "1.0"), location) for name, location in DOCTOR_TOOLS)
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            (workdir / "flake.nix").write_text("{}\n", encoding="ascii")
            transport = mock.Mock()

            def run(argv: tuple[str, ...], **_: object) -> CommandResult:
                if argv == ("/nix/store/test/bin/nix", "--version"):
                    return CommandResult(0, False, 1, b"nix (Nix) 2.28.5\n", b"")
                name = argv[-1]
                location = dict(doctor_module._NIX_COMPARE_TOOLS)[name]
                detail = f"Copyright 2005-2025\nCuda compilation tools, release {versions[name]}, V{versions[name]}.1" if name == "nvcc" else f"{name} {versions[name]}"
                return CommandResult(0, False, 1, f"TARGETCTL_PATH={location}\n{detail}\n".encode("ascii"), b"")

            transport.run.side_effect = run
            with mock.patch.object(doctor_module, "_find_nix", return_value="/nix/store/test/bin/nix"):
                self.assertEqual(doctor_module._nix_identity(transport, workdir, tools), ("matched", "2.28.5"))
        self.assertEqual(transport.run.call_count, 4)
        for call in transport.run.call_args_list:
            self.assertEqual(call.kwargs["env"]["PATH"], "/usr/local/cuda/bin:/usr/bin:/bin")

    def test_nix_identity_fails_on_tool_resolution_drift(self) -> None:
        versions = {"nvcc": "12.8", "gcc": "14.2", "g++": "14.2"}
        tools = tuple((name, versions.get(name, "1.0"), location) for name, location in DOCTOR_TOOLS)
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            (workdir / "flake.nix").write_text("{}\n", encoding="ascii")
            transport = mock.Mock()

            def run(argv: tuple[str, ...], **_: object) -> CommandResult:
                if argv[-1] == "--version":
                    return CommandResult(0, False, 1, b"nix (Nix) 2.28.5\n", b"")
                name = argv[-1]
                location = "/nix/store/compiler/bin/gcc" if name == "gcc" else dict(doctor_module._NIX_COMPARE_TOOLS)[name]
                detail = f"Copyright 2005-2025\nCuda compilation tools, release {versions[name]}, V{versions[name]}.1" if name == "nvcc" else f"{name} {versions[name]}"
                return CommandResult(0, False, 1, f"TARGETCTL_PATH={location}\n{detail}\n".encode("ascii"), b"")

            transport.run.side_effect = run
            with mock.patch.object(doctor_module, "_find_nix", return_value="/nix/store/test/bin/nix"):
                with self.assertRaises(TargetError) as raised:
                    doctor_module._nix_identity(transport, workdir, tools)
        self.assertEqual(raised.exception.code, "doctor_nix_mismatch")

    def test_nix_identity_records_absence_without_running_a_command(self) -> None:
        transport = mock.Mock()
        with mock.patch.object(doctor_module, "_find_nix", return_value=None):
            self.assertEqual(doctor_module._nix_identity(transport, Path("/unneeded"), ()), ("absent", None))
        transport.run.assert_not_called()

    def test_cuda_version_ignores_copyright_years(self) -> None:
        output = b"Copyright (c) 2005-2025 NVIDIA\nCuda compilation tools, release 12.8, V12.8.93\n"
        self.assertEqual(doctor_module._version("nvcc", output), "12.8")
        self.assertEqual(doctor_module._version("cuobjdump", output), "12.8")

    def test_remote_doctor_extension_registers_with_complete_helper_source(self) -> None:
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module._SOURCE_EXTENSION + doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        self.assertIs(namespace["ACTIONS"]["target_doctor"], namespace["target_doctor"])  # type: ignore[index]
        self.assertTrue(callable(namespace["_doctor_cmd"]))  # type: ignore[index]
        self.assertEqual(namespace["_doctor_version"]("nvcc", b"Copyright 2005-2025\nCuda compilation tools, release 12.8, V12.8.93\n"), "12.8")  # type: ignore[index,operator]

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

    def test_remote_build_extension_registers_with_complete_helper_source(self) -> None:
        extension_source = (
            build_module._SOURCE_EXTENSION
            + build_module.REMOTE_REDACTION_EXTENSION
            + build_module.REMOTE_BUILD_EXTENSION
        )
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(extension_source), namespace)
        self.assertIs(namespace["ACTIONS"]["target_build"], namespace["target_build"])

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

    def test_remote_result_rejects_injected_or_mismatched_identity(self) -> None:
        snapshot = SimpleNamespace(snapshot_id="a" * 64, applied_tree_hash="b" * 64)
        payload = {
            "status": "succeeded", "failure_class": None,
            "source_snapshot_id": snapshot.snapshot_id,
            "source_applied_tree_hash": snapshot.applied_tree_hash,
            "binary_sha256": "c" * 64, "command": "make-cuda-spark",
            "version": "1.2.3", "binary_size": 10, "sass": "verified",
            "build_log_sha256": "d" * 64, "exit_code": 0, "duration_ns": 1,
        }
        payload["build_id"] = build_module._build_id(snapshot, payload["binary_sha256"], payload["version"], payload["binary_size"])
        self.assertEqual(build_module._remote_result(payload, snapshot).build_id, payload["build_id"])
        for key, value in (("command", "/private/target-controlled-command"), ("source_snapshot_id", "e" * 64)):
            invalid = dict(payload)
            invalid[key] = value
            with self.assertRaisesRegex(TargetError, "build_command_failed"):
                build_module._remote_result(invalid, snapshot)

    def test_local_build_refuses_uncompleted_lifecycle_before_make(self) -> None:
        snapshot = SimpleNamespace(snapshot_id="a" * 64, applied_tree_hash="b" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            run_dir.mkdir(mode=0o700)
            state = {
                "schema_version": 1, "run_id": "run-aaaaaaaaaaaaaaaaaaaaaaaa", "state": "failed_startup",
                "source_snapshot_id": "1" * 64, "applied_tree_hash": "2" * 64,
                "build_id": "3" * 64, "binary_sha256": "4" * 64, "port": 8000,
                "launch_profile": {"schema_version": 1, "accelerator": "cuda", "context_tokens": 32768, "bind": "loopback", "continuation_mtp_mode": 2, "dspark_enabled": True, "drafter_enabled": True},
                "supervisor_pid": None, "supervisor_start_ticks": None, "supervisor_cmdline_sha256": None,
                "child_pid": None, "child_start_ticks": None, "child_pgid": None, "child_cmdline_sha256": None,
                "listener_inode": None, "cleanup_complete": False, "cleanup": None,
            }
            (run_dir / "run.json").write_text(json.dumps(state), encoding="ascii")
            os.chmod(run_dir / "run.json", 0o600)
            transport = mock.Mock()
            config = SimpleNamespace(source_root=temporary, local_run_dir=run_dir)
            with self.assertRaisesRegex(TargetError, "build_running"):
                build_module._build_local(config, transport, snapshot, jobs=1)
            transport.run.assert_not_called()
            self.assertFalse((run_dir / "build.log").exists())

    def test_remote_post_build_capture_is_process_group_bounded(self) -> None:
        namespace: dict[str, object] = {"HelperError": Exception, "_fail": lambda code: (_ for _ in ()).throw(TargetError(code))}
        extension = build_module.REMOTE_REDACTION_EXTENSION + build_module.REMOTE_BUILD_EXTENSION.split("@register_action('target_build')", 1)[0]
        exec(extension, namespace)
        code, stdout, stderr, timed_out, oversize = namespace["_build_capture"]((sys.executable, "-c", "import sys; sys.stdout.write('x' * 65536)"), 10, 32)  # type: ignore[operator]
        self.assertTrue(oversize)
        self.assertFalse(timed_out)
        self.assertLessEqual(len(stdout), 32)
        self.assertLessEqual(len(stderr), 32)
        self.assertIsInstance(code, int)
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "descendant.pid"
            started = time.monotonic()
            code, stdout, stderr, timed_out, oversize = namespace["_build_capture"](self._leader_exits_while_descendant_holds_pipes(pid_path), 0.05, 32)  # type: ignore[operator]
            elapsed = time.monotonic() - started
            descendant = int(pid_path.read_text(encoding="ascii"))
            try:
                self.assertLess(elapsed, 2)
                self.assertTrue(timed_out)
                self.assertFalse(oversize)
                self.assertLessEqual(len(stdout), 32)
                self.assertLessEqual(len(stderr), 32)
                self.assertIsInstance(code, int)
                self.assert_process_not_running(descendant)
            finally:
                try:
                    os.kill(descendant, 9)
                except ProcessLookupError:
                    pass


    def test_dirty_snapshot_is_rejected_before_local_nix_work(self) -> None:
        snapshot = SourceSnapshot((), (), True, "a" * 64, "b" * 64)
        config = SimpleNamespace(validate_for=mock.Mock(), mode="local")
        with mock.patch.object(doctor_module, "_local_doctor") as local_doctor, mock.patch.object(doctor_module, "_nix_identity") as nix:
            result = doctor_module.doctor(config, mock.Mock(), snapshot=snapshot, runtime=RuntimeInput("/model", "/draft", 1))
        self.assertEqual(result.failure_class, "preflight")
        local_doctor.assert_not_called()
        nix.assert_not_called()

    def test_ssh_doctor_uses_exact_lock_and_release_responses(self) -> None:
        snapshot = SourceSnapshot((), (), False, "a" * 64, "b" * 64)
        config = SimpleNamespace(
            validate_for=mock.Mock(),
            mode="ssh",
            source_root="/source",
            name="target",
            run_dir="/run",
            model_path="/model",
            drafter_path="/draft",
        )
        transport = mock.Mock(spec=doctor_module.SSHTransport)
        lock_token = "c" * 64
        transport.run_helper.side_effect = [
            {"lock_token": lock_token, "reclaimed": False, "stale_receiver_pairs_cleaned": 0, "stale_lock_stages_cleaned": 0},
            {},
            {"released": True},
        ]
        expected = DoctorResult("succeeded", None, "Linux", "6.1", "aarch64", tuple((name, "1.0", path) for name, path in DOCTOR_TOOLS), ("GB10", "sm_121"), 1, 1, True, "d" * 64, "e" * 64)
        with mock.patch.object(doctor_module, "_load_capabilities", return_value={"run_token": "f" * 64}), mock.patch.object(doctor_module, "_remote_payload", return_value={"entries": []}), mock.patch.object(doctor_module, "_validate_result_payload", return_value=expected):
            result = doctor_module.doctor(config, transport, snapshot=snapshot)
        self.assertIs(result, expected)
        acquire, _, release = transport.run_helper.call_args_list
        self.assertEqual(acquire.args[0], "acquire_lock")
        self.assertEqual(acquire.args[1], {"run_dir": "/run", "run_token": "f" * 64, "lease_seconds": doctor_module.DOCTOR_LOCK_LEASE_SECONDS})
        self.assertEqual(release.args[0], "release_lock")
        self.assertEqual(release.args[1], {"run_dir": "/run", "run_token": "f" * 64, "lock_token": lock_token})

    def test_remote_source_state_mismatch_is_rejected(self) -> None:
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        with tempfile.TemporaryDirectory() as temporary:
            source_state = Path(temporary) / "source.json"
            source_state.write_text(json.dumps({"schema_version": 1, "snapshot_id": "a" * 64, "applied_tree_hash": "b" * 64, "dirty": False}), encoding="ascii")
            os.chmod(source_state, 0o600)
            fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(namespace["HelperError"]):  # type: ignore[arg-type,index]
                    namespace["_doctor_source_state"](fd, {"snapshot_id": "c" * 64, "applied_tree_hash": "b" * 64, "dirty": False})  # type: ignore[index,operator]
            finally:
                os.close(fd)

    def test_remote_nix_uses_inherited_pinned_work_descriptor(self) -> None:
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "flake.nix").write_text("{}\n", encoding="ascii")
            fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            calls: list[tuple[tuple[str, ...], tuple[int, ...]]] = []
            real_stat = os.stat
            nix_path = "/nix/var/nix/profiles/default/bin/nix"

            def stat_path(path: object, *args: object, **kwargs: object) -> os.stat_result | SimpleNamespace:
                if path == nix_path:
                    return SimpleNamespace(st_mode=0o100100, st_uid=os.geteuid())
                return real_stat(path, *args, **kwargs)  # type: ignore[arg-type]

            def doctor_cmd(argv: tuple[str, ...], timeout: float = 5, pass_fds: tuple[int, ...] = ()) -> bytes:
                calls.append((argv, pass_fds))
                if argv[-1] == "--version":
                    return b"nix (Nix) 2.28.5\n"
                name = argv[-1]
                path = dict(doctor_module._NIX_COMPARE_TOOLS)[name]
                detail = f"Cuda compilation tools, release 1.0, V1.0.0\n" if name == "nvcc" else f"{name} 1.0\n"
                return f"TARGETCTL_PATH={path}\n{detail}".encode("ascii")

            try:
                with mock.patch.object(os, "stat", side_effect=stat_path):
                    namespace["_doctor_cmd"] = doctor_cmd
                    tools = [{"name": name, "version": "1.0", "location": path} for name, path in DOCTOR_TOOLS]
                    self.assertEqual(namespace["_doctor_nix"](tools, fd)["status"], "matched")  # type: ignore[index,operator]
            finally:
                os.close(fd)
        develops = [call for call in calls if "develop" in call[0]]
        self.assertEqual(len(develops), 3)
        self.assertTrue(all(any(argument.startswith("path:/proc/self/fd/") for argument in call[0]) for call in develops))
        self.assertTrue(all(call[1] == (fd,) for call in develops))

    def test_remote_command_capture_bounds_oversize_and_timeout(self) -> None:
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        error = namespace["HelperError"]  # type: ignore[index]
        with self.assertRaises(error):  # type: ignore[arg-type]
            namespace["_doctor_cmd"]((sys.executable, "-c", "import sys;sys.stdout.write('x'*20000)"), 5)  # type: ignore[index,operator]
        started = time.monotonic()
        with self.assertRaises(error):  # type: ignore[arg-type]
            namespace["_doctor_cmd"]((sys.executable, "-c", "import time;time.sleep(60)"), 0.05)  # type: ignore[index,operator]
        self.assertLess(time.monotonic() - started, 3)
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "descendant.pid"
            started = time.monotonic()
            with self.assertRaises(error):  # type: ignore[arg-type]
                namespace["_doctor_cmd"](self._leader_exits_while_descendant_holds_pipes(pid_path), 0.05)  # type: ignore[index,operator]
            elapsed = time.monotonic() - started
            descendant = int(pid_path.read_text(encoding="ascii"))
            try:
                self.assertLess(elapsed, 2)
                self.assert_process_not_running(descendant)
            finally:
                try:
                    os.kill(descendant, 9)
                except ProcessLookupError:
                    pass