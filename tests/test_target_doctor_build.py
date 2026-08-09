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
    @staticmethod
    def _successful_remote_payload(snapshot: SourceSnapshot) -> dict[str, object]:
        binary_hash = "c" * 64
        version = "1.2.3"
        size = 10
        return {
            "status": "succeeded",
            "failure_class": None,
            "source_snapshot_id": snapshot.snapshot_id,
            "source_applied_tree_hash": snapshot.applied_tree_hash,
            "build_id": build_module._build_id(snapshot, binary_hash, version, size),
            "binary_sha256": binary_hash,
            "command": "make-cuda-spark",
            "version": version,
            "binary_size": size,
            "sass": "verified",
            "build_log_sha256": "d" * 64,
            "exit_code": 0,
            "duration_ns": 17,
        }

    @staticmethod
    def _reconciliation_payload(
        result: dict[str, object],
        attempt_id: str,
        *,
        lease_state: str = "released",
    ) -> dict[str, object]:
        report = {
            "schema_version": 1,
            "record_type": "build-attempt",
            "attempt_id": attempt_id,
            **result,
        }
        encoded = json.dumps(
            report, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
        return {
            "report": report,
            "report_sha256": hashlib.sha256(encoded).hexdigest(),
            "build_log_sha256": result["build_log_sha256"],
            "lease_state": lease_state,
        }

    @staticmethod
    def _remote_build_config() -> SimpleNamespace:
        return SimpleNamespace(
            validate_for=mock.Mock(),
            mode="ssh",
            source_root="/controller/source",
            name="spark",
            run_dir="/target/run",
        )

    def _call_remote_build(
        self,
        snapshot: SourceSnapshot,
        side_effect: list[object],
        attempt_id: str,
    ) -> tuple[BuildResult, mock.Mock]:
        transport = mock.Mock(spec=build_module.SSHTransport)
        transport.run_helper.side_effect = side_effect
        state = {"run_token": "f" * 64}
        with (
            mock.patch.object(build_module, "_validate_snapshot", return_value=snapshot),
            mock.patch.object(build_module, "_load_capabilities", return_value=state),
            mock.patch.object(build_module, "_remote_payload", return_value={"entries": []}),
            mock.patch.object(build_module, "_expect_root_identities"),
            mock.patch.object(build_module.secrets, "token_hex", return_value=attempt_id),
        ):
            result = build_module.build(
                self._remote_build_config(), transport, snapshot=snapshot, jobs=1,
            )
        return result, transport

    @staticmethod
    def _remote_action_fixture(
        root: Path,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(
            helper_source(
                build_module._SOURCE_EXTENSION
                + build_module.REMOTE_REDACTION_EXTENSION
                + build_module.REMOTE_BUILD_EXTENSION
            ),
            namespace,
        )
        model = root / "models" / "model.gguf"
        drafter = root / "models" / "draft.gguf"
        model.parent.mkdir(parents=True)
        model.write_bytes(b"model")
        drafter.write_bytes(b"draft")
        roots = {
            "workdir": str(root / "work"),
            "run_dir": str(root / "run"),
            "model_path": str(model),
            "drafter_path": str(drafter),
        }
        initialized = namespace["initialize_roots"](roots)  # type: ignore[index,operator]
        applied_hash = namespace["_frame_hash"]([])  # type: ignore[index,operator]
        payload = {
            **roots,
            "work_token": initialized["work"]["token"],  # type: ignore[index]
            "run_token": initialized["run"]["token"],  # type: ignore[index]
            "entries": [],
            "snapshot_id": "a" * 64,
            "applied_tree_hash": applied_hash,
            "dirty": False,
            "allow_dirty": None,
            "jobs": 1,
            "attempt_id": "e" * 64,
        }
        lock = namespace["acquire_lock"]({  # type: ignore[index,operator]
            "run_dir": roots["run_dir"],
            "run_token": payload["run_token"],
            "lease_seconds": build_module.BUILD_LOCK_LEASE_SECONDS,
        })
        payload["lock_token"] = lock["lock_token"]
        return namespace, payload, roots

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

    def test_nix_identity_matches_resolved_native_alias_paths_and_versions(self) -> None:
        versions = {"nvcc": "12.8", "gcc": "14.2", "g++": "14.2"}
        canonical = {
            "nvcc": "/usr/local/cuda/bin/nvcc",
            "gcc": "/usr/bin/gcc-14",
            "g++": "/usr/bin/g++-14",
        }
        tools = tuple(
            (name, versions.get(name, "1.0"), canonical.get(name, alias))
            for name, alias in DOCTOR_TOOLS
        )
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            (workdir / "flake.nix").write_text("{}\n", encoding="ascii")
            transport = mock.Mock()

            def run(argv: tuple[str, ...], **_: object) -> CommandResult:
                if argv == ("/nix/store/test/bin/nix", "--version"):
                    return CommandResult(0, False, 1, b"nix (Nix) 2.28.5\n", b"")
                name = argv[-1]
                detail = f"Copyright 2005-2025\nCuda compilation tools, release {versions[name]}, V{versions[name]}.1" if name == "nvcc" else f"{name} {versions[name]}"
                return CommandResult(0, False, 1, f"TARGETCTL_PATH={canonical[name]}\n{detail}\n".encode("ascii"), b"")

            transport.run.side_effect = run
            with mock.patch.object(doctor_module, "_find_nix", return_value="/nix/store/test/bin/nix"):
                self.assertEqual(doctor_module._nix_identity(transport, workdir, tools), ("matched", "2.28.5"))
        self.assertEqual(transport.run.call_count, 4)
        self.assertEqual(
            [call.args[0][-1] for call in transport.run.call_args_list[1:]],
            ["nvcc", "gcc", "g++"],
        )
        for call in transport.run.call_args_list:
            self.assertEqual(call.kwargs["env"]["PATH"], "/usr/local/cuda/bin:/usr/bin:/bin")

    def test_nix_identity_fails_on_tool_resolution_drift(self) -> None:
        versions = {"nvcc": "12.8", "gcc": "14.2", "g++": "14.2"}
        canonical = {
            "nvcc": "/usr/local/cuda/bin/nvcc",
            "gcc": "/usr/bin/gcc-14",
            "g++": "/usr/bin/g++-14",
        }
        tools = tuple(
            (name, versions.get(name, "1.0"), canonical.get(name, alias))
            for name, alias in DOCTOR_TOOLS
        )
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            (workdir / "flake.nix").write_text("{}\n", encoding="ascii")
            transport = mock.Mock()

            def run(argv: tuple[str, ...], **_: object) -> CommandResult:
                if argv[-1] == "--version":
                    return CommandResult(0, False, 1, b"nix (Nix) 2.28.5\n", b"")
                name = argv[-1]
                location = "/nix/store/compiler/bin/gcc" if name == "gcc" else canonical[name]
                detail = f"Copyright 2005-2025\nCuda compilation tools, release {versions[name]}, V{versions[name]}.1" if name == "nvcc" else f"{name} {versions[name]}"
                return CommandResult(0, False, 1, f"TARGETCTL_PATH={location}\n{detail}\n".encode("ascii"), b"")

            transport.run.side_effect = run
            with mock.patch.object(doctor_module, "_find_nix", return_value="/nix/store/test/bin/nix"):
                with self.assertRaises(TargetError) as raised:
                    doctor_module._nix_identity(transport, workdir, tools)
        self.assertEqual(raised.exception.code, "doctor_nix_mismatch")

    def test_nix_identity_rejects_missing_or_duplicate_compared_tool(self) -> None:
        versions = {"nvcc": "12.8", "gcc": "14.2", "g++": "14.2"}
        canonical = {
            "nvcc": "/usr/local/cuda/bin/nvcc",
            "gcc": "/usr/bin/gcc-14",
            "g++": "/usr/bin/g++-14",
        }
        tools = tuple(
            (name, versions.get(name, "1.0"), canonical.get(name, alias))
            for name, alias in DOCTOR_TOOLS
        )
        missing = tuple(tool for tool in tools if tool[0] != "g++")
        duplicate = tools + (next(tool for tool in tools if tool[0] == "gcc"),)
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            (workdir / "flake.nix").write_text("{}\n", encoding="ascii")
            with mock.patch.object(doctor_module, "_find_nix", return_value="/nix/store/test/bin/nix"):
                for label, invalid_tools in (("missing", missing), ("duplicate", duplicate)):
                    with self.subTest(label=label):
                        transport = mock.Mock()
                        transport.run.return_value = CommandResult(
                            0, False, 1, b"nix (Nix) 2.28.5\n", b"",
                        )
                        with self.assertRaises(TargetError) as raised:
                            doctor_module._nix_identity(transport, workdir, invalid_tools)
                        self.assertEqual(raised.exception.code, "doctor_nix_mismatch")
                        self.assertEqual(transport.run.call_count, 1)

    def test_nix_identity_records_absence_without_running_a_command(self) -> None:
        transport = mock.Mock()
        with mock.patch.object(doctor_module, "_find_nix", return_value=None):
            self.assertEqual(doctor_module._nix_identity(transport, Path("/unneeded"), ()), ("absent", None))
        transport.run.assert_not_called()

    def test_cuda_version_ignores_copyright_years(self) -> None:
        output = b"Copyright (c) 2005-2025 NVIDIA\nCuda compilation tools, release 12.8, V12.8.93\n"
        self.assertEqual(doctor_module._version("nvcc", output), "12.8")
        self.assertEqual(doctor_module._version("cuobjdump", output), "12.8")

    def test_time_sync_file_success_skips_timedatectl_local_and_embedded(self) -> None:
        local_capture = mock.Mock()
        with (
            mock.patch.object(Path, "read_bytes", return_value=b"yes\n"),
            mock.patch.object(doctor_module, "_pinned_tool_capture", local_capture),
        ):
            self.assertTrue(doctor_module._time_synchronized())
        local_capture.assert_not_called()

        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        embedded_capture = mock.Mock()
        namespace["open"] = mock.mock_open(read_data=b"yes\n")
        namespace["_doctor_pinned"] = embedded_capture
        self.assertTrue(namespace["_doctor_time_synchronized"]())  # type: ignore[index,operator]
        embedded_capture.assert_not_called()

    def test_time_sync_uses_exact_pinned_timedatectl_fallback_local_and_embedded(self) -> None:
        local_capture = mock.Mock(return_value=(b"yes\n", "/usr/bin/timedatectl"))
        with (
            mock.patch.object(Path, "read_bytes", return_value=b"no\n"),
            mock.patch.object(doctor_module, "_pinned_tool_capture", local_capture),
        ):
            self.assertTrue(doctor_module._time_synchronized())
        local_capture.assert_called_once_with(
            "/usr/bin/timedatectl",
            ("show", "--property=NTPSynchronized", "--value"),
        )

        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        embedded_capture = mock.Mock(return_value=(b"yes\n", "/usr/bin/timedatectl"))
        namespace["open"] = mock.mock_open(read_data=b"no\n")
        namespace["_doctor_pinned"] = embedded_capture
        self.assertTrue(namespace["_doctor_time_synchronized"]())  # type: ignore[index,operator]
        embedded_capture.assert_called_once_with(
            "/usr/bin/timedatectl",
            ("show", "--property=NTPSynchronized", "--value"),
        )

    def test_time_sync_rejects_no_or_ambiguous_records_local_and_embedded(self) -> None:
        for output in (b"", b"no\n", b"yes \n", b"yes\r\n", b"yes\nno\n", b"\xff\n"):
            with self.subTest(output=output):
                with (
                    mock.patch.object(Path, "read_bytes", side_effect=FileNotFoundError),
                    mock.patch.object(
                        doctor_module,
                        "_pinned_tool_capture",
                        return_value=(output, "/usr/bin/timedatectl"),
                    ),
                    self.assertRaises(TargetError) as local,
                ):
                    doctor_module._time_synchronized()
                self.assertEqual(local.exception.code, "doctor_time_unsynchronized")

                namespace: dict[str, object] = {"__name__": "targetctl_helper"}
                exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
                namespace["open"] = mock.Mock(side_effect=FileNotFoundError)
                namespace["_doctor_pinned"] = mock.Mock(
                    return_value=(output, "/usr/bin/timedatectl"),
                )
                with self.assertRaises(namespace["HelperError"]) as embedded:  # type: ignore[arg-type,index]
                    namespace["_doctor_time_synchronized"]()  # type: ignore[index,operator]
                self.assertEqual(embedded.exception.code, "doctor_time_unsynchronized")

    def test_time_sync_preserves_safe_tool_timeout_and_missing_failures(self) -> None:
        for code in ("doctor_command_timeout", "doctor_tool_missing"):
            with self.subTest(code=code):
                with (
                    mock.patch.object(Path, "read_bytes", side_effect=FileNotFoundError),
                    mock.patch.object(
                        doctor_module,
                        "_pinned_tool_capture",
                        side_effect=TargetError(code, "target doctor failed"),
                    ),
                    self.assertRaises(TargetError) as local,
                ):
                    doctor_module._time_synchronized()
                self.assertEqual(local.exception.code, code)

                namespace: dict[str, object] = {"__name__": "targetctl_helper"}
                exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
                namespace["open"] = mock.Mock(side_effect=FileNotFoundError)
                namespace["_doctor_pinned"] = mock.Mock(
                    side_effect=lambda *_: namespace["_fail"](code),  # type: ignore[index,operator]
                )
                with self.assertRaises(namespace["HelperError"]) as embedded:  # type: ignore[arg-type,index]
                    namespace["_doctor_time_synchronized"]()  # type: ignore[index,operator]
                self.assertEqual(embedded.exception.code, code)

    def test_time_sync_rejects_timedatectl_symlink_chain_swap_local_and_embedded(self) -> None:
        resolved = os.path.realpath("/usr/bin/python3")
        identity = doctor_module._tool_identity(os.stat(resolved, follow_symlinks=False))
        original_chain = (("/usr/bin/timedatectl", identity),)
        replaced_chain = (("/usr/bin/timedatectl", (*identity[:-1], identity[-1] + 1)),)

        local_first_fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC)
        local_second_fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC)
        with (
            mock.patch.object(Path, "read_bytes", return_value=b"no\n"),
            mock.patch.object(
                doctor_module,
                "_open_tool_alias",
                side_effect=(
                    (resolved, local_first_fd, identity, original_chain),
                    (resolved, local_second_fd, identity, replaced_chain),
                ),
            ),
            mock.patch.object(doctor_module, "_pinned_tool_output", return_value=b"yes\n"),
            self.assertRaises(TargetError) as local,
        ):
            doctor_module._time_synchronized()
        self.assertEqual(local.exception.code, "doctor_tool_missing")

        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        embedded_first_fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC)
        embedded_second_fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC)
        embedded_identity = namespace["_doctor_tool_identity"](os.fstat(embedded_first_fd))  # type: ignore[index,operator]
        namespace["open"] = mock.mock_open(read_data=b"no\n")
        namespace["_doctor_open_tool"] = mock.Mock(side_effect=(
            (resolved, embedded_first_fd, embedded_identity, original_chain),
            (resolved, embedded_second_fd, embedded_identity, replaced_chain),
        ))
        namespace["_doctor_cmd"] = mock.Mock(return_value=b"yes\n")
        with self.assertRaises(namespace["HelperError"]) as embedded:  # type: ignore[arg-type,index]
            namespace["_doctor_time_synchronized"]()  # type: ignore[index,operator]
        self.assertEqual(embedded.exception.code, "doctor_tool_missing")

    def test_embedded_doctor_action_gates_time_sync_before_weight_hashing(self) -> None:
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(
            helper_source(
                doctor_module._SOURCE_EXTENSION + doctor_module.REMOTE_DOCTOR_EXTENSION
            ),
            namespace,
        )
        payload = {
            "model_path": "/target/models/model.gguf",
            "drafter_path": "/target/models/drafter.gguf",
            "run_dir": "/target/run",
            "workdir": "/target/work",
            "work_token": "a" * 64,
            "run_token": "b" * 64,
            "entries": [],
            "snapshot_id": "c" * 64,
            "applied_tree_hash": "d" * 64,
            "dirty": False,
            "allow_dirty": None,
            "lock_token": "e" * 64,
        }

        def command(argv: tuple[str, ...], *_: object, **__: object) -> bytes:
            if "--query-gpu=name,compute_cap" in argv:
                return b"NVIDIA GB10, 12.1\n"
            return b""

        namespace["_source_roots"] = mock.Mock(return_value=(None, {"root": "pinned"}))
        namespace["_doctor_bound_source"] = mock.Mock()
        namespace["_doctor_tool"] = mock.Mock(
            side_effect=lambda name, location: {
                "name": name,
                "version": "1.0",
                "location": location,
            },
        )
        namespace["_doctor_cmd"] = mock.Mock(side_effect=command)
        namespace["_doctor_nix"] = mock.Mock(
            return_value={"status": "absent", "version": None},
        )

        cases = (
            ("false", False, False),
            ("truthy_non_boolean", 1, False),
            ("true", True, True),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for label, synchronized, succeeds in cases:
                with self.subTest(label=label):
                    work_fd = os.open(
                        temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                    )
                    run_fd = os.open(
                        temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                    )
                    namespace["_source_open"] = mock.Mock(
                        return_value=(work_fd, run_fd, {"work": 1}, {"run": 1}),
                    )
                    sync = mock.Mock(return_value=synchronized)
                    hashes = mock.Mock(side_effect=("f" * 64, "0" * 64))
                    output = mock.Mock()
                    namespace["_doctor_time_synchronized"] = sync
                    namespace["_doctor_hash"] = hashes
                    namespace["sys"] = SimpleNamespace(
                        stdout=SimpleNamespace(buffer=output),
                    )
                    request = json.dumps(
                        {
                            "protocol_version": namespace["PROTOCOL_VERSION"],
                            "action": "target_doctor",
                            "payload": payload,
                        },
                    ).encode("utf-8")

                    namespace["run"](request)  # type: ignore[index,operator]

                    output.write.assert_called_once()
                    response = json.loads(output.write.call_args.args[0])
                    sync.assert_called_once_with()
                    self.assertIs(response["ok"], succeeds)
                    if succeeds:
                        self.assertEqual(response["result"]["status"], "succeeded")
                        self.assertIs(response["result"]["time_sync"], True)
                        self.assertEqual(
                            hashes.call_args_list,
                            [
                                mock.call(payload["model_path"]),
                                mock.call(payload["drafter_path"]),
                            ],
                        )
                    else:
                        self.assertEqual(
                            response["error"]["code"],
                            "doctor_time_unsynchronized",
                        )
                        self.assertNotIn("result", response)
                        hashes.assert_not_called()

    def test_local_pinned_capture_bounds_arbitrary_fixed_argv(self) -> None:
        python = dict(DOCTOR_TOOLS)["python3"]
        with (
            mock.patch.object(doctor_module, "MAX_COMMAND_OUTPUT_BYTES", 32),
            self.assertRaises(TargetError) as oversized,
        ):
            doctor_module._pinned_tool_capture(
                python,
                ("-c", "import sys;sys.stdout.write('x'*128)"),
            )
        self.assertEqual(oversized.exception.code, "doctor_command_failed")

        started = time.monotonic()
        with (
            mock.patch.object(doctor_module, "COMMAND_TIMEOUT_SECONDS", 0.05),
            self.assertRaises(TargetError) as timed_out,
        ):
            doctor_module._pinned_tool_capture(
                python,
                ("-c", "import time;time.sleep(60)"),
            )
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(timed_out.exception.code, "doctor_command_timeout")

    def test_remote_doctor_extension_registers_with_complete_helper_source(self) -> None:
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module._SOURCE_EXTENSION + doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        self.assertIs(namespace["ACTIONS"]["target_doctor"], namespace["target_doctor"])  # type: ignore[index]
        self.assertTrue(callable(namespace["_doctor_cmd"]))  # type: ignore[index]
        self.assertEqual(namespace["_doctor_version"]("nvcc", b"Copyright 2005-2025\nCuda compilation tools, release 12.8, V12.8.93\n"), "12.8")  # type: ignore[index,operator]

    def test_embedded_nix_identity_matches_controller_resolved_path_rules(self) -> None:
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        versions = {"nvcc": "12.8", "gcc": "14.2", "g++": "14.2"}
        canonical = {
            "nvcc": "/usr/local/cuda/bin/nvcc",
            "gcc": "/usr/bin/gcc-14",
            "g++": "/usr/bin/g++-14",
        }
        tools = [
            {
                "name": name,
                "version": versions.get(name, "1.0"),
                "location": canonical.get(name, alias),
            }
            for name, alias in DOCTOR_TOOLS
        ]
        probe_locations = dict(canonical)
        nix_path = os.path.realpath(sys.executable)
        real_realpath = os.path.realpath

        def resolve_nix(candidate: str) -> str:
            if candidate == "/nix/var/nix/profiles/default/bin/nix":
                return nix_path
            return real_realpath(candidate)

        def run(argv: tuple[str, ...], *_: object, **__: object) -> bytes:
            if argv == (nix_path, "--version"):
                return b"nix (Nix) 2.28.5\n"
            name = argv[-1]
            detail = f"Copyright 2005-2025\nCuda compilation tools, release {versions[name]}, V{versions[name]}.1" if name == "nvcc" else f"{name} {versions[name]}"
            return f"TARGETCTL_PATH={probe_locations[name]}\n{detail}\n".encode("ascii")

        namespace["_doctor_cmd"] = mock.Mock(side_effect=run)
        helper_error = namespace["HelperError"]
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            (workdir / "flake.nix").write_text("{}\n", encoding="ascii")
            work_fd = os.open(workdir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                with mock.patch.object(os.path, "realpath", side_effect=resolve_nix):
                    self.assertEqual(
                        namespace["_doctor_nix"](tools, work_fd),  # type: ignore[index,operator]
                        {"status": "matched", "version": "2.28.5"},
                    )
                    probe_locations["gcc"] = "/nix/store/compiler/bin/gcc"
                    with self.assertRaises(helper_error) as drift:  # type: ignore[arg-type]
                        namespace["_doctor_nix"](tools, work_fd)  # type: ignore[index,operator]
                    self.assertEqual(drift.exception.code, "doctor_nix_mismatch")
                    probe_locations["gcc"] = canonical["gcc"]
                    missing = [tool for tool in tools if tool["name"] != "g++"]
                    duplicate = tools + [next(tool for tool in tools if tool["name"] == "gcc")]
                    for label, invalid_tools in (("missing", missing), ("duplicate", duplicate)):
                        with self.subTest(label=label):
                            with self.assertRaises(helper_error) as invalid:  # type: ignore[arg-type]
                                namespace["_doctor_nix"](invalid_tools, work_fd)  # type: ignore[index,operator]
                            self.assertEqual(invalid.exception.code, "doctor_nix_mismatch")
            finally:
                os.close(work_fd)

    def test_standard_system_tool_symlinks_resolve_to_pinned_public_locations(self) -> None:
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        aliases = dict(DOCTOR_TOOLS)
        available = tuple(name for name in ("gcc", "g++", "python3") if os.path.lexists(aliases[name]))
        self.assertTrue(available)
        for name in available:
            alias = aliases[name]
            with self.subTest(name=name):
                expected = os.path.realpath(alias)
                controller_version, controller_location = doctor_module._tool_version(name, alias)
                embedded = namespace["_doctor_tool"](name, alias)  # type: ignore[index,operator]
                self.assertRegex(controller_version, r"[0-9]+(?:\.[0-9]+){0,3}\Z")
                self.assertEqual(controller_location, expected)
                self.assertEqual(embedded["location"], expected)  # type: ignore[index]
                self.assertRegex(embedded["version"], r"[0-9]+(?:\.[0-9]+){0,3}\Z")  # type: ignore[index]
                self.assertRegex(expected, r"/(?:usr|nix/store)/[A-Za-z0-9._+@=/:-]+\Z")

    def test_tool_alias_identity_swap_is_rejected_after_version_capture(self) -> None:
        resolved = os.path.realpath("/usr/bin/gcc")
        first_fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC)
        second_fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC)
        identity = doctor_module._tool_identity(os.fstat(first_fd))
        original_chain = (("/usr/bin/gcc", identity),)
        replaced_chain = (("/usr/bin/gcc", (*identity[:-1], identity[-1] + 1)),)
        with (
            mock.patch.object(
                doctor_module,
                "_open_tool_alias",
                side_effect=(
                    (resolved, first_fd, identity, original_chain),
                    (resolved, second_fd, identity, replaced_chain),
                ),
            ),
            mock.patch.object(doctor_module, "_pinned_tool_output", return_value=b"gcc 14.2\n"),
            self.assertRaises(TargetError) as raised,
        ):
            doctor_module._tool_version("gcc", "/usr/bin/gcc")
        self.assertEqual(raised.exception.code, "doctor_tool_missing")
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        embedded_first_fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC)
        embedded_second_fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC)
        embedded_identity = namespace["_doctor_tool_identity"](os.fstat(embedded_first_fd))  # type: ignore[index,operator]
        namespace["_doctor_open_tool"] = mock.Mock(side_effect=(
            (resolved, embedded_first_fd, embedded_identity, original_chain),
            (resolved, embedded_second_fd, embedded_identity, replaced_chain),
        ))
        namespace["_doctor_cmd"] = mock.Mock(return_value=b"gcc 14.2\n")
        with self.assertRaises(namespace["HelperError"]) as embedded_raised:  # type: ignore[arg-type,index]
            namespace["_doctor_tool"]("gcc", "/usr/bin/gcc")  # type: ignore[index,operator]
        self.assertEqual(embedded_raised.exception.code, "doctor_tool_missing")

    def test_unsafe_tool_symlink_target_is_rejected_without_path_disclosure(self) -> None:
        namespace: dict[str, object] = {"__name__": "targetctl_helper"}
        exec(helper_source(doctor_module.REMOTE_DOCTOR_EXTENSION), namespace)
        real_lstat = os.lstat
        alias_item = real_lstat("/usr/bin/gcc")
        fake_link = SimpleNamespace(
            st_dev=alias_item.st_dev,
            st_ino=alias_item.st_ino,
            st_mode=0o120777,
            st_uid=os.geteuid(),
            st_gid=alias_item.st_gid,
            st_size=11,
            st_mtime_ns=alias_item.st_mtime_ns,
            st_ctime_ns=alias_item.st_ctime_ns,
        )

        def lstat(path: object, *args: object, **kwargs: object) -> object:
            if path == "/usr/bin/gcc":
                return fake_link
            return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

        with (
            mock.patch.object(os, "lstat", side_effect=lstat),
            mock.patch.object(os, "readlink", return_value="/tmp/targetctl-unsafe-tool"),
        ):
            with self.assertRaises(TargetError) as controller:
                doctor_module._open_tool_alias("/usr/bin/gcc")
            with self.assertRaises(namespace["HelperError"]) as embedded:  # type: ignore[arg-type,index]
                namespace["_doctor_open_tool"]("/usr/bin/gcc")  # type: ignore[index,operator]
        self.assertEqual(controller.exception.code, "doctor_tool_missing")
        self.assertEqual(embedded.exception.code, "doctor_tool_missing")
        self.assertNotIn("tmp", str(controller.exception))
        self.assertNotIn("tmp", str(embedded.exception))

    def test_doctor_response_accepts_only_canonical_public_tool_locations(self) -> None:
        locations = dict(DOCTOR_TOOLS)
        locations.update({
            "gcc": "/usr/bin/gcc-14",
            "g++": "/usr/bin/g++-14",
            "python3": "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-python3/bin/python3.13",
        })
        result = DoctorResult(
            "succeeded", None, "Linux", "6.12.0", "aarch64",
            tuple((name, "1.2.3", locations[name]) for name, _ in DOCTOR_TOOLS),
            ("GB10", "sm_121"), 1024, 2048, True, "a" * 64, "b" * 64,
        )
        validated = doctor_module._validate_result_payload(result.controller_payload())
        self.assertEqual(dict((name, location) for name, _, location in validated.tools), locations)
        for unsafe in (
            "/tmp/gcc",
            "/home/target/bin/gcc",
            "/usr/bin/../private/gcc",
            "usr/bin/gcc",
            "/usr/bin/gcc name",
        ):
            with self.subTest(location=unsafe):
                payload = result.controller_payload()
                payload["tools"][2]["location"] = unsafe
                with self.assertRaises(TargetError) as raised:
                    doctor_module._validate_result_payload(payload)
                self.assertEqual(raised.exception.code, "doctor_response_invalid")

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

    def test_invalid_jobs_fail_before_source_verification_or_remote_calls(self) -> None:
        snapshot = SourceSnapshot((), (), False, "a" * 64, "b" * 64)
        for jobs in (0, 257, True, "1"):
            with self.subTest(jobs=jobs):
                config = self._remote_build_config()
                transport = mock.Mock(spec=build_module.SSHTransport)
                with (
                    mock.patch.object(build_module, "_validate_snapshot") as validate_snapshot,
                    mock.patch.object(build_module, "_failed", wraps=build_module._failed) as failed,
                ):
                    result = build_module.build(
                        config, transport, snapshot=snapshot, jobs=jobs,  # type: ignore[arg-type]
                    )
                failed.assert_called_once_with("build_jobs_invalid", snapshot)
                validate_snapshot.assert_not_called()
                transport.run_helper.assert_not_called()
                self.assertEqual((result.status, result.failure_class), ("failed", "preflight"))

    def test_remote_build_reuses_jobs_normalized_once(self) -> None:
        snapshot = SourceSnapshot((), (), False, "a" * 64, "b" * 64)
        attempt_id = "e" * 64
        verified = {"sha256": snapshot.applied_tree_hash, "entry_count": 0}
        lock = {
            "lock_token": "c" * 64,
            "reclaimed": False,
            "stale_receiver_pairs_cleaned": 0,
            "stale_lock_stages_cleaned": 0,
        }
        with mock.patch.object(build_module, "_jobs", wraps=build_module._jobs) as normalize:
            result, transport = self._call_remote_build(
                snapshot,
                [verified, lock, self._successful_remote_payload(snapshot)],
                attempt_id,
            )
        normalize.assert_called_once_with(1)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(transport.run_helper.call_args_list[2].args[1]["jobs"], 1)

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

    def test_remote_response_loss_reconciles_exact_success_and_failure_evidence(self) -> None:
        snapshot = SourceSnapshot((), (), False, "a" * 64, "b" * 64)
        attempt_id = "e" * 64
        verified = {"sha256": snapshot.applied_tree_hash, "entry_count": 0}
        lock = {
            "lock_token": "c" * 64,
            "reclaimed": False,
            "stale_receiver_pairs_cleaned": 0,
            "stale_lock_stages_cleaned": 0,
        }
        succeeded = self._successful_remote_payload(snapshot)
        direct, direct_transport = self._call_remote_build(
            snapshot, [verified, lock, succeeded], attempt_id,
        )
        reconciled, lost_transport = self._call_remote_build(
            snapshot,
            [
                verified,
                lock,
                TargetError("helper_execution_failed", "target helper failed"),
                self._reconciliation_payload(succeeded, attempt_id),
            ],
            attempt_id,
        )
        self.assertEqual(reconciled, direct)
        failed_payload = {
            **succeeded,
            "status": "failed",
            "failure_class": "command_failed",
            "build_id": None,
            "binary_sha256": None,
            "version": None,
            "binary_size": None,
            "sass": None,
            "exit_code": 2,
        }
        failed, _ = self._call_remote_build(
            snapshot,
            [
                verified,
                lock,
                TargetError("helper_timeout", "target helper timed out"),
                self._reconciliation_payload(failed_payload, attempt_id),
            ],
            attempt_id,
        )
        self.assertEqual(
            (failed.status, failed.failure_class, failed.exit_code, failed.build_log_sha256),
            ("failed", "command_failed", 2, succeeded["build_log_sha256"]),
        )
        for transport in (direct_transport, lost_transport):
            actions = [call.args[0] for call in transport.run_helper.call_args_list]
            self.assertNotIn("release_lock", actions)
        self.assertEqual(
            [call.args[0] for call in lost_transport.run_helper.call_args_list],
            ["source_verify", "acquire_lock", "target_build", "target_build_reconcile"],
        )

    def test_remote_release_failure_after_persistence_is_reconciled(self) -> None:
        snapshot = SourceSnapshot((), (), False, "a" * 64, "b" * 64)
        attempt_id = "e" * 64
        succeeded = self._successful_remote_payload(snapshot)
        result, transport = self._call_remote_build(
            snapshot,
            [
                {"sha256": snapshot.applied_tree_hash, "entry_count": 0},
                {
                    "lock_token": "c" * 64,
                    "reclaimed": False,
                    "stale_receiver_pairs_cleaned": 0,
                    "stale_lock_stages_cleaned": 0,
                },
                TargetError("lock_release_failed", "target lock release failed"),
                self._reconciliation_payload(
                    succeeded, attempt_id, lease_state="retained",
                ),
            ],
            attempt_id,
        )
        self.assertEqual(result.controller_payload(), succeeded)
        self.assertNotIn(
            "release_lock",
            [call.args[0] for call in transport.run_helper.call_args_list],
        )

    def test_remote_reconciliation_after_reacquisition_rejects_unusable_evidence(self) -> None:
        snapshot = SourceSnapshot((), (), False, "a" * 64, "b" * 64)
        attempt_id = "e" * 64
        verified = {"sha256": snapshot.applied_tree_hash, "entry_count": 0}
        lock = {
            "lock_token": "c" * 64,
            "reclaimed": False,
            "stale_receiver_pairs_cleaned": 0,
            "stale_lock_stages_cleaned": 0,
        }
        for name, reconciliation_code in (
            ("missing", "build_reconcile_unavailable"),
            ("malformed-or-prior", "build_reconcile_invalid"),
        ):
            with self.subTest(name=name), self.assertRaises(TargetError) as raised:
                self._call_remote_build(
                    snapshot,
                    [
                        verified,
                        lock,
                        TargetError("helper_timeout", "target helper timed out"),
                        TargetError(reconciliation_code, "target evidence is unusable"),
                    ],
                    attempt_id,
                )
            self.assertEqual(raised.exception.code, "build_reconciliation_failed")

    def test_response_loss_while_target_activity_is_unknown_retains_lease(self) -> None:
        snapshot = SourceSnapshot((), (), False, "a" * 64, "b" * 64)
        attempt_id = "e" * 64
        transport = mock.Mock(spec=build_module.SSHTransport)
        transport.run_helper.side_effect = [
            {"sha256": snapshot.applied_tree_hash, "entry_count": 0},
            {
                "lock_token": "c" * 64,
                "reclaimed": False,
                "stale_receiver_pairs_cleaned": 0,
                "stale_lock_stages_cleaned": 0,
            },
            TargetError("helper_timeout", "target helper timed out"),
            TargetError("lock_busy", "target lock is active"),
        ]
        with (
            mock.patch.object(build_module, "_validate_snapshot", return_value=snapshot),
            mock.patch.object(build_module, "_load_capabilities", return_value={"run_token": "f" * 64}),
            mock.patch.object(build_module, "_remote_payload", return_value={"entries": []}),
            mock.patch.object(build_module, "_expect_root_identities"),
            mock.patch.object(build_module.secrets, "token_hex", return_value=attempt_id),
            self.assertRaises(TargetError) as raised,
        ):
            build_module.build(
                self._remote_build_config(), transport, snapshot=snapshot, jobs=1,
            )
        self.assertEqual(raised.exception.code, "build_reconciliation_required")
        self.assertNotIn(
            "release_lock",
            [call.args[0] for call in transport.run_helper.call_args_list],
        )

    def test_owned_live_lock_retains_unusable_commit_without_strict_loading(self) -> None:
        prior_commit = json.dumps(
            {
                "schema_version": 1,
                "record_type": "build-attempt-commit",
                "attempt_id": "9" * 64,
                "attempt_report_sha256": "c" * 64,
                "attempt_log_sha256": "d" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        for name, commit_content in (
            ("missing", None),
            ("malformed", b'{"attempt_id":'),
            ("prior-attempt", prior_commit),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                namespace, payload, roots = self._remote_action_fixture(Path(temporary))
                run_dir = Path(roots["run_dir"])
                lock_path = run_dir / namespace["LOCK_NAME"]  # type: ignore[index]
                commit_path = run_dir / namespace["_build_attempt_names"](payload["attempt_id"])[2]  # type: ignore[index,operator]
                if commit_content is not None:
                    commit_path.write_bytes(commit_content)
                original_lock = lock_path.read_bytes()
                strict_loader = mock.Mock(wraps=namespace["_build_load_commit"])
                namespace["_build_load_commit"] = strict_loader
                applied_hash = mock.Mock(
                    side_effect=AssertionError("source evidence inspected before live ownership"),
                )
                namespace["_build_applied_hash"] = applied_hash

                helper_error = namespace["HelperError"]
                with self.assertRaises(helper_error) as raised:  # type: ignore[arg-type]
                    namespace["target_build_reconcile"](payload)  # type: ignore[index,operator]

                self.assertEqual(raised.exception.code, "lock_busy")
                strict_loader.assert_not_called()
                applied_hash.assert_not_called()
                self.assertEqual(lock_path.read_bytes(), original_lock)
                if commit_content is None:
                    self.assertFalse(commit_path.exists())
                else:
                    self.assertEqual(commit_path.read_bytes(), commit_content)

    def test_response_loss_with_live_second_attempt_does_not_reuse_first_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            namespace, first_payload, roots = self._remote_action_fixture(Path(temporary))
            binary_hash = "c" * 64
            namespace["_build_make"] = mock.Mock(
                return_value=(0, 17, b"sanitized build output\n", False, False, False),
            )
            namespace["_build_file_hash"] = mock.Mock(return_value=(binary_hash, 10))
            namespace["_build_capture"] = mock.Mock(side_effect=[
                (0, b"ds4-server 1.2.3\n", b"", False, False),
                (0, b"Function : sm_121\n", b"", False, False),
            ])
            first_result = namespace["target_build"](first_payload)  # type: ignore[index,operator]
            run_dir = Path(roots["run_dir"])
            lock_path = run_dir / namespace["LOCK_NAME"]  # type: ignore[index]
            commit_path = run_dir / namespace["_build_attempt_names"](first_payload["attempt_id"])[2]  # type: ignore[index,operator]
            self.assertFalse(lock_path.exists())
            self.assertEqual(
                json.loads(commit_path.read_text(encoding="ascii"))["attempt_id"],
                first_payload["attempt_id"],
            )

            snapshot = SourceSnapshot(
                repositories=(),
                entries=(),
                dirty=False,
                applied_tree_hash=first_payload["applied_tree_hash"],
                snapshot_id=first_payload["snapshot_id"],
            )
            source_payload = {
                key: first_payload[key]
                for key in (
                    "workdir", "run_dir", "model_path", "drafter_path",
                    "work_token", "run_token", "entries",
                )
            }
            second_attempt_id = "9" * 64
            second_payload: dict[str, object] = {}
            helper_error = namespace["HelperError"]

            def response_loss(action: str, payload: dict[str, object], **_: object) -> object:
                if action == "source_verify":
                    return {
                        "sha256": snapshot.applied_tree_hash,
                        "entry_count": len(snapshot.entries),
                    }
                if action == "acquire_lock":
                    return namespace["acquire_lock"](payload)  # type: ignore[index,operator]
                if action == "target_build":
                    second_payload.update(payload)
                    raise TargetError("helper_timeout", "target helper timed out")
                if action == "target_build_reconcile":
                    try:
                        return namespace["target_build_reconcile"](payload)  # type: ignore[index,operator]
                    except helper_error as error:  # type: ignore[misc]
                        raise TargetError(error.code, error.safe_message) from None
                self.fail(f"unexpected helper action: {action}")

            transport = build_module.SSHTransport("spark")
            transport.run_helper = mock.Mock(side_effect=response_loss)  # type: ignore[method-assign]
            config = self._remote_build_config()
            config.run_dir = roots["run_dir"]
            with (
                mock.patch.object(build_module, "_validate_snapshot", return_value=snapshot),
                mock.patch.object(
                    build_module,
                    "_load_capabilities",
                    return_value={"run_token": first_payload["run_token"]},
                ),
                mock.patch.object(build_module, "_remote_payload", return_value=source_payload),
                mock.patch.object(build_module, "_expect_root_identities"),
                mock.patch.object(
                    build_module.secrets, "token_hex", return_value=second_attempt_id,
                ),
                self.assertRaises(TargetError) as raised,
            ):
                build_module.build(config, transport, snapshot=snapshot, jobs=1)

            self.assertEqual(raised.exception.code, "build_reconciliation_required")
            self.assertEqual(second_payload["attempt_id"], second_attempt_id)
            self.assertTrue(lock_path.is_file())
            self.assertEqual(
                json.loads(lock_path.read_text(encoding="ascii"))["token"],
                second_payload["lock_token"],
            )
            self.assertEqual(
                json.loads(commit_path.read_text(encoding="ascii"))["attempt_id"],
                first_payload["attempt_id"],
            )
            self.assertNotEqual(first_result["build_id"], None)  # type: ignore[index]

            namespace["_build_capture"] = mock.Mock(side_effect=[
                (0, b"ds4-server 1.2.3\n", b"", False, False),
                (0, b"Function : sm_121\n", b"", False, False),
            ])
            second_result = namespace["target_build"](second_payload)  # type: ignore[index,operator]
            self.assertFalse(lock_path.exists())
            eventual = namespace["target_build_reconcile"](second_payload)  # type: ignore[index,operator]
            self.assertEqual(eventual["report"]["attempt_id"], second_attempt_id)  # type: ignore[index]
            self.assertEqual(
                {key: eventual["report"][key] for key in namespace["_BUILD_RESULT_KEYS"]},  # type: ignore[index]
                second_result,
            )
            self.assertFalse(lock_path.exists())

            stale_payload = dict(second_payload)
            stale_payload["attempt_id"] = "8" * 64
            with self.assertRaises(helper_error) as stale:  # type: ignore[arg-type]
                namespace["target_build_reconcile"](stale_payload)  # type: ignore[index,operator]
            self.assertEqual(stale.exception.code, "build_reconcile_unavailable")
            self.assertFalse(lock_path.exists())

            namespace["_build_file_hash"] = mock.Mock(return_value=("f" * 64, 10))
            with self.assertRaises(helper_error) as injected:  # type: ignore[arg-type]
                namespace["target_build_reconcile"](second_payload)  # type: ignore[index,operator]
            self.assertEqual(injected.exception.code, "build_reconcile_invalid")
            self.assertFalse(lock_path.exists())

    def test_reconciliation_rejects_stale_injected_and_mismatched_reports(self) -> None:
        snapshot = SourceSnapshot((), (), False, "a" * 64, "b" * 64)
        attempt_id = "e" * 64
        payload = self._successful_remote_payload(snapshot)
        valid = self._reconciliation_payload(payload, attempt_id)
        self.assertEqual(
            build_module._remote_reconciled_result(valid, snapshot, attempt_id).build_id,
            payload["build_id"],
        )
        malformed: list[dict[str, object]] = []
        stale = self._reconciliation_payload(payload, "9" * 64)
        malformed.append(stale)
        wrong_source_payload = {**payload, "source_snapshot_id": "9" * 64}
        malformed.append(
            self._reconciliation_payload(wrong_source_payload, attempt_id),
        )
        wrong_binary_payload = {**payload, "binary_sha256": "9" * 64}
        malformed.append(
            self._reconciliation_payload(wrong_binary_payload, attempt_id),
        )
        wrong_log = self._reconciliation_payload(payload, attempt_id)
        wrong_log["build_log_sha256"] = "9" * 64
        malformed.append(wrong_log)
        injected = self._reconciliation_payload(payload, attempt_id)
        injected["report"] = {**injected["report"], "private": "/target/private"}  # type: ignore[arg-type]
        malformed.append(injected)
        for candidate in malformed:
            with self.subTest(candidate=candidate):
                with self.assertRaises(TargetError) as raised:
                    build_module._remote_reconciled_result(
                        candidate, snapshot, attempt_id,
                    )
                self.assertEqual(raised.exception.code, "build_reconciliation_failed")

    def test_target_action_persists_digest_bound_report_before_releasing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            namespace, payload, roots = self._remote_action_fixture(Path(temporary))
            binary_hash = "c" * 64
            namespace["_build_make"] = mock.Mock(
                return_value=(0, 17, b"sanitized build output\n", False, False, False),
            )
            namespace["_build_file_hash"] = mock.Mock(return_value=(binary_hash, 10))
            namespace["_build_capture"] = mock.Mock(side_effect=[
                (0, b"ds4-server 1.2.3\n", b"", False, False),
                (0, b"Function : sm_121\n", b"", False, False),
            ])
            direct = namespace["target_build"](payload)  # type: ignore[index,operator]
            capture_calls = namespace["_build_capture"].call_args_list  # type: ignore[attr-defined,index]
            self.assertEqual(len(capture_calls), 2)
            version_call, sass_call = (call.args for call in capture_calls)
            self.assertEqual(version_call[3], sass_call[3])
            self.assertIs(version_call[4], sass_call[4])
            pinned_binary = f"/proc/self/fd/{version_call[3]}/engine/ds4/ds4-server"
            self.assertEqual(version_call[0], (pinned_binary, "--version"))
            self.assertEqual(
                sass_call[0],
                ("/usr/local/cuda/bin/cuobjdump", "--dump-sass", pinned_binary),
            )
            lock_path = Path(roots["run_dir"]) / namespace["LOCK_NAME"]  # type: ignore[index]
            self.assertFalse(lock_path.exists())
            run_dir = Path(roots["run_dir"])
            report_name, attempt_log_name, commit_name = namespace["_build_attempt_names"](payload["attempt_id"])  # type: ignore[index,operator]
            active_path = run_dir / "build.json"
            report_path = run_dir / report_name
            attempt_log_path = run_dir / attempt_log_name
            commit_path = run_dir / commit_name
            self.assertTrue(active_path.is_file())
            self.assertTrue(report_path.is_file())
            self.assertTrue(attempt_log_path.is_file())
            self.assertTrue(commit_path.is_file())
            active = json.loads(active_path.read_text(encoding="ascii"))
            self.assertEqual(set(active), namespace["_BUILD_ACTIVE_KEYS"])  # type: ignore[index]
            self.assertEqual(active["record_type"], "build")
            self.assertNotIn("attempt_id", active)
            commit = json.loads(commit_path.read_text(encoding="ascii"))
            self.assertEqual(commit["record_type"], "build-attempt-commit")
            self.assertEqual(commit["attempt_id"], payload["attempt_id"])
            self.assertEqual(commit["attempt_report_sha256"], hashlib.sha256(report_path.read_bytes()).hexdigest())
            self.assertEqual(commit["attempt_log_sha256"], hashlib.sha256(attempt_log_path.read_bytes()).hexdigest())
            reconciled = namespace["target_build_reconcile"](payload)  # type: ignore[index,operator]
            self.assertEqual(
                {key: reconciled["report"][key] for key in namespace["_BUILD_RESULT_KEYS"]},  # type: ignore[index]
                direct,
            )
            self.assertEqual(reconciled["lease_state"], "released")  # type: ignore[index]
            self.assertFalse(lock_path.exists())

            payload = dict(payload)
            payload["attempt_id"] = "9" * 64
            lock = namespace["acquire_lock"]({  # type: ignore[index,operator]
                "run_dir": roots["run_dir"],
                "run_token": payload["run_token"],
                "lease_seconds": build_module.BUILD_LOCK_LEASE_SECONDS,
            })
            payload["lock_token"] = lock["lock_token"]
            report_name, attempt_log_name, commit_name = namespace["_build_attempt_names"](payload["attempt_id"])  # type: ignore[index,operator]
            report_path = run_dir / report_name
            attempt_log_path = run_dir / attempt_log_name
            commit_path = run_dir / commit_name
            namespace["_build_capture"] = mock.Mock(side_effect=[
                (0, b"ds4-server 1.2.3\n", b"", False, False),
                (0, b"Function : sm_121\n", b"", False, False),
            ])
            release = namespace["_release_lock_at_root"]
            release_observation: list[tuple[bool, bool, bool]] = []

            def fail_release(*_: object) -> None:
                release_observation.append((report_path.is_file(), attempt_log_path.is_file(), commit_path.is_file()))
                raise namespace["HelperError"]("lock_release_failed")  # type: ignore[index,operator]

            namespace["_release_lock_at_root"] = fail_release
            with self.assertRaises(namespace["HelperError"]):  # type: ignore[arg-type,index]
                namespace["target_build"](payload)  # type: ignore[index,operator]
            self.assertEqual(release_observation, [(True, True, True)])
            self.assertTrue(lock_path.exists())
            namespace["_release_lock_at_root"] = release
            recovered = namespace["target_build_reconcile"](payload)  # type: ignore[index,operator]
            self.assertEqual(recovered["lease_state"], "released")  # type: ignore[index]
            self.assertFalse(lock_path.exists())

    def test_target_action_pre_spawn_failure_persists_evidence_and_releases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            namespace, payload, roots = self._remote_action_fixture(Path(temporary))
            kill_group = mock.Mock()
            namespace["_build_kill_group"] = kill_group
            release = namespace["_release_lock_at_root"]
            released_tokens: list[str] = []

            def record_release(*args: object) -> object:
                released_tokens.append(args[3])  # type: ignore[arg-type]
                return release(*args)  # type: ignore[operator]

            namespace["_release_lock_at_root"] = record_release
            with mock.patch.object(
                namespace["_build_subprocess"],  # type: ignore[arg-type,index]
                "Popen",
                side_effect=OSError("private spawn detail"),
            ):
                result = namespace["target_build"](payload)  # type: ignore[index,operator]

            empty_hash = hashlib.sha256(b"").hexdigest()
            self.assertEqual(result["status"], "failed")  # type: ignore[index]
            self.assertEqual(result["failure_class"], "command_failed")  # type: ignore[index]
            self.assertEqual(result["command"], "make-cuda-spark")  # type: ignore[index]
            self.assertIsNone(result["exit_code"])  # type: ignore[index]
            self.assertEqual(result["build_log_sha256"], empty_hash)  # type: ignore[index]
            self.assertTrue(
                all(
                    result[key] is None  # type: ignore[index]
                    for key in ("build_id", "binary_sha256", "version", "binary_size", "sass")
                )
            )
            self.assertGreaterEqual(result["duration_ns"], 1)  # type: ignore[index]
            self.assertLessEqual(result["duration_ns"], 3_630_000_000_000)  # type: ignore[index]
            run_dir = Path(roots["run_dir"])
            self.assertEqual((run_dir / "build.log").read_bytes(), b"")
            report_name, attempt_log_name, commit_name = namespace["_build_attempt_names"](payload["attempt_id"])  # type: ignore[index,operator]
            report_path = run_dir / report_name
            report = json.loads(report_path.read_text(encoding="ascii"))
            self.assertNotIn(
                "private spawn detail",
                report_path.read_text(encoding="ascii"),
            )
            self.assertEqual(report["record_type"], "build-attempt")
            self.assertEqual(report["attempt_id"], payload["attempt_id"])
            self.assertEqual(
                {key: report[key] for key in namespace["_BUILD_RESULT_KEYS"]},  # type: ignore[index]
                result,
            )
            self.assertEqual((run_dir / attempt_log_name).read_bytes(), b"")
            self.assertTrue((run_dir / commit_name).is_file())
            self.assertFalse((run_dir / "build.json").exists())
            self.assertFalse((run_dir / namespace["LOCK_NAME"]).exists())  # type: ignore[index]
            self.assertEqual(released_tokens, [payload["lock_token"]])
            kill_group.assert_not_called()

    def test_failed_later_attempt_reconciles_without_replacing_active_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            namespace, first_payload, roots = self._remote_action_fixture(Path(temporary))
            namespace["_build_make"] = mock.Mock(side_effect=[
                (0, 17, b"successful build\n", False, False, False),
                (None, 19, b"", False, False, True),
            ])
            namespace["_build_file_hash"] = mock.Mock(return_value=("c" * 64, 10))
            namespace["_build_capture"] = mock.Mock(side_effect=[
                (0, b"ds4-server 1.2.3\n", b"", False, False),
                (0, b"Function : sm_121\n", b"", False, False),
            ])
            first = namespace["target_build"](first_payload)  # type: ignore[index,operator]
            run_dir = Path(roots["run_dir"])
            active_path = run_dir / "build.json"
            active_success = active_path.read_bytes()

            second_payload = dict(first_payload)
            second_payload["attempt_id"] = "9" * 64
            lock = namespace["acquire_lock"]({  # type: ignore[index,operator]
                "run_dir": roots["run_dir"],
                "run_token": second_payload["run_token"],
                "lease_seconds": build_module.BUILD_LOCK_LEASE_SECONDS,
            })
            second_payload["lock_token"] = lock["lock_token"]
            second = namespace["target_build"](second_payload)  # type: ignore[index,operator]

            self.assertEqual(first["status"], "succeeded")  # type: ignore[index]
            self.assertEqual((second["status"], second["failure_class"]), ("failed", "command_failed"))  # type: ignore[index]
            self.assertEqual(active_path.read_bytes(), active_success)
            active = json.loads(active_success)
            self.assertEqual(active["build_id"], first["build_id"])  # type: ignore[index]
            self.assertNotIn("attempt_id", active)
            for attempt_id in (first_payload["attempt_id"], second_payload["attempt_id"]):
                self.assertTrue(all((run_dir / name).is_file() for name in namespace["_build_attempt_names"](attempt_id)))  # type: ignore[index,operator]

            reconciled = namespace["target_build_reconcile"](second_payload)  # type: ignore[index,operator]
            self.assertEqual(
                {key: reconciled["report"][key] for key in namespace["_BUILD_RESULT_KEYS"]},  # type: ignore[index]
                second,
            )
            self.assertEqual(active_path.read_bytes(), active_success)

    def test_target_action_post_spawn_group_ambiguity_retains_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            namespace, payload, roots = self._remote_action_fixture(Path(temporary))
            release = mock.Mock()
            namespace["_release_lock_at_root"] = release

            def ambiguous_group(
                cwd: str,
                jobs: int,
                private_paths: tuple[str, ...],
                additional_secrets: tuple[str, ...],
                activity: dict[str, bool],
            ) -> tuple[object, ...]:
                self.assertRegex(cwd, r"\A/proc/self/fd/[0-9]+\Z")
                self.assertEqual(jobs, payload["jobs"])
                self.assertEqual(private_paths, (payload["model_path"], payload["drafter_path"]))
                self.assertEqual(additional_secrets, (payload["workdir"], payload["run_dir"]))
                self.assertEqual(activity, {"mutation_dispatched": False, "process_groups_gone": True})
                activity["mutation_dispatched"] = True
                activity["process_groups_gone"] = False
                raise namespace["HelperError"]("build_process_unknown")  # type: ignore[index,operator]

            namespace["_build_make"] = mock.Mock(side_effect=ambiguous_group)
            with self.assertRaises(namespace["HelperError"]) as raised:  # type: ignore[arg-type,index]
                namespace["target_build"](payload)  # type: ignore[index,operator]
            self.assertEqual(raised.exception.code, "build_process_unknown")
            run_dir = Path(roots["run_dir"])
            self.assertTrue((run_dir / namespace["LOCK_NAME"]).is_file())  # type: ignore[index]
            release.assert_not_called()
            self.assertFalse((run_dir / "build.log").exists())
            self.assertFalse((run_dir / "build.json").exists())
            self.assertFalse(any(run_dir.glob(".targetctl-build-attempt-v1-*")))

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
        work_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        activity = {"mutation_dispatched": True, "process_groups_gone": True}
        try:
            code, stdout, stderr, timed_out, oversize = namespace["_build_capture"]((sys.executable, "-c", "import sys; sys.stdout.write('x' * 65536)"), 10, 32, work_fd, activity)  # type: ignore[operator]
            self.assertTrue(oversize)
            self.assertFalse(timed_out)
            self.assertLessEqual(len(stdout), 32)
            self.assertLessEqual(len(stderr), 32)
            self.assertIsInstance(code, int)
            self.assertTrue(activity["process_groups_gone"])
            with tempfile.TemporaryDirectory() as temporary:
                pid_path = Path(temporary) / "descendant.pid"
                started = time.monotonic()
                code, stdout, stderr, timed_out, oversize = namespace["_build_capture"](self._leader_exits_while_descendant_holds_pipes(pid_path), 0.05, 32, work_fd, activity)  # type: ignore[operator]
                elapsed = time.monotonic() - started
                descendant = int(pid_path.read_text(encoding="ascii"))
                try:
                    self.assertLess(elapsed, 2)
                    self.assertTrue(timed_out)
                    self.assertFalse(oversize)
                    self.assertLessEqual(len(stdout), 32)
                    self.assertLessEqual(len(stderr), 32)
                    self.assertIsInstance(code, int)
                    self.assertTrue(activity["process_groups_gone"])
                    self.assert_process_not_running(descendant)
                finally:
                    try:
                        os.kill(descendant, 9)
                    except ProcessLookupError:
                        pass
        finally:
            os.close(work_fd)

    def test_remote_post_build_captures_inherit_pinned_work_descriptor(self) -> None:
        namespace: dict[str, object] = {"HelperError": Exception, "_fail": lambda code: (_ for _ in ()).throw(TargetError(code))}
        extension = build_module.REMOTE_REDACTION_EXTENSION + build_module.REMOTE_BUILD_EXTENSION.split("@register_action('target_build')", 1)[0]
        exec(extension, namespace)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "engine" / "ds4" / "ds4-server"
            binary.parent.mkdir(parents=True)
            binary.write_text(
                f"#!{sys.executable}\nprint('ds4-server 1.2.3')\n",
                encoding="ascii",
            )
            binary.chmod(0o700)
            work_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            pinned_binary = f"/proc/self/fd/{work_fd}/engine/ds4/ds4-server"
            activity = {"mutation_dispatched": True, "process_groups_gone": True}
            real_popen = namespace["_build_subprocess"].Popen  # type: ignore[attr-defined,index]
            inherited: list[tuple[int, ...]] = []

            def record_popen(*args: object, **kwargs: object) -> object:
                inherited.append(kwargs["pass_fds"])  # type: ignore[arg-type]
                return real_popen(*args, **kwargs)

            try:
                with mock.patch.object(
                    namespace["_build_subprocess"],  # type: ignore[arg-type,index]
                    "Popen",
                    side_effect=record_popen,
                ):
                    version = namespace["_build_capture"]((pinned_binary, "--version"), 10, 16_384, work_fd, activity)  # type: ignore[operator]
                    sass = namespace["_build_capture"](
                        (
                            sys.executable,
                            "-c",
                            "import pathlib,sys; pathlib.Path(sys.argv[1]).read_bytes(); print('Function : sm_121')",
                            pinned_binary,
                        ),
                        10,
                        16_384,
                        work_fd,
                        activity,
                    )  # type: ignore[operator]
            finally:
                os.close(work_fd)
            self.assertEqual(version, (0, b"ds4-server 1.2.3\n", b"", False, False))
            self.assertEqual(sass, (0, b"Function : sm_121\n", b"", False, False))
            self.assertEqual(inherited, [(work_fd,), (work_fd,)])
            self.assertTrue(activity["process_groups_gone"])


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
            tools = [{"name": name, "version": "1.0", "location": path} for name, path in DOCTOR_TOOLS]
            native_locations = {tool["name"]: tool["location"] for tool in tools}

            def stat_path(path: object, *args: object, **kwargs: object) -> os.stat_result | SimpleNamespace:
                if path == nix_path:
                    return SimpleNamespace(st_mode=0o100100, st_uid=os.geteuid())
                return real_stat(path, *args, **kwargs)  # type: ignore[arg-type]

            def doctor_cmd(argv: tuple[str, ...], timeout: float = 5, pass_fds: tuple[int, ...] = ()) -> bytes:
                calls.append((argv, pass_fds))
                if argv[-1] == "--version":
                    return b"nix (Nix) 2.28.5\n"
                name = argv[-1]
                path = native_locations[name]
                detail = f"Cuda compilation tools, release 1.0, V1.0.0\n" if name == "nvcc" else f"{name} 1.0\n"
                return f"TARGETCTL_PATH={path}\n{detail}".encode("ascii")

            try:
                with mock.patch.object(os, "stat", side_effect=stat_path):
                    namespace["_doctor_cmd"] = doctor_cmd
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
        with self.assertRaises(error) as oversized:  # type: ignore[arg-type]
            namespace["_doctor_cmd"]((sys.executable, "-c", "import sys;sys.stdout.write('x'*20000)"), 5)  # type: ignore[index,operator]
        self.assertEqual(oversized.exception.code, "doctor_command_failed")
        started = time.monotonic()
        with self.assertRaises(error) as timed_out:  # type: ignore[arg-type]
            namespace["_doctor_cmd"]((sys.executable, "-c", "import time;time.sleep(60)"), 0.05)  # type: ignore[index,operator]
        self.assertEqual(timed_out.exception.code, "doctor_command_timeout")
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

    def _persist_remote_success(
        self,
        namespace: dict[str, object],
        payload: dict[str, object],
    ) -> None:
        namespace["_build_make"] = mock.Mock(
            return_value=(0, 17, b"sanitized build output\n", False, False, False),
        )
        namespace["_build_file_hash"] = mock.Mock(return_value=("c" * 64, 10))
        namespace["_build_capture"] = mock.Mock(side_effect=[
            (0, b"ds4-server 1.2.3\n", b"", False, False),
            (0, b"Function : sm_121\n", b"", False, False),
        ])
        namespace["target_build"](payload)  # type: ignore[index,operator]

    def test_reconciliation_rejects_expiry_or_reclaim_during_validation(self) -> None:
        for event in ("expiry", "reclaim"):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as temporary:
                namespace, payload, roots = self._remote_action_fixture(Path(temporary))
                self._persist_remote_success(namespace, payload)
                run_dir = Path(roots["run_dir"])
                lock_path = run_dir / namespace["LOCK_NAME"]  # type: ignore[index]
                if event == "expiry":
                    lock = namespace["acquire_lock"]({  # type: ignore[index,operator]
                        "run_dir": roots["run_dir"],
                        "run_token": payload["run_token"],
                        "lease_seconds": build_module.BUILD_RECONCILE_LEASE_SECONDS,
                    })
                    payload["lock_token"] = lock["lock_token"]
                validate = namespace["_build_validate_result"]
                replacement: dict[str, object] = {}

                def invalidate_lease(*args: object) -> object:
                    result = validate(*args)  # type: ignore[operator]
                    state = json.loads(lock_path.read_text(encoding="ascii"))
                    state["deadline_monotonic_ns"] = time.monotonic_ns() - 1
                    lock_path.write_text(
                        json.dumps(state, sort_keys=True, separators=(",", ":")),
                        encoding="ascii",
                    )
                    if event == "reclaim":
                        replacement.update(namespace["acquire_lock"]({  # type: ignore[index,operator]
                            "run_dir": roots["run_dir"],
                            "run_token": payload["run_token"],
                            "lease_seconds": build_module.BUILD_RECONCILE_LEASE_SECONDS,
                        }))
                    return result

                namespace["_build_validate_result"] = invalidate_lease
                helper_error = namespace["HelperError"]
                with self.assertRaises(helper_error) as raised:  # type: ignore[arg-type]
                    namespace["target_build_reconcile"](payload)  # type: ignore[index,operator]
                self.assertEqual(raised.exception.code, "build_reconcile_invalid")
                retained = json.loads(lock_path.read_text(encoding="ascii"))
                expected_token = (
                    payload["lock_token"]
                    if event == "expiry"
                    else replacement["lock_token"]
                )
                self.assertEqual(retained["token"], expected_token)

    def test_reconciliation_release_failure_requires_exact_live_ownership(self) -> None:
        self.assertGreater(
            build_module.BUILD_LOCK_LEASE_SECONDS,
            build_module.BUILD_TIMEOUT_SECONDS
            + 30.0
            + build_module.BUILD_RECONCILE_TIMEOUT_SECONDS,
        )
        self.assertGreater(
            build_module.BUILD_RECONCILE_LEASE_SECONDS,
            build_module.BUILD_RECONCILE_TIMEOUT_SECONDS,
        )
        for event in ("exact-live", "replaced"):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as temporary:
                namespace, payload, roots = self._remote_action_fixture(Path(temporary))
                self._persist_remote_success(namespace, payload)
                run_dir = Path(roots["run_dir"])
                lock_path = run_dir / namespace["LOCK_NAME"]  # type: ignore[index]
                replacement: dict[str, object] = {}
                released_token: list[str] = []

                def fail_release(*args: object) -> None:
                    released_token.append(args[3])  # type: ignore[arg-type]
                    if event == "replaced" and not replacement:
                        state = json.loads(lock_path.read_text(encoding="ascii"))
                        state["deadline_monotonic_ns"] = time.monotonic_ns() - 1
                        lock_path.write_text(
                            json.dumps(state, sort_keys=True, separators=(",", ":")),
                            encoding="ascii",
                        )
                        replacement.update(namespace["acquire_lock"]({  # type: ignore[index,operator]
                            "run_dir": roots["run_dir"],
                            "run_token": payload["run_token"],
                            "lease_seconds": build_module.BUILD_RECONCILE_LEASE_SECONDS,
                        }))
                    raise namespace["HelperError"]("lock_release_failed")  # type: ignore[index,operator]

                namespace["_release_lock_at_root"] = fail_release
                if event == "exact-live":
                    reconciled = namespace["target_build_reconcile"](payload)  # type: ignore[index,operator]
                    self.assertEqual(reconciled["lease_state"], "retained")
                    state = json.loads(lock_path.read_text(encoding="ascii"))
                    self.assertEqual(state["token"], released_token[0])
                    self.assertGreater(
                        state["deadline_monotonic_ns"],
                        time.monotonic_ns(),
                    )
                else:
                    helper_error = namespace["HelperError"]
                    with self.assertRaises(helper_error) as raised:  # type: ignore[arg-type]
                        namespace["target_build_reconcile"](payload)  # type: ignore[index,operator]
                    self.assertEqual(raised.exception.code, "build_reconcile_invalid")
                    state = json.loads(lock_path.read_text(encoding="ascii"))
                    self.assertEqual(state["token"], replacement["lock_token"])