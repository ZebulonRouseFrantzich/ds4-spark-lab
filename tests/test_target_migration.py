from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from scripts.targetctl.common import TargetError
from scripts.targetctl import migration, remote
from scripts.targetctl.transport import LocalTransport


LEGACY_PROFILE = {
    "schema_version": 1,
    "accelerator": "cuda",
    "context_tokens": 32768,
    "bind": "loopback",
    "continuation_mtp_mode": 2,
    "dspark_enabled": True,
    "drafter_enabled": True,
}
LIFECYCLE_FILES = {
    "run.json",
    "launch.json",
    "supervisor.py",
    "server.log",
    "ack.json",
    ".targetctl-lifecycle-v1.lock",
}


def _unused_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


def _process_ticks(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    return int(raw[raw.rfind(")") + 2 :].split()[19])


def _process_cmdline_sha256(pid: int) -> str:
    raw = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0")
    return hashlib.sha256(b" ".join(raw.split(b"\0"))).hexdigest()


def _legacy_state(
    *,
    port: int | None = None,
    server_log: bytes | None = None,
    supervisor_pid: int | None = None,
    supervisor_start_ticks: int | None = None,
    supervisor_cmdline_sha256: str | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": "run-aaaaaaaaaaaaaaaaaaaaaaaa",
        "state": "stopped",
        "source_snapshot_id": "1" * 64,
        "applied_tree_hash": "2" * 64,
        "build_id": "3" * 64,
        "binary_sha256": "4" * 64,
        "port": _unused_port() if port is None else port,
        "launch_profile": dict(LEGACY_PROFILE),
        "supervisor_pid": supervisor_pid,
        "supervisor_start_ticks": supervisor_start_ticks,
        "supervisor_cmdline_sha256": supervisor_cmdline_sha256,
        "child_pid": None,
        "child_start_ticks": None,
        "child_pgid": None,
        "child_cmdline_sha256": None,
        "listener_inode": None,
        "cleanup_complete": True,
        "cleanup": {
            "process": "cleared",
            "socket": "cleared",
            "lock": "cleared",
            "temp": "cleared",
            "server_log_sha256": (
                hashlib.sha256(server_log).hexdigest() if server_log is not None else None
            ),
        },
    }


def _current_state() -> dict[str, object]:
    state = _legacy_state()
    state["launch_profile"] = {
        **remote.LAUNCH_PROFILE,
        "speculative_overrides": dict(remote.LAUNCH_PROFILE["speculative_overrides"]),
    }
    return state


class MigrationHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work = self.root / "work"
        self.run = self.root / "run"
        self.model = self.root / "private-models" / "primary.gguf"
        self.drafter = self.root / "private-models" / "draft.gguf"
        initialized = remote.initialize_roots(
            {
                "workdir": str(self.work),
                "run_dir": str(self.run),
                "model_path": str(self.model),
                "drafter_path": str(self.drafter),
            }
        )
        self.run_token = initialized["run"]["token"]
        self.transport = LocalTransport()

    def _write(self, name: str, content: bytes) -> Path:
        path = self.run / name
        path.write_bytes(content)
        os.chmod(path, 0o600)
        return path

    def _write_state(self, state: dict[str, object]) -> bytes:
        raw = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("ascii")
        self._write("run.json", raw)
        return raw

    def _call(self) -> dict[str, str]:
        return self.transport.run_helper(
            "migrate_state",
            {
                "run_dir": str(self.run),
                "run_token": self.run_token,
                "lease_seconds": 30,
            },
            extension_source=migration.MIGRATION_EXTENSION,
            allowed_error_codes=migration._MIGRATION_ERRORS,
            timeout=15.0,
        )

    def _assert_refused(self, code: str) -> None:
        with self.assertRaises(TargetError) as raised:
            self._call()
        self.assertEqual(raised.exception.code, code)

    def test_exact_safe_migration_is_contained_and_idempotent(self) -> None:
        log = b"bounded retired server log\n"
        self._write_state(_legacy_state(server_log=log))
        for name, content in (
            ("launch.json", b"{}"),
            ("supervisor.py", b"pass\n"),
            ("server.log", log),
            ("ack.json", b"{}"),
            (".targetctl-lifecycle-v1.lock", b""),
        ):
            self._write(name, content)
        source = self._write("source.json", b"source-evidence")
        build = self._write("build.json", b"build-evidence")

        self.assertEqual(self._call(), {"status": "migrated"})
        self.assertFalse(any((self.run / name).exists() for name in LIFECYCLE_FILES))
        self.assertEqual(source.read_bytes(), b"source-evidence")
        self.assertEqual(build.read_bytes(), b"build-evidence")
        self.assertEqual(self._call(), {"status": "not_found"})

    def test_current_schema_v2_profile_is_an_exact_no_op(self) -> None:
        raw = self._write_state(_current_state())
        before = os.stat(self.run / "run.json", follow_symlinks=False)
        self.assertEqual(self._call(), {"status": "current"})
        after = os.stat(self.run / "run.json", follow_symlinks=False)
        self.assertEqual((before.st_dev, before.st_ino, before.st_mtime_ns), (after.st_dev, after.st_ino, after.st_mtime_ns))
        self.assertEqual((self.run / "run.json").read_bytes(), raw)
        self.assertFalse((self.run / remote.LOCK_NAME).exists())

    def test_normal_validator_still_rejects_the_legacy_profile(self) -> None:
        state = _legacy_state()
        self.assertFalse(remote._valid_launch_profile(state["launch_profile"]))
        self.assertFalse(remote._valid_run_state(state, terminal=True))

    def test_active_and_stale_pid_records_are_refused_without_mutation(self) -> None:
        pid = os.getpid()
        ticks = _process_ticks(pid)
        digest = _process_cmdline_sha256(pid)
        for observed_ticks in (ticks, ticks + 1):
            with self.subTest(observed_ticks=observed_ticks):
                state = _legacy_state(
                    supervisor_pid=pid,
                    supervisor_start_ticks=observed_ticks,
                    supervisor_cmdline_sha256=digest,
                )
                raw = self._write_state(state)
                self._assert_refused("migration_target_live")
                self.assertEqual((self.run / "run.json").read_bytes(), raw)
                self.assertFalse((self.run / remote.LOCK_NAME).exists())
                (self.run / "run.json").unlink()

    def test_live_listener_is_refused_without_mutation(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        raw = self._write_state(_legacy_state(port=int(listener.getsockname()[1])))
        self._assert_refused("migration_target_live")
        self.assertEqual((self.run / "run.json").read_bytes(), raw)
        self.assertFalse((self.run / remote.LOCK_NAME).exists())

    def test_malformed_and_extra_state_fields_are_refused(self) -> None:
        cases: list[dict[str, object]] = []
        outer = _legacy_state()
        outer["unexpected"] = None
        cases.append(outer)
        profile = _legacy_state()
        assert isinstance(profile["launch_profile"], dict)
        profile["launch_profile"]["unexpected"] = None
        cases.append(profile)
        wrong_cleanup = _legacy_state()
        assert isinstance(wrong_cleanup["cleanup"], dict)
        wrong_cleanup["cleanup"]["process"] = "unknown"
        cases.append(wrong_cleanup)
        for state in cases:
            with self.subTest(keys=tuple(state)):
                raw = self._write_state(state)
                self._assert_refused("migration_state_invalid")
                self.assertEqual((self.run / "run.json").read_bytes(), raw)
                (self.run / "run.json").unlink()

    def test_symlink_hardlink_special_and_wrong_mode_run_files_are_refused(self) -> None:
        raw = json.dumps(_legacy_state(), sort_keys=True, separators=(",", ":")).encode("ascii")
        outside = self.root / "outside.json"
        outside.write_bytes(raw)
        os.chmod(outside, 0o600)
        fixtures = ("symlink", "hardlink", "fifo", "mode")
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                run = self.run / "run.json"
                if fixture == "symlink":
                    run.symlink_to(outside)
                elif fixture == "hardlink":
                    os.link(outside, run)
                elif fixture == "fifo":
                    os.mkfifo(run, 0o600)
                else:
                    run.write_bytes(raw)
                    os.chmod(run, 0o644)
                self._assert_refused("migration_entries_invalid")
                self.assertTrue(os.path.lexists(run))
                self.assertEqual(outside.read_bytes(), raw)
                run.unlink()

    def test_unsafe_optional_lifecycle_files_are_refused_before_deletion(self) -> None:
        raw = self._write_state(_legacy_state())
        outside = self.root / "outside-supervisor.py"
        outside.write_bytes(b"private payload")
        os.chmod(outside, 0o600)
        (self.run / "supervisor.py").symlink_to(outside)
        self._assert_refused("migration_entries_invalid")
        self.assertEqual((self.run / "run.json").read_bytes(), raw)
        self.assertEqual(outside.read_bytes(), b"private payload")

    def test_concurrent_operation_lease_is_refused_and_preserved(self) -> None:
        raw = self._write_state(_legacy_state())
        acquired = remote.acquire_lock(
            {"run_dir": str(self.run), "run_token": self.run_token, "lease_seconds": 30}
        )
        try:
            self._assert_refused("lock_busy")
            self.assertEqual((self.run / "run.json").read_bytes(), raw)
            self.assertTrue((self.run / remote.LOCK_NAME).is_file())
        finally:
            remote.release_lock(
                {
                    "run_dir": str(self.run),
                    "run_token": self.run_token,
                    "lock_token": acquired["lock_token"],
                }
            )

    def test_partial_and_extra_legacy_leftovers_fail_closed(self) -> None:
        leftover = self._write("launch.json", b"{}")
        self._assert_refused("migration_entries_invalid")
        self.assertEqual(leftover.read_bytes(), b"{}")
        leftover.unlink()

        raw = self._write_state(_legacy_state())
        extra = self._write(".run.json.retired-temp", b"{}")
        self._assert_refused("migration_entries_invalid")
        self.assertEqual((self.run / "run.json").read_bytes(), raw)
        self.assertEqual(extra.read_bytes(), b"{}")


class MigrationControllerTests(unittest.TestCase):
    @staticmethod
    def _config(mode: str = "ssh") -> SimpleNamespace:
        config = SimpleNamespace(
            mode=mode,
            name="spark" if mode == "ssh" else "local",
            run_dir="/srv/targetctl/run/state",
            source_root=Path("."),
        )
        config.validate_for = mock.Mock()
        return config

    def test_controller_calls_one_embedded_action_and_accepts_only_bounded_status(self) -> None:
        config = self._config()
        transport = mock.Mock()
        transport.run_helper.return_value = {"status": "migrated"}
        with mock.patch.object(migration, "load_operational_target", return_value=config), mock.patch.object(
            migration,
            "_load_capabilities",
            return_value={"run_token": "a" * 64},
        ):
            self.assertEqual(migration.migrate_state(Path.cwd(), "spark", transport=transport), "migrated")
        config.validate_for.assert_called_once_with("migrate-state")
        transport.run_helper.assert_called_once_with(
            "migrate_state",
            {
                "run_dir": config.run_dir,
                "run_token": "a" * 64,
                "lease_seconds": migration._MIGRATION_LEASE_SECONDS,
            },
            extension_source=migration.MIGRATION_EXTENSION,
            allowed_error_codes=migration._MIGRATION_ERRORS,
            timeout=60.0,
        )

        for malformed in ({"status": "unknown"}, {"status": "current", "extra": None}, "current"):
            with self.subTest(malformed=malformed):
                transport.reset_mock()
                transport.run_helper.return_value = malformed
                with mock.patch.object(migration, "load_operational_target", return_value=self._config()), mock.patch.object(
                    migration,
                    "_load_capabilities",
                    return_value={"run_token": "a" * 64},
                ), self.assertRaises(TargetError) as raised:
                    migration.migrate_state(Path.cwd(), "spark", transport=transport)
                self.assertEqual(raised.exception.code, "migration_response_invalid")

    def test_local_mode_is_rejected_before_transport_or_helper_use(self) -> None:
        config = self._config("local")
        with mock.patch.object(migration, "load_operational_target", return_value=config), mock.patch.object(
            migration, "_load_capabilities"
        ) as capabilities, mock.patch.object(migration, "select_transport") as selected, self.assertRaises(TargetError) as raised:
            migration.migrate_state(Path.cwd(), "local")
        self.assertEqual(raised.exception.code, "migration_local_unsupported")
        capabilities.assert_not_called()
        selected.assert_not_called()

    def test_structured_errors_never_echo_private_values(self) -> None:
        private = "/private/target/model-and-host"
        with mock.patch.object(
            migration,
            "execute_migration",
            side_effect=TargetError("migration_state_invalid", private),
        ):
            result = migration.structured_migration_result(Path.cwd(), "spark")
        encoded = json.dumps(result, sort_keys=True)
        self.assertEqual(
            result,
            {
                "schema": 1,
                "operation": "migrate-state",
                "target": "spark",
                "status": "failed",
                "error": "migration_state_invalid",
            },
        )
        self.assertNotIn(private, encoded)


if __name__ == "__main__":
    unittest.main()
