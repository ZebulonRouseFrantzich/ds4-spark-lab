from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.targetctl import remote


class RemoteFdSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.tmp_path = Path(self._temporary_directory.name)

    def _payload(self) -> dict[str, str]:
        models = self.tmp_path / "models"
        models.mkdir(mode=0o700, exist_ok=True)
        model = models / "model.gguf"
        drafter = models / "draft.gguf"
        model.write_bytes(b"model")
        drafter.write_bytes(b"drafter")
        return {
            "workdir": str(self.tmp_path / "work"),
            "run_dir": str(self.tmp_path / "run"),
            "model_path": str(model),
            "drafter_path": str(drafter),
        }

    def _write_at(self, directory_fd: int, name: str, content: bytes) -> None:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
        try:
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)

    def test_missing_intermediate_and_symlink_component_are_rejected(self) -> None:
        payload = self._payload()
        payload["workdir"] = str(self.tmp_path / "missing" / "work")
        with self.assertRaisesRegex(remote.HelperError, "target helper rejected") as missing:
            remote.initialize_roots(payload)
        self.assertEqual(missing.exception.code, "missing_path")

        linked = self.tmp_path / "linked"
        linked.symlink_to(self.tmp_path / "elsewhere")
        payload = self._payload()
        payload["workdir"] = str(linked / "work")
        with self.assertRaises(remote.HelperError) as symlink:
            remote.initialize_roots(payload)
        self.assertEqual(symlink.exception.code, "symlink_path")

    def test_marker_lock_report_and_hash_use_the_pinned_directory(self) -> None:
        payload = self._payload()
        initialized = remote.initialize_roots(payload)
        run = Path(payload["run_dir"])
        original = self.tmp_path / "original-run"
        replacement = self.tmp_path / "replacement"
        replacement.mkdir(mode=0o700)
        root_fd = remote._open_root(str(run))
        try:
            pinned = remote._identity(root_fd)
            os.rename(run, original)
            run.symlink_to(replacement, target_is_directory=True)

            self.assertEqual(remote._read_marker(root_fd, "run", initialized["run"]["token"])["kind"], "run")
            self.assertTrue(remote._install_lock(root_fd, {"boot_id": remote._boot_id(), "deadline_monotonic_ns": 1, "token": "a" * 64}))
            self._write_at(root_fd, "doctor.json", b"{}")
            report_fd, _ = remote._open_regular("doctor.json", dir_fd=root_fd)
            try:
                self.assertEqual(os.read(report_fd, 16), b"{}")
            finally:
                os.close(report_fd)
            self._write_at(root_fd, "entry.txt", b"entry")
            self.assertEqual(remote._entry_hash(root_fd, "entry.txt")[0], "entry.txt")

            self.assertFalse((replacement / remote._marker_name("run")).exists())
            self.assertFalse((replacement / remote.LOCK_NAME).exists())
            self.assertFalse((replacement / "doctor.json").exists())
            self.assertFalse((replacement / "entry.txt").exists())
            remote._assert_pinned_root(root_fd, pinned)
            with self.assertRaises(remote.HelperError) as changed:
                remote._assert_pinned_root(root_fd, {"device": pinned["device"], "inode": pinned["inode"] + 1})
            self.assertEqual(changed.exception.code, "unsafe_root")

            lock_fd, _ = remote._open_regular(remote.LOCK_NAME, dir_fd=root_fd)
            try:
                lock_identity = remote._identity(lock_fd)
                remote._remove_lock(root_fd, lock_fd, lock_identity)
            finally:
                os.close(lock_fd)
            os.unlink("doctor.json", dir_fd=root_fd)
            os.unlink("entry.txt", dir_fd=root_fd)
            os.fsync(root_fd)
        finally:
            os.close(root_fd)

    def test_lock_action_cleans_up_through_its_root_fd(self) -> None:
        payload = self._payload()
        initialized = remote.initialize_roots(payload)
        token = initialized["run"]["token"]
        acquired = remote.acquire_lock({"run_dir": payload["run_dir"], "run_token": token, "lease_seconds": 60})
        self.assertEqual(
            remote.release_lock({"run_dir": payload["run_dir"], "run_token": token, "lock_token": acquired["lock_token"]}),
            {"released": True},
        )
        self.assertFalse((Path(payload["run_dir"]) / remote.LOCK_NAME).exists())

    def _initialized_run(self) -> tuple[dict[str, str], str, Path]:
        payload = self._payload()
        state = remote.initialize_roots(payload)
        return payload, state["run"]["token"], Path(payload["run_dir"])

    @staticmethod
    def _write_report(path: Path, content: bytes) -> str:
        path.write_bytes(content)
        path.chmod(0o600)
        return hashlib.sha256(content).hexdigest()

    def test_remove_reports_removes_only_exact_digest_bound_reports_and_marks_missing(self) -> None:
        payload, token, run = self._initialized_run()
        build_digest = self._write_report(run / "build.log", b"build output")
        server_digest = self._write_report(run / "server.log", b"server output")
        canary = run / "canary"
        self._write_report(canary, b"retain")

        self.assertEqual(
            remote.remove_reports({"run_dir": payload["run_dir"], "run_token": token, "reports": [
                {"name": "server.log", "sha256": server_digest},
                {"name": "build.log", "sha256": build_digest},
            ]}),
            {"reports": [{"name": "server.log", "result": "cleared"}, {"name": "build.log", "result": "cleared"}]},
        )
        self.assertFalse((run / "build.log").exists())
        self.assertFalse((run / "server.log").exists())
        self.assertTrue(canary.exists())
        self.assertFalse((run / remote.LOCK_NAME).exists())
        self.assertEqual(
            remote.remove_reports({"run_dir": payload["run_dir"], "run_token": token, "reports": [
                {"name": "build.log", "sha256": build_digest},
            ]}),
            {"reports": [{"name": "build.log", "result": "not_found"}]},
        )
        self.assertFalse((run / remote.LOCK_NAME).exists())

    def test_remove_reports_rejects_changed_and_unsafe_reports_without_deletion(self) -> None:
        payload, token, run = self._initialized_run()
        report = run / "build.log"
        digest = self._write_report(report, b"original")

        with self.assertRaises(remote.HelperError) as changed:
            remote.remove_reports({"run_dir": payload["run_dir"], "run_token": token, "reports": [{"name": "build.log", "sha256": hashlib.sha256(b"changed").hexdigest()}]})
        self.assertEqual(changed.exception.code, "unsafe_state")
        self.assertEqual(report.read_bytes(), b"original")
        self.assertFalse((run / remote.LOCK_NAME).exists())

        report.unlink()
        report.symlink_to(run / remote._marker_name("run"))
        with self.assertRaises(remote.HelperError) as symlink:
            remote.remove_reports({"run_dir": payload["run_dir"], "run_token": token, "reports": [{"name": "build.log", "sha256": digest}]})
        self.assertEqual(symlink.exception.code, "unsafe_state")
        self.assertTrue(report.is_symlink())
        self.assertFalse((run / remote.LOCK_NAME).exists())

        report.unlink()
        hardlink_source = run / "canary"
        self._write_report(hardlink_source, b"original")
        os.link(hardlink_source, report)
        with self.assertRaises(remote.HelperError) as hardlink:
            remote.remove_reports({"run_dir": payload["run_dir"], "run_token": token, "reports": [{"name": "build.log", "sha256": digest}]})
        self.assertEqual(hardlink.exception.code, "unsafe_state")
        self.assertTrue(report.exists())
        self.assertTrue(hardlink_source.exists())
        self.assertFalse((run / remote.LOCK_NAME).exists())

        report.unlink()
        self._write_report(report, b"original")
        report.chmod(0o644)
        with self.assertRaises(remote.HelperError) as permissive:
            remote.remove_reports({"run_dir": payload["run_dir"], "run_token": token, "reports": [{"name": "build.log", "sha256": digest}]})
        self.assertEqual(permissive.exception.code, "unsafe_state")
        self.assertTrue(report.exists())
        self.assertFalse((run / remote.LOCK_NAME).exists())

        report.chmod(0o600)
        root_fd = remote._open_root(payload["run_dir"])
        try:
            identity = remote._root_identity(root_fd, "run", token)
            with mock.patch.object(remote.os, "geteuid", return_value=os.geteuid() + 1):
                with self.assertRaises(remote.HelperError) as wrong_owner:
                    remote._remove_report(root_fd, identity, token, "build.log", digest)
            self.assertEqual(wrong_owner.exception.code, "unsafe_state")
        finally:
            os.close(root_fd)
        self.assertTrue(report.exists())

    def test_read_report_rejects_hardlink_without_touching_canary(self) -> None:
        payload, token, run = self._initialized_run()
        canary = self.tmp_path / "outside-canary"
        content = b"outside data must survive"
        self._write_report(canary, content)
        os.link(canary, run / "server.log")

        with self.assertRaises(remote.HelperError) as raised:
            remote.read_report(
                {"run_dir": payload["run_dir"], "run_token": token, "name": "server.log"}
            )
        self.assertEqual(raised.exception.code, "unsafe_state")
        self.assertEqual(canary.read_bytes(), content)


    def test_remove_reports_respects_locks_and_uses_its_pinned_root(self) -> None:
        payload, token, run = self._initialized_run()
        digest = self._write_report(run / "build.log", b"original")
        held = remote.acquire_lock({"run_dir": payload["run_dir"], "run_token": token, "lease_seconds": 60})
        with self.assertRaises(remote.HelperError) as busy:
            remote.remove_reports({"run_dir": payload["run_dir"], "run_token": token, "reports": [{"name": "build.log", "sha256": digest}]})
        self.assertEqual(busy.exception.code, "lock_busy")
        self.assertTrue((run / "build.log").exists())
        remote.release_lock({"run_dir": payload["run_dir"], "run_token": token, "lock_token": held["lock_token"]})

        replacement = self.tmp_path / "replacement"
        remote._init_root(str(replacement), "run")
        replacement_digest = self._write_report(replacement / "build.log", b"replacement")
        original = self.tmp_path / "original-run"
        acquire = remote._acquire_lock_at_root

        def acquire_then_swap(root_fd: int, identity: dict[str, int], run_token: str, lease_seconds: int) -> str:
            lock_token = acquire(root_fd, identity, run_token, lease_seconds)
            os.rename(run, original)
            os.rename(replacement, run)
            return lock_token

        with mock.patch.object(remote, "_acquire_lock_at_root", side_effect=acquire_then_swap):
            self.assertEqual(
                remote.remove_reports({"run_dir": payload["run_dir"], "run_token": token, "reports": [{"name": "build.log", "sha256": digest}]}),
                {"reports": [{"name": "build.log", "result": "cleared"}]},
            )
        self.assertFalse((original / "build.log").exists())
        self.assertEqual((run / "build.log").read_bytes(), b"replacement")
        self.assertEqual(hashlib.sha256((run / "build.log").read_bytes()).hexdigest(), replacement_digest)
        self.assertFalse((original / remote.LOCK_NAME).exists())


if __name__ == "__main__":
    unittest.main()
