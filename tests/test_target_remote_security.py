from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
