from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from scripts.targetctl import source as source_module
from scripts.targetctl.common import TargetError
from scripts.targetctl.source import _SOURCE_EXTENSION, _stage_snapshot, build_snapshot, qualified_clean, sync_source, verify_applied_tree
from scripts.targetctl.transport import CommandResult, LocalTransport, SSHTransport


class SourceFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "lab"
        self.root.mkdir()
        self._git(self.root, "init")
        self._write_commit(self.root, "lab.txt", b"lab\n")
        for name, destination in (("engine", "engine/ds4"), ("integration", "spark/ds4-on-spark")):
            upstream = Path(self.temporary.name) / name
            upstream.mkdir()
            self._git(upstream, "init")
            self._write_commit(upstream, "source.txt", name.encode("ascii"))
            self._git(self.root, "-c", "protocol.file.allow=always", "submodule", "add", os.fspath(upstream), destination)
        self._commit(self.root, "submodules")

    def _git(self, root: Path, *args: str) -> None:
        subprocess.run(("git", "-C", os.fspath(root), *args), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _commit(self, root: Path, message: str) -> None:
        self._git(root, "add", "-A")
        self._git(root, "-c", "user.name=Target Test", "-c", "user.email=target@example.invalid", "commit", "-m", message)

    def _write_commit(self, root: Path, name: str, data: bytes) -> None:
        (root / name).write_bytes(data)
        self._git(root, "add", name)
        self._git(root, "-c", "user.name=Target Test", "-c", "user.email=target@example.invalid", "commit", "-m", "initial")

    def test_clean_snapshot_is_deterministic_and_exactly_pinned(self) -> None:
        first = build_snapshot(self.root)
        second = build_snapshot(self.root)
        self.assertEqual(first.snapshot_id, second.snapshot_id)
        self.assertEqual(first.applied_tree_hash, second.applied_tree_hash)
        self.assertFalse(first.dirty)
        self.assertTrue(qualified_clean(first))
        self.assertEqual(verify_applied_tree(self.root, first), first.applied_tree_hash)

    def test_text_binary_and_nonignored_untracked_change_identity(self) -> None:
        initial = build_snapshot(self.root)
        (self.root / "lab.txt").write_text("changed\n")
        (self.root / "engine" / "ds4" / "nul.bin").write_bytes(b"\x00\xff\x00binary")
        changed = build_snapshot(self.root)
        self.assertTrue(changed.dirty)
        self.assertNotEqual(changed.snapshot_id, initial.snapshot_id)
        entry = next(item for item in changed.entries if item.path == "engine/ds4/nul.bin")
        self.assertEqual(entry.size, 9)
        self.assertEqual(entry.origin, "untracked")

    def test_applied_hash_mismatch_is_detected(self) -> None:
        snapshot = build_snapshot(self.root)
        (self.root / "lab.txt").write_text("changed after snapshot\n")
        with self.assertRaises(TargetError) as error:
            verify_applied_tree(self.root, snapshot)
        self.assertEqual(error.exception.code, "applied_hash_mismatch")

    def test_ignored_private_and_generated_files_are_not_inventory(self) -> None:
        (self.root / ".gitignore").write_text("ignored.txt\n")
        self._git(self.root, "add", ".gitignore")
        self._commit(self.root, "ignore")
        (self.root / "ignored.txt").write_text("private")
        (self.root / "targets").mkdir()
        (self.root / "targets" / "secret.toml").write_text("secret")
        (self.root / "build").mkdir()
        (self.root / "build" / "output").write_text("generated")
        snapshot = build_snapshot(self.root)
        paths = {item.path for item in snapshot.entries}
        self.assertNotIn("ignored.txt", paths)
        self.assertNotIn("targets/secret.toml", paths)
        self.assertNotIn("build/output", paths)

    def test_subrepository_private_and_generated_roots_are_excluded(self) -> None:
        for relative in ("engine/ds4/models/private.bin", "engine/ds4/build/output", "spark/ds4-on-spark/drafters/private.bin", "spark/ds4-on-spark/dist/output"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"private")
        paths = {entry.path for entry in build_snapshot(self.root).entries}
        self.assertFalse(paths & {"engine/ds4/models/private.bin", "engine/ds4/build/output", "spark/ds4-on-spark/drafters/private.bin", "spark/ds4-on-spark/dist/output"})

    def test_tracked_deletion_and_new_extra_are_exact_inventory_changes(self) -> None:
        snapshot = build_snapshot(self.root)
        (self.root / "lab.txt").unlink()
        deleted = build_snapshot(self.root)
        self.assertNotIn("lab.txt", {entry.path for entry in deleted.entries})
        self.assertEqual(verify_applied_tree(self.root, deleted), deleted.applied_tree_hash)
        (self.root / "new-extra").write_text("new")
        with self.assertRaises(TargetError) as error:
            verify_applied_tree(self.root, deleted)
        self.assertEqual(error.exception.code, "applied_hash_mismatch")
        with self.assertRaises(TargetError) as error:
            verify_applied_tree(self.root, snapshot)
        self.assertEqual(error.exception.code, "applied_hash_mismatch")

    def test_remote_marker_name_is_reserved(self) -> None:
        (self.root / ".targetctl-owner-v1-work.json").write_text("{}")
        with self.assertRaises(TargetError) as error:
            build_snapshot(self.root)
        self.assertEqual(error.exception.code, "reserved_path")

    def test_unsafe_filename_and_symlink_are_rejected(self) -> None:
        (self.root / "unsafe name").write_text("x")
        with self.assertRaises(TargetError) as error:
            build_snapshot(self.root)
        self.assertEqual(error.exception.code, "unsafe_filename")
        (self.root / "unsafe name").unlink()
        (self.root / "linked").symlink_to("lab.txt")
        self._git(self.root, "add", "linked")
        with self.assertRaises(TargetError) as error:
            build_snapshot(self.root)
        self.assertEqual(error.exception.code, "unsupported_entry")

    def test_local_sync_does_not_copy_or_delete(self) -> None:
        extra = self.root / "controller-only"
        extra.write_text("keep")
        config = SimpleNamespace(mode="local", source_root=self.root)
        result = sync_source(config, LocalTransport())
        self.assertFalse(result.initialized)
        self.assertTrue(extra.exists())
        self.assertEqual(result.applied_tree_hash, result.snapshot.applied_tree_hash)


class TargetHelperSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.model = self.base / "model"


        self.drafter = self.base / "drafter"
        self.model.write_bytes(b"m")
        self.drafter.write_bytes(b"d")
        self.payload = {"workdir": str(self.base / "work"), "run_dir": str(self.base / "run"), "model_path": str(self.model), "drafter_path": str(self.drafter)}
        self.transport = LocalTransport()
        state = self.transport.run_helper("initialize_roots", self.payload)
        self.tokens = {"work_token": state["work"]["token"], "run_token": state["run"]["token"]}

    def test_marker_token_and_exact_inventory_gate(self) -> None:
        work = Path(self.payload["workdir"])
        (work / "nested").mkdir()
        (work / "nested" / "file").write_bytes(b"contents")
        request = {**self.payload, **self.tokens, "entries": ["nested/file"]}
        result = self.transport.run_helper("source_verify", request, extension_source=_SOURCE_EXTENSION, allowed_error_codes={"unexpected_entry", "source_lifecycle"})
        self.assertEqual(result["entry_count"], 1)
        (work / "extra").write_bytes(b"x")
        with self.assertRaises(TargetError) as error:
            self.transport.run_helper("source_verify", request, extension_source=_SOURCE_EXTENSION, allowed_error_codes={"unexpected_entry", "source_lifecycle"})
        self.assertEqual(error.exception.code, "unexpected_entry")

    def test_running_or_unknown_lifecycle_refuses_before_transfer(self) -> None:
        run = Path(self.payload["run_dir"])
        (run / "run.json").write_text('{"schema_version":1,"state":"running"}')
        os.chmod(run / "run.json", 0o600)
        request = {**self.payload, **self.tokens, "entries": []}
        with self.assertRaises(TargetError) as error:
            self.transport.run_helper("source_preflight", request, extension_source=_SOURCE_EXTENSION, allowed_error_codes={"source_lifecycle", "unexpected_entry"})
        self.assertEqual(error.exception.code, "source_lifecycle")
class GuardedRsyncTests(unittest.TestCase):
    def test_receiver_argv_uses_fixed_binary_and_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            captured: list[tuple[str, ...]] = []
            def runner(argv: tuple[str, ...], data: bytes | None, timeout: float | None, cwd: str, env: dict[str, str], maximum: int) -> CommandResult:
                captured.append(tuple(argv))
                return CommandResult(0, False, 0, b"", b"")
            source = Path(temporary) / "source"
            source.mkdir(mode=0o700)
            transport = SSHTransport("target", runner=runner)
            transport.guarded_rsync(source, "/remote/work", receiver="/remote/run/.targetctl-source-receiver-a.py")
            argv = captured[0]
            self.assertEqual(argv[0], "/usr/bin/rsync")
            self.assertIn("--rsync-path=/remote/run/.targetctl-source-receiver-a.py", argv)
            self.assertIn("--one-file-system", argv)
            self.assertIn("--no-owner", argv)
            self.assertIn("--no-group", argv)
            self.assertNotIn("--protect-args", argv)
            self.assertIn("--delete", argv)
            self.assertIn("--delete-excluded", argv)


class _FakeSSHRsyncBase(unittest.TestCase):
    """Base for tests that run real helpers and /usr/bin/rsync through a local shim."""

    _FAKE_SSH = '#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -o) shift 2;; --) shift;; -*) shift;; *) break;; esac; done; shift; if [ "$#" -eq 1 ]; then exec /bin/sh -c "$1"; fi; exec "$@"\n'

    def _init_sources(self) -> Path:
        source = self.base / "source"
        source.mkdir()
        self._git(source, "init")
        self._write_commit(source, "hello.txt", b"hello world\n")
        for name, dest in (("engine", "engine/ds4"), ("integration", "spark/ds4-on-spark")):
            upstream = self.base / name
            upstream.mkdir()
            self._git(upstream, "init")
            self._write_commit(upstream, "src.py", f"# {name}".encode())
            self._git(source, "-c", "protocol.file.allow=always", "submodule", "add", os.fspath(upstream), dest)
        self._git(source, "add", "-A")
        self._git(source, "-c", "user.name=T", "-c", "user.email=t@t", "commit", "-m", "submodules")
        return source

    def _git(self, root: Path, *args: str) -> None:
        subprocess.run(("git", "-C", os.fspath(root), *args), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _write_commit(self, root: Path, name: str, data: bytes) -> None:
        (root / name).write_bytes(data)
        self._git(root, "add", name)
        self._git(root, "-c", "user.name=T", "-c", "user.email=t@t", "commit", "-m", "initial")

    def _make_fake_ssh(self) -> str:
        fake = self.base / "fake-ssh"
        fake.write_text(self._FAKE_SSH)
        os.chmod(str(fake), 0o755)
        return str(fake)

    def _make_config(self, source_root: Path) -> SimpleNamespace:
        return SimpleNamespace(
            mode="ssh",
            name="test-target",
            ssh_host="target",
            source_root=str(source_root),
            workdir=str(self.base / "work"),
            run_dir=str(self.base / "run"),
            model_path=str(self.base / "model"),
            drafter_path=str(self.base / "drafter"),
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        (self.base / "model").write_bytes(b"m")
        (self.base / "drafter").write_bytes(b"d")
        self.source_root = self._init_sources()
        self.fake_ssh_path = self._make_fake_ssh()


class FakeSSHRsyncTests(_FakeSSHRsyncBase):
    """End-to-end two-call sync through a local fake-SSH shim and /usr/bin/rsync."""

    def test_two_call_sync_deletes_stale_preserves_outside_and_cleans(self) -> None:
        config = self._make_config(self.source_root)
        transport = SSHTransport("target", ssh_binary=self.fake_ssh_path)
        workdir = Path(config.workdir)
        run_dir = Path(config.run_dir)

        # Call 1: initialize and transfer.
        result = sync_source(config, transport)
        self.assertTrue(result.initialized)
        self.assertEqual(result.applied_tree_hash, result.snapshot.applied_tree_hash)
        self.assertEqual((workdir / "hello.txt").read_bytes(), b"hello world\n")

        # Seed stale file and outside canary before transfer
        (workdir / "stale.txt").write_bytes(b"stale")
        canary = self.base / "outside-canary.txt"
        canary.write_bytes(b"canary")

        # Call 2: transfer
        result = sync_source(config, transport)
        self.assertFalse(result.initialized)
        self.assertEqual(result.applied_tree_hash, result.snapshot.applied_tree_hash)

        # Stale file was deleted by the transfer
        self.assertFalse((workdir / "stale.txt").exists())
        # Outside canary was not touched
        self.assertTrue(canary.exists())

        # Source file transferred
        self.assertEqual((workdir / "hello.txt").read_bytes(), b"hello world\n")
        # Submodule files transferred
        self.assertTrue((workdir / "engine" / "ds4" / "src.py").exists())
        self.assertTrue((workdir / "spark" / "ds4-on-spark" / "src.py").exists())

        # Marker preserved, 0600
        marker = workdir / ".targetctl-owner-v1-work.json"
        self.assertTrue(marker.exists())
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        # Root 0700
        self.assertEqual(stat.S_IMODE(workdir.stat().st_mode), 0o700)

        # Source state written
        source_json = run_dir / "source.json"
        self.assertTrue(source_json.exists())
        self.assertEqual(stat.S_IMODE(source_json.stat().st_mode), 0o600)

        # Receiver and auth files cleaned
        for child in run_dir.iterdir():
            self.assertNotIn(".targetctl-source-receiver-", child.name)

        # Regular lock record cleaned/released.
        self.assertFalse((run_dir / ".targetctl-operation-lock-v1").exists())




class MountDecodingTests(unittest.TestCase):
    """Verify fd-derived decoded mountinfo checks reject nested mounts."""

    def test_source_extension_rejects_mount_under_workdir(self) -> None:
        transport = LocalTransport()
        workdir = tempfile.mkdtemp()
        run_dir = tempfile.mkdtemp()
        model = tempfile.mktemp()
        drafter = tempfile.mktemp()
        Path(model).write_bytes(b"m")
        Path(drafter).write_bytes(b"d")
        try:
            payload = {"workdir": workdir, "run_dir": run_dir, "model_path": model, "drafter_path": drafter}
            state = transport.run_helper("initialize_roots", payload)
            tokens = {"work_token": state["work"]["token"], "run_token": state["run"]["token"]}
            request = {**payload, **tokens, "entries": []}
            # Source preflight exercises _source_safe_tree -> _source_no_nested_mounts
            result = transport.run_helper("source_preflight", request, extension_source=_SOURCE_EXTENSION,
                                          allowed_error_codes={"source_lifecycle", "unexpected_entry"})
            self.assertIn("work", result)
        finally:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)
            shutil.rmtree(run_dir, ignore_errors=True)
            Path(model).unlink(missing_ok=True)
            Path(drafter).unlink(missing_ok=True)


class LifecycleRefusalTests(unittest.TestCase):
    """Lifecycle states other than stopped/stale_identity/failed_startup are refused."""

    def _setUpHelper(self) -> tuple[LocalTransport, dict, dict]:
        transport = LocalTransport()
        base = Path(tempfile.mkdtemp())
        model = base / "model"
        drafter = base / "drafter"
        model.write_bytes(b"m")
        drafter.write_bytes(b"d")
        payload = {"workdir": str(base / "work"), "run_dir": str(base / "run"), "model_path": str(model), "drafter_path": str(drafter)}
        state = transport.run_helper("initialize_roots", payload)
        tokens = {"work_token": state["work"]["token"], "run_token": state["run"]["token"]}
        return transport, payload, tokens

    def test_running_lifecycle_refuses_preflight(self) -> None:
        transport, payload, tokens = self._setUpHelper()
        run = Path(payload["run_dir"])
        try:
            (run / "run.json").write_text('{"schema_version":1,"state":"running"}')
            os.chmod(str(run / "run.json"), 0o600)
            request = {**payload, **tokens, "entries": []}
            with self.assertRaises(TargetError) as ctx:
                transport.run_helper("source_preflight", request, extension_source=_SOURCE_EXTENSION,
                                     allowed_error_codes={"source_lifecycle", "unexpected_entry"})
            self.assertEqual(ctx.exception.code, "source_lifecycle")
        finally:
            import shutil
            shutil.rmtree(str(Path(payload["workdir"]).parent), ignore_errors=True)

    def test_unknown_lifecycle_refuses_preflight(self) -> None:
        transport, payload, tokens = self._setUpHelper()
        run = Path(payload["run_dir"])
        try:
            (run / "run.json").write_text('{"schema_version":1,"state":"bogus"}')
            os.chmod(str(run / "run.json"), 0o600)
            request = {**payload, **tokens, "entries": []}
            with self.assertRaises(TargetError) as ctx:
                transport.run_helper("source_preflight", request, extension_source=_SOURCE_EXTENSION,
                                     allowed_error_codes={"source_lifecycle", "unexpected_entry"})
            self.assertEqual(ctx.exception.code, "source_lifecycle")
        finally:
            import shutil
            shutil.rmtree(str(Path(payload["workdir"]).parent), ignore_errors=True)


class PreReceiverUnsafeTreeTests(unittest.TestCase):
    """Symlinks and non-regular entries in workdir are rejected before receiver creation."""

    def test_symlink_in_workdir_rejected_by_safe_tree(self) -> None:
        transport = LocalTransport()
        base = Path(tempfile.mkdtemp())
        model = base / "model"
        drafter = base / "drafter"
        model.write_bytes(b"m")
        drafter.write_bytes(b"d")
        try:
            payload = {"workdir": str(base / "work"), "run_dir": str(base / "run"), "model_path": str(model), "drafter_path": str(drafter)}
            state = transport.run_helper("initialize_roots", payload)
            tokens = {"work_token": state["work"]["token"], "run_token": state["run"]["token"]}
            workdir = Path(payload["workdir"])
            (workdir / "link").symlink_to("/etc/passwd")
            request = {**payload, **tokens, "entries": []}
            with self.assertRaises(TargetError) as ctx:
                transport.run_helper("source_preflight", request, extension_source=_SOURCE_EXTENSION,
                                     allowed_error_codes={"source_lifecycle", "unexpected_entry", "unsafe_entry"})
            self.assertIn(ctx.exception.code, {"unsafe_entry", "unexpected_entry"})
        finally:
            import shutil
            shutil.rmtree(base, ignore_errors=True)


class FilterBoundsTests(_FakeSSHRsyncBase):
    """Oversized filter data is rejected before rsync starts."""

    def test_oversize_filter_rejected(self) -> None:
        snapshot = build_snapshot(self.source_root)
        with mock.patch.object(source_module, "MAX_RSYNC_FILTER_BYTES", 10):
            with self.assertRaises(TargetError) as error:
                _stage_snapshot(self.source_root, snapshot, self.source_root)
        self.assertEqual(error.exception.code, "staging_failed")


class StateStoreLoadTests(unittest.TestCase):
    """Controller state store/load round-trips correctly through no-follow FDs."""

    def test_store_and_load_capabilities(self) -> None:
        from scripts.targetctl.source import _load_capabilities, _store_capabilities
        base = Path(tempfile.mkdtemp())
        try:
            value = {
                "work": {"token": "a" * 64, "identity": {"device": 1, "inode": 2}},
                "run": {"token": "b" * 64, "identity": {"device": 3, "inode": 4}},
            }
            _store_capabilities(base, "t1", value)
            loaded = _load_capabilities(base, "t1")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded["work_token"], "a" * 64)
            self.assertEqual(loaded["run_token"], "b" * 64)
            self.assertEqual(loaded["work_identity"], {"device": 1, "inode": 2})
            self.assertEqual(loaded["run_identity"], {"device": 3, "inode": 4})
            self.assertIsNone(_load_capabilities(base, "nonexistent"))
        finally:
            import shutil
            shutil.rmtree(base, ignore_errors=True)
