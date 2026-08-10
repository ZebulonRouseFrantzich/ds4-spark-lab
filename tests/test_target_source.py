from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import signal
import subprocess
import tempfile
import unittest
import time
from types import SimpleNamespace
from unittest import mock

from scripts.targetctl import source as source_module
from scripts.targetctl.common import TargetError, record_id_for
from scripts.targetctl.source import _SOURCE_EXTENSION, _stage_snapshot, build_snapshot, qualified_clean, sync_source, verify_applied_tree
from scripts.targetctl.remote import LAUNCH_PROFILE, _valid_launch_profile, _valid_run_state
from scripts.targetctl.transport import CommandResult, LocalTransport, SSHTransport


def _launch_profile(**changes: object) -> dict[str, object]:
    profile = {
        **LAUNCH_PROFILE,
        "speculative_overrides": dict(LAUNCH_PROFILE["speculative_overrides"]),
    }
    profile.update(changes)
    return profile


def _run_state(
    *,
    state: str = "failed_startup",
    cleanup_complete: bool = False,
    launch_profile: dict[str, object] | None = None,
) -> dict[str, object]:
    active = state == "running"
    return {
        "schema_version": 1,
        "run_id": "run-aaaaaaaaaaaaaaaaaaaaaaaa",
        "state": state,
        "source_snapshot_id": "1" * 64,
        "applied_tree_hash": "2" * 64,
        "build_id": "3" * 64,
        "binary_sha256": "4" * 64,
        "port": 8000,
        "launch_profile": (
            _launch_profile() if launch_profile is None else launch_profile
        ),
        "supervisor_pid": 101 if active else None,
        "supervisor_start_ticks": 1001 if active else None,
        "supervisor_cmdline_sha256": "5" * 64 if active else None,
        "child_pid": 102 if active else None,
        "child_start_ticks": 1002 if active else None,
        "child_pgid": 102 if active else None,
        "child_cmdline_sha256": "6" * 64 if active else None,
        "listener_inode": "12345" if active else None,
        "cleanup_complete": cleanup_complete,
        "cleanup": (
            {
                "process": "not_found",
                "socket": "not_found",
                "lock": "not_found",
                "temp": "not_found",
                "server_log_sha256": None,
            }
            if cleanup_complete
            else None
        ),
    }


class RunStateLaunchProfileTests(unittest.TestCase):
    def test_every_bounded_schema_v2_profile_is_valid(self) -> None:
        for context_tokens in (32768, 262144):
            for bind in ("loopback", "private_lan"):
                for decode_policy in ("shipped", "plain"):
                    profile = _launch_profile(
                        context_tokens=context_tokens,
                        bind=bind,
                        decode_policy=decode_policy,
                    )
                    with self.subTest(
                        context_tokens=context_tokens,
                        bind=bind,
                        decode_policy=decode_policy,
                    ):
                        self.assertTrue(_valid_launch_profile(profile))
                        self.assertTrue(
                            _valid_run_state(
                                _run_state(
                                    cleanup_complete=True,
                                    launch_profile=profile,
                                ),
                                terminal=True,
                            )
                        )

    def test_missing_extra_legacy_and_type_invalid_profiles_are_rejected(self) -> None:
        missing = _launch_profile()
        missing.pop("decode_policy")
        nested_missing = _launch_profile()
        nested_missing["speculative_overrides"].pop("shadow_budget")  # type: ignore[union-attr]
        malformed = (
            {
                "schema_version": 1,
                "accelerator": "cuda",
                "context_tokens": 32768,
                "bind": "loopback",
                "continuation_mtp_mode": 2,
                "dspark_enabled": True,
                "drafter_enabled": True,
            },
            missing,
            {**_launch_profile(), "unknown": None},
            _launch_profile(dspark_max_nlive=True),
            _launch_profile(context_tokens=65536),
            _launch_profile(terminal_yield_quench=1),
            nested_missing,
            _launch_profile(
                speculative_overrides={
                    **LAUNCH_PROFILE["speculative_overrides"],
                    "unknown": None,
                }
            ),
            _launch_profile(
                speculative_overrides={
                    **LAUNCH_PROFILE["speculative_overrides"],
                    "shadow_guard": False,
                }
            ),
        )
        for profile in malformed:
            with self.subTest(profile=profile):
                self.assertFalse(_valid_launch_profile(profile))
                self.assertFalse(
                    _valid_run_state(
                        _run_state(
                            cleanup_complete=True,
                            launch_profile=profile,
                        ),
                        terminal=True,
                    )
                )


def _active_build_manifest(
    snapshot_id: str,
    applied_tree_hash: str,
    binary: bytes,
    *,
    sass_identity: str = "sm_121a",
) -> dict[str, object]:
    binary_hash = hashlib.sha256(binary).hexdigest()
    version = "1.2.3"
    identity = {
        "schema_version": 1,
        "source_snapshot_id": snapshot_id,
        "source_applied_tree_hash": applied_tree_hash,
        "binary_sha256": binary_hash,
        "version": version,
        "binary_size": len(binary),
        "sass": sass_identity,
    }
    return {
        "schema_version": 1,
        "record_type": "build",
        "source_snapshot_id": snapshot_id,
        "source_applied_tree_hash": applied_tree_hash,
        "build_id": record_id_for(identity),
        "binary_sha256": binary_hash,
        "binary_size": len(binary),
        "version": version,
        "sass": "verified",
        "build_log_sha256": hashlib.sha256(b"successful build\n").hexdigest(),
        "exit_code": 0,
        "duration_ns": 1,
    }


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
        (run / "run.json").write_text(
            json.dumps(_run_state(state="running")),
            encoding="ascii",
        )
        os.chmod(run / "run.json", 0o600)
        request = {**self.payload, **self.tokens, "entries": []}
        with self.assertRaises(TargetError) as error:
            self.transport.run_helper("source_preflight", request, extension_source=_SOURCE_EXTENSION, allowed_error_codes={"source_lifecycle", "unexpected_entry"})
        self.assertEqual(error.exception.code, "source_lifecycle")

    def test_source_state_refuses_non_active_or_multiply_linked_build_manifest(self) -> None:
        run = Path(self.payload["run_dir"])
        build_path = run / "build.json"
        lock = self.transport.run_helper(
            "acquire_lock",
            {"run_dir": self.payload["run_dir"], "run_token": self.tokens["run_token"], "lease_seconds": 60},
        )
        request = {
            "run_dir": self.payload["run_dir"],
            "run_token": self.tokens["run_token"],
            "lock_token": lock["lock_token"],
            "snapshot_id": "1" * 64,
            "applied_tree_hash": "2" * 64,
            "dirty": False,
        }
        try:
            malformed = b'{"record_type":"build-attempt","schema_version":1}'
            build_path.write_bytes(malformed)
            os.chmod(build_path, 0o600)
            with self.assertRaises(TargetError) as malformed_error:
                self.transport.run_helper(
                    "source_write_state",
                    request,
                    extension_source=_SOURCE_EXTENSION,
                    allowed_error_codes={"unsafe_state", "unsafe_lock"},
                )
            self.assertEqual(malformed_error.exception.code, "unsafe_state")
            self.assertEqual(build_path.read_bytes(), malformed)
            self.assertFalse((run / "source.json").exists())

            build_path.unlink()
            legacy = _active_build_manifest(
                "1" * 64, "2" * 64, b"binary", sass_identity="sm_121",
            )
            legacy_raw = json.dumps(
                legacy, sort_keys=True, separators=(",", ":"),
            ).encode("ascii")
            build_path.write_bytes(legacy_raw)
            os.chmod(build_path, 0o600)
            with self.assertRaises(TargetError) as legacy_error:
                self.transport.run_helper(
                    "source_write_state",
                    request,
                    extension_source=_SOURCE_EXTENSION,
                    allowed_error_codes={"unsafe_state", "unsafe_lock"},
                )
            self.assertEqual(legacy_error.exception.code, "unsafe_state")
            self.assertEqual(build_path.read_bytes(), legacy_raw)
            self.assertFalse((run / "source.json").exists())
            build_path.unlink()
            active = _active_build_manifest("1" * 64, "2" * 64, b"binary")
            active_raw = json.dumps(active, sort_keys=True, separators=(",", ":")).encode("ascii")
            build_path.write_bytes(active_raw)
            os.chmod(build_path, 0o600)
            linked = run / "build-link-canary"
            os.link(build_path, linked)
            with self.assertRaises(TargetError) as linked_error:
                self.transport.run_helper(
                    "source_write_state",
                    request,
                    extension_source=_SOURCE_EXTENSION,
                    allowed_error_codes={"unsafe_state", "unsafe_lock"},
                )
            self.assertEqual(linked_error.exception.code, "unsafe_state")
            self.assertEqual(build_path.read_bytes(), active_raw)
            self.assertEqual(linked.read_bytes(), active_raw)
            self.assertFalse((run / "source.json").exists())
            self.assertTrue((run / ".targetctl-operation-lock-v1").exists())
        finally:
            self.transport.run_helper(
                "release_lock",
                {
                    "run_dir": self.payload["run_dir"],
                    "run_token": self.tokens["run_token"],
                    "lock_token": lock["lock_token"],
                },
            )
        self.assertFalse((run / ".targetctl-operation-lock-v1").exists())
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
        self._write_commit(source, ".gitignore", b"/targets/\n")
        self._write_commit(source, "hello.txt", b"hello world\n")
        for name, dest in (("engine", "engine/ds4"), ("integration", "spark/ds4-on-spark")):
            upstream = self.base / name
            upstream.mkdir()
            self._git(upstream, "init")
            self._write_commit(upstream, "src.py", f"# {name}".encode())
            if name == "engine":
                self._write_commit(upstream, ".gitignore", b"/ds4-server\n")
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
        real_run_helper = transport.run_helper
        milestones: list[str] = []
        completed_reports: list[dict[str, object]] = []
        released_locks: list[bool] = []
        build_invalidations: list[bool] = []
        acquired_lock_tokens: list[str] = []

        def traced_helper(action: str, *args: object, **kwargs: object) -> object:
            if action in {
                "source_receiver_postflight",
                "source_verify",
                "source_write_state",
                "source_complete_receiver",
                "release_lock",
            }:
                milestones.append(action)
            if action in {"source_write_state", "release_lock"}:
                payload = args[0]
                self.assertIsInstance(payload, dict)
                assert isinstance(payload, dict)
                self.assertEqual(payload["lock_token"], acquired_lock_tokens[-1])
            if action == "source_complete_receiver":
                payload = args[0]
                self.assertIsInstance(payload, dict)
                assert isinstance(payload, dict)
                report_path = Path(str(payload["receiver"])).with_suffix(".report.json")
                report = json.loads(report_path.read_text(encoding="ascii"))
                self.assertEqual(report["snapshot_id"], payload["snapshot_id"])
                self.assertEqual(report["applied_tree_hash"], payload["applied_tree_hash"])
                self.assertTrue(report["child_group_gone"])
                self.assertFalse(any("token" in key for key in report))
                self.assertTrue((run_dir / ".targetctl-operation-lock-v1").exists())
                self.assertEqual(
                    json.loads((run_dir / "source.json").read_text(encoding="ascii")),
                    {
                        "schema_version": 1,
                        "snapshot_id": payload["snapshot_id"],
                        "applied_tree_hash": payload["applied_tree_hash"],
                        "dirty": False,
                    },
                )
                completed_reports.append(report)
            if action == "release_lock":
                self.assertEqual(list(run_dir.glob(".targetctl-source-receiver-*")), [])
                self.assertTrue((run_dir / ".targetctl-operation-lock-v1").exists())
            result = real_run_helper(action, *args, **kwargs)
            if action == "acquire_lock":
                self.assertIsInstance(result, dict)
                assert isinstance(result, dict)
                acquired_lock_tokens.append(result["lock_token"])
            if action == "source_write_state":
                self.assertIsInstance(result, dict)
                assert isinstance(result, dict)
                self.assertEqual(set(result), {"stored", "build_invalidated"})
                build_invalidations.append(result["build_invalidated"])
            if action == "release_lock":
                released_locks.append(not (run_dir / ".targetctl-operation-lock-v1").exists())
            return result

        with mock.patch.object(transport, "run_helper", side_effect=traced_helper):
            # Call 1: initialize and transfer.
            first = sync_source(config, transport)
            self.assertTrue(first.initialized)
            self.assertEqual(first.applied_tree_hash, first.snapshot.applied_tree_hash)
            self.assertEqual((workdir / "hello.txt").read_bytes(), b"hello world\n")

            # Seed stale file and outside canary before transfer.
            (workdir / "stale.txt").write_bytes(b"stale")
            canary = self.base / "outside-canary.txt"
            canary.write_bytes(b"canary")
            ignored_binary = workdir / "engine" / "ds4" / "ds4-server"
            binary_bytes = b"ignored generated executable\n"
            ignored_binary.write_bytes(binary_bytes)
            os.chmod(ignored_binary, 0o700)
            self.assertNotIn("engine/ds4/ds4-server", {entry.path for entry in first.snapshot.entries})
            active_build_path = run_dir / "build.json"
            active_build = _active_build_manifest(first.snapshot.snapshot_id, first.applied_tree_hash, binary_bytes)
            active_build_path.write_text(json.dumps(active_build, sort_keys=True, separators=(",", ":")), encoding="ascii")
            os.chmod(active_build_path, 0o600)

            attempt_id = "a" * 64
            attempt_log = b"later build failed\n"
            attempt_report = {
                "schema_version": 1,
                "record_type": "build-attempt",
                "attempt_id": attempt_id,
                "status": "failed",
                "failure_class": "command_failed",
                "source_snapshot_id": first.snapshot.snapshot_id,
                "source_applied_tree_hash": first.applied_tree_hash,
                "build_id": None,
                "binary_sha256": None,
                "command": "make-cuda-spark",
                "version": None,
                "binary_size": None,
                "sass": None,
                "build_log_sha256": hashlib.sha256(attempt_log).hexdigest(),
                "exit_code": 2,
                "duration_ns": 1,
            }
            attempt_report_raw = json.dumps(attempt_report, sort_keys=True, separators=(",", ":")).encode("ascii")
            attempt_commit = {
                "schema_version": 1,
                "record_type": "build-attempt-commit",
                "attempt_id": attempt_id,
                "attempt_report_sha256": hashlib.sha256(attempt_report_raw).hexdigest(),
                "attempt_log_sha256": hashlib.sha256(attempt_log).hexdigest(),
            }
            attempt_stem = ".targetctl-build-attempt-v1-" + attempt_id
            attempt_evidence = {
                attempt_stem + ".json": attempt_report_raw,
                attempt_stem + ".log": attempt_log,
                attempt_stem + ".commit.json": json.dumps(attempt_commit, sort_keys=True, separators=(",", ":")).encode("ascii"),
            }
            for name, content in attempt_evidence.items():
                path = run_dir / name
                path.write_bytes(content)
                os.chmod(path, 0o600)

            # Call 2: transfer the same exact clean snapshot.
            second = sync_source(config, transport)
            self.assertFalse(second.initialized)
            self.assertEqual(second.snapshot.snapshot_id, first.snapshot.snapshot_id)
            self.assertEqual(second.applied_tree_hash, first.applied_tree_hash)
            self.assertEqual(second.applied_tree_hash, second.snapshot.applied_tree_hash)

        self.assertEqual(
            milestones,
            [
                "source_receiver_postflight",
                "source_verify",
                "source_write_state",
                "source_complete_receiver",
                "release_lock",
            ] * 2,
        )
        self.assertEqual(len(completed_reports), 2)
        self.assertEqual(released_locks, [True, True])
        self.assertEqual(build_invalidations, [False, True])

        # Stale file was deleted by the transfer.
        self.assertFalse((workdir / "stale.txt").exists())
        # Outside canary was not touched.
        self.assertTrue(canary.exists())
        # The same-snapshot transfer removed the ignored executable, and the
        # lease-pinned source commit removed only its active successful build.
        self.assertFalse(ignored_binary.exists())
        self.assertFalse(active_build_path.exists())
        for name, content in attempt_evidence.items():
            self.assertEqual((run_dir / name).read_bytes(), content)

        # Source and submodule files transferred.
        self.assertEqual((workdir / "hello.txt").read_bytes(), b"hello world\n")
        self.assertTrue((workdir / "engine" / "ds4" / "src.py").exists())
        self.assertTrue((workdir / "spark" / "ds4-on-spark" / "src.py").exists())

        # Marker preserved, 0600, and root preserved, 0700.
        marker = workdir / ".targetctl-owner-v1-work.json"
        self.assertTrue(marker.exists())
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(workdir.stat().st_mode), 0o700)

        # Exact source state was written before receiver completion.
        source_json = run_dir / "source.json"
        self.assertTrue(source_json.exists())
        self.assertEqual(stat.S_IMODE(source_json.stat().st_mode), 0o600)
        self.assertEqual(
            json.loads(source_json.read_text(encoding="ascii")),
            {
                "schema_version": 1,
                "snapshot_id": second.snapshot.snapshot_id,
                "applied_tree_hash": second.applied_tree_hash,
                "dirty": False,
            },
        )

        # Receiver, authority, exact private report, and fresh lock were cleaned.
        self.assertEqual(list(run_dir.glob(".targetctl-source-receiver-*")), [])
        self.assertFalse((run_dir / ".targetctl-operation-lock-v1").exists())

    def test_ambiguous_dispatch_keeps_target_owned_lease_until_child_exit(self) -> None:
        config = self._make_config(self.source_root)
        transport = SSHTransport("target", ssh_binary=self.fake_ssh_path)
        actions: list[str] = []
        process: subprocess.Popen[bytes] | None = None
        planted_marker = self.base / "planted-import-ran"
        real_run_helper = transport.run_helper

        def record_helper(action: str, *args: object, **kwargs: object) -> object:
            actions.append(action)
            return real_run_helper(action, *args, **kwargs)

        def lose_response(
            source_root: Path,
            remote_workdir: str,
            *,
            receiver: str,
            filters: object = (),
            filter_file: Path | None = None,
            timeout: float | None = 300.0,
        ) -> None:
            nonlocal process
            del source_root, filters, filter_file, timeout
            run_dir = Path(config.run_dir)
            for module in ("hashlib.py", "hmac.py", "json.py"):
                (run_dir / module).write_text(
                    f'open({os.fspath(planted_marker)!r}, "ab").write({module.encode()!r})\n'
                    'raise RuntimeError("writable run_dir import executed")\n'
                )
            process = subprocess.Popen(
                (
                    receiver,
                    "--server",
                    "-tprxe.iLsfxCIvu",
                    "--delete-excluded",
                    ".",
                    remote_workdir + "/",
                ),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            auth_path = Path(receiver).with_suffix(".json")
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                try:
                    owner = json.loads(auth_path.read_text(encoding="ascii"))
                except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError):
                    time.sleep(0.02)
                    continue
                if owner.get("phase") == "running" and owner.get("child_pid", 0) > 0:
                    break
                time.sleep(0.02)
            else:
                self.fail("target receiver did not assume the transfer lease")
            self.assertFalse(planted_marker.exists())
            raise TargetError("rsync_timeout", "simulated response loss")

        try:
            with (
                mock.patch.object(transport, "run_helper", side_effect=record_helper),
                mock.patch.object(transport, "guarded_rsync", side_effect=lose_response),
            ):
                with self.assertRaises(TargetError) as error:
                    sync_source(config, transport)
                self.assertEqual(error.exception.code, "rsync_timeout")
                self.assertIsNotNone(process)
                self.assertIsNone(process.poll())
                self.assertFalse(planted_marker.exists())
                self.assertNotIn("source_cleanup_receiver", actions)
                self.assertNotIn("release_lock", actions)

                with self.assertRaises(TargetError) as busy:
                    sync_source(config, transport)
                self.assertEqual(busy.exception.code, "lock_busy")
                self.assertIsNone(process.poll())
                self.assertNotIn("source_cleanup_receiver", actions)
                self.assertNotIn("release_lock", actions)

            process.send_signal(signal.SIGHUP)
            process.wait(timeout=10.0)
            run_dir = Path(config.run_dir)
            self.assertFalse((run_dir / ".targetctl-operation-lock-v1").exists())
            self.assertFalse(Path(process.args[0]).exists())
            self.assertFalse(Path(process.args[0]).with_suffix(".json").exists())
            reports = list(run_dir.glob(".targetctl-source-receiver-*.report.json"))
            self.assertEqual(len(reports), 1)
            report = json.loads(reports[0].read_text(encoding="ascii"))
            self.assertTrue(report["child_group_gone"])
            self.assertFalse(any("token" in key for key in report))
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10.0)
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()




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
    """Source mutation requires an absent run or completed terminal cleanup."""
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
            (run / "run.json").write_text(
                json.dumps(_run_state(state="running")),
                encoding="ascii",
            )
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

    def test_embedded_preflight_rejects_malformed_schema_v2_profile(self) -> None:
        transport, payload, tokens = self._setUpHelper()
        run = Path(payload["run_dir"])
        state = _run_state(
            cleanup_complete=True,
            launch_profile=_launch_profile(context_tokens=65536),
        )
        encoded = json.dumps(state)
        request = {**payload, **tokens, "entries": []}
        try:
            (run / "run.json").write_text(encoded, encoding="ascii")
            os.chmod(run / "run.json", 0o600)
            with self.assertRaises(TargetError) as raised:
                transport.run_helper(
                    "source_preflight",
                    request,
                    extension_source=_SOURCE_EXTENSION,
                    allowed_error_codes={"source_lifecycle", "unexpected_entry"},
                )
            self.assertEqual(raised.exception.code, "source_lifecycle")
            self.assertEqual(
                (run / "run.json").read_text(encoding="ascii"),
                encoded,
            )
        finally:
            import shutil
            shutil.rmtree(str(Path(payload["workdir"]).parent), ignore_errors=True)

    def test_terminal_lifecycle_requires_completed_cleanup(self) -> None:
        transport, payload, tokens = self._setUpHelper()
        run = Path(payload["run_dir"])
        state = _run_state()
        request = {**payload, **tokens, "entries": []}
        try:
            (run / "run.json").write_text(json.dumps(state), encoding="ascii")
            os.chmod(run / "run.json", 0o600)
            with self.assertRaises(TargetError) as raised:
                transport.run_helper(
                    "source_preflight", request,
                    extension_source=_SOURCE_EXTENSION,
                    allowed_error_codes={"source_lifecycle", "unexpected_entry"},
                )
            self.assertEqual(raised.exception.code, "source_lifecycle")
            state["cleanup_complete"] = True
            state["cleanup"] = {
                "process": "not_found",
                "socket": "not_found",
                "lock": "not_found",
                "temp": "not_found",
                "server_log_sha256": None,
            }
            (run / "run.json").write_text(json.dumps(state), encoding="ascii")
            result = transport.run_helper(
                "source_preflight", request,
                extension_source=_SOURCE_EXTENSION,
                allowed_error_codes={"source_lifecycle", "unexpected_entry"},
            )
            self.assertEqual(set(result), {"work", "run"})
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
