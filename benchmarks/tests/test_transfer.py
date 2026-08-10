from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from ds4bench.artifacts import RESULT_FILES
from ds4bench.stats import canonical_json_bytes
from ds4bench.transfer import (
    MAX_RUNTIME_FILE_BYTES,
    RUNTIME_MANIFEST_NAME,
    PromotionResult,
    TransferError,
    create_transfer_manifest,
    framed_aggregate_sha256,
    load_transfer_manifest,
    promote_verified_payload,
    validate_transfer_manifest,
    verify_transfer,
    write_transfer_manifest,
)

_LOCK_HASH = "a" * 64


def _runtime_payload(path: Path, *, bundle: bytes = b"zipapp", licenses: bytes = b"{}\n") -> None:
    path.mkdir()
    (path / "ds4bench.pyz").write_bytes(bundle)
    (path / "licenses.json").write_bytes(licenses)


def _result_payload(path: Path, *, requests_size: int = 32) -> None:
    path.mkdir()
    for name in RESULT_FILES:
        payload = (name + "\n").encode()
        if name == "requests.jsonl":
            payload = b"r" * requests_size
        (path / name).write_bytes(payload)


class ManifestTests(unittest.TestCase):
    def test_runtime_manifest_is_canonical_sorted_and_non_self_referential(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            _runtime_payload(payload)
            sidecar = write_transfer_manifest(
                payload,
                root / RUNTIME_MANIFEST_NAME,
                kind="runtime",
                run_id="runtime-1",
                lock_sha256=_LOCK_HASH,
            )

            self.assertEqual(sidecar.path.read_bytes(), canonical_json_bytes(sidecar.manifest))
            self.assertEqual(sidecar.sha256, hashlib.sha256(sidecar.path.read_bytes()).hexdigest())
            self.assertEqual(
                [entry["path"] for entry in sidecar.manifest["entries"]],
                ["ds4bench.pyz", "licenses.json"],
            )
            self.assertNotIn(RUNTIME_MANIFEST_NAME, [entry["path"] for entry in sidecar.manifest["entries"]])
            self.assertEqual(
                sidecar.manifest["aggregate_sha256"],
                framed_aggregate_sha256(sidecar.manifest["entries"]),
            )
            loaded = load_transfer_manifest(sidecar.path, sidecar.sha256)
            self.assertEqual(loaded, sidecar.manifest)

    def test_result_manifest_accepts_requests_larger_than_helper_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "result-stage"
            _result_payload(payload, requests_size=1024 * 1024 + 257)
            sidecar = write_transfer_manifest(
                payload,
                root / "result-manifest.json",
                kind="result",
                run_id="run-1",
                lock_sha256=_LOCK_HASH,
            )
            verified = verify_transfer(
                payload,
                sidecar.path,
                sidecar.sha256,
                expected_kind="result",
                expected_run_id="run-1",
                expected_lock_sha256=_LOCK_HASH,
            )
            requests = next(entry for entry in verified["entries"] if entry["path"] == "requests.jsonl")
            self.assertGreater(requests["size"], 1024 * 1024)

    def test_exact_schema_path_order_and_aggregate_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            _runtime_payload(payload)
            manifest = create_transfer_manifest(
                payload,
                kind="runtime",
                run_id="runtime-1",
                lock_sha256=_LOCK_HASH,
            )

            unknown = copy.deepcopy(manifest)
            unknown["extra"] = None
            with self.assertRaisesRegex(TransferError, "manifest_fields"):
                validate_transfer_manifest(unknown)

            traversal = copy.deepcopy(manifest)
            traversal["entries"][0]["path"] = "../ds4bench.pyz"
            with self.assertRaisesRegex(TransferError, "unsafe_payload_path"):
                validate_transfer_manifest(traversal)

            absolute = copy.deepcopy(manifest)
            absolute["entries"][0]["path"] = "/ds4bench.pyz"
            with self.assertRaisesRegex(TransferError, "unsafe_payload_path"):
                validate_transfer_manifest(absolute)

            non_ascii = copy.deepcopy(manifest)
            non_ascii["entries"][0]["path"] = "d	s4bench.pyz"
            with self.assertRaisesRegex(TransferError, "unsafe_payload_path"):
                validate_transfer_manifest(non_ascii)

            unsorted = copy.deepcopy(manifest)
            unsorted["entries"].reverse()
            with self.assertRaisesRegex(TransferError, "entries_not_sorted"):
                validate_transfer_manifest(unsorted)

            changed_hash = copy.deepcopy(manifest)
            changed_hash["entries"][0]["sha256"] = "b" * 64
            with self.assertRaisesRegex(TransferError, "aggregate_sha256_mismatch"):
                validate_transfer_manifest(changed_hash)

    def test_expected_sidecar_hash_is_checked_before_manifest_is_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            _runtime_payload(payload)
            sidecar = write_transfer_manifest(
                payload,
                root / RUNTIME_MANIFEST_NAME,
                kind="runtime",
                run_id="runtime-1",
                lock_sha256=_LOCK_HASH,
            )
            with self.assertRaisesRegex(TransferError, "sidecar_sha256_mismatch"):
                load_transfer_manifest(sidecar.path, "0" * 64)

            value = json.loads(sidecar.path.read_bytes())
            sidecar.path.write_bytes(json.dumps(value, indent=2).encode())
            changed_sidecar_hash = hashlib.sha256(sidecar.path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(TransferError, "sidecar_not_canonical"):
                load_transfer_manifest(sidecar.path, changed_sidecar_hash)

    def test_sidecar_must_be_outside_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            _runtime_payload(payload)
            with self.assertRaisesRegex(TransferError, "sidecar_inside_payload"):
                write_transfer_manifest(
                    payload,
                    payload / RUNTIME_MANIFEST_NAME,
                    kind="runtime",
                    run_id="runtime-1",
                    lock_sha256=_LOCK_HASH,
                )


class VerificationBoundaryTests(unittest.TestCase):
    def test_payload_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            _runtime_payload(payload)
            sidecar = write_transfer_manifest(
                payload,
                root / RUNTIME_MANIFEST_NAME,
                kind="runtime",
                run_id="runtime-1",
                lock_sha256=_LOCK_HASH,
            )
            (payload / "ds4bench.pyz").write_bytes(b"changed")
            with self.assertRaisesRegex(TransferError, "payload_manifest_mismatch"):
                verify_transfer(payload, sidecar.path, sidecar.sha256)

    def test_per_file_bounds_are_enforced_before_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "runtime"
            _runtime_payload(payload)
            with (payload / "ds4bench.pyz").open("wb") as stream:
                stream.truncate(MAX_RUNTIME_FILE_BYTES + 1)
            with self.assertRaisesRegex(TransferError, "file_size_limit:ds4bench.pyz"):
                create_transfer_manifest(
                    payload,
                    kind="runtime",
                    run_id="runtime-1",
                    lock_sha256=_LOCK_HASH,
                )

            result = root / "result"
            _result_payload(result)
            with (result / "server.log").open("wb") as stream:
                stream.truncate(1024 * 1024 + 1)
            with self.assertRaisesRegex(TransferError, "file_size_limit:server.log"):
                create_transfer_manifest(
                    result,
                    kind="result",
                    run_id="run-1",
                    lock_sha256=_LOCK_HASH,
                )

    def test_missing_and_extra_payload_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / "missing"
            _runtime_payload(missing)
            (missing / "licenses.json").unlink()
            with self.assertRaisesRegex(TransferError, "runtime_file_set"):
                create_transfer_manifest(
                    missing,
                    kind="runtime",
                    run_id="runtime-1",
                    lock_sha256=_LOCK_HASH,
                )

            extra = root / "extra"
            _runtime_payload(extra)
            (extra / "manifest.json").write_bytes(b"self")
            with self.assertRaisesRegex(TransferError, "runtime_file_set"):
                create_transfer_manifest(
                    extra,
                    kind="runtime",
                    run_id="runtime-1",
                    lock_sha256=_LOCK_HASH,
                )

    def test_symlink_hardlink_and_special_file_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            symlinked = root / "symlinked"
            _runtime_payload(symlinked)
            (symlinked / "licenses.json").unlink()
            (symlinked / "licenses.json").symlink_to(symlinked / "ds4bench.pyz")
            with self.assertRaisesRegex(TransferError, "invalid_payload_file"):
                create_transfer_manifest(
                    symlinked,
                    kind="runtime",
                    run_id="runtime-1",
                    lock_sha256=_LOCK_HASH,
                )

            hardlinked = root / "hardlinked"
            _runtime_payload(hardlinked)
            external = root / "external-license"
            external.write_bytes(b"{}\n")
            (hardlinked / "licenses.json").unlink()
            os.link(external, hardlinked / "licenses.json")
            with self.assertRaisesRegex(TransferError, "invalid_payload_file"):
                create_transfer_manifest(
                    hardlinked,
                    kind="runtime",
                    run_id="runtime-1",
                    lock_sha256=_LOCK_HASH,
                )

            special = root / "special"
            _runtime_payload(special)
            (special / "licenses.json").unlink()
            os.mkfifo(special / "licenses.json")
            with self.assertRaisesRegex(TransferError, "invalid_payload_file"):
                create_transfer_manifest(
                    special,
                    kind="runtime",
                    run_id="runtime-1",
                    lock_sha256=_LOCK_HASH,
                )


class PromotionTests(unittest.TestCase):
    def test_verified_stage_is_atomically_promoted_and_equal_retry_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "stage-one"
            _runtime_payload(staging)
            sidecar = write_transfer_manifest(
                staging,
                root / RUNTIME_MANIFEST_NAME,
                kind="runtime",
                run_id="runtime-1",
                lock_sha256=_LOCK_HASH,
            )
            destination = root / "runtime-final"
            first = promote_verified_payload(
                staging,
                destination,
                sidecar.path,
                sidecar.sha256,
                expected_kind="runtime",
                expected_run_id="runtime-1",
                expected_lock_sha256=_LOCK_HASH,
            )
            self.assertEqual(
                first,
                PromotionResult(
                    path=destination,
                    promoted=True,
                    manifest_sha256=sidecar.sha256,
                ),
            )
            self.assertFalse(staging.exists())
            verify_transfer(destination, sidecar.path, sidecar.sha256)

            retry_stage = root / "stage-two"
            _runtime_payload(retry_stage)
            second = promote_verified_payload(
                retry_stage,
                destination,
                sidecar.path,
                sidecar.sha256,
            )
            self.assertFalse(second.promoted)
            self.assertFalse(retry_stage.exists())
            verify_transfer(destination, sidecar.path, sidecar.sha256)

    def test_unequal_existing_destination_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "stage"
            _runtime_payload(staging)
            sidecar = write_transfer_manifest(
                staging,
                root / RUNTIME_MANIFEST_NAME,
                kind="runtime",
                run_id="runtime-1",
                lock_sha256=_LOCK_HASH,
            )
            destination = root / "destination"
            _runtime_payload(destination, bundle=b"different")
            with self.assertRaisesRegex(TransferError, "payload_manifest_mismatch"):
                promote_verified_payload(
                    staging,
                    destination,
                    sidecar.path,
                    sidecar.sha256,
                )
            self.assertTrue(staging.is_dir())
            self.assertEqual((destination / "ds4bench.pyz").read_bytes(), b"different")

    def test_tampered_stage_is_not_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "stage"
            _runtime_payload(staging)
            sidecar = write_transfer_manifest(
                staging,
                root / RUNTIME_MANIFEST_NAME,
                kind="runtime",
                run_id="runtime-1",
                lock_sha256=_LOCK_HASH,
            )
            (staging / "licenses.json").write_bytes(b"tampered\n")
            destination = root / "destination"
            with self.assertRaisesRegex(TransferError, "payload_manifest_mismatch"):
                promote_verified_payload(
                    staging,
                    destination,
                    sidecar.path,
                    sidecar.sha256,
                )
            self.assertTrue(staging.is_dir())
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
