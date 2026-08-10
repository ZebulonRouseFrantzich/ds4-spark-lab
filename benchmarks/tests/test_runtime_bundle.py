from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from ds4bench.runtime_bundle import (
    BUNDLE_NAME,
    LICENSE_INVENTORY_NAME,
    UV_TIMEOUT_SECONDS,
    ZIP_TIMESTAMP,
    RuntimeBundleError,
    assemble_runtime_payload,
    build_runtime_bundle,
)
from ds4bench.stats import canonical_json_bytes
from ds4bench.transfer import RUNTIME_MANIFEST_NAME, verify_transfer


_ARCHIVE_HASH = "a" * 64


def _record_field(payload: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")


def _write_distribution(
    site: Path,
    name: str,
    version: str,
    *,
    tag: str = "py3-none-any",
    license_expression: str = "MIT",
) -> None:
    import_name = name.replace("-", "_")
    dist_name = import_name
    dist_info = site / f"{dist_name}-{version}.dist-info"
    package = site / import_name
    license_path = dist_info / "licenses" / "LICENSE.txt"
    package.mkdir(parents=True)
    license_path.parent.mkdir(parents=True)
    files = {
        f"{import_name}/__init__.py": f'__version__ = "{version}"\n'.encode(),
        f"{import_name}/__pycache__/ignored.pyc": b"bytecode-is-not-runtime-input",
        f"{dist_info.name}/METADATA": (
            "Metadata-Version: 2.4\n"
            f"Name: {name}\n"
            f"Version: {version}\n"
            f"License-Expression: {license_expression}\n"
            "License-File: licenses/LICENSE.txt\n"
            "\n"
        ).encode(),
        f"{dist_info.name}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: fixture\n"
            "Root-Is-Purelib: true\n"
            f"Tag: {tag}\n"
            "\n"
        ).encode(),
        f"{dist_info.name}/licenses/LICENSE.txt": f"{name} fixture license\n".encode(),
    }
    for relative, payload in files.items():
        path = site / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    record_buffer = io.StringIO(newline="")
    writer = csv.writer(record_buffer, lineterminator="\n")
    for relative in sorted(files):
        payload = files[relative]
        writer.writerow((relative, _record_field(payload), str(len(payload))))
    record_relative = f"{dist_info.name}/RECORD"
    writer.writerow((record_relative, "", ""))
    (site / record_relative).write_text(record_buffer.getvalue(), encoding="utf-8")


def _write_lock(path: Path, *, archive_hash: str = _ARCHIVE_HASH) -> bytes:
    payload = (
        'version = 1\nrevision = 3\nrequires-python = ">=3.12"\n\n'
        "[[package]]\n"
        'name = "ds4bench"\n'
        'version = "0.1.0"\n'
        'source = { editable = "." }\n'
        'dependencies = [{ name = "fixture-dep" }]\n\n'
        "[[package]]\n"
        'name = "fixture-dep"\n'
        'version = "1.2.3"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        "wheels = [\n"
        "  { url = \"https://files.pythonhosted.org/fixture_dep-1.2.3-py3-none-any.whl\", "
        f'hash = "sha256:{archive_hash}" }},\n'
        "]\n"
    ).encode()
    path.write_bytes(payload)
    return payload


def _fixture_tree(root: Path) -> tuple[Path, Path]:
    site = root / "site-packages"
    site.mkdir()
    _write_distribution(site, "ds4bench", "0.1.0")
    _write_distribution(site, "fixture-dep", "1.2.3", license_expression="BSD-3-Clause")
    lock = root / "uv.lock"
    _write_lock(lock)
    return site, lock


class RuntimePayloadTests(unittest.TestCase):
    def test_zipapp_is_byte_identical_and_inventory_is_lock_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site, lock = _fixture_tree(root)
            first = assemble_runtime_payload(site, root / "payload-a", lock)
            second = assemble_runtime_payload(site, root / "payload-b", lock)

            self.assertEqual(first.bundle_path.read_bytes(), second.bundle_path.read_bytes())
            self.assertEqual(first.licenses_path.read_bytes(), second.licenses_path.read_bytes())
            self.assertEqual(first.bundle_sha256, second.bundle_sha256)
            self.assertEqual(first.lock_sha256, hashlib.sha256(lock.read_bytes()).hexdigest())

            inventory = json.loads(first.licenses_path.read_bytes())
            self.assertEqual(first.licenses_path.read_bytes(), canonical_json_bytes(inventory))
            self.assertEqual(inventory["lock_sha256"], first.lock_sha256)
            self.assertEqual([item["name"] for item in inventory["packages"]], ["ds4bench", "fixture-dep"])
            dependency = inventory["packages"][1]
            self.assertEqual(dependency["version"], "1.2.3")
            self.assertEqual(dependency["license"], "BSD-3-Clause")
            self.assertEqual(dependency["wheel_tag"], "py3-none-any")
            self.assertEqual(dependency["locked_archive_sha256"], _ARCHIVE_HASH)
            self.assertRegex(dependency["wheel_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(dependency["record_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(dependency["license_files"][0]["path"], "licenses/LICENSE.txt")
            self.assertRegex(dependency["license_files"][0]["sha256"], r"^[0-9a-f]{64}$")

            with zipfile.ZipFile(first.bundle_path) as archive:
                names = archive.namelist()
                self.assertEqual(names, sorted(names))
                self.assertEqual(
                    names,
                    [
                        "__main__.py",
                        "ds4bench/__init__.py",
                        "fixture_dep/__init__.py",
                    ],
                )
                self.assertEqual(
                    archive.read("__main__.py"),
                    b"from ds4bench.__main__ import main\nraise SystemExit(main())\n",
                )
                for info in archive.infolist():
                    self.assertEqual(info.date_time, ZIP_TIMESTAMP)
                    self.assertEqual((info.external_attr >> 16) & 0o777, 0o644)
                    self.assertNotIn(".dist-info", info.filename)
                    self.assertNotIn("__pycache__", info.filename)
                    self.assertFalse(info.filename.endswith((".pyc", ".pyo")))

    def test_lock_bytes_change_inventory_and_payload_address(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site, lock = _fixture_tree(root)
            first = assemble_runtime_payload(site, root / "payload-a", lock)
            second_lock = root / "uv-second.lock"
            _write_lock(second_lock, archive_hash="b" * 64)
            second = assemble_runtime_payload(site, root / "payload-b", second_lock)
            self.assertEqual(first.bundle_sha256, second.bundle_sha256)
            self.assertNotEqual(first.lock_sha256, second.lock_sha256)
            self.assertNotEqual(first.licenses_sha256, second.licenses_sha256)

    def test_impure_or_multiple_wheel_tags_are_rejected(self) -> None:
        for tag in ("cp312-cp312-linux_x86_64", "py2.py3-none-any"):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                site = root / "site-packages"
                site.mkdir()
                _write_distribution(site, "ds4bench", "0.1.0")
                _write_distribution(site, "fixture-dep", "1.2.3", tag=tag)
                lock = root / "uv.lock"
                _write_lock(lock)
                with self.assertRaisesRegex(RuntimeBundleError, "impure_wheel_tag"):
                    assemble_runtime_payload(site, root / "payload", lock)

    def test_installed_version_must_match_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site = root / "site-packages"
            site.mkdir()
            _write_distribution(site, "ds4bench", "0.1.0")
            _write_distribution(site, "fixture-dep", "9.9.9")
            lock = root / "uv.lock"
            _write_lock(lock)
            with self.assertRaisesRegex(RuntimeBundleError, "installed_version_mismatch"):
                assemble_runtime_payload(site, root / "payload", lock)

    def test_record_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site, lock = _fixture_tree(root)
            (site / "fixture_dep" / "__init__.py").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(RuntimeBundleError, "record_hash_mismatch"):
                assemble_runtime_payload(site, root / "payload", lock)


class RuntimeBuildTests(unittest.TestCase):
    def test_builder_uses_fixed_uv_sync_argv_and_emits_content_addressed_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / "fixture"
            fixture_root.mkdir()
            fixture_site, _ = _fixture_tree(fixture_root)
            project = root / "project"
            project.mkdir()
            lock_bytes = _write_lock(project / "uv.lock")
            (project / "pyproject.toml").write_text(
                "[project]\nname='ds4bench'\nversion='0.1.0'\nrequires-python='>=3.12'\n",
                encoding="utf-8",
            )
            calls: list[tuple[list[str], dict[str, object]]] = []

            def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                calls.append((argv, kwargs))
                environment = kwargs["env"]
                self.assertIsInstance(environment, dict)
                venv = Path(environment["UV_PROJECT_ENVIRONMENT"])
                installed = (
                    venv
                    / "lib"
                    / f"python{sys.version_info.major}.{sys.version_info.minor}"
                    / "site-packages"
                )
                installed.parent.mkdir(parents=True)
                shutil.copytree(fixture_site, installed)
                return subprocess.CompletedProcess(argv, 0)

            output = root / "untracked-runtime"
            with patch("ds4bench.runtime_bundle.subprocess.run", side_effect=fake_run):
                built = build_runtime_bundle(
                    project,
                    output,
                    uv_executable="/controller/bin/uv",
                    python_executable=sys.executable,
                )

            self.assertEqual(len(calls), 1)
            argv, kwargs = calls[0]
            self.assertEqual(
                argv,
                [
                    "/controller/bin/uv",
                    "sync",
                    "--frozen",
                    "--no-dev",
                    "--no-editable",
                    "--project",
                    str(project.resolve()),
                    "--python",
                    str(Path(sys.executable).resolve()),
                ],
            )
            self.assertEqual(kwargs["cwd"], project.resolve())
            self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
            self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
            self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
            self.assertIs(kwargs["check"], True)
            self.assertEqual(kwargs["timeout"], UV_TIMEOUT_SECONDS)
            environment = kwargs["env"]
            self.assertEqual(environment["UV_PYTHON_DOWNLOADS"], "never")
            self.assertEqual(environment["UV_PYTHON"], str(Path(sys.executable).resolve()))
            self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")

            self.assertEqual(built.root.name, built.aggregate_sha256)
            self.assertEqual(set(path.name for path in built.root.iterdir()), {"payload", RUNTIME_MANIFEST_NAME})
            self.assertEqual(set(path.name for path in built.payload_dir.iterdir()), {BUNDLE_NAME, LICENSE_INVENTORY_NAME})
            self.assertEqual(built.lock_sha256, hashlib.sha256(lock_bytes).hexdigest())
            manifest = verify_transfer(
                built.payload_dir,
                built.manifest_path,
                built.manifest_sha256,
                expected_kind="runtime",
                expected_run_id=built.aggregate_sha256,
                expected_lock_sha256=built.lock_sha256,
            )
            self.assertEqual([entry["path"] for entry in manifest["entries"]], [BUNDLE_NAME, LICENSE_INVENTORY_NAME])
            self.assertNotIn(RUNTIME_MANIFEST_NAME, [entry["path"] for entry in manifest["entries"]])


if __name__ == "__main__":
    unittest.main()
