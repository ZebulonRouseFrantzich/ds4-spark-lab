from __future__ import annotations

import base64
import csv
import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from collections import deque
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath
from typing import Mapping

from .stats import canonical_json_bytes
from .transfer import (
    MAX_RUNTIME_FILE_BYTES,
    RUNTIME_MANIFEST_NAME,
    TransferError,
    create_transfer_manifest,
    verify_transfer,
    write_transfer_manifest,
)

SCHEMA_VERSION = 1
TARGET_PYTHON = "3.12"
BUNDLE_NAME = "ds4bench.pyz"
LICENSE_INVENTORY_NAME = "licenses.json"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_MODE = stat.S_IFREG | 0o644
MAX_INSTALLED_FILES = 4096
MAX_INSTALLED_FILE_BYTES = 8 * 1024 * 1024
MAX_INSTALLED_BYTES = 64 * 1024 * 1024
MAX_LOCK_BYTES = 8 * 1024 * 1024
UV_TIMEOUT_SECONDS = 600
_MAIN = b"from ds4bench.__main__ import main\nraise SystemExit(main())\n"
_NAME_SEPARATORS = re.compile(r"[-_.]+")
_NAME = re.compile(r"\A[a-z0-9][a-z0-9-]{0,127}\Z")
_VERSION = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z.!+_-]{0,127}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_INSTALLED_COMPONENT = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9._+-]{0,254}\Z")
_GENERATED_SCRIPT = re.compile(r"\A\.\./\.\./\.\./bin/[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\Z")
_LOCKED_WHEEL_URL = re.compile(
    r"\Ahttps://files\.pythonhosted\.org/[A-Za-z0-9_./+-]+-py3-none-any\.whl\Z"
)
_MARKER = re.compile(
    r"\Apython_(full_)?version\s*(==|!=|<=|>=|<|>)\s*'([0-9]+(?:\.[0-9]+){1,2})'\Z"
)


class RuntimeBundleError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RuntimePayload:
    payload_dir: Path
    bundle_path: Path
    licenses_path: Path
    bundle_sha256: str
    licenses_sha256: str
    lock_sha256: str


@dataclass(frozen=True, slots=True)
class RuntimeBundle:
    root: Path
    payload_dir: Path
    bundle_path: Path
    licenses_path: Path
    manifest_path: Path
    bundle_sha256: str
    licenses_sha256: str
    manifest_sha256: str
    aggregate_sha256: str
    lock_sha256: str


@dataclass(frozen=True, slots=True)
class _LockedPackage:
    name: str
    version: str
    locked_archive_sha256: str | None
    locked_archive_url: str | None


@dataclass(frozen=True, slots=True)
class _RecordedFile:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _InstalledDistribution:
    inventory: dict[str, object]
    files: tuple[_RecordedFile, ...]


def build_runtime_bundle(
    project_dir: Path | str,
    output_root: Path | str,
    *,
    uv_executable: Path | str = "uv",
    python_executable: Path | str | None = None,
) -> RuntimeBundle:
    project = Path(project_dir).resolve(strict=True)
    if not project.is_dir():
        raise RuntimeBundleError("invalid_project_directory")
    lock_path = project / "uv.lock"
    lock_bytes = _read_regular_path(lock_path, MAX_LOCK_BYTES, "lock")
    pyproject_bytes = _read_regular_path(project / "pyproject.toml", MAX_LOCK_BYTES, "pyproject")
    _validate_project_requires_python(pyproject_bytes)
    controller_python = _controller_python(python_executable)
    output = _prepare_output_root(Path(output_root))

    with tempfile.TemporaryDirectory(prefix=".ds4bench-runtime-", dir=output) as temporary:
        temporary_root = Path(temporary)
        environment = os.environ.copy()
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "UV_PROJECT_ENVIRONMENT": str(temporary_root / "venv"),
                "UV_PYTHON": str(controller_python),
                "UV_PYTHON_DOWNLOADS": "never",
            }
        )
        argv = [
            os.fspath(uv_executable),
            "sync",
            "--frozen",
            "--no-dev",
            "--no-editable",
            "--project",
            str(project),
            "--python",
            str(controller_python),
        ]
        _run_uv(argv, project, environment, "uv_sync_failed")

        site_packages = _site_packages(temporary_root / "venv")
        _install_missing_target_packages(
            site_packages,
            _locked_runtime_packages(lock_bytes),
            uv_executable=os.fspath(uv_executable),
            controller_python=controller_python,
            project=project,
            environment=environment,
        )
        candidate = temporary_root / "candidate"
        candidate.mkdir(mode=0o700)
        payload = assemble_runtime_payload(site_packages, candidate / "payload", lock_path)
        provisional = create_transfer_manifest(
            payload.payload_dir,
            kind="runtime",
            run_id="runtime-provisional",
            lock_sha256=payload.lock_sha256,
        )
        aggregate = provisional["aggregate_sha256"]
        if not isinstance(aggregate, str):
            raise RuntimeBundleError("invalid_runtime_aggregate")
        sidecar = write_transfer_manifest(
            payload.payload_dir,
            candidate / RUNTIME_MANIFEST_NAME,
            kind="runtime",
            run_id=aggregate,
            lock_sha256=payload.lock_sha256,
        )
        destination = output / aggregate
        _promote_content_addressed(candidate, destination, sidecar.sha256, payload.lock_sha256)
        return RuntimeBundle(
            root=destination,
            payload_dir=destination / "payload",
            bundle_path=destination / "payload" / BUNDLE_NAME,
            licenses_path=destination / "payload" / LICENSE_INVENTORY_NAME,
            manifest_path=destination / RUNTIME_MANIFEST_NAME,
            bundle_sha256=payload.bundle_sha256,
            licenses_sha256=payload.licenses_sha256,
            manifest_sha256=sidecar.sha256,
            aggregate_sha256=aggregate,
            lock_sha256=payload.lock_sha256,
        )


def assemble_runtime_payload(
    site_packages: Path | str,
    payload_dir: Path | str,
    lock_path: Path | str,
) -> RuntimePayload:
    site = Path(site_packages)
    if not site.exists() or not site.is_dir() or site.is_symlink():
        raise RuntimeBundleError("invalid_site_packages")
    lock_bytes = _read_regular_path(Path(lock_path), MAX_LOCK_BYTES, "lock")
    lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    locked = _locked_runtime_packages(lock_bytes)
    distributions = _installed_distributions(site, locked)

    inventory = {
        "schema_version": SCHEMA_VERSION,
        "lock_sha256": lock_sha256,
        "packages": [distribution.inventory for distribution in distributions],
    }
    licenses_bytes = canonical_json_bytes(inventory)
    if len(licenses_bytes) > MAX_RUNTIME_FILE_BYTES:
        raise RuntimeBundleError("license_inventory_size_limit")

    files: dict[str, _RecordedFile] = {}
    for distribution in distributions:
        for recorded in distribution.files:
            if _excluded_runtime_path(recorded.path):
                continue
            if recorded.path == "__main__.py":
                raise RuntimeBundleError("reserved_main_path")
            previous = files.setdefault(recorded.path, recorded)
            if previous != recorded:
                raise RuntimeBundleError("installed_path_collision")
    if len(files) + 1 > MAX_INSTALLED_FILES:
        raise RuntimeBundleError("installed_file_count_limit")
    total = len(_MAIN)
    for recorded in files.values():
        total += recorded.size
        if total > MAX_INSTALLED_BYTES:
            raise RuntimeBundleError("installed_size_limit")

    destination = Path(payload_dir)
    if destination.exists() or destination.is_symlink():
        raise RuntimeBundleError("payload_destination_exists")
    parent = destination.parent
    if not parent.is_dir() or parent.is_symlink():
        raise RuntimeBundleError("invalid_payload_parent")
    destination.mkdir(mode=0o700)
    try:
        bundle_path = destination / BUNDLE_NAME
        _write_zipapp(bundle_path, site, files)
        licenses_path = destination / LICENSE_INVENTORY_NAME
        _write_new_file(licenses_path, licenses_bytes)
        bundle_size = bundle_path.stat(follow_symlinks=False).st_size
        if bundle_size > MAX_RUNTIME_FILE_BYTES:
            raise RuntimeBundleError("bundle_size_limit")
        bundle_sha256 = _hash_path(bundle_path)
        licenses_sha256 = hashlib.sha256(licenses_bytes).hexdigest()
        _fsync_directory(destination)
    except Exception:
        _remove_incomplete_payload(destination)
        raise
    return RuntimePayload(
        payload_dir=destination,
        bundle_path=bundle_path,
        licenses_path=licenses_path,
        bundle_sha256=bundle_sha256,
        licenses_sha256=licenses_sha256,
        lock_sha256=lock_sha256,
    )


def _validate_project_requires_python(payload: bytes) -> None:
    try:
        value = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RuntimeBundleError("invalid_pyproject") from error
    project = value.get("project") if isinstance(value, dict) else None
    if not isinstance(project, dict) or project.get("requires-python") != ">=3.12":
        raise RuntimeBundleError("project_requires_python")


def _controller_python(python_executable: Path | str | None) -> Path:
    configured = python_executable or os.environ.get("UV_PYTHON") or sys.executable
    candidate = Path(configured)
    if not candidate.is_absolute():
        raise RuntimeBundleError("controller_python_not_absolute")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise RuntimeBundleError("controller_python_unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise RuntimeBundleError("controller_python_unavailable")
    return resolved


def _run_uv(
    argv: list[str],
    project: Path,
    environment: Mapping[str, str],
    failure_code: str,
) -> None:
    try:
        subprocess.run(
            argv,
            cwd=project,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=UV_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as error:
        raise RuntimeBundleError("uv_not_found") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeBundleError("uv_timeout") from error
    except subprocess.CalledProcessError as error:
        raise RuntimeBundleError(failure_code) from error


def _install_missing_target_packages(
    site: Path,
    locked: Mapping[str, _LockedPackage],
    *,
    uv_executable: str,
    controller_python: Path,
    project: Path,
    environment: Mapping[str, str],
) -> None:
    present = _installed_distribution_names(site)
    missing = sorted(set(locked) - present)
    if "ds4bench" in missing:
        raise RuntimeBundleError("sync_missing_ds4bench")
    requirements: list[str] = []
    for name in missing:
        package = locked[name]
        if package.locked_archive_url is None or package.locked_archive_sha256 is None:
            raise RuntimeBundleError("missing_locked_wheel")
        requirements.append(
            f"{package.locked_archive_url}#sha256={package.locked_archive_sha256}"
        )
    if not requirements:
        return
    argv = [
        uv_executable,
        "pip",
        "install",
        "--target",
        str(site),
        "--python",
        str(controller_python),
        "--no-deps",
        "--no-compile-bytecode",
        *requirements,
    ]
    _run_uv(argv, project, environment, "uv_target_install_failed")


def _installed_distribution_names(site: Path) -> set[str]:
    names: set[str] = set()
    try:
        dist_infos = sorted(entry for entry in site.iterdir() if entry.name.endswith(".dist-info"))
    except OSError as error:
        raise RuntimeBundleError("site_packages_unreadable") from error
    for dist_info in dist_infos:
        _validate_directory(dist_info, "dist_info")
        metadata = _read_site_file(site, f"{dist_info.name}/METADATA")
        name = _normalized_name(BytesParser(policy=compat32).parsebytes(metadata).get("Name"))
        if name in names:
            raise RuntimeBundleError("duplicate_installed_distribution")
        names.add(name)
    return names


def _locked_runtime_packages(lock_bytes: bytes) -> dict[str, _LockedPackage]:
    try:
        value = tomllib.loads(lock_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RuntimeBundleError("invalid_lock") from error
    packages = value.get("package") if isinstance(value, dict) else None
    if not isinstance(packages, list):
        raise RuntimeBundleError("invalid_lock_packages")
    if value.get("requires-python") != ">=3.12":
        raise RuntimeBundleError("lock_requires_python")

    raw_by_name: dict[str, dict[str, object]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise RuntimeBundleError("invalid_lock_package")
        name = _normalized_name(package.get("name"))
        if name in raw_by_name:
            raise RuntimeBundleError("duplicate_lock_package")
        version = package.get("version")
        if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
            raise RuntimeBundleError("invalid_lock_version")
        raw_by_name[name] = package
    if "ds4bench" not in raw_by_name:
        raise RuntimeBundleError("lock_missing_ds4bench")

    selected: dict[str, _LockedPackage] = {}
    pending = deque(["ds4bench"])
    while pending:
        name = pending.popleft()
        if name in selected:
            continue
        try:
            package = raw_by_name[name]
        except KeyError as error:
            raise RuntimeBundleError("lock_dependency_missing") from error
        version = package["version"]
        if not isinstance(version, str):
            raise RuntimeBundleError("invalid_lock_version")
        archive_hash, archive_url = _locked_archive(package, local=name == "ds4bench")
        selected[name] = _LockedPackage(
            name=name,
            version=version,
            locked_archive_sha256=archive_hash,
            locked_archive_url=archive_url,
        )
        dependencies = package.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise RuntimeBundleError("invalid_lock_dependencies")
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                raise RuntimeBundleError("invalid_lock_dependency")
            marker = dependency.get("marker")
            if marker is not None and not _marker_applies(marker):
                continue
            pending.append(_normalized_name(dependency.get("name")))
    return selected


def _locked_archive(
    package: Mapping[str, object],
    *,
    local: bool,
) -> tuple[str | None, str | None]:
    wheels = package.get("wheels")
    if wheels is None:
        if local:
            return None, None
        raise RuntimeBundleError("lock_missing_pure_wheel")
    if not isinstance(wheels, list):
        raise RuntimeBundleError("invalid_lock_wheels")
    pure: list[tuple[str, str]] = []
    for wheel in wheels:
        if not isinstance(wheel, dict):
            raise RuntimeBundleError("invalid_lock_wheel")
        url = wheel.get("url")
        digest = wheel.get("hash")
        if not isinstance(url, str) or not isinstance(digest, str):
            raise RuntimeBundleError("invalid_lock_wheel")
        filename = url.rsplit("/", 1)[-1]
        if filename.endswith("-py3-none-any.whl"):
            if (
                _LOCKED_WHEEL_URL.fullmatch(url) is None
                or not digest.startswith("sha256:")
                or _SHA256.fullmatch(digest[7:]) is None
            ):
                raise RuntimeBundleError("invalid_lock_wheel_hash")
            pure.append((digest[7:], url))
    if len(pure) != 1:
        raise RuntimeBundleError("lock_pure_wheel_ambiguity")
    return pure[0]


def _marker_applies(value: object) -> bool:
    if not isinstance(value, str):
        raise RuntimeBundleError("invalid_lock_marker")
    match = _MARKER.fullmatch(value)
    if match is None:
        raise RuntimeBundleError("unsupported_lock_marker")
    full, operator, expected_text = match.groups()
    actual = _version_tuple("3.12.0" if full else TARGET_PYTHON)
    expected = _version_tuple(expected_text)
    if operator == "==":
        return actual == expected
    if operator == "!=":
        return actual != expected
    if operator == "<=":
        return actual <= expected
    if operator == ">=":
        return actual >= expected
    if operator == "<":
        return actual < expected
    return actual > expected


def _version_tuple(value: str) -> tuple[int, int, int]:
    parts = [int(part) for part in value.split(".")]
    padded = parts + [0, 0]
    return padded[0], padded[1], padded[2]


def _installed_distributions(
    site: Path,
    locked: Mapping[str, _LockedPackage],
) -> tuple[_InstalledDistribution, ...]:
    try:
        dist_infos = sorted(entry for entry in site.iterdir() if entry.name.endswith(".dist-info"))
    except OSError as error:
        raise RuntimeBundleError("site_packages_unreadable") from error
    if len(dist_infos) != len(locked):
        raise RuntimeBundleError("installed_distribution_set")

    installed: dict[str, _InstalledDistribution] = {}
    owned_paths: dict[str, str] = {}
    for dist_info in dist_infos:
        distribution = _inspect_distribution(site, dist_info, locked)
        name = distribution.inventory["name"]
        if not isinstance(name, str):
            raise RuntimeBundleError("invalid_installed_name")
        if name in installed:
            raise RuntimeBundleError("duplicate_installed_distribution")
        for recorded in distribution.files:
            owner = owned_paths.setdefault(recorded.path, name)
            if owner != name:
                raise RuntimeBundleError("installed_path_collision")
        installed[name] = distribution
    if set(installed) != set(locked):
        raise RuntimeBundleError("installed_distribution_set")
    return tuple(installed[name] for name in sorted(installed))


def _inspect_distribution(
    site: Path,
    dist_info: Path,
    locked: Mapping[str, _LockedPackage],
) -> _InstalledDistribution:
    _validate_directory(dist_info, "dist_info")
    relative_dist_info = dist_info.relative_to(site).as_posix()
    metadata_path = f"{relative_dist_info}/METADATA"
    wheel_path = f"{relative_dist_info}/WHEEL"
    record_path = f"{relative_dist_info}/RECORD"
    metadata_bytes = _read_site_file(site, metadata_path)
    wheel_bytes = _read_site_file(site, wheel_path)
    record_bytes = _read_site_file(site, record_path)

    metadata = BytesParser(policy=compat32).parsebytes(metadata_bytes)
    name = _normalized_name(metadata.get("Name"))
    version = metadata.get("Version")
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        raise RuntimeBundleError("invalid_installed_version")
    try:
        expected = locked[name]
    except KeyError as error:
        raise RuntimeBundleError("unexpected_installed_distribution") from error
    if version != expected.version:
        raise RuntimeBundleError("installed_version_mismatch")

    wheel_metadata = BytesParser(policy=compat32).parsebytes(wheel_bytes)
    tags = [value.strip() for value in wheel_metadata.get_all("Tag", [])]
    if tags != ["py3-none-any"]:
        raise RuntimeBundleError("impure_wheel_tag")
    root_is_pure = wheel_metadata.get("Root-Is-Purelib")
    if not isinstance(root_is_pure, str) or root_is_pure.strip().lower() != "true":
        raise RuntimeBundleError("impure_wheel_root")

    records = _parse_and_verify_record(site, record_path, record_bytes)
    record_by_path = {record.path: record for record in records}
    for required in (metadata_path, wheel_path, record_path):
        if required not in record_by_path:
            raise RuntimeBundleError("record_missing_metadata")

    license_value = metadata.get("License-Expression") or metadata.get("License")
    if not isinstance(license_value, str):
        raise RuntimeBundleError("missing_license")
    license_text = " ".join(license_value.split())
    if not license_text or len(license_text) > 512 or not license_text.isprintable():
        raise RuntimeBundleError("invalid_license")

    license_files: list[dict[str, str]] = []
    declared_license_files = metadata.get_all("License-File", [])
    for declared in sorted(set(declared_license_files)):
        if not isinstance(declared, str):
            raise RuntimeBundleError("invalid_license_file")
        relative = _safe_relative_path(declared)
        candidates = (
            f"{relative_dist_info}/{relative}",
            f"{relative_dist_info}/licenses/{relative}",
        )
        recorded = next(
            (record_by_path[candidate] for candidate in candidates if candidate in record_by_path),
            None,
        )
        if recorded is None:
            raise RuntimeBundleError("license_file_not_recorded")
        license_files.append({"path": relative, "sha256": recorded.sha256})

    return _InstalledDistribution(
        inventory={
            "name": name,
            "version": version,
            "license": license_text,
            "wheel_tag": "py3-none-any",
            "wheel_sha256": hashlib.sha256(wheel_bytes).hexdigest(),
            "record_sha256": hashlib.sha256(record_bytes).hexdigest(),
            "locked_archive_sha256": expected.locked_archive_sha256,
            "license_files": license_files,
        },
        files=records,
    )


def _parse_and_verify_record(
    site: Path,
    record_path: str,
    record_bytes: bytes,
) -> tuple[_RecordedFile, ...]:
    try:
        text = record_bytes.decode("utf-8")
        rows = list(csv.reader(text.splitlines()))
    except (UnicodeDecodeError, csv.Error) as error:
        raise RuntimeBundleError("invalid_record") from error
    records: list[_RecordedFile] = []
    seen: set[str] = set()
    for row in rows:
        if len(row) != 3:
            raise RuntimeBundleError("invalid_record")
        if _generated_script_path(row[0]):
            continue
        path = _safe_relative_path(row[0])
        if path in seen:
            raise RuntimeBundleError("duplicate_record_path")
        seen.add(path)
        hash_field, size_field = row[1], row[2]
        payload = _read_site_file(site, path)
        if path == record_path:
            if hash_field or size_field:
                raise RuntimeBundleError("record_self_hash")
            digest = hashlib.sha256(payload).hexdigest()
            size = len(payload)
        else:
            if not hash_field.startswith("sha256=") or not size_field.isascii() or not size_field.isdecimal():
                raise RuntimeBundleError("unsupported_record_hash")
            expected_digest = hash_field[7:]
            actual_digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
            if expected_digest != actual_digest or int(size_field) != len(payload):
                raise RuntimeBundleError("record_hash_mismatch")
            digest = hashlib.sha256(payload).hexdigest()
            size = len(payload)
        if size > MAX_INSTALLED_FILE_BYTES:
            raise RuntimeBundleError("installed_file_size_limit")
        records.append(_RecordedFile(path=path, size=size, sha256=digest))
    if len(records) > MAX_INSTALLED_FILES:
        raise RuntimeBundleError("installed_file_count_limit")
    return tuple(sorted(records, key=lambda record: record.path))


def _write_zipapp(destination: Path, site: Path, files: Mapping[str, _RecordedFile]) -> None:
    with destination.open("xb", buffering=0) as stream:
        with zipfile.ZipFile(
            stream,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for path in sorted(["__main__.py", *files]):
                payload = _MAIN if path == "__main__.py" else _read_site_file(site, path)
                if path != "__main__.py":
                    recorded = files[path]
                    if len(payload) != recorded.size or hashlib.sha256(payload).hexdigest() != recorded.sha256:
                        raise RuntimeBundleError("installed_file_changed")
                info = zipfile.ZipInfo(path, date_time=ZIP_TIMESTAMP)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = ZIP_MODE << 16
                info.flag_bits = 0
                archive.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o644)


def _excluded_runtime_path(path: str) -> bool:
    components = PurePosixPath(path).parts
    return (
        any(component == "__pycache__" for component in components)
        or any(component.endswith((".dist-info", ".egg-info")) for component in components)
        or path.endswith((".pyc", ".pyo"))
    )


def _read_site_file(site: Path, relative: str) -> bytes:
    safe = _safe_relative_path(relative)
    current = site
    components = safe.split("/")
    for component in components[:-1]:
        current = current / component
        _validate_directory(current, "installed_directory")
    return _read_regular_path(current / components[-1], MAX_INSTALLED_FILE_BYTES, "installed_file")


def _safe_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeBundleError("unsafe_installed_path")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as error:
        raise RuntimeBundleError("unsafe_installed_path") from error
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or "\\" in value
        or value != pure.as_posix()
        or any(
            component in {"", ".", ".."} or _INSTALLED_COMPONENT.fullmatch(component) is None
            for component in pure.parts
        )
    ):
        raise RuntimeBundleError("unsafe_installed_path")
    return value




def _generated_script_path(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return _GENERATED_SCRIPT.fullmatch(value) is not None


def _normalized_name(value: object) -> str:
    if not isinstance(value, str):
        raise RuntimeBundleError("invalid_package_name")
    normalized = _NAME_SEPARATORS.sub("-", value).lower()
    if _NAME.fullmatch(normalized) is None:
        raise RuntimeBundleError("invalid_package_name")
    return normalized


def _site_packages(venv: Path) -> Path:
    candidates: list[Path] = []
    for library_name in ("lib", "lib64"):
        library = venv / library_name
        if not library.exists() or library.is_symlink() or not library.is_dir():
            continue
        for version_dir in library.iterdir():
            if (
                version_dir.is_dir()
                and not version_dir.is_symlink()
                and re.fullmatch(r"python[0-9]+\.[0-9]+", version_dir.name) is not None
            ):
                candidate = version_dir / "site-packages"
                if candidate.exists():
                    candidates.append(candidate)
    if len(candidates) != 1:
        raise RuntimeBundleError("site_packages_not_found")
    candidate = candidates[0]
    if candidate.is_symlink() or not candidate.is_dir():
        raise RuntimeBundleError("invalid_site_packages")
    return candidate


def _prepare_output_root(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        absolute.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise RuntimeBundleError("output_root_unavailable") from error
    _validate_directory(absolute, "output_root")
    return absolute


def _promote_content_addressed(
    candidate: Path,
    destination: Path,
    expected_manifest_sha256: str,
    expected_lock_sha256: str,
) -> None:
    try:
        os.rename(candidate, destination)
    except FileExistsError:
        _verify_existing_runtime(destination, expected_manifest_sha256, expected_lock_sha256)
    except OSError as error:
        if destination.exists():
            _verify_existing_runtime(destination, expected_manifest_sha256, expected_lock_sha256)
        else:
            raise RuntimeBundleError("runtime_promotion_failed") from error
    else:
        _fsync_directory(destination.parent)


def _verify_existing_runtime(
    root: Path,
    expected_manifest_sha256: str,
    expected_lock_sha256: str,
) -> None:
    _validate_directory(root, "runtime_root")
    try:
        names = {entry.name for entry in root.iterdir()}
    except OSError as error:
        raise RuntimeBundleError("runtime_root_unreadable") from error
    if names != {"payload", RUNTIME_MANIFEST_NAME}:
        raise RuntimeBundleError("runtime_layout")
    try:
        verify_transfer(
            root / "payload",
            root / RUNTIME_MANIFEST_NAME,
            expected_manifest_sha256,
            expected_kind="runtime",
            expected_run_id=root.name,
            expected_lock_sha256=expected_lock_sha256,
        )
    except TransferError as error:
        raise RuntimeBundleError(f"existing_runtime_invalid:{error.code}") from error


def _read_regular_path(path: Path, limit: int, field: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise RuntimeBundleError(f"invalid_{field}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.getuid()
        or before.st_size > limit
    ):
        raise RuntimeBundleError(f"invalid_{field}")
    try:
        with path.open("rb", buffering=0) as stream:
            opened = os.fstat(stream.fileno())
            if _identity(before) != _identity(opened):
                raise RuntimeBundleError(f"{field}_changed")
            payload = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise RuntimeBundleError(f"invalid_{field}") from error
    if len(payload) > limit or len(payload) != opened.st_size:
        raise RuntimeBundleError(f"invalid_{field}")
    if _mutable_identity(opened) != _mutable_identity(after):
        raise RuntimeBundleError(f"{field}_changed")
    return payload


def _validate_directory(path: Path, field: str) -> None:
    try:
        value = path.lstat()
    except OSError as error:
        raise RuntimeBundleError(f"invalid_{field}") from error
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid():
        raise RuntimeBundleError(f"invalid_{field}")


def _write_new_file(path: Path, payload: bytes) -> None:
    with path.open("xb", buffering=0) as stream:
        view = memoryview(payload)
        while view:
            written = stream.write(view)
            if written is None or written <= 0:
                raise RuntimeBundleError("short_write")
            view = view[written:]
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o644)


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _remove_incomplete_payload(path: Path) -> None:
    try:
        entries = list(path.iterdir())
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_file() and not entry.is_symlink():
                entry.unlink()
        except OSError:
            pass
    try:
        path.rmdir()
    except OSError:
        pass


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink


def _mutable_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink
