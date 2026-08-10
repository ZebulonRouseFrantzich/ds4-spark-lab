"""Targetctl-owned Phase 02 benchmark orchestration.

The existing lifecycle remains the only server-process owner.  This module owns
only finite benchmark staging, a portable client subprocess, and descriptor-
verified result return.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import subprocess
import tempfile
from typing import Any, Iterable, Mapping

from benchmarks.src.ds4bench.artifacts import RESULT_FILE_LIMITS, RESULT_FILES, verify_result
from benchmarks.src.ds4bench.runtime_bundle import (
    BUNDLE_NAME,
    LICENSE_INVENTORY_NAME,
    RUNTIME_MANIFEST_NAME,
    RuntimeBundle,
    build_runtime_bundle,
)
from benchmarks.src.ds4bench.schema import Scenario, load_scenario, normalize_scenario
from benchmarks.src.ds4bench.stats import canonical_json_bytes
from benchmarks.src.ds4bench.transfer import (
    TransferError,
    promote_verified_payload,
    validate_transfer_manifest,
    verify_transfer,
    write_transfer_manifest,
)

from .artifacts import controller_provenance
from .common import TargetError
from .doctor import DoctorResult, doctor
from .lifecycle import cleanup, launch_profile_from_scenario, logs, serve
from .transport import select_transport

MODEL_ID = "deepseek-v4-flash"
RESULT_ROOT = Path("benchmarks/results")
_RUNTIME_ROOT = Path("targets/.state/benchmark-runtime-v1")
_PROMPT_MANIFEST = Path("benchmarks/prompts/manifest.json")
SCENARIOS = {
    "bench-s1": Path("benchmarks/scenarios/s1.json"),
    "bench-s2": Path("benchmarks/scenarios/s2.json"),
    "bench-s3": Path("benchmarks/scenarios/s3.json"),
    "bench-s5a": Path("benchmarks/scenarios/s5a.json"),
    "bench-s5b": Path("benchmarks/scenarios/s5b.json"),
}
BENCHMARK_OPERATIONS = frozenset({"bench-smoke", *SCENARIOS, "bench-v1-baseline", "compare"})
CHUNK_BYTES = 384 * 1024
MAX_STAGE_FILE_BYTES = 8 * 1024 * 1024
MAX_STAGE_BYTES = 80 * 1024 * 1024
MAX_STAGE_FILES = 64
_STAGE_DOMAIN = b"targetctl-benchmark-stage-v1\0"
_SAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
_HELPER_ERRORS = frozenset(
    {
        "benchmark_cleanup_failed",
        "benchmark_chunk_invalid",
        "benchmark_execute_failed",
        "benchmark_result_invalid",
        "benchmark_stage_conflict",
        "benchmark_stage_incomplete",
        "benchmark_stage_invalid",
    }
)
_REPOSITORY_URLS = {
    "lab": "https://github.com/ZebulonRouseFrantzich/ds4-spark-lab.git",
    "engine": "https://github.com/ZebulonRouseFrantzich/ds4.git",
    "integration": "https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git",
}


@dataclass(frozen=True, slots=True)
class StageFile:
    path: str
    size: int
    sha256: str
    source: Path | None = None
    content: bytes | None = None
    identity: tuple[int, ...] | None = None


@dataclass(frozen=True, slots=True)
class PreparedBenchmark:
    root: Path
    config: Any
    transport: Any
    source: Any
    build: Mapping[str, Any]
    runtime: Any
    scenario_path: Path
    scenario: Scenario
    normalized: dict[str, Any]
    portable: RuntimeBundle
    source_manifest: dict[str, object]
    prompt_manifest_sha256: str
    result_root: Path


def _fail(code: str) -> None:
    raise TargetError(code, "benchmark operation failed")


def _id(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 64 or value in {".", ".."} or any(char not in _SAFE for char in value):
        _fail("benchmark_input_invalid")
    return value


def _relative(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or not value.isascii() or "\\" in value:
        _fail("benchmark_input_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in value.split("/")):
        _fail("benchmark_input_invalid")
    if any(len(part) > 128 or any(char not in _SAFE for char in part) for part in path.parts):
        _fail("benchmark_input_invalid")
    return value


def _identity(item: os.stat_result) -> tuple[int, ...]:
    return (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def _directory(path: Path, *, create: bool = False) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        if create:
            absolute.mkdir(mode=0o700, parents=True, exist_ok=True)
        item = absolute.lstat()
    except OSError:
        _fail("benchmark_path_unavailable")
    if not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode) or item.st_uid != os.geteuid():
        _fail("benchmark_path_unavailable")
    return absolute


def _inspect_file(path: Path, limit: int, expected: str | None = None) -> tuple[int, str, tuple[int, ...]]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or not 0 <= before.st_size <= limit:
            raise OSError
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        _fail("benchmark_input_invalid")
    digest = hashlib.sha256()
    total = 0
    try:
        if _identity(before) != _identity(os.fstat(fd)):
            _fail("benchmark_input_changed")
        while chunk := os.read(fd, min(1024 * 1024, limit - total + 1)):
            total += len(chunk)
            if total > limit:
                _fail("benchmark_input_invalid")
            digest.update(chunk)
        after = os.fstat(fd)
        if _identity(before) != _identity(after):
            _fail("benchmark_input_changed")
    finally:
        os.close(fd)
    actual = digest.hexdigest()
    if expected is not None and actual != expected:
        _fail("benchmark_input_changed")
    return total, actual, _identity(after)


def _path_file(relative: str, path: Path, expected: str | None = None) -> StageFile:
    size, digest, identity = _inspect_file(path, MAX_STAGE_FILE_BYTES, expected)
    return StageFile(_relative(relative), size, digest, source=path, identity=identity)


def _content_file(relative: str, content: bytes) -> StageFile:
    if not isinstance(content, bytes) or len(content) > MAX_STAGE_FILE_BYTES:
        _fail("benchmark_input_invalid")
    return StageFile(_relative(relative), len(content), hashlib.sha256(content).hexdigest(), content=content)


def _stage_manifest(run_id: str, files: Iterable[StageFile]) -> dict[str, object]:
    ordered = sorted(files, key=lambda item: item.path)
    if not 1 <= len(ordered) <= MAX_STAGE_FILES or len({item.path for item in ordered}) != len(ordered):
        _fail("benchmark_stage_invalid")
    digest = hashlib.sha256(_STAGE_DOMAIN)
    digest.update(len(ordered).to_bytes(4, "big"))
    total = 0
    entries: list[dict[str, object]] = []
    for item in ordered:
        total += item.size
        if item.size > MAX_STAGE_FILE_BYTES or total > MAX_STAGE_BYTES:
            _fail("benchmark_stage_invalid")
        name = item.path.encode("ascii")
        digest.update(len(name).to_bytes(2, "big"))
        digest.update(name)
        digest.update(item.size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(item.sha256))
        entries.append({"path": item.path, "size": item.size, "sha256": item.sha256})
    return {"schema_version": 1, "kind": "benchmark_stage", "run_id": _id(run_id), "entries": entries, "aggregate_sha256": digest.hexdigest()}


def _chunks(item: StageFile):
    if item.content is not None:
        for offset in range(0, item.size, CHUNK_BYTES):
            yield offset, item.content[offset : offset + CHUNK_BYTES]
        return
    if item.source is None or item.identity is None:
        _fail("benchmark_stage_invalid")
    try:
        fd = os.open(item.source, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        _fail("benchmark_input_changed")
    offset = 0
    try:
        if _identity(os.fstat(fd)) != item.identity:
            _fail("benchmark_input_changed")
        while offset < item.size:
            content = os.read(fd, min(CHUNK_BYTES, item.size - offset))
            if not content:
                _fail("benchmark_input_changed")
            yield offset, content
            offset += len(content)
        if os.read(fd, 1) or _identity(os.fstat(fd)) != item.identity:
            _fail("benchmark_input_changed")
    finally:
        os.close(fd)


def _helper(prepared: PreparedBenchmark, action: str, payload: Mapping[str, Any], timeout: float = 30.0) -> Any:
    return prepared.transport.run_helper(
        action,
        payload,
        extension_source=BENCHMARK_HELPER_EXTENSION,
        allowed_error_codes=_HELPER_ERRORS,
        timeout=timeout,
    )


def _root_payload(prepared: PreparedBenchmark, run_id: str) -> dict[str, object]:
    return {"run_dir": prepared.config.run_dir, "run_token": prepared.runtime.run_token, "run_id": run_id}


def _stage(prepared: PreparedBenchmark, run_id: str, metadata: Mapping[str, object]) -> None:
    files = [
        _path_file(BUNDLE_NAME, prepared.portable.bundle_path, prepared.portable.bundle_sha256),
        _path_file(LICENSE_INVENTORY_NAME, prepared.portable.licenses_path, prepared.portable.licenses_sha256),
        _path_file(RUNTIME_MANIFEST_NAME, prepared.portable.manifest_path, prepared.portable.manifest_sha256),
        _content_file("scenario.json", canonical_json_bytes(prepared.normalized)),
        _content_file("metadata.json", canonical_json_bytes(dict(metadata))),
        _content_file("source-manifest.json", canonical_json_bytes(prepared.source_manifest)),
        _path_file(_PROMPT_MANIFEST.as_posix(), prepared.root / _PROMPT_MANIFEST, prepared.prompt_manifest_sha256),
    ]
    for prompt in prepared.scenario.prompts:
        files.append(_path_file(prompt.path, prepared.root.joinpath(*PurePosixPath(prompt.path).parts), prompt.sha256))
    manifest = _stage_manifest(run_id, files)
    payload = _root_payload(prepared, run_id)
    result = _helper(prepared, "benchmark_stage_begin", {**payload, "manifest": manifest})
    if result not in ({"status": "ready"}, {"status": "committed"}):
        _fail("benchmark_stage_invalid")
    if result == {"status": "committed"}:
        return
    by_path = {item.path: item for item in files}
    for entry in manifest["entries"]:
        item = by_path[entry["path"]]
        for offset, content in _chunks(item):
            response = _helper(
                prepared,
                "benchmark_stage_chunk",
                {
                    **payload,
                    "path": item.path,
                    "offset": offset,
                    "content_b64": base64.b64encode(content).decode("ascii"),
                    "chunk_sha256": hashlib.sha256(content).hexdigest(),
                },
            )
            if response != {"offset": offset, "size": len(content)}:
                _fail("benchmark_chunk_invalid")
    if _helper(prepared, "benchmark_stage_commit", payload) != {"status": "committed"}:
        _fail("benchmark_stage_incomplete")


def _remove_stage(prepared: PreparedBenchmark, run_id: str) -> None:
    result = _helper(prepared, "benchmark_stage_remove", _root_payload(prepared, run_id))
    if result not in ({"status": "removed"}, {"status": "not_found"}):
        _fail("benchmark_cleanup_failed")


def _available(value: object) -> dict[str, object]:
    if isinstance(value, str) and 1 <= len(value) <= 256 and value.isascii() and all(0x20 <= ord(char) <= 0x7E for char in value):
        return {"status": "available", "value": value}
    return {"status": "unavailable", "value": None}


def _uv_version() -> str:
    try:
        result = subprocess.run(
            ("uv", "--version"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            shell=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
        output = result.stdout.decode("ascii").strip()
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
        _fail("benchmark_environment_unavailable")
    if result.returncode != 0 or not output.startswith("uv ") or len(output) > 259:
        _fail("benchmark_environment_unavailable")
    return output[3:]


def _source_manifest(root: Path, source: Any, build: Mapping[str, Any], observed: DoctorResult) -> dict[str, object]:
    provenance = controller_provenance(root)
    public = provenance.get("repositories")
    if not isinstance(public, list) or len(public) != 3 or source.dirty:
        _fail("benchmark_identity_unavailable")
    source_repos = {item.name: item for item in source.repositories}
    repositories: dict[str, dict[str, object]] = {}
    for position, (name, identity) in enumerate((("lab", "lab"), ("engine", "engine/ds4"), ("integration", "spark/ds4-on-spark"))):
        item = source_repos.get(name)
        record = public[position]
        if item is None or not isinstance(record, Mapping) or record.get("identity") != identity or record.get("commit") != item.head or record.get("clean") is not (not item.dirty):
            _fail("benchmark_identity_unavailable")
        value: dict[str, object] = {"url": _REPOSITORY_URLS[name], "commit": item.head, "clean": not item.dirty}
        if name == "lab":
            value.update({"source_snapshot_id": source.snapshot_id, "applied_tree_hash": source.applied_tree_hash})
        repositories[name] = value
    tools = {name: version for name, version, _location in observed.tools}
    gpu = observed.gpu[0] if observed.gpu else None
    capability = observed.gpu[1] if observed.gpu else None
    target = {
        "os": _available(observed.os), "kernel": _available(observed.kernel), "arch": _available(observed.arch),
        "hardware_vendor": _available(None), "hardware_model": _available(None), "soc": _available(gpu),
        "gpu": _available(gpu), "compute_capability": _available(capability), "firmware": _available(None),
        "driver": _available(None), "cuda": _available(tools.get("nvcc")), "nvcc": _available(tools.get("nvcc")),
        "c_compiler": _available(tools.get("gcc")), "cpp_compiler": _available(tools.get("g++")),
        "clock_sync": _available("synchronized" if observed.time_sync is True else "unsynchronized" if observed.time_sync is False else None),
    }
    if not isinstance(observed.primary_weight_sha256, str) or not isinstance(observed.draft_weight_sha256, str):
        _fail("benchmark_identity_unavailable")
    return {
        "schema_version": 1,
        "lab": repositories["lab"], "engine": repositories["engine"], "integration": repositories["integration"],
        "userspace": {"flake_lock_sha256": provenance["flake_lock_hash"], "nixpkgs_revision": provenance["nixpkgs_revision"], "python_version": tools.get("python3") or "unavailable", "uv_version": _uv_version()},
        "controller": dict(provenance["system"]), "target": target,
        "build": {"build_id": build["build_id"], "binary_sha256": build["binary_sha256"], "source_snapshot_id": source.snapshot_id},
        "weights": {"model_sha256": observed.primary_weight_sha256, "drafter_sha256": observed.draft_weight_sha256},
    }


def prepare_benchmark(repo_root: str | os.PathLike[str], target: str, scenario_path: Path) -> PreparedBenchmark:
    from . import workflow

    root = workflow._root(repo_root)
    # No target operation, portable build, or server launch precedes this load.
    try:
        scenario = load_scenario(root / scenario_path, root)
        normalized = normalize_scenario(scenario)
    except Exception as error:
        if error.__class__.__module__.startswith("benchmarks.src.ds4bench"):
            _fail("benchmark_scenario_invalid")
        raise
    config = workflow.load_operational_target(root, target)
    config.validate_for("benchmark")
    transport = select_transport(config, repo_root=root)
    source, build = workflow._ready(root, config.name)
    if workflow.build_snapshot(root).as_dict() != source.as_dict():
        _fail("workflow_source_stale")
    workflow._verify_current_binary(config, build)
    runtime = workflow._runtime(config, source, build)
    try:
        portable = build_runtime_bundle(root / "benchmarks", root / _RUNTIME_ROOT)
        verify_transfer(portable.payload_dir, portable.manifest_path, portable.manifest_sha256, expected_kind="runtime", expected_run_id=portable.aggregate_sha256, expected_lock_sha256=portable.lock_sha256)
    except Exception as error:
        if error.__class__.__module__.startswith("benchmarks.src.ds4bench"):
            _fail("benchmark_runtime_invalid")
        raise
    observed = doctor(config, transport, snapshot=source, allow_dirty=None, runtime=workflow._doctor_runtime(config))
    if observed.status != "succeeded":
        _fail("benchmark_preflight_failed")
    manifest = _source_manifest(root, source, build, observed)
    _size, prompt_hash, _file_id = _inspect_file(root / _PROMPT_MANIFEST, MAX_STAGE_FILE_BYTES)
    return PreparedBenchmark(root, config, transport, source, build, runtime, root / scenario_path, scenario, normalized, portable, manifest, prompt_hash, _directory(root / RESULT_ROOT, create=True))


def _metadata(prepared: PreparedBenchmark, run_id: str, repetition: int) -> dict[str, object]:
    local = prepared.scenario.vantage == "target_local"
    return {
        "schema_version": 1, "run_id": run_id, "scenario_id": prepared.scenario.id,
        "prompt_manifest_sha256": prepared.prompt_manifest_sha256, "vantage": prepared.scenario.vantage,
        "clock_domain": "target_monotonic" if local else "controller_monotonic", "started_utc": datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "configured_policy": dict(prepared.normalized["server"]),
        "observed_execution": {"status": "unavailable", "reason": "not_exposed_by_frozen_source"},
        "network": {"path": "target_loopback" if local else "direct_private_lan", "http_version": "HTTP/1.1", "tls": False, "link_speed_mbps": None, "mtu_bytes": None},
        "warmup_repetitions": prepared.scenario.warmup_repetitions, "measured_repetitions": prepared.scenario.measured_repetitions,
        "pairing": {"pair_id": None, "block_id": None, "order": None, "repetition": repetition},
        "runtime_bundle": {"bundle_sha256": prepared.portable.bundle_sha256, "manifest_sha256": prepared.portable.manifest_sha256, "lock_sha256": prepared.portable.lock_sha256} if local else None,
    }


def _endpoint(prepared: PreparedBenchmark) -> str:
    if prepared.scenario.vantage == "controller_lan":
        if not isinstance(prepared.config.lan_api_base_url, str):
            _fail("benchmark_endpoint_unavailable")
        return prepared.config.lan_api_base_url + "/v1/chat/completions"
    return f"http://127.0.0.1:{prepared.runtime.port}/v1/chat/completions"


def _server_cleanup(prepared: PreparedBenchmark, run_id: str) -> Any:
    from . import workflow

    result = cleanup(prepared.config, prepared.transport, prepared.runtime, run_id=run_id)
    if result.status != "succeeded":
        _fail("benchmark_server_cleanup_failed")
    workflow._clear_pending_run(prepared.root, prepared.config.name, run_id)
    return result


def _remove_report(prepared: PreparedBenchmark, cleanup_result: Any) -> None:
    if cleanup_result.server_log_sha256 is None:
        return
    from . import workflow

    result = workflow._cleanup_promoted_reports(prepared.config, prepared.transport, (("server.log", cleanup_result.server_log_sha256),))
    if result.get("status") != "succeeded":
        _fail("benchmark_server_cleanup_failed")


def _run_controller(prepared: PreparedBenchmark, metadata: Mapping[str, object], case_id: str, repetition: int, work: Path) -> Path:
    # Import the HTTP client only in the controller-LAN execution path.  Root
    # targetctl operations intentionally remain importable without benchmark
    # runtime dependencies; benchmark recipes enter the frozen uv environment.
    from benchmarks.src.ds4bench.execution import run_case_from_files
    metadata_path = work / "metadata.json"
    source_path = work / "source-manifest.json"
    metadata_path.write_bytes(canonical_json_bytes(dict(metadata)))
    source_path.write_bytes(canonical_json_bytes(prepared.source_manifest))
    result_root = work / "result"
    result_root.mkdir(mode=0o700)
    return asyncio.run(run_case_from_files(prepared.scenario_path, prepared.root, _endpoint(prepared), MODEL_ID, result_root, metadata_path, source_path, case_id, repetition))


def _run_target(prepared: PreparedBenchmark, run_id: str, case_id: str, repetition: int) -> None:
    timeout = int(prepared.scenario.deadlines.server_seconds) + 30
    result = _helper(prepared, "benchmark_run_case", {**_root_payload(prepared, run_id), "case_id": _id(case_id), "repetition": repetition, "endpoint": _endpoint(prepared), "model": MODEL_ID, "timeout_seconds": timeout}, timeout + 30)
    if result != {"status": "completed"}:
        _fail("benchmark_execute_failed")


def _write_fd(parent_fd: int, name: str, content: bytes) -> None:
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent_fd)
        try:
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        _fail("benchmark_result_invalid")


def _copy_controller_result(source: Path, staging: Path, server_log: bytes) -> None:
    client_log = b"controller benchmark client completed\n"
    if len(server_log) > RESULT_FILE_LIMITS["server.log"]:
        _fail("benchmark_result_invalid")
    staging.mkdir(mode=0o700)
    fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        for name in sorted(RESULT_FILES):
            if name == "server.log":
                content = server_log
            elif name == "client.log":
                content = client_log
            else:
                size, digest, _item = _inspect_file(source / name, RESULT_FILE_LIMITS[name])
                content = (source / name).read_bytes()
                if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
                    _fail("benchmark_result_invalid")
            if name == "metadata.json":
                try:
                    metadata = json.loads(content)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    _fail("benchmark_result_invalid")
                if not isinstance(metadata, dict) or canonical_json_bytes(metadata) != content:
                    _fail("benchmark_result_invalid")
                metadata["logs"] = {
                    "server": {"sha256": hashlib.sha256(server_log).hexdigest(), "retained_bytes": len(server_log), "truncated": False, "total_bytes": len(server_log)},
                    "client": {"sha256": hashlib.sha256(client_log).hexdigest(), "retained_bytes": len(client_log), "truncated": False, "total_bytes": len(client_log)},
                }
                content = canonical_json_bytes(metadata)
            _write_fd(fd, name, content)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        verify_result(staging)
    except Exception:
        _fail("benchmark_result_invalid")


def _remove_local_tree(path: Path) -> None:
    try:
        item = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        _fail("benchmark_cleanup_failed")
    if not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode) or item.st_uid != os.geteuid():
        _fail("benchmark_cleanup_failed")
    try:
        for entry in os.scandir(path):
            child = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                _remove_local_tree(child)
            else:
                child.unlink()
        path.rmdir()
    except OSError:
        _fail("benchmark_cleanup_failed")


def _promote_controller(prepared: PreparedBenchmark, source: Path, run_id: str, server_log: bytes) -> Path:
    staging = prepared.result_root / f".download-{run_id}-{secrets.token_hex(6)}"
    sidecar = prepared.result_root / f".manifest-{run_id}-{secrets.token_hex(6)}.json"
    try:
        _copy_controller_result(source, staging, server_log)
        transfer = write_transfer_manifest(staging, sidecar, kind="result", run_id=run_id, lock_sha256=prepared.portable.lock_sha256)
        promoted = promote_verified_payload(staging, prepared.result_root / run_id, sidecar, transfer.sha256, expected_kind="result", expected_run_id=run_id, expected_lock_sha256=prepared.portable.lock_sha256)
        verify_result(promoted.path)
        return promoted.path
    except TransferError:
        _fail("benchmark_result_invalid")
    finally:
        try:
            sidecar.unlink()
        except FileNotFoundError:
            pass
        if staging.exists():
            _remove_local_tree(staging)


def _download_target(prepared: PreparedBenchmark, run_id: str) -> Path:
    payload = _root_payload(prepared, run_id)
    response = _helper(prepared, "benchmark_result_prepare", {**payload, "lock_sha256": prepared.portable.lock_sha256}, 60)
    if not isinstance(response, Mapping) or set(response) != {"manifest", "manifest_sha256"}:
        _fail("benchmark_result_invalid")
    try:
        manifest = validate_transfer_manifest(response["manifest"])
        manifest_bytes = canonical_json_bytes(manifest)
    except Exception:
        _fail("benchmark_result_invalid")
    manifest_sha = response["manifest_sha256"]
    if not isinstance(manifest_sha, str) or hashlib.sha256(manifest_bytes).hexdigest() != manifest_sha or manifest["run_id"] != run_id or manifest["lock_sha256"] != prepared.portable.lock_sha256:
        _fail("benchmark_result_invalid")
    staging = prepared.result_root / f".download-{run_id}-{secrets.token_hex(6)}"
    sidecar = prepared.result_root / f".manifest-{run_id}-{secrets.token_hex(6)}.json"
    try:
        staging.mkdir(mode=0o700)
        root_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        try:
            for entry in manifest["entries"]:
                fd = os.open(entry["path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=root_fd)
                digest = hashlib.sha256()
                try:
                    offset = 0
                    while offset < entry["size"]:
                        length = min(CHUNK_BYTES, entry["size"] - offset)
                        chunk = _helper(prepared, "benchmark_result_chunk", {**payload, "manifest_sha256": manifest_sha, "path": entry["path"], "offset": offset, "length": length})
                        if not isinstance(chunk, Mapping) or set(chunk) != {"content_b64", "offset", "size", "chunk_sha256", "eof"}:
                            _fail("benchmark_chunk_invalid")
                        try:
                            content = base64.b64decode(chunk["content_b64"], validate=True)
                        except (TypeError, ValueError):
                            _fail("benchmark_chunk_invalid")
                        if chunk["offset"] != offset or chunk["size"] != len(content) or len(content) != length or chunk["chunk_sha256"] != hashlib.sha256(content).hexdigest() or chunk["eof"] is not (offset + length == entry["size"]):
                            _fail("benchmark_chunk_invalid")
                        view = memoryview(content)
                        while view:
                            written = os.write(fd, view)
                            if written <= 0:
                                _fail("benchmark_result_invalid")
                            view = view[written:]
                        digest.update(content)
                        offset += length
                    if digest.hexdigest() != entry["sha256"]:
                        _fail("benchmark_result_invalid")
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        with sidecar.open("xb", buffering=0) as stream:
            stream.write(manifest_bytes)
            os.fsync(stream.fileno())
        promoted = promote_verified_payload(staging, prepared.result_root / run_id, sidecar, manifest_sha, expected_kind="result", expected_run_id=run_id, expected_lock_sha256=prepared.portable.lock_sha256)
        verify_result(promoted.path)
        return promoted.path
    except TransferError:
        _fail("benchmark_result_invalid")
    finally:
        try:
            sidecar.unlink()
        except FileNotFoundError:
            pass
        if staging.exists():
            _remove_local_tree(staging)


def run_repetition(prepared: PreparedBenchmark, case_id: str, repetition: int, *, retain: bool) -> Path | None:
    from . import workflow

    run_id = "b-" + secrets.token_hex(15)
    metadata = _metadata(prepared, run_id, repetition)
    staged = pending = False
    cleanup_result = None
    client_result = promoted = None
    primary: BaseException | None = None
    cleanup_error: BaseException | None = None
    work: tempfile.TemporaryDirectory[str] | None = None
    try:
        # Removal is idempotent, so claim cleanup responsibility before the
        # first staging request can create any target-side state.
        staged = True
        _stage(prepared, run_id, metadata)
        workflow._store_pending_run(prepared.root, prepared.config.name, prepared.source, prepared.build, run_id)
        pending = True
        profile = launch_profile_from_scenario(prepared.normalized["server"], prepared.scenario.vantage)
        bind_host = prepared.config.lan_bind_host if prepared.scenario.vantage == "controller_lan" else None
        try:
            serve(prepared.config, prepared.transport, prepared.runtime, run_id=run_id, launch_profile=profile, bind_host=bind_host)
        except TargetError as error:
            workflow._clear_new_pending_on_refusal(prepared.root, prepared.config.name, run_id, error)
            if error.code == "serve_not_dispatched":
                pending = False
            raise
        if prepared.scenario.vantage == "controller_lan":
            state = _directory(prepared.root / "targets/.state", create=True)
            work = tempfile.TemporaryDirectory(prefix=".controller-case-", dir=state)
            client_result = _run_controller(prepared, metadata, case_id, repetition, Path(work.name))
        else:
            _run_target(prepared, run_id, case_id, repetition)
    except BaseException as error:
        primary = error
    finally:
        if pending:
            try:
                cleanup_result = _server_cleanup(prepared, run_id)
            except BaseException as error:
                if primary is None:
                    primary = error
        if primary is None and cleanup_result is not None:
            try:
                if prepared.scenario.vantage == "controller_lan":
                    server = logs(prepared.config, prepared.transport, prepared.runtime, run_id=run_id)
                    if not isinstance(server, bytes):
                        _fail("benchmark_result_invalid")
                    if retain:
                        promoted = _promote_controller(prepared, client_result, run_id, server)
                else:
                    if _helper(prepared, "benchmark_result_finalize", _root_payload(prepared, run_id), 60) != {"status": "verified"}:
                        _fail("benchmark_result_invalid")
                    if retain:
                        promoted = _download_target(prepared, run_id)
            except BaseException as error:
                primary = error
        if cleanup_result is not None:
            try:
                _remove_report(prepared, cleanup_result)
            except BaseException as error:
                cleanup_error = error
        if staged:
            try:
                _remove_stage(prepared, run_id)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        if work is not None:
            try:
                work.cleanup()
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
    if cleanup_error is not None:
        if isinstance(cleanup_error, TargetError):
            raise cleanup_error
        _fail("benchmark_cleanup_failed")
    if primary is not None:
        if isinstance(primary, (TargetError, KeyboardInterrupt, asyncio.CancelledError)):
            raise primary
        _fail("benchmark_execution_failed")
    return promoted


def _plan(scenario: Scenario, smoke: bool) -> tuple[tuple[str, int, bool], ...]:
    cases = scenario.schedule.case_matrix[:1] if smoke else scenario.schedule.case_matrix
    result: list[tuple[str, int, bool]] = []
    for case in cases:
        if not smoke:
            result.extend((case.id, warmup % scenario.measured_repetitions, False) for warmup in range(scenario.warmup_repetitions))
        result.extend((case.id, repetition, True) for repetition in (range(1) if smoke else range(scenario.measured_repetitions)))
    return tuple(result)


def run_scenario(repo_root: str | os.PathLike[str], target: str, operation: str, *, smoke: bool = False) -> dict[str, object]:
    selected = "bench-s1" if operation == "bench-smoke" else operation
    if selected not in SCENARIOS:
        _fail("benchmark_operation_invalid")
    prepared = prepare_benchmark(repo_root, target, SCENARIOS[selected])
    artifacts: list[str] = []
    for case_id, repetition, retain in _plan(prepared.scenario, smoke):
        result = run_repetition(prepared, case_id, repetition, retain=retain)
        if result is not None:
            try:
                artifacts.append(result.relative_to(prepared.root).as_posix())
            except ValueError:
                _fail("benchmark_result_invalid")
    return {"status": "succeeded", "scenario": prepared.scenario.id, "vantage": prepared.scenario.vantage, "artifacts": artifacts, "measured_results": len(artifacts)}


def run_baseline(repo_root: str | os.PathLike[str], target: str) -> dict[str, object]:
    return {"status": "succeeded", "scenarios": [run_scenario(repo_root, target, operation) for operation in ("bench-s1", "bench-s2", "bench-s3", "bench-s5a", "bench-s5b")]}


def compare(repo_root: str | os.PathLike[str], baseline: str | os.PathLike[str], candidate: str | os.PathLike[str]) -> dict[str, object]:
    from benchmarks.src.ds4bench.compare import compare_results

    root = _directory(Path(repo_root))
    paths: list[Path] = []
    for value in (baseline, candidate):
        try:
            path = Path(value)
            path = path if path.is_absolute() else root / path
            path = Path(os.path.abspath(os.fspath(path)))
        except (OSError, TypeError, ValueError):
            _fail("benchmark_compare_invalid")
        if len(os.fspath(path)) > 4096:
            _fail("benchmark_compare_invalid")
        paths.append(path)
    try:
        result = compare_results(paths[0], paths[1])
    except Exception:
        _fail("benchmark_compare_invalid")
    return {"status": "succeeded", "comparison": result}


def execute_benchmark(repo_root: str | os.PathLike[str], target: str, operation: str, *, baseline: str | os.PathLike[str] | None = None, candidate: str | os.PathLike[str] | None = None) -> dict[str, object]:
    if operation == "compare":
        if baseline is None or candidate is None:
            _fail("benchmark_compare_invalid")
        return compare(repo_root, baseline, candidate)
    if baseline is not None or candidate is not None:
        _fail("benchmark_input_invalid")
    if operation == "bench-v1-baseline":
        return run_baseline(repo_root, target)
    if operation == "bench-smoke":
        return run_scenario(repo_root, target, operation, smoke=True)
    return run_scenario(repo_root, target, operation)


def structured_benchmark_result(repo_root: str | os.PathLike[str], target: str, operation: str, *, baseline: str | os.PathLike[str] | None = None, candidate: str | os.PathLike[str] | None = None) -> dict[str, object]:
    try:
        return {"schema": 1, "operation": operation, "target": target, **execute_benchmark(repo_root, target, operation, baseline=baseline, candidate=candidate)}
    except KeyboardInterrupt:
        return {"schema": 1, "operation": operation, "target": target, "status": "failed", "error": "interrupted"}
    except TargetError as error:
        return {"schema": 1, "operation": operation, "target": target, "status": "failed", "error": error.code}
    except BaseException:
        return {"schema": 1, "operation": operation, "target": target, "status": "failed", "error": "internal_error"}


BENCHMARK_HELPER_EXTENSION = r'''
import signal
import subprocess

_BM_BASE = "benchmark-v2"
_BM_MANIFEST = ".stage-manifest.json"
_BM_RESULT_STATE = ".result-transfer.json"
_BM_CHUNK = 384 * 1024
_BM_SAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
_BM_RESULT_LIMITS = {"metadata.json":8388608,"scenario.json":8388608,"source-manifest.json":8388608,"requests.jsonl":134217728,"server.log":1048576,"client.log":1048576,"telemetry.jsonl":67108864,"summary.json":8388608,"summary.md":8388608}


def _bm_id(value):
  if not isinstance(value,str) or not 1 <= len(value) <= 64 or value in (".","..") or any(char not in _BM_SAFE for char in value): _fail("benchmark_stage_invalid")
  return value


def _bm_relative(value):
  if not isinstance(value,str) or not value or len(value)>512 or not value.isascii() or "\\" in value: _fail("benchmark_stage_invalid")
  path=PurePosixPath(value); parts=value.split("/")
  if path.is_absolute() or path.as_posix()!=value or any(part in ("",".","..") for part in parts): _fail("benchmark_stage_invalid")
  if any(len(part)>128 or any(char not in _BM_SAFE for char in part) for part in parts): _fail("benchmark_stage_invalid")
  return value


def _bm_json(value):
  try: return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
  except (TypeError,ValueError): _fail("benchmark_stage_invalid")


def _bm_manifest(value,run_id):
  value=_require_object(value,{"schema_version","kind","run_id","entries","aggregate_sha256"})
  if value["schema_version"]!=1 or value["kind"]!="benchmark_stage" or value["run_id"]!=run_id or not _is_hex_digest(value["aggregate_sha256"]): _fail("benchmark_stage_invalid")
  entries=value["entries"]
  if not isinstance(entries,list) or not 1<=len(entries)<=64: _fail("benchmark_stage_invalid")
  clean=[]; total=0
  for raw in entries:
    raw=_require_object(raw,{"path","size","sha256"}); path=_bm_relative(raw["path"]); size=raw["size"]
    if not isinstance(size,int) or isinstance(size,bool) or not 0<=size<=8388608 or not _is_hex_digest(raw["sha256"]): _fail("benchmark_stage_invalid")
    total+=size
    if total>83886080: _fail("benchmark_stage_invalid")
    clean.append({"path":path,"size":size,"sha256":raw["sha256"]})
  if [x["path"] for x in clean]!=sorted(x["path"] for x in clean) or len({x["path"] for x in clean})!=len(clean): _fail("benchmark_stage_invalid")
  required={"ds4bench.pyz","licenses.json","runtime-manifest.json","scenario.json","metadata.json","source-manifest.json","benchmarks/prompts/manifest.json"}
  if not required <= {x["path"] for x in clean}: _fail("benchmark_stage_invalid")
  digest=hashlib.sha256(b"targetctl-benchmark-stage-v1\0"); digest.update(len(clean).to_bytes(4,"big"))
  for item in clean:
    name=item["path"].encode("ascii"); digest.update(len(name).to_bytes(2,"big")); digest.update(name); digest.update(item["size"].to_bytes(8,"big")); digest.update(bytes.fromhex(item["sha256"]))
  if digest.hexdigest()!=value["aggregate_sha256"]: _fail("benchmark_stage_invalid")
  return {"schema_version":1,"kind":"benchmark_stage","run_id":run_id,"entries":clean,"aggregate_sha256":value["aggregate_sha256"]}


def _bm_root(run_dir,token):
  fd=_open_root(_validate_absolute_path(run_dir))
  try: _read_marker(fd,"run",token); _root_identity(fd,"run",token)
  except BaseException: os.close(fd); raise
  return fd


def _bm_dir(parent,name,create=False):
  try: item=os.stat(name,dir_fd=parent,follow_symlinks=False)
  except FileNotFoundError:
    if not create: raise
    try: os.mkdir(name,0o700,dir_fd=parent); item=os.stat(name,dir_fd=parent,follow_symlinks=False)
    except OSError: _fail("benchmark_stage_invalid")
  except OSError: _fail("benchmark_stage_invalid")
  if not stat.S_ISDIR(item.st_mode) or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o700: _fail("benchmark_stage_invalid")
  return _open_directory(parent,name)


def _bm_parent(root,relative,create=False):
  parts=_bm_relative(relative).split("/"); current=os.dup(root)
  try:
    for part in parts[:-1]:
      child=_bm_dir(current,part,create); os.close(current); current=child
    return current,parts[-1]
  except BaseException: os.close(current); raise


def _bm_write(parent,name,content):
  try: fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=parent)
  except OSError: _fail("benchmark_stage_conflict")
  try:
    view=memoryview(content)
    while view:
      count=os.write(fd,view)
      if count<=0: _fail("benchmark_stage_invalid")
      view=view[count:]
    os.fsync(fd)
  finally: os.close(fd)


def _bm_read(parent,name,limit):
  fd,item=_open_regular(name,dir_fd=parent)
  try:
    if item.st_uid!=os.geteuid() or item.st_nlink!=1 or item.st_size>limit: _fail("benchmark_stage_invalid")
    out=bytearray()
    while chunk:=os.read(fd,min(131072,limit-len(out)+1)):
      out.extend(chunk)
      if len(out)>limit: _fail("benchmark_stage_invalid")
    after=os.fstat(fd)
    identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    if identity(item)!=identity(after): _fail("benchmark_stage_invalid")
    return bytes(out)
  finally: os.close(fd)


def _bm_open(payload,incoming=False):
  data=_require_object(payload,{"run_dir","run_token","run_id"}); run_id=_bm_id(data["run_id"]); root=_bm_root(data["run_dir"],data["run_token"]); base=_bm_dir(root,_BM_BASE); name=(".incoming-" if incoming else "")+run_id
  try: stage=_bm_dir(base,name)
  except BaseException: os.close(base); os.close(root); raise
  return root,base,stage,run_id


def _bm_close(items):
  for fd in reversed(items[:3]): os.close(fd)


def _bm_loaded(stage,run_id):
  try: value=json.loads(_bm_read(stage,_BM_MANIFEST,1048576).decode("ascii"))
  except (ValueError,UnicodeDecodeError): _fail("benchmark_stage_invalid")
  value=_bm_manifest(value,run_id)
  if _bm_json(value)!=_bm_read(stage,_BM_MANIFEST,1048576): _fail("benchmark_stage_invalid")
  return value


def _bm_hash(stage,entry):
  parent,name=_bm_parent(stage,entry["path"])
  try:
    fd,item=_open_regular(name,dir_fd=parent)
    try:
      if item.st_uid!=os.geteuid() or item.st_nlink!=1 or item.st_size!=entry["size"]: _fail("benchmark_stage_incomplete")
      digest=hashlib.sha256(); total=0
      while chunk:=os.read(fd,min(1048576,entry["size"]-total+1)):
        total+=len(chunk); digest.update(chunk)
        if total>entry["size"]: _fail("benchmark_stage_incomplete")
      after=os.fstat(fd)
      identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
      if identity(item)!=identity(after) or total!=entry["size"] or digest.hexdigest()!=entry["sha256"]: _fail("benchmark_stage_incomplete")
    finally: os.close(fd)
  finally: os.close(parent)


def _bm_layout(stage,manifest):
  files={item["path"] for item in manifest["entries"]}|{_BM_MANIFEST}; directories={"results"}
  for path in files:
    parts=path.split("/")
    directories.update("/".join(parts[:index]) for index in range(1,len(parts)))
  def walk(directory,prefix):
    for name in os.listdir(directory):
      relative=name if not prefix else prefix+"/"+name
      try: item=os.stat(name,dir_fd=directory,follow_symlinks=False)
      except OSError: _fail("benchmark_stage_invalid")
      if stat.S_ISDIR(item.st_mode):
        if relative not in directories or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o700: _fail("benchmark_stage_invalid")
        child=_bm_dir(directory,name)
        try: walk(child,relative)
        finally: os.close(child)
      elif stat.S_ISREG(item.st_mode):
        if relative not in files or item.st_uid!=os.geteuid() or item.st_nlink!=1: _fail("benchmark_stage_invalid")
      else: _fail("benchmark_stage_invalid")
  walk(stage,"")


def _bm_remove(parent,name):
  try: item=os.stat(name,dir_fd=parent,follow_symlinks=False)
  except FileNotFoundError: return False
  if not stat.S_ISDIR(item.st_mode):
    try: os.unlink(name,dir_fd=parent); return True
    except OSError: _fail("benchmark_cleanup_failed")
  directory=_bm_dir(parent,name)
  try:
    for child in os.listdir(directory): _bm_remove(directory,child)
  finally: os.close(directory)
  try: os.rmdir(name,dir_fd=parent)
  except OSError: _fail("benchmark_cleanup_failed")
  return True


def _bm_ticks(pid):
  try:
    raw=open("/proc/%d/stat"%pid,"rb").read(8192); close=raw.rfind(b")"); return int(raw[close+2:].split()[19])
  except (OSError,ValueError,IndexError): return None


@register_action("benchmark_stage_begin")
def benchmark_stage_begin(payload):
  data=_require_object(payload,{"run_dir","run_token","run_id","manifest"}); run_id=_bm_id(data["run_id"]); manifest=_bm_manifest(data["manifest"],run_id); root=_bm_root(data["run_dir"],data["run_token"])
  try:
    base=_bm_dir(root,_BM_BASE,True)
    try:
      try: final=_bm_dir(base,run_id)
      except FileNotFoundError: final=None
      if final is not None:
        try:
          if _bm_loaded(final,run_id)!=manifest: _fail("benchmark_stage_conflict")
          for entry in manifest["entries"]: _bm_hash(final,entry)
          return {"status":"committed"}
        finally: os.close(final)
      incoming=".incoming-"+run_id
      try: stage=_bm_dir(base,incoming)
      except FileNotFoundError:
        try: os.mkdir(incoming,0o700,dir_fd=base)
        except OSError: _fail("benchmark_stage_conflict")
        stage=_bm_dir(base,incoming)
        _bm_write(stage,_BM_MANIFEST,_bm_json(manifest)); results_fd=_bm_dir(stage,"results",True); os.close(results_fd)
        for entry in manifest["entries"]:
          parent,_name=_bm_parent(stage,entry["path"],True); os.close(parent)
      try:
        if _bm_loaded(stage,run_id)!=manifest: _fail("benchmark_stage_conflict")
      finally: os.close(stage)
      return {"status":"ready"}
    finally: os.close(base)
  finally: os.close(root)


@register_action("benchmark_stage_chunk")
def benchmark_stage_chunk(payload):
  data=_require_object(payload,{"run_dir","run_token","run_id","path","offset","content_b64","chunk_sha256"}); handles=_bm_open({key:data[key] for key in ("run_dir","run_token","run_id")},True)
  try:
    manifest=_bm_loaded(handles[2],handles[3]); path=_bm_relative(data["path"]); matches=[x for x in manifest["entries"] if x["path"]==path]
    if len(matches)!=1: _fail("benchmark_chunk_invalid")
    entry=matches[0]; offset=data["offset"]
    try: content=base64.b64decode(data["content_b64"],validate=True)
    except (TypeError,ValueError): _fail("benchmark_chunk_invalid")
    if not isinstance(offset,int) or isinstance(offset,bool) or not content or len(content)>_BM_CHUNK or not 0<=offset or offset+len(content)>entry["size"] or hashlib.sha256(content).hexdigest()!=data["chunk_sha256"]: _fail("benchmark_chunk_invalid")
    parent,name=_bm_parent(handles[2],path)
    try:
      try: fd=os.open(name,os.O_RDWR|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),dir_fd=parent)
      except FileNotFoundError: fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=parent)
      except OSError: _fail("benchmark_chunk_invalid")
      try:
        item=os.fstat(fd)
        if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.geteuid() or item.st_nlink!=1 or item.st_size>entry["size"]: _fail("benchmark_chunk_invalid")
        if offset<item.st_size:
          if offset+len(content)>item.st_size or os.pread(fd,len(content),offset)!=content: _fail("benchmark_chunk_invalid")
        elif offset==item.st_size:
          view=memoryview(content)
          while view:
            count=os.write(fd,view)
            if count<=0: _fail("benchmark_chunk_invalid")
            view=view[count:]
          os.fsync(fd)
        else: _fail("benchmark_chunk_invalid")
      finally: os.close(fd)
    finally: os.close(parent)
    return {"offset":offset,"size":len(content)}
  finally: _bm_close(handles)


@register_action("benchmark_stage_commit")
def benchmark_stage_commit(payload):
  data=_require_object(payload,{"run_dir","run_token","run_id"}); run_id=_bm_id(data["run_id"]); root=_bm_root(data["run_dir"],data["run_token"])
  try:
    base=_bm_dir(root,_BM_BASE)
    try:
      try: final=_bm_dir(base,run_id)
      except FileNotFoundError: final=None
      if final is not None:
        try:
          for entry in _bm_loaded(final,run_id)["entries"]: _bm_hash(final,entry)
          return {"status":"committed"}
        finally: os.close(final)
      incoming=".incoming-"+run_id; stage=_bm_dir(base,incoming)
      try:
        manifest=_bm_loaded(stage,run_id); _bm_layout(stage,manifest)
        for entry in manifest["entries"]: _bm_hash(stage,entry)
        os.fsync(stage)
      finally: os.close(stage)
      try: os.rename(incoming,run_id,src_dir_fd=base,dst_dir_fd=base); os.fsync(base)
      except OSError: _fail("benchmark_stage_conflict")
      return {"status":"committed"}
    finally: os.close(base)
  finally: os.close(root)


@register_action("benchmark_run_case")
def benchmark_run_case(payload):
  data=_require_object(payload,{"run_dir","run_token","run_id","case_id","repetition","endpoint","model","timeout_seconds"}); handles=_bm_open({key:data[key] for key in ("run_dir","run_token","run_id")}); stage=handles[2]; process=None; outfd=errfd=None
  try:
    case=_bm_id(data["case_id"]); repetition=data["repetition"]; timeout=data["timeout_seconds"]
    if not isinstance(repetition,int) or isinstance(repetition,bool) or not 0<=repetition<=99 or not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=86400: _fail("benchmark_execute_failed")
    if not isinstance(data["endpoint"],str) or not 1<=len(data["endpoint"])<=2048 or not isinstance(data["model"],str) or not 1<=len(data["model"])<=256: _fail("benchmark_execute_failed")
    outfd=os.open(".client.stdout",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600,dir_fd=stage); errfd=os.open(".client.stderr",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600,dir_fd=stage); root="/proc/self/fd/%d"%stage
    argv=("/usr/bin/python3",root+"/ds4bench.pyz","run-case","--scenario",root+"/scenario.json","--repo-root",root,"--endpoint",data["endpoint"],"--model",data["model"],"--result-root",root+"/results","--metadata",root+"/metadata.json","--source-manifest",root+"/source-manifest.json","--case",case,"--repetition",str(repetition))
    try: process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=outfd,stderr=errfd,cwd=root,env={"LANG":"C","LC_ALL":"C","PATH":"/usr/bin:/bin","PYTHONDONTWRITEBYTECODE":"1"},shell=False,start_new_session=True,pass_fds=(stage,))
    except OSError: _fail("benchmark_execute_failed")
    ticks=_bm_ticks(process.pid)
    if ticks is None: _fail("benchmark_execute_failed")
    _bm_write(stage,".client-state.json",_bm_json({"pid":process.pid,"start_ticks":ticks}))
    try: code=process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
      try: os.killpg(process.pid,signal.SIGKILL)
      except ProcessLookupError: pass
      process.wait(); _fail("benchmark_execute_failed")
    finally:
      try: os.unlink(".client-state.json",dir_fd=stage)
      except FileNotFoundError: pass
    os.close(outfd); outfd=None; os.close(errfd); errfd=None; stdout=_bm_read(stage,".client.stdout",65536); stderr=_bm_read(stage,".client.stderr",65536)
    try: response=json.loads(stdout.decode("ascii"))
    except (ValueError,UnicodeDecodeError): _fail("benchmark_execute_failed")
    expected={"case_id":case,"command":"run-case","repetition":repetition,"status":"ok"}
    if code!=0 or stderr or response!=expected: _fail("benchmark_execute_failed")
    return {"status":"completed"}
  finally:
    if outfd is not None: os.close(outfd)
    if errfd is not None: os.close(errfd)
    if process is not None and process.poll() is None:
      try: os.killpg(process.pid,signal.SIGKILL)
      except ProcessLookupError: pass
      process.wait()
    _bm_close(handles)


def _bm_replace(parent,name,content):
  temporary=".replace-"+secrets.token_hex(12); _bm_write(parent,temporary,content)
  try: os.replace(temporary,name,src_dir_fd=parent,dst_dir_fd=parent); os.fsync(parent)
  except OSError: _fail("benchmark_result_invalid")


def _bm_result(stage,run_id):
  results=_bm_dir(stage,"results")
  try: return _bm_dir(results,run_id)
  finally: os.close(results)


@register_action("benchmark_result_finalize")
def benchmark_result_finalize(payload):
  handles=_bm_open(payload); result=None
  try:
    result=_bm_result(handles[2],handles[3]); server=_bm_read(handles[0],"server.log",1048576); client=_bm_read(handles[2],".client.stdout",65536); _bm_replace(result,"server.log",server); _bm_replace(result,"client.log",client)
    try: metadata=json.loads(_bm_read(result,"metadata.json",8388608).decode("utf-8"))
    except (ValueError,UnicodeDecodeError): _fail("benchmark_result_invalid")
    if not isinstance(metadata,dict) or metadata.get("run_id")!=handles[3]: _fail("benchmark_result_invalid")
    metadata["logs"]={"server":{"sha256":hashlib.sha256(server).hexdigest(),"retained_bytes":len(server),"truncated":False,"total_bytes":len(server)},"client":{"sha256":hashlib.sha256(client).hexdigest(),"retained_bytes":len(client),"truncated":False,"total_bytes":len(client)}}; _bm_replace(result,"metadata.json",_bm_json(metadata)); root="/proc/self/fd/%d"%handles[2]
    checked=subprocess.run(("/usr/bin/python3",root+"/ds4bench.pyz","verify-result",root+"/results/"+handles[3]),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=root,env={"LANG":"C","LC_ALL":"C","PATH":"/usr/bin:/bin","PYTHONDONTWRITEBYTECODE":"1"},shell=False,timeout=60,check=False,pass_fds=(handles[2],))
    if checked.returncode!=0 or checked.stderr or len(checked.stdout)>65536: _fail("benchmark_result_invalid")
    try: response=json.loads(checked.stdout.decode("ascii"))
    except (ValueError,UnicodeDecodeError): _fail("benchmark_result_invalid")
    if response!={"command":"verify-result","status":"ok"}: _fail("benchmark_result_invalid")
    for name in (".client.stdout",".client.stderr"):
      try: os.unlink(name,dir_fd=handles[2])
      except FileNotFoundError: pass
    return {"status":"verified"}
  finally:
    if result is not None: os.close(result)
    _bm_close(handles)


def _bm_result_entries(result):
  if set(os.listdir(result))!=set(_BM_RESULT_LIMITS): _fail("benchmark_result_invalid")
  entries=[]; identities={}; total=0
  for name in sorted(_BM_RESULT_LIMITS):
    fd,item=_open_regular(name,dir_fd=result)
    try:
      if item.st_uid!=os.geteuid() or item.st_nlink!=1 or item.st_size>_BM_RESULT_LIMITS[name]: _fail("benchmark_result_invalid")
      digest=hashlib.sha256(); count=0
      while chunk:=os.read(fd,min(1048576,_BM_RESULT_LIMITS[name]-count+1)):
        count+=len(chunk); digest.update(chunk)
        if count>_BM_RESULT_LIMITS[name]: _fail("benchmark_result_invalid")
      after=os.fstat(fd); identity=[after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns]
      if identity!=[item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns]: _fail("benchmark_result_invalid")
      total+=count
      if total>268435456: _fail("benchmark_result_invalid")
      entries.append({"path":name,"size":count,"sha256":digest.hexdigest()}); identities[name]=identity
    finally: os.close(fd)
  return entries,identities


def _bm_transfer(entries,run_id,lock):
  if not _is_hex_digest(lock): _fail("benchmark_result_invalid")
  digest=hashlib.sha256(b"ds4bench-transfer-aggregate-v1\0"); digest.update(len(entries).to_bytes(4,"big"))
  for entry in entries:
    name=entry["path"].encode("ascii"); digest.update(len(name).to_bytes(2,"big")); digest.update(name); digest.update(entry["size"].to_bytes(8,"big")); digest.update(bytes.fromhex(entry["sha256"]))
  return {"schema_version":1,"kind":"result","run_id":run_id,"entries":entries,"aggregate_sha256":digest.hexdigest(),"lock_sha256":lock}


@register_action("benchmark_result_prepare")
def benchmark_result_prepare(payload):
  data=_require_object(payload,{"run_dir","run_token","run_id","lock_sha256"}); handles=_bm_open({key:data[key] for key in ("run_dir","run_token","run_id")}); result=None
  try:
    result=_bm_result(handles[2],handles[3]); entries,identities=_bm_result_entries(result); manifest=_bm_transfer(entries,handles[3],data["lock_sha256"]); manifest_sha=hashlib.sha256(_bm_json(manifest)).hexdigest(); state={"manifest":manifest,"manifest_sha256":manifest_sha,"identities":identities}
    try: existing=_bm_read(handles[2],_BM_RESULT_STATE,1048576)
    except HelperError as error:
      if error.code!="missing_path": raise
      _bm_write(handles[2],_BM_RESULT_STATE,_bm_json(state))
    else:
      if existing!=_bm_json(state): _fail("benchmark_result_invalid")
    return {"manifest":manifest,"manifest_sha256":manifest_sha}
  finally:
    if result is not None: os.close(result)
    _bm_close(handles)


@register_action("benchmark_result_chunk")
def benchmark_result_chunk(payload):
  data=_require_object(payload,{"run_dir","run_token","run_id","manifest_sha256","path","offset","length"}); handles=_bm_open({key:data[key] for key in ("run_dir","run_token","run_id")}); result=fd=None
  try:
    try: state=json.loads(_bm_read(handles[2],_BM_RESULT_STATE,1048576).decode("ascii"))
    except (ValueError,UnicodeDecodeError): _fail("benchmark_result_invalid")
    path=_bm_relative(data["path"]); entries=[x for x in state.get("manifest",{}).get("entries",[]) if x.get("path")==path]; offset=data["offset"]; length=data["length"]
    if state.get("manifest_sha256")!=data["manifest_sha256"] or len(entries)!=1 or path not in state.get("identities",{}) or not isinstance(offset,int) or isinstance(offset,bool) or not isinstance(length,int) or isinstance(length,bool) or not 0<=offset<entries[0]["size"] or not 1<=length<=_BM_CHUNK or offset+length>entries[0]["size"]: _fail("benchmark_chunk_invalid")
    result=_bm_result(handles[2],handles[3]); fd,item=_open_regular(path,dir_fd=result); identity=[item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns]
    if identity!=state["identities"][path]: _fail("benchmark_result_invalid")
    content=os.pread(fd,length,offset); after=os.fstat(fd)
    if len(content)!=length or identity!=[after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns]: _fail("benchmark_result_invalid")
    return {"content_b64":base64.b64encode(content).decode("ascii"),"offset":offset,"size":len(content),"chunk_sha256":hashlib.sha256(content).hexdigest(),"eof":offset+len(content)==entries[0]["size"]}
  finally:
    if fd is not None: os.close(fd)
    if result is not None: os.close(result)
    _bm_close(handles)


@register_action("benchmark_stage_remove")
def benchmark_stage_remove(payload):
  data=_require_object(payload,{"run_dir","run_token","run_id"}); run_id=_bm_id(data["run_id"]); root=_bm_root(data["run_dir"],data["run_token"])
  try:
    base=_bm_dir(root,_BM_BASE,True)
    try:
      for name in (run_id,".incoming-"+run_id):
        try: stage=_bm_dir(base,name)
        except FileNotFoundError: continue
        try:
          try: state=json.loads(_bm_read(stage,".client-state.json",4096).decode("ascii"))
          except HelperError as error:
            if error.code!="missing_path": raise
            state=None
          if isinstance(state,dict) and set(state)=={"pid","start_ticks"} and _bm_ticks(state["pid"])==state["start_ticks"]:
            try: os.killpg(state["pid"],signal.SIGKILL)
            except ProcessLookupError: pass
        finally: os.close(stage)
      removed=_bm_remove(base,run_id); removed=_bm_remove(base,".incoming-"+run_id) or removed; os.fsync(base); return {"status":"removed" if removed else "not_found"}
    finally: os.close(base)
  finally: os.close(root)
'''

__all__ = ["BENCHMARK_HELPER_EXTENSION", "BENCHMARK_OPERATIONS", "MODEL_ID", "SCENARIOS", "compare", "execute_benchmark", "prepare_benchmark", "run_baseline", "run_repetition", "run_scenario", "structured_benchmark_result"]
