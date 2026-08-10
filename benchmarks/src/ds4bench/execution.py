"""Strict file-oriented entry points for the portable benchmark runtime."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import httpx

from .artifacts import (
    ArtifactError,
    validate_metadata,
    validate_source_manifest,
    verify_result,
)
from .client import OpenAIChatClient, run_request
from .runner import ArtifactInputs, RunnerError, run_case
from .schema import (
    Case,
    Deadlines,
    OutputBudget,
    Sampling,
    Scenario,
    ScenarioError,
    ScenarioRequest,
    load_calibration_manifest,
    load_scenario,
    normalize_scenario,
)
from .stats import canonical_json_bytes, sha256_bytes

MAX_PATH_CHARS = 4096
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_PROMPT_BYTES = 2 * 1024 * 1024
MAX_PROMPT_AGGREGATE_BYTES = 64 * 1024 * 1024
MAX_ENDPOINT_CHARS = 2048
MAX_MODEL_CHARS = 256

_METADATA_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "scenario_id",
        "prompt_manifest_sha256",
        "vantage",
        "clock_domain",
        "started_utc",
        "configured_policy",
        "observed_execution",
        "network",
        "warmup_repetitions",
        "measured_repetitions",
        "pairing",
        "runtime_bundle",
    }
)
_CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}\Z", re.ASCII)
_COMPLETED_FINISHES = frozenset({"stop", "length"})
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class ExecutionError(ValueError):
    """A fixed, bounded portable-execution failure classification."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


async def run_case_from_files(
    scenario_path: Path | str,
    repo_root: Path | str,
    endpoint: str,
    model: str,
    result_root: Path | str,
    metadata_path: Path | str,
    source_manifest_path: Path | str,
    case_id: str,
    repetition: int,
    *,
    headers: Mapping[str, str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Path:
    """Validate every file and identity before delegating to the async runner."""

    root = _existing_directory(repo_root, "invalid_repo_root")
    scenario_file = _regular_input_path(scenario_path, "invalid_scenario_path")
    try:
        scenario = load_scenario(scenario_file, root)
    except (ScenarioError, OSError) as error:
        raise ExecutionError("scenario_invalid") from error

    checked_case = _select_case(scenario, case_id)
    checked_repetition = _repetition(repetition, scenario.measured_repetitions)

    metadata = _canonical_object_file(metadata_path, "metadata_invalid")
    source_manifest = _canonical_object_file(
        source_manifest_path, "source_manifest_invalid"
    )
    normalized = normalize_scenario(scenario)
    _validate_run_inputs(
        metadata,
        source_manifest,
        normalized,
        checked_repetition,
    )

    checked_endpoint = _endpoint(endpoint)
    checked_model = _model(model)
    destination = _output_root(result_root)
    _preflight_case_prompts(scenario, checked_case, root)

    try:
        return await run_case(
            scenario,
            checked_case,
            checked_repetition,
            repo_root=root,
            endpoint=checked_endpoint,
            model=checked_model,
            result_root=destination,
            artifacts=ArtifactInputs(metadata=metadata, source_manifest=source_manifest),
            headers=headers,
            transport=transport,
        )
    except RunnerError as error:
        raise ExecutionError("case_execution_invalid") from error
    except ArtifactError as error:
        raise ExecutionError("result_write_failed") from error
    except OSError as error:
        raise ExecutionError("result_write_failed") from error


async def calibrate_prompts(
    manifest_path: Path | str,
    repo_root: Path | str,
    endpoint: str,
    model: str,
    output_path: Path | str,
    *,
    headers: Mapping[str, str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Path:
    """Measure every unmeasured prompt once and atomically write its manifest."""

    root = _existing_directory(repo_root, "invalid_repo_root")
    manifest_file = _regular_input_path(manifest_path, "calibration_manifest_invalid")
    manifest_bytes, _ = _read_canonical_object(
        manifest_file, MAX_MANIFEST_BYTES, "calibration_manifest_invalid"
    )
    manifest_sha256 = sha256_bytes(manifest_bytes)
    try:
        manifest = load_calibration_manifest(manifest_file, root)
    except (ScenarioError, OSError) as error:
        raise ExecutionError("calibration_manifest_invalid") from error
    if any(prompt.status != "unmeasured" or prompt.token_count is not None for prompt in manifest.prompts):
        raise ExecutionError("calibration_manifest_not_unmeasured")
    if sha256_bytes(_read_regular_bytes(manifest_file, MAX_MANIFEST_BYTES, "calibration_manifest_invalid")) != manifest_sha256:
        raise ExecutionError("calibration_input_changed")

    checked_endpoint = _endpoint(endpoint)
    checked_model = _model(model)
    destination, destination_parent = _output_file(output_path)

    loaded: list[tuple[object, Path, bytes, str]] = []
    aggregate_size = 0
    prompt_destinations: set[Path] = set()
    for prompt in manifest.prompts:
        relative = PurePosixPath(prompt.path)
        prompt_path = root.joinpath(*relative.parts)
        payload = _read_regular_bytes(
            prompt_path, MAX_PROMPT_BYTES, "calibration_prompt_invalid"
        )
        aggregate_size += len(payload)
        if aggregate_size > MAX_PROMPT_AGGREGATE_BYTES:
            raise ExecutionError("calibration_prompt_aggregate_too_large")
        digest = sha256_bytes(payload)
        if digest != prompt.sha256:
            raise ExecutionError("calibration_prompt_hash_mismatch")
        try:
            payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ExecutionError("calibration_prompt_invalid_utf8") from error
        resolved_prompt = prompt_path.resolve(strict=True)
        prompt_destinations.add(resolved_prompt)
        loaded.append((prompt, resolved_prompt, payload, digest))

    if _prospective_resolved_path(destination) in prompt_destinations:
        raise ExecutionError("calibration_output_conflicts_with_prompt")

    request_spec = ScenarioRequest(
        id="calibration-request",
        prompt_id="calibration-prompt",
        start_offset_ms=0,
        trigger=None,
        output_budget=OutputBudget(kind="explicit", tokens=1),
    )
    sampling = Sampling(temperature=0.0, top_p=1.0, seed=0)
    deadlines = Deadlines(
        connect_seconds=30.0,
        read_seconds=900.0,
        overall_seconds=900.0,
        server_seconds=900.0,
    )
    counts: list[int] = []
    try:
        async with OpenAIChatClient(
            checked_endpoint,
            concurrency=1,
            deadlines=deadlines,
            headers=headers,
            transport=transport,
        ) as client:
            for prompt, _, payload, _ in loaded:
                text = payload.decode("utf-8", errors="strict")
                sample = await run_request(
                    client,
                    request_spec,
                    scenario_run_id="calibration",
                    repetition=0,
                    prompt=text,
                    model=checked_model,
                    sampling=sampling,
                    clock_domain="calibration_monotonic",
                )
                if sample.error_class == "usage_unavailable" or sample.prompt_tokens is None:
                    raise ExecutionError("calibration_usage_missing")
                if (
                    sample.error_class is not None
                    or sample.status_code is None
                    or not 200 <= sample.status_code < 300
                    or sample.finish_class not in _COMPLETED_FINISHES
                    or sample.generated_tokens is None
                ):
                    raise ExecutionError("calibration_response_invalid")
                count = sample.prompt_tokens
                if isinstance(count, bool) or not 1 <= count <= 524_288:
                    raise ExecutionError("calibration_usage_invalid")
                counts.append(count)
    except ExecutionError:
        raise
    except (ValueError, RuntimeError) as error:
        raise ExecutionError("calibration_client_invalid") from error

    if len(counts) != len(loaded):
        raise ExecutionError("calibration_incomplete")
    if sha256_bytes(_read_regular_bytes(manifest_file, MAX_MANIFEST_BYTES, "calibration_manifest_invalid")) != manifest_sha256:
        raise ExecutionError("calibration_input_changed")
    for _, prompt_path, _, expected_digest in loaded:
        payload = _read_regular_bytes(
            prompt_path, MAX_PROMPT_BYTES, "calibration_prompt_invalid"
        )
        if sha256_bytes(payload) != expected_digest:
            raise ExecutionError("calibration_input_changed")

    measured = {
        "version": manifest.version,
        "prompts": [
            {
                "id": prompt.id,
                "path": prompt.path,
                "sha256": prompt.sha256,
                "token_count": count,
                "license": prompt.license,
                "status": "measured",
            }
            for (prompt, _, _, _), count in zip(loaded, counts, strict=True)
        ],
    }
    payload = canonical_json_bytes(measured)
    _atomic_replace(destination_parent, destination.name, payload)
    return destination


def verify_result_from_path(path: Path | str) -> dict[str, object]:
    """Recompute and verify the exact nine-file result bundle."""

    result_path = _bounded_path(path, "invalid_result_path")
    try:
        return verify_result(result_path)
    except (ArtifactError, OSError) as error:
        raise ExecutionError("result_verification_failed") from error


def _validate_run_inputs(
    metadata: dict[str, object],
    source_manifest: dict[str, object],
    normalized_scenario: dict[str, Any],
    repetition: int,
) -> None:
    if set(metadata) != _METADATA_INPUT_FIELDS:
        raise ExecutionError("metadata_invalid")
    try:
        validate_source_manifest(source_manifest)
        scenario_bytes = canonical_json_bytes(normalized_scenario)
        source_bytes = canonical_json_bytes(source_manifest)
        materialized = dict(metadata)
        materialized.update(
            {
                "result_state": "success",
                "scenario_sha256": sha256_bytes(scenario_bytes),
                "source_manifest_sha256": sha256_bytes(source_bytes),
                "completed_utc": metadata.get("started_utc"),
                "logs": {
                    "server": {
                        "sha256": _EMPTY_SHA256,
                        "retained_bytes": 0,
                        "truncated": False,
                        "total_bytes": 0,
                    },
                    "client": {
                        "sha256": _EMPTY_SHA256,
                        "retained_bytes": 0,
                        "truncated": False,
                        "total_bytes": 0,
                    },
                },
                "primary_error": None,
                "cleanup_error": None,
            }
        )
        validate_metadata(materialized)
    except (ArtifactError, ValueError) as error:
        raise ExecutionError("metadata_invalid") from error

    if (
        metadata.get("scenario_id") != normalized_scenario.get("id")
        or metadata.get("vantage") != normalized_scenario.get("vantage")
        or metadata.get("configured_policy") != normalized_scenario.get("server")
        or metadata.get("warmup_repetitions")
        != normalized_scenario.get("warmup_repetitions")
        or metadata.get("measured_repetitions")
        != normalized_scenario.get("measured_repetitions")
    ):
        raise ExecutionError("metadata_scenario_mismatch")
    pairing = metadata.get("pairing")
    if not isinstance(pairing, dict) or pairing.get("repetition") != repetition:
        raise ExecutionError("metadata_repetition_mismatch")


def _select_case(scenario: Scenario, case_id: str) -> Case:
    if not isinstance(case_id, str) or _CASE_ID.fullmatch(case_id) is None:
        raise ExecutionError("invalid_case")
    matches = tuple(case for case in scenario.schedule.case_matrix if case.id == case_id)
    if len(matches) != 1:
        raise ExecutionError("unknown_case")
    return matches[0]


def _repetition(value: int, measured_repetitions: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < measured_repetitions:
        raise ExecutionError("invalid_repetition")
    return value


def _preflight_case_prompts(scenario: Scenario, case: Case, root: Path) -> None:
    request_by_id = {request.id: request for request in scenario.requests}
    prompt_by_id = {prompt.id: prompt for prompt in scenario.prompts}
    required = {
        request_by_id[request_id].prompt_id for request_id in case.request_ids
    }
    aggregate = 0
    for prompt_id in sorted(required):
        prompt = prompt_by_id[prompt_id]
        relative = PurePosixPath(prompt.path)
        path = root.joinpath(*relative.parts)
        payload = _read_regular_bytes(path, MAX_PROMPT_BYTES, "prompt_invalid")
        aggregate += len(payload)
        if aggregate > MAX_PROMPT_AGGREGATE_BYTES:
            raise ExecutionError("prompt_aggregate_too_large")
        if sha256_bytes(payload) != prompt.sha256:
            raise ExecutionError("prompt_hash_mismatch")
        try:
            payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ExecutionError("prompt_invalid_utf8") from error


def _endpoint(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_ENDPOINT_CHARS
        or not value.isascii()
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
    ):
        raise ExecutionError("invalid_endpoint")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ExecutionError("invalid_endpoint") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not value.startswith(parsed.scheme + "://")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname in {None, "", "0.0.0.0", "::"}
        or port is None
        or not 1 <= port <= 65_535
        or parsed.path != "/v1/chat/completions"
        or parsed.query
        or parsed.fragment
    ):
        raise ExecutionError("invalid_endpoint")
    return value


def _model(value: object) -> str:
    if not isinstance(value, str) or _MODEL_ID.fullmatch(value) is None:
        raise ExecutionError("invalid_model")
    return value


def _bounded_path(value: Path | str, code: str) -> Path:
    try:
        text = os.fspath(value)
    except TypeError as error:
        raise ExecutionError(code) from error
    if (
        not isinstance(text, str)
        or not 1 <= len(text) <= MAX_PATH_CHARS
        or "\x00" in text
        or any(ord(character) < 0x20 for character in text)
    ):
        raise ExecutionError(code)
    path = Path(text)
    if ".." in path.parts:
        raise ExecutionError(code)
    return path


def _existing_directory(value: Path | str, code: str) -> Path:
    path = _bounded_path(value, code)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ExecutionError(code) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ExecutionError(code)
    return resolved


def _regular_input_path(value: Path | str, code: str) -> Path:
    path = _bounded_path(value, code)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ExecutionError(code) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_ISLNK(metadata.st_mode)
    ):
        raise ExecutionError(code)
    return path


def _read_regular_bytes(path: Path, maximum: int, code: str) -> bytes:
    try:
        metadata_before = path.lstat()
        if (
            not stat.S_ISREG(metadata_before.st_mode)
            or metadata_before.st_nlink != 1
            or metadata_before.st_size > maximum
        ):
            raise ExecutionError(code)
        with path.open("rb") as stream:
            payload = stream.read(maximum + 1)
            metadata_after = os.fstat(stream.fileno())
    except ExecutionError:
        raise
    except OSError as error:
        raise ExecutionError(code) from error
    if (
        len(payload) > maximum
        or metadata_before.st_dev != metadata_after.st_dev
        or metadata_before.st_ino != metadata_after.st_ino
        or metadata_after.st_size != len(payload)
    ):
        raise ExecutionError(code)
    return payload


def _canonical_object_file(value: Path | str, code: str) -> dict[str, object]:
    path = _regular_input_path(value, code)
    _, parsed = _read_canonical_object(path, MAX_MANIFEST_BYTES, code)
    return parsed


def _read_canonical_object(
    path: Path, maximum: int, code: str
) -> tuple[bytes, dict[str, object]]:
    payload = _read_regular_bytes(path, maximum, code)
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExecutionError(code) from error
    if not isinstance(parsed, dict):
        raise ExecutionError(code)
    try:
        canonical = canonical_json_bytes(parsed)
    except ValueError as error:
        raise ExecutionError(code) from error
    if canonical != payload:
        raise ExecutionError(code)
    return payload, parsed


def _output_root(value: Path | str) -> Path:
    path = _bounded_path(value, "invalid_result_root")
    try:
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ExecutionError("invalid_result_root")
            return path.resolve(strict=True)
        parent = path.parent.resolve(strict=True)
    except ExecutionError:
        raise
    except OSError as error:
        raise ExecutionError("invalid_result_root") from error
    if not parent.is_dir() or parent.is_symlink() or path.name in {"", ".", ".."}:
        raise ExecutionError("invalid_result_root")
    return parent / path.name


def _output_file(value: Path | str) -> tuple[Path, Path]:
    path = _bounded_path(value, "invalid_calibration_output")
    if path.name in {"", ".", ".."}:
        raise ExecutionError("invalid_calibration_output")
    try:
        parent = path.parent.resolve(strict=True)
        parent_metadata = parent.lstat()
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
            raise ExecutionError("invalid_calibration_output")
        destination = parent / path.name
        if destination.exists() or destination.is_symlink():
            metadata = destination.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ExecutionError("invalid_calibration_output")
    except ExecutionError:
        raise
    except OSError as error:
        raise ExecutionError("invalid_calibration_output") from error
    return destination, parent


def _prospective_resolved_path(path: Path) -> Path:
    try:
        return path.resolve(strict=path.exists())
    except OSError as error:
        raise ExecutionError("invalid_calibration_output") from error


def _atomic_replace(parent: Path, name: str, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    temporary_name = ""
    try:
        descriptor = os.open(parent, directory_flags)
        for nonce in range(128):
            temporary_name = f".{name}.tmp-{os.getpid()}-{nonce}"
            try:
                temporary = os.open(
                    temporary_name,
                    flags,
                    0o644,
                    dir_fd=descriptor,
                )
                break
            except FileExistsError:
                continue
        else:
            raise ExecutionError("calibration_output_write_failed")
        try:
            view = memoryview(payload)
            while view:
                written = os.write(temporary, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(temporary)
        finally:
            os.close(temporary)
        os.replace(
            temporary_name,
            name,
            src_dir_fd=descriptor,
            dst_dir_fd=descriptor,
        )
        temporary_name = ""
        os.fsync(descriptor)
    except ExecutionError:
        raise
    except OSError as error:
        raise ExecutionError("calibration_output_write_failed") from error
    finally:
        if descriptor >= 0:
            if temporary_name:
                try:
                    os.unlink(temporary_name, dir_fd=descriptor)
                except OSError:
                    pass
            os.close(descriptor)


__all__ = [
    "ExecutionError",
    "calibrate_prompts",
    "run_case_from_files",
    "verify_result_from_path",
]
