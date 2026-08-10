"""Async execution of one validated scenario case and repetition."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable

import httpx

from .artifacts import ResultWriter, validate_normalized_scenario
from .client import OpenAIChatClient, RequestSample, settle_request
from .redaction import CanarySet
from .schema import Case, Scenario, ScenarioRequest, normalize_scenario
from .stats import SCHEMA_VERSION


class RunnerError(ValueError):
    """A bounded runner setup or prompt-integrity failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class CaseRepetition:
    """A measured case/repetition identity in deterministic execution order."""

    case_id: str
    repetition: int


@dataclass(frozen=True, slots=True)
class ArtifactInputs:
    """Exact sanitized inputs supplied by the lifecycle orchestrator."""

    metadata: Mapping[str, object]
    source_manifest: Mapping[str, object]
    telemetry: tuple[Mapping[str, object], ...] = ()
    server_log: str | bytes = b""
    client_log: str | bytes = b""
    server_total_bytes: int | None = None
    client_total_bytes: int | None = None
    primary_error: Mapping[str, object] | None = None
    cleanup_error: Mapping[str, object] | None = None
    canaries: CanarySet | None = None


@dataclass(slots=True)
class _LiveRequest:
    first_model_token_ns: int | None = None
    terminal: bool = False


@dataclass(frozen=True, slots=True)
class _TaskOutcome:
    request_id: str
    sample: RequestSample
    harness_error: bool = False
    trigger_unmet: bool = False


def case_repetitions(scenario: Scenario) -> tuple[CaseRepetition, ...]:
    """Enumerate every measured case and repetition without inventing run IDs."""

    normalized = normalize_scenario(scenario)
    validate_normalized_scenario(normalized)
    return tuple(
        CaseRepetition(case.id, repetition)
        for case in scenario.schedule.case_matrix
        for repetition in range(scenario.measured_repetitions)
    )


async def run_case(
    scenario: Scenario,
    case: Case,
    repetition: int,
    *,
    repo_root: Path | str,
    endpoint: str,
    model: str,
    result_root: Path | str,
    artifacts: ArtifactInputs,
    headers: Mapping[str, str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    clock: Callable[[], int] = time.monotonic_ns,
) -> Path:
    """Execute one case independently and atomically promote its result bundle.

    The supplied ``Scenario`` must already have come through the strict schema
    loader. It is normalized and checked again before a result writer or any
    network operation is opened. The writer predeclares the complete case,
    settles every request exactly once, and owns raw-before-summary ordering.
    """

    normalized = normalize_scenario(scenario)
    validate_normalized_scenario(normalized)
    checked_case = _validated_case(scenario, case)
    if (
        isinstance(repetition, bool)
        or not isinstance(repetition, int)
        or not 0 <= repetition < scenario.measured_repetitions
    ):
        raise RunnerError("invalid_repetition")
    if not isinstance(endpoint, str) or not endpoint:
        raise RunnerError("invalid_endpoint")
    if not isinstance(model, str) or not model:
        raise RunnerError("invalid_model")
    if not callable(clock):
        raise RunnerError("invalid_clock")

    run_id = artifacts.metadata.get("run_id")
    clock_domain = artifacts.metadata.get("clock_domain")
    if not isinstance(run_id, str) or not isinstance(clock_domain, str):
        raise RunnerError("invalid_artifact_identity")

    writer = ResultWriter(
        result_root,
        artifacts.metadata,
        normalized,
        artifacts.source_manifest,
        checked_case.request_ids,
        canaries=artifacts.canaries,
    )
    runner_primary: dict[str, str] | None = None
    outcomes: list[_TaskOutcome] = []
    execution_cancelled: asyncio.CancelledError | None = None

    try:
        prompts = _load_case_prompts(
            scenario,
            checked_case,
            repo_root=repo_root,
        )
    except RunnerError as error:
        runner_primary = {"class": "scenario", "code": error.code}
    else:
        request_by_id = {request.id: request for request in scenario.requests}
        requests = tuple(request_by_id[item] for item in checked_case.request_ids)
        capacity = len(requests)
        async with OpenAIChatClient(
            endpoint,
            concurrency=capacity,
            deadlines=scenario.deadlines,
            headers=headers,
            transport=transport,
        ) as client:
            live = {request.id: _LiveRequest() for request in requests}
            changed = asyncio.Event()
            loop = asyncio.get_running_loop()
            started_at = loop.time()
            deadline_at = started_at + scenario.deadlines.server_seconds
            tasks = tuple(
                asyncio.create_task(
                    _run_scheduled_request(
                        client,
                        request,
                        scenario=scenario,
                        repetition=repetition,
                        prompt=prompts[request.prompt_id],
                        model=model,
                        run_id=run_id,
                        clock_domain=clock_domain,
                        live=live,
                        changed=changed,
                        started_at=started_at,
                        deadline_at=deadline_at,
                        clock=clock,
                    ),
                    name=f"ds4bench-{request.id}",
                )
                for request in requests
            )
            try:
                outcomes, deadline_expired = await _collect_outcomes(
                    tasks,
                    request_ids=checked_case.request_ids,
                    deadline_at=deadline_at,
                )
            except asyncio.CancelledError as error:
                execution_cancelled = error
                outcomes = await _cancel_and_settle(
                    tasks,
                    request_ids=checked_case.request_ids,
                )
                deadline_expired = False
            if execution_cancelled is not None:
                runner_primary = {
                    "class": "cancelled",
                    "code": "runner_cancelled",
                }
            elif any(outcome.harness_error for outcome in outcomes):
                runner_primary = {
                    "class": "harness",
                    "code": "request_execution_error",
                }
            elif any(outcome.trigger_unmet for outcome in outcomes):
                runner_primary = {
                    "class": "timeout",
                    "code": "trigger_not_met",
                }
            elif deadline_expired:
                runner_primary = {
                    "class": "timeout",
                    "code": "case_deadline",
                }

    for outcome in outcomes:
        writer.append_sample(outcome.sample.to_dict())

    try:
        for item in artifacts.telemetry:
            writer.append_telemetry(item)
    except Exception:
        if runner_primary is None:
            runner_primary = {
                "class": "harness",
                "code": "invalid_telemetry_input",
            }

    try:
        writer.set_logs(
            artifacts.server_log,
            artifacts.client_log,
            server_total_bytes=artifacts.server_total_bytes,
            client_total_bytes=artifacts.client_total_bytes,
        )
    except Exception:
        if runner_primary is None:
            runner_primary = {
                "class": "harness",
                "code": "invalid_log_input",
            }

    primary_error = artifacts.primary_error or runner_primary
    final_path = writer.finalize(
        primary_error=primary_error,
        cleanup_error=artifacts.cleanup_error,
    )
    if execution_cancelled is not None:
        raise execution_cancelled
    return final_path


def _validated_case(scenario: Scenario, case: Case) -> Case:
    if not isinstance(case, Case):
        raise RunnerError("invalid_case")
    matches = tuple(item for item in scenario.schedule.case_matrix if item.id == case.id)
    if len(matches) != 1 or matches[0] != case:
        raise RunnerError("unknown_case")
    return matches[0]


def _load_case_prompts(
    scenario: Scenario,
    case: Case,
    *,
    repo_root: Path | str,
) -> dict[str, str]:
    try:
        root = Path(repo_root).resolve(strict=True)
    except OSError as error:
        raise RunnerError("invalid_repo_root") from error
    if not root.is_dir():
        raise RunnerError("invalid_repo_root")
    artifact_root = (root / "benchmarks" / "prompts" / "artifacts").resolve(
        strict=False
    )
    if not artifact_root.is_relative_to(root):
        raise RunnerError("unsafe_prompt_path")

    request_by_id = {request.id: request for request in scenario.requests}
    prompt_by_id = {prompt.id: prompt for prompt in scenario.prompts}
    required = {
        request_by_id[request_id].prompt_id for request_id in case.request_ids
    }
    loaded: dict[str, str] = {}
    for prompt_id in sorted(required):
        prompt = prompt_by_id[prompt_id]
        relative = PurePosixPath(prompt.path)
        candidate = root.joinpath(*relative.parts)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise RunnerError("prompt_file_missing") from error
        if not resolved.is_relative_to(artifact_root):
            raise RunnerError("unsafe_prompt_path")
        try:
            status = resolved.stat()
            if not resolved.is_file():
                raise RunnerError("invalid_prompt_file")
            with resolved.open("rb") as stream:
                payload = stream.read()
        except RunnerError:
            raise
        except OSError as error:
            raise RunnerError("prompt_read_error") from error
        if status.st_size != len(payload):
            raise RunnerError("prompt_changed_during_read")
        if hashlib.sha256(payload).hexdigest() != prompt.sha256:
            raise RunnerError("prompt_hash_mismatch")
        try:
            loaded[prompt_id] = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise RunnerError("prompt_invalid_utf8") from error
    return loaded


async def _run_scheduled_request(
    client: OpenAIChatClient,
    request: ScenarioRequest,
    *,
    scenario: Scenario,
    repetition: int,
    prompt: str,
    model: str,
    run_id: str,
    clock_domain: str,
    live: dict[str, _LiveRequest],
    changed: asyncio.Event,
    started_at: float,
    deadline_at: float,
    clock: Callable[[], int],
) -> _TaskOutcome:
    state = live[request.id]
    started = False
    trigger_unmet = False

    def first_model_token(timestamp_ns: int) -> None:
        if state.first_model_token_ns is None:
            state.first_model_token_ns = timestamp_ns
            changed.set()

    try:
        release_at = started_at + request.start_offset_ms / 1000.0
        if request.trigger is None:
            released = await _wait_until(release_at, deadline_at)
        else:
            released = await _wait_for_live_trigger(
                live,
                own_request_id=request.id,
                minimum=request.trigger.minimum_requests,
                release_at=release_at,
                deadline_at=deadline_at,
                changed=changed,
            )
            trigger_unmet = not released
        if not released:
            return _TaskOutcome(
                request.id,
                _incomplete_sample(request, run_id=run_id, repetition=repetition),
                trigger_unmet=trigger_unmet,
            )
        started = True
        sample = await settle_request(
            client,
            request,
            scenario_run_id=run_id,
            repetition=repetition,
            prompt=prompt,
            model=model,
            sampling=scenario.sampling,
            clock_domain=clock_domain,
            clock=clock,
            on_first_model_token=first_model_token,
        )
        if state.first_model_token_ns is None:
            state.first_model_token_ns = sample.first_model_token_ns
        return _TaskOutcome(request.id, sample)
    except asyncio.CancelledError:
        # Cancellation before send has no timing observations. Once started,
        # settle_request consumes cancellation and normally returns its sample.
        return _TaskOutcome(
            request.id,
            _incomplete_sample(request, run_id=run_id, repetition=repetition),
            trigger_unmet=request.trigger is not None and not started,
        )
    except Exception:
        return _TaskOutcome(
            request.id,
            _incomplete_sample(request, run_id=run_id, repetition=repetition),
            harness_error=True,
            trigger_unmet=request.trigger is not None and not started,
        )
    finally:
        state.terminal = True
        changed.set()


async def _wait_until(release_at: float, deadline_at: float) -> bool:
    loop = asyncio.get_running_loop()
    remaining = min(release_at, deadline_at) - loop.time()
    if remaining > 0:
        await asyncio.sleep(remaining)
    return loop.time() >= release_at and loop.time() < deadline_at


async def _wait_for_live_trigger(
    live: Mapping[str, _LiveRequest],
    *,
    own_request_id: str,
    minimum: int,
    release_at: float,
    deadline_at: float,
    changed: asyncio.Event,
) -> bool:
    loop = asyncio.get_running_loop()
    while True:
        now = loop.time()
        active = sum(
            state.first_model_token_ns is not None and not state.terminal
            for request_id, state in live.items()
            if request_id != own_request_id
        )
        if now >= release_at and active >= minimum:
            return True
        if now >= deadline_at:
            return False
        changed.clear()
        # No other task can mutate state between clear and this synchronous
        # recheck, avoiding a lost event before the wait below.
        active = sum(
            state.first_model_token_ns is not None and not state.terminal
            for request_id, state in live.items()
            if request_id != own_request_id
        )
        now = loop.time()
        if now >= release_at and active >= minimum:
            return True
        wake_at = deadline_at if now >= release_at else min(release_at, deadline_at)
        try:
            await asyncio.wait_for(changed.wait(), timeout=max(0.0, wake_at - now))
        except TimeoutError:
            pass


async def _collect_outcomes(
    tasks: tuple[asyncio.Task[_TaskOutcome], ...],
    *,
    request_ids: tuple[str, ...],
    deadline_at: float,
) -> tuple[list[_TaskOutcome], bool]:
    pending = set(tasks)
    outcomes: dict[str, _TaskOutcome] = {}
    deadline_expired = False
    loop = asyncio.get_running_loop()
    while pending:
        remaining = deadline_at - loop.time()
        if remaining <= 0:
            deadline_expired = True
            break
        done, pending = await asyncio.wait(
            pending,
            timeout=remaining,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not done:
            deadline_expired = True
            break
        for task in done:
            outcome = task.result()
            outcomes[outcome.request_id] = outcome
    if pending:
        for task in pending:
            task.cancel()
        settled = await asyncio.gather(*pending)
        for outcome in settled:
            outcomes[outcome.request_id] = outcome
    return [outcomes[request_id] for request_id in request_ids], deadline_expired


async def _cancel_and_settle(
    tasks: tuple[asyncio.Task[_TaskOutcome], ...],
    *,
    request_ids: tuple[str, ...],
) -> list[_TaskOutcome]:
    for task in tasks:
        if not task.done():
            task.cancel()
    settled = await asyncio.gather(*tasks)
    by_id = {outcome.request_id: outcome for outcome in settled}
    return [by_id[request_id] for request_id in request_ids]


def _incomplete_sample(
    request: ScenarioRequest,
    *,
    run_id: str,
    repetition: int,
) -> RequestSample:
    return RequestSample(
        schema_version=SCHEMA_VERSION,
        scenario_run_id=run_id,
        request_id=request.id,
        repetition=repetition,
        scheduled_offset_ns=request.start_offset_ms * 1_000_000,
        send_ns=None,
        http_accept_ns=None,
        first_byte_ns=None,
        first_model_token_ns=None,
        token_event_timestamps_ns=(),
        itl_ns=(),
        completion_ns=None,
        status_code=None,
        retry_count=0,
        retry_after=None,
        finish_class="incomplete",
        error_class=None,
        redacted_error_body=None,
        prompt_tokens=None,
        generated_tokens=None,
        output_budget_kind=request.output_budget.kind,
        output_budget_value=request.output_budget.tokens,
        timing_granularity="unavailable",
    )


__all__ = [
    "ArtifactInputs",
    "CaseRepetition",
    "RunnerError",
    "case_repetitions",
    "run_case",
]
