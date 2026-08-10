"""Strict canonical scenario-v1 schema and calibration manifest loading."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

_SCHEMA_VERSION = 1
_DEFAULT_OUTPUT_TOKENS = 393_216
_MAX_CONTEXT_TOKENS = 524_288
_MAX_REQUESTS = 256
_MAX_CASE_REQUESTS = 64
_MAX_JSON_BYTES = 1 << 20
_SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PROMPT_PREFIX = ("benchmarks", "prompts", "artifacts")
_SCENARIO_IDS = frozenset({"S1", "S2", "S3", "S5A", "S5B"})
_VANTAGES = frozenset({"controller_lan", "target_local"})
_S1_CONCURRENCIES = (1, 2, 4, 8, 12, 16)
_S2_ROLES = ("planner", "coder", "reviewer", "advisor")
_OVERRIDE_FIELDS = (
    "shadow_guard",
    "shadow_alpha",
    "shadow_min_evidence",
    "shadow_budget",
    "shadow_credit_cap",
)


class ScenarioError(ValueError):
    """A bounded, programmatically classifiable scenario validation error."""

    __slots__ = ("code",)

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message if message is not None else code)


@dataclass(frozen=True, slots=True)
class SpeculativeOverrides:
    shadow_guard: None
    shadow_alpha: None
    shadow_min_evidence: None
    shadow_budget: None
    shadow_credit_cap: None


@dataclass(frozen=True, slots=True)
class ServerConfig:
    context_tokens: int
    default_output_tokens: int
    decode_policy: str
    dspark_max_nlive: int
    terminal_yield_quench: bool
    speculative_overrides: SpeculativeOverrides


@dataclass(frozen=True, slots=True)
class Prompt:
    id: str
    path: str
    sha256: str
    token_count: int
    license: str


@dataclass(frozen=True, slots=True)
class CalibrationPrompt:
    id: str
    path: str
    sha256: str
    token_count: int | None
    license: str
    status: str


@dataclass(frozen=True, slots=True)
class CalibrationManifest:
    version: int
    prompts: tuple[CalibrationPrompt, ...]


@dataclass(frozen=True, slots=True)
class ActiveDecodeTrigger:
    kind: str
    minimum_requests: int


@dataclass(frozen=True, slots=True)
class OutputBudget:
    kind: str
    tokens: int | None


@dataclass(frozen=True, slots=True)
class ScenarioRequest:
    id: str
    prompt_id: str
    start_offset_ms: int
    trigger: ActiveDecodeTrigger | None
    output_budget: OutputBudget


@dataclass(frozen=True, slots=True)
class Case:
    id: str
    request_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Schedule:
    kind: str
    case_matrix: tuple[Case, ...]


@dataclass(frozen=True, slots=True)
class Sampling:
    temperature: float
    top_p: float
    seed: int


@dataclass(frozen=True, slots=True)
class Deadlines:
    connect_seconds: float
    read_seconds: float
    overall_seconds: float
    server_seconds: float


@dataclass(frozen=True, slots=True)
class Preconditions:
    server_restart_each_repetition: bool
    cache_state: str
    warmup_server_is_separate: bool
    cooldown_seconds: float
    prompt_reuse: str


@dataclass(frozen=True, slots=True)
class Scenario:
    version: int
    id: str
    description: str
    vantage: str
    server: ServerConfig
    prompts: tuple[Prompt, ...]
    requests: tuple[ScenarioRequest, ...]
    schedule: Schedule
    sampling: Sampling
    warmup_repetitions: int
    measured_repetitions: int
    deadlines: Deadlines
    preconditions: Preconditions


def _fail(code: str, message: str) -> Any:
    raise ScenarioError(code, message)


def _reject_constant(value: str) -> Any:
    return _fail("invalid_json", f"non-finite JSON number {value!r} is forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_field", f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def _load_json(path: str | Path) -> Any:
    source = Path(path)
    try:
        raw = source.read_bytes()
    except OSError as error:
        raise ScenarioError("scenario_read_error", "unable to read JSON input") from error
    if len(raw) > _MAX_JSON_BYTES:
        _fail("scenario_too_large", "JSON input exceeds the 1 MiB schema limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ScenarioError("invalid_json", "JSON input must be UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ScenarioError:
        raise
    except json.JSONDecodeError as error:
        raise ScenarioError("invalid_json", "malformed JSON input") from error


def _object(value: Any, context: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("invalid_type", f"{context} must be an object")
    return value


def _exact(value: Any, fields: tuple[str, ...], context: str) -> dict[str, Any]:
    obj = _object(value, context)
    expected = set(fields)
    actual = set(obj)
    unknown = actual - expected
    if unknown:
        _fail("unknown_field", f"{context} has unknown field {sorted(unknown)[0]!r}")
    missing = expected - actual
    if missing:
        _fail("missing_field", f"{context} is missing field {sorted(missing)[0]!r}")
    return obj


def _string(value: Any, context: str, *, maximum: int, nonempty: bool = True) -> str:
    if type(value) is not str:
        _fail("invalid_type", f"{context} must be a string")
    if (nonempty and not value) or len(value) > maximum:
        _fail("invalid_value", f"{context} has an invalid length")
    return value


def _slug(value: Any, context: str) -> str:
    text = _string(value, context, maximum=64)
    if _SLUG_RE.fullmatch(text) is None:
        _fail("invalid_value", f"{context} must be a bounded ASCII slug")
    return text


def _integer(
    value: Any,
    context: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        _fail("invalid_type", f"{context} must be an integer")
    if minimum is not None and value < minimum:
        _fail("invalid_value", f"{context} is below its minimum")
    if maximum is not None and value > maximum:
        _fail("invalid_value", f"{context} exceeds its maximum")
    return value


def _boolean(value: Any, context: str) -> bool:
    if type(value) is not bool:
        _fail("invalid_type", f"{context} must be a boolean")
    return value


def _number(
    value: Any,
    context: str,
    *,
    minimum: float,
    maximum: float,
    strictly_positive: bool = False,
) -> float:
    if type(value) not in (int, float):
        _fail("invalid_type", f"{context} must be a number")
    result = float(value)
    if not math.isfinite(result):
        _fail("invalid_value", f"{context} must be finite")
    if strictly_positive and result <= 0:
        _fail("invalid_value", f"{context} must be positive")
    if result < minimum or result > maximum:
        _fail("invalid_value", f"{context} is outside its allowed range")
    return result


def _repo_root(repo_root: str | Path) -> Path:
    try:
        root = Path(repo_root).resolve(strict=True)
    except OSError as error:
        raise ScenarioError("invalid_repo_root", "repository root does not exist") from error
    if not root.is_dir():
        _fail("invalid_repo_root", "repository root must be a directory")
    artifact_root = (root / "benchmarks" / "prompts" / "artifacts").resolve(strict=False)
    if not artifact_root.is_relative_to(root):
        _fail("unsafe_prompt_path", "prompt artifact root escapes the repository")
    return root


def _prompt_path(value: Any, repo_root: Path, context: str) -> tuple[str, Path]:
    text = _string(value, context, maximum=512)
    if "\\" in text or not text.isascii():
        _fail("unsafe_prompt_path", f"{context} must be an ASCII POSIX path")
    path = PurePosixPath(text)
    if path.is_absolute() or tuple(path.parts[:3]) != _PROMPT_PREFIX or len(path.parts) <= 3:
        _fail("unsafe_prompt_path", f"{context} must remain under benchmarks/prompts/artifacts")
    if any(part in ("", ".", "..") for part in text.split("/")) or path.as_posix() != text:
        _fail("unsafe_prompt_path", f"{context} is not a normalized repository-relative path")

    artifact_root = (repo_root / "benchmarks" / "prompts" / "artifacts").resolve(strict=False)
    candidate = repo_root.joinpath(*path.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ScenarioError("prompt_file_missing", "prompt artifact is missing") from error
    if not resolved.is_relative_to(artifact_root):
        _fail("unsafe_prompt_path", f"{context} resolves outside the prompt artifact root")
    if not resolved.is_file():
        _fail("invalid_prompt_file", "prompt artifact must be a regular file")
    return text, resolved


def _sha256(value: Any, context: str) -> str:
    text = _string(value, context, maximum=64)
    if _SHA256_RE.fullmatch(text) is None:
        _fail("invalid_hash", f"{context} must be 64 lowercase hexadecimal characters")
    return text


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(128 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ScenarioError("prompt_read_error", "unable to read prompt artifact") from error
    return digest.hexdigest()


def _parse_server(value: Any) -> ServerConfig:
    obj = _exact(
        value,
        (
            "context_tokens",
            "default_output_tokens",
            "decode_policy",
            "dspark_max_nlive",
            "terminal_yield_quench",
            "speculative_overrides",
        ),
        "server",
    )
    context_tokens = _integer(
        obj["context_tokens"], "server.context_tokens", minimum=1, maximum=_MAX_CONTEXT_TOKENS
    )
    default_output_tokens = _integer(
        obj["default_output_tokens"],
        "server.default_output_tokens",
        minimum=1,
        maximum=_MAX_CONTEXT_TOKENS,
    )
    if default_output_tokens != _DEFAULT_OUTPUT_TOKENS:
        _fail("invalid_server_profile", "server.default_output_tokens must retain the frozen default")
    policy = _string(obj["decode_policy"], "server.decode_policy", maximum=16)
    if policy not in {"shipped", "plain"}:
        _fail("invalid_server_profile", "server.decode_policy must be shipped or plain")
    max_nlive = _integer(obj["dspark_max_nlive"], "server.dspark_max_nlive", minimum=1, maximum=64)
    if max_nlive != 1:
        _fail("invalid_server_profile", "the frozen DSpark profile requires dspark_max_nlive 1")
    quench = _boolean(obj["terminal_yield_quench"], "server.terminal_yield_quench")
    if not quench:
        _fail("invalid_server_profile", "the frozen profile requires terminal yield quench")

    overrides_obj = _exact(
        obj["speculative_overrides"], _OVERRIDE_FIELDS, "server.speculative_overrides"
    )
    for field in _OVERRIDE_FIELDS:
        if overrides_obj[field] is not None:
            _fail("invalid_server_profile", f"server.speculative_overrides.{field} must be null")
    overrides = SpeculativeOverrides(**overrides_obj)
    return ServerConfig(
        context_tokens=context_tokens,
        default_output_tokens=default_output_tokens,
        decode_policy=policy,
        dspark_max_nlive=max_nlive,
        terminal_yield_quench=quench,
        speculative_overrides=overrides,
    )


def _parse_prompt_common(
    value: Any,
    repo_root: Path,
    context: str,
    *,
    calibration: bool,
) -> Prompt | CalibrationPrompt:
    fields = ("id", "path", "sha256", "token_count", "license", "status") if calibration else (
        "id",
        "path",
        "sha256",
        "token_count",
        "license",
    )
    obj = _exact(value, fields, context)
    prompt_id = _slug(obj["id"], f"{context}.id")
    path_text, resolved_path = _prompt_path(obj["path"], repo_root, f"{context}.path")
    digest = _sha256(obj["sha256"], f"{context}.sha256")
    if _file_sha256(resolved_path) != digest:
        _fail("prompt_hash_mismatch", f"{context}.sha256 does not match the prompt artifact")
    license_name = _string(obj["license"], f"{context}.license", maximum=128)

    if not calibration:
        count = _integer(obj["token_count"], f"{context}.token_count", minimum=1, maximum=_MAX_CONTEXT_TOKENS)
        return Prompt(prompt_id, path_text, digest, count, license_name)

    status = _string(obj["status"], f"{context}.status", maximum=16)
    raw_count = obj["token_count"]
    if status == "unmeasured":
        if raw_count is not None:
            _fail("invalid_calibration_count", f"{context}.token_count must be null while unmeasured")
        count = None
    elif status == "measured":
        count = _integer(
            raw_count, f"{context}.token_count", minimum=1, maximum=_MAX_CONTEXT_TOKENS
        )
    else:
        _fail("invalid_calibration_status", f"{context}.status must be measured or unmeasured")
    return CalibrationPrompt(prompt_id, path_text, digest, count, license_name, status)


def _parse_prompts(value: Any, repo_root: Path) -> tuple[Prompt, ...]:
    if type(value) is not list:
        _fail("invalid_type", "prompts must be an array")
    if not 1 <= len(value) <= 64:
        _fail("invalid_value", "prompts must contain between 1 and 64 entries")
    prompts = tuple(
        _parse_prompt_common(item, repo_root, f"prompts[{index}]", calibration=False)
        for index, item in enumerate(value)
    )
    typed_prompts = tuple(prompt for prompt in prompts if isinstance(prompt, Prompt))
    ids = [prompt.id for prompt in typed_prompts]
    if len(ids) != len(set(ids)):
        _fail("duplicate_id", "prompt ids must be unique")
    paths = [prompt.path for prompt in typed_prompts]
    if len(paths) != len(set(paths)):
        _fail("duplicate_prompt_path", "prompt paths must be unique")
    return typed_prompts


def _parse_trigger(value: Any, context: str) -> ActiveDecodeTrigger | None:
    if value is None:
        return None
    obj = _exact(value, ("kind", "minimum_requests"), context)
    kind = _string(obj["kind"], f"{context}.kind", maximum=32)
    if kind != "active_decode":
        _fail("invalid_trigger", f"{context}.kind must be active_decode")
    minimum = _integer(
        obj["minimum_requests"],
        f"{context}.minimum_requests",
        minimum=1,
        maximum=_MAX_CASE_REQUESTS - 1,
    )
    return ActiveDecodeTrigger(kind=kind, minimum_requests=minimum)


def _parse_output_budget(value: Any, context: str) -> OutputBudget:
    obj = _object(value, context)
    kind = obj.get("kind")
    if kind == "explicit":
        obj = _exact(obj, ("kind", "tokens"), context)
        tokens = _integer(
            obj["tokens"], f"{context}.tokens", minimum=1, maximum=_DEFAULT_OUTPUT_TOKENS
        )
        return OutputBudget(kind="explicit", tokens=tokens)
    if kind == "omitted":
        _exact(obj, ("kind",), context)
        return OutputBudget(kind="omitted", tokens=None)
    if type(kind) is not str:
        _fail("invalid_type", f"{context}.kind must be a string")
    _fail("invalid_output_budget", f"{context}.kind must be explicit or omitted")


def _parse_requests(value: Any) -> tuple[ScenarioRequest, ...]:
    if type(value) is not list:
        _fail("invalid_type", "requests must be an array")
    if not 1 <= len(value) <= _MAX_REQUESTS:
        _fail("invalid_value", f"requests must contain between 1 and {_MAX_REQUESTS} entries")
    requests: list[ScenarioRequest] = []
    for index, item in enumerate(value):
        context = f"requests[{index}]"
        obj = _exact(
            item,
            ("id", "prompt_id", "start_offset_ms", "trigger", "output_budget"),
            context,
        )
        requests.append(
            ScenarioRequest(
                id=_slug(obj["id"], f"{context}.id"),
                prompt_id=_slug(obj["prompt_id"], f"{context}.prompt_id"),
                start_offset_ms=_integer(
                    obj["start_offset_ms"],
                    f"{context}.start_offset_ms",
                    minimum=0,
                    maximum=86_400_000,
                ),
                trigger=_parse_trigger(obj["trigger"], f"{context}.trigger"),
                output_budget=_parse_output_budget(obj["output_budget"], f"{context}.output_budget"),
            )
        )
    ids = [request.id for request in requests]
    if len(ids) != len(set(ids)):
        _fail("duplicate_id", "request ids must be unique")
    return tuple(requests)


def _parse_schedule(value: Any) -> Schedule:
    obj = _exact(value, ("kind", "case_matrix"), "schedule")
    kind = _string(obj["kind"], "schedule.kind", maximum=32)
    if kind not in {"offsets", "active_decode_injection"}:
        _fail("invalid_schedule", "schedule.kind must be offsets or active_decode_injection")
    raw_cases = obj["case_matrix"]
    if type(raw_cases) is not list:
        _fail("invalid_type", "schedule.case_matrix must be an array")
    if not 1 <= len(raw_cases) <= 64:
        _fail("invalid_case_matrix", "schedule.case_matrix must contain between 1 and 64 cases")
    cases: list[Case] = []
    for index, raw_case in enumerate(raw_cases):
        context = f"schedule.case_matrix[{index}]"
        case_obj = _exact(raw_case, ("id", "request_ids"), context)
        raw_ids = case_obj["request_ids"]
        if type(raw_ids) is not list:
            _fail("invalid_type", f"{context}.request_ids must be an array")
        if not 1 <= len(raw_ids) <= _MAX_CASE_REQUESTS:
            _fail("invalid_case_matrix", f"{context}.request_ids has invalid cardinality")
        request_ids = tuple(
            _slug(request_id, f"{context}.request_ids[{request_index}]")
            for request_index, request_id in enumerate(raw_ids)
        )
        if len(request_ids) != len(set(request_ids)):
            _fail("invalid_case_matrix", f"{context}.request_ids must be unique")
        cases.append(Case(id=_slug(case_obj["id"], f"{context}.id"), request_ids=request_ids))
    case_ids = [case.id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        _fail("duplicate_id", "case ids must be unique")
    request_sets = [case.request_ids for case in cases]
    if len(request_sets) != len(set(request_sets)):
        _fail("invalid_case_matrix", "case request sets must be distinct")
    return Schedule(kind=kind, case_matrix=tuple(cases))


def _parse_sampling(value: Any) -> Sampling:
    obj = _exact(value, ("temperature", "top_p", "seed"), "sampling")
    if type(obj["temperature"]) is not float or obj["temperature"] != 0.0:
        _fail("invalid_sampling", "sampling.temperature must be the JSON float 0.0")
    if type(obj["top_p"]) is not float or obj["top_p"] != 1.0:
        _fail("invalid_sampling", "sampling.top_p must be the JSON float 1.0")
    seed = _integer(obj["seed"], "sampling.seed")
    if seed != 0:
        _fail("invalid_sampling", "sampling.seed must be 0")
    return Sampling(temperature=0.0, top_p=1.0, seed=0)


def _parse_deadlines(value: Any) -> Deadlines:
    obj = _exact(
        value,
        ("connect_seconds", "read_seconds", "overall_seconds", "server_seconds"),
        "deadlines",
    )
    connect = _number(
        obj["connect_seconds"],
        "deadlines.connect_seconds",
        minimum=0.0,
        maximum=86_400.0,
        strictly_positive=True,
    )
    read = _number(
        obj["read_seconds"],
        "deadlines.read_seconds",
        minimum=0.0,
        maximum=86_400.0,
        strictly_positive=True,
    )
    overall = _number(
        obj["overall_seconds"],
        "deadlines.overall_seconds",
        minimum=0.0,
        maximum=86_400.0,
        strictly_positive=True,
    )
    server = _number(
        obj["server_seconds"],
        "deadlines.server_seconds",
        minimum=0.0,
        maximum=86_400.0,
        strictly_positive=True,
    )
    if connect > overall or read > overall or server > overall:
        _fail("invalid_deadlines", "connect, read, and server deadlines must not exceed overall")
    return Deadlines(connect, read, overall, server)


def _parse_preconditions(value: Any) -> Preconditions:
    obj = _exact(
        value,
        (
            "server_restart_each_repetition",
            "cache_state",
            "warmup_server_is_separate",
            "cooldown_seconds",
            "prompt_reuse",
        ),
        "preconditions",
    )
    restart = _boolean(
        obj["server_restart_each_repetition"], "preconditions.server_restart_each_repetition"
    )
    cache_state = _string(obj["cache_state"], "preconditions.cache_state", maximum=8)
    if cache_state not in {"cold", "warm"}:
        _fail("invalid_preconditions", "preconditions.cache_state must be cold or warm")
    separate = _boolean(obj["warmup_server_is_separate"], "preconditions.warmup_server_is_separate")
    cooldown = _number(
        obj["cooldown_seconds"],
        "preconditions.cooldown_seconds",
        minimum=0.0,
        maximum=3_600.0,
    )
    reuse = _string(obj["prompt_reuse"], "preconditions.prompt_reuse", maximum=8)
    if reuse not in {"forbid", "allow"}:
        _fail("invalid_preconditions", "preconditions.prompt_reuse must be forbid or allow")
    if cache_state == "cold" and (not restart or not separate):
        _fail(
            "invalid_preconditions",
            "cold qualification requires per-repetition restart and a separate warmup server",
        )
    return Preconditions(restart, cache_state, separate, cooldown, reuse)


def _validate_common_references(scenario: Scenario) -> None:
    prompt_by_id = {prompt.id: prompt for prompt in scenario.prompts}
    request_by_id = {request.id: request for request in scenario.requests}
    for request in scenario.requests:
        if request.prompt_id not in prompt_by_id:
            _fail("unknown_prompt", f"request {request.id!r} references an unknown prompt")
    scheduled: set[str] = set()
    for case in scenario.schedule.case_matrix:
        for request_id in case.request_ids:
            if request_id not in request_by_id:
                _fail("unknown_request", f"case {case.id!r} references an unknown request")
            scheduled.add(request_id)
    if scheduled != set(request_by_id):
        _fail("invalid_case_matrix", "every request must be selected by at least one case")
    referenced_prompts = {request.prompt_id for request in scenario.requests}
    if referenced_prompts != set(prompt_by_id):
        _fail("invalid_scenario", "every declared prompt must be used by a request")

    for request in scenario.requests:
        budget = request.output_budget
        if budget.kind == "omitted":
            if scenario.id != "S5B":
                _fail("invalid_output_budget", "omitted output budgets are exclusive to S5B")
            continue
        if scenario.id == "S5B":
            _fail("invalid_output_budget", "S5B must truly omit every request output budget")
        prompt = prompt_by_id[request.prompt_id]
        assert budget.tokens is not None
        if prompt.token_count + budget.tokens > scenario.server.context_tokens:
            _fail(
                "impossible_token_budget",
                "qualified explicit prompt and output budgets must fit the server context",
            )


def _validate_s1(scenario: Scenario) -> None:
    if scenario.schedule.kind != "offsets" or any(request.trigger for request in scenario.requests):
        _fail("invalid_s1", "S1 uses only fixed offsets")
    request_by_id = {request.id: request for request in scenario.requests}
    matrix: set[tuple[str, int]] = set()
    prompt_ids: set[str] = set()
    for case in scenario.schedule.case_matrix:
        concurrency = len(case.request_ids)
        if concurrency not in _S1_CONCURRENCIES:
            _fail("invalid_s1_matrix", "S1 case concurrency is outside the fixed matrix")
        case_prompts = {request_by_id[request_id].prompt_id for request_id in case.request_ids}
        if len(case_prompts) != 1:
            _fail("invalid_s1_matrix", "each S1 case must use one prompt class")
        prompt_id = next(iter(case_prompts))
        pair = (prompt_id, concurrency)
        if pair in matrix:
            _fail("invalid_s1_matrix", "S1 has a duplicate prompt/concurrency case")
        matrix.add(pair)
        prompt_ids.add(prompt_id)
    if len(prompt_ids) != 2:
        _fail("invalid_s1_matrix", "S1 requires exactly the short and 32K prompt classes")
    expected = {(prompt_id, concurrency) for prompt_id in prompt_ids for concurrency in _S1_CONCURRENCIES}
    if matrix != expected or len(scenario.schedule.case_matrix) != 12:
        _fail("invalid_s1_matrix", "S1 must cover both prompts at 1,2,4,8,12,16 concurrency")
    counts = {prompt.token_count for prompt in scenario.prompts}
    if len(counts) != 2:
        _fail("invalid_s1_matrix", "S1 short and 32K prompt token counts must be distinct")


def _validate_s2(scenario: Scenario) -> None:
    if scenario.schedule.kind != "offsets" or any(request.trigger for request in scenario.requests):
        _fail("invalid_s2", "S2 uses only fixed offsets")
    request_by_id = {request.id: request for request in scenario.requests}
    if set(request_by_id) != set(_S2_ROLES):
        _fail("invalid_s2", "S2 request ids must be planner, coder, reviewer, and advisor")
    if len(scenario.schedule.case_matrix) != 1 or set(
        scenario.schedule.case_matrix[0].request_ids
    ) != set(_S2_ROLES):
        _fail("invalid_s2", "S2 requires one fixed four-role case")
    offsets = [request_by_id[role].start_offset_ms for role in _S2_ROLES]
    if offsets[0] != 0 or offsets != sorted(offsets):
        _fail("invalid_s2", "S2 role offsets must begin at zero and be nondecreasing")
    role_prompts = {role: request_by_id[role].prompt_id for role in _S2_ROLES}
    if len(set(role_prompts.values())) != 4:
        _fail("invalid_s2", "S2 roles require four distinct prompt artifacts")
    prompt_counts = {prompt.id: prompt.token_count for prompt in scenario.prompts}
    if not (
        prompt_counts[role_prompts["planner"]]
        > prompt_counts[role_prompts["coder"]]
        > prompt_counts[role_prompts["advisor"]]
        > prompt_counts[role_prompts["reviewer"]]
    ):
        _fail("invalid_s2", "S2 prompt counts must preserve planner/coder/advisor/reviewer sizing")


def _validate_s3(scenario: Scenario) -> None:
    if scenario.schedule.kind != "active_decode_injection":
        _fail("invalid_s3", "S3 requires active_decode_injection scheduling")
    triggered = [request for request in scenario.requests if request.trigger is not None]
    if len(triggered) != 1:
        _fail("invalid_s3", "S3 requires exactly one active-decode injection request")
    injection = triggered[0]
    assert injection.trigger is not None
    for case in scenario.schedule.case_matrix:
        if injection.id not in case.request_ids:
            _fail("invalid_s3", "every S3 case must include the injection request")
        initial_count = len(case.request_ids) - 1
        if initial_count < injection.trigger.minimum_requests:
            _fail("invalid_s3", "S3 trigger minimum exceeds the case's initial active requests")


def _validate_s5(scenario: Scenario) -> None:
    if scenario.schedule.kind != "offsets" or any(request.trigger for request in scenario.requests):
        _fail("invalid_s5", "S5 scenarios use only fixed offsets")
    if scenario.id == "S5A":
        if any(
            request.output_budget.kind != "explicit" or request.output_budget.tokens != 512
            for request in scenario.requests
        ):
            _fail("invalid_s5a", "S5A requires an explicit 512-token budget on every request")
        return
    prompt_by_id = {prompt.id: prompt for prompt in scenario.prompts}
    if any(request.output_budget.kind != "omitted" for request in scenario.requests):
        _fail("invalid_s5b", "S5B must omit every output budget")
    if any(
        prompt_by_id[request.prompt_id].token_count + scenario.server.default_output_tokens
        <= scenario.server.context_tokens
        for request in scenario.requests
    ):
        _fail(
            "invalid_s5b",
            "S5B must retain its intentional prompt-plus-default-liability excess",
        )


def _validate_semantics(scenario: Scenario) -> None:
    if scenario.server.decode_policy == "plain" and not (
        scenario.id == "S1" and scenario.vantage == "target_local"
    ):
        _fail(
            "invalid_server_profile",
            "plain decode is restricted to the target-local S1 paired control",
        )
    _validate_common_references(scenario)
    if scenario.id == "S1":
        _validate_s1(scenario)
    elif scenario.id == "S2":
        _validate_s2(scenario)
    elif scenario.id == "S3":
        _validate_s3(scenario)
    else:
        _validate_s5(scenario)


def load_scenario(path: str | Path, repo_root: str | Path) -> Scenario:
    """Load and fully validate one qualified canonical scenario-v1 JSON file."""

    raw = _exact(
        _load_json(path),
        (
            "version",
            "id",
            "description",
            "vantage",
            "server",
            "prompts",
            "requests",
            "schedule",
            "sampling",
            "warmup_repetitions",
            "measured_repetitions",
            "deadlines",
            "preconditions",
        ),
        "scenario",
    )
    version = _integer(raw["version"], "version")
    if version != _SCHEMA_VERSION:
        _fail("unsupported_version", "scenario version must be 1")
    scenario_id = _string(raw["id"], "id", maximum=4)
    if scenario_id not in _SCENARIO_IDS:
        _fail("invalid_scenario_id", "scenario id is not part of canonical v1")
    vantage = _string(raw["vantage"], "vantage", maximum=16)
    if vantage not in _VANTAGES:
        _fail("invalid_vantage", "vantage must be controller_lan or target_local")
    scenario = Scenario(
        version=version,
        id=scenario_id,
        description=_string(raw["description"], "description", maximum=2_048),
        vantage=vantage,
        server=_parse_server(raw["server"]),
        prompts=_parse_prompts(raw["prompts"], _repo_root(repo_root)),
        requests=_parse_requests(raw["requests"]),
        schedule=_parse_schedule(raw["schedule"]),
        sampling=_parse_sampling(raw["sampling"]),
        warmup_repetitions=_integer(
            raw["warmup_repetitions"], "warmup_repetitions", minimum=1, maximum=100
        ),
        measured_repetitions=_integer(
            raw["measured_repetitions"], "measured_repetitions", minimum=1, maximum=100
        ),
        deadlines=_parse_deadlines(raw["deadlines"]),
        preconditions=_parse_preconditions(raw["preconditions"]),
    )
    _validate_semantics(scenario)
    return scenario


def load_calibration_manifest(
    path: str | Path, repo_root: str | Path
) -> CalibrationManifest:
    """Load the non-qualification prompt manifest, including explicit unmeasured counts."""

    raw = _exact(_load_json(path), ("version", "prompts"), "calibration manifest")
    version = _integer(raw["version"], "calibration manifest.version")
    if version != _SCHEMA_VERSION:
        _fail("unsupported_version", "calibration manifest version must be 1")
    raw_prompts = raw["prompts"]
    if type(raw_prompts) is not list:
        _fail("invalid_type", "calibration manifest.prompts must be an array")
    if not 1 <= len(raw_prompts) <= 64:
        _fail("invalid_value", "calibration manifest.prompts has invalid cardinality")
    root = _repo_root(repo_root)
    parsed = tuple(
        _parse_prompt_common(
            item,
            root,
            f"calibration manifest.prompts[{index}]",
            calibration=True,
        )
        for index, item in enumerate(raw_prompts)
    )
    prompts = tuple(prompt for prompt in parsed if isinstance(prompt, CalibrationPrompt))
    ids = [prompt.id for prompt in prompts]
    paths = [prompt.path for prompt in prompts]
    if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
        _fail("duplicate_id", "calibration prompt ids and paths must be unique")
    return CalibrationManifest(version=version, prompts=prompts)


def normalize_scenario(scenario: Scenario) -> dict[str, Any]:
    """Return the canonical JSON-compatible plain-dictionary scenario identity."""

    if not isinstance(scenario, Scenario):
        _fail("invalid_type", "normalize_scenario requires a Scenario")
    return {
        "version": scenario.version,
        "id": scenario.id,
        "description": scenario.description,
        "vantage": scenario.vantage,
        "server": {
            "context_tokens": scenario.server.context_tokens,
            "default_output_tokens": scenario.server.default_output_tokens,
            "decode_policy": scenario.server.decode_policy,
            "dspark_max_nlive": scenario.server.dspark_max_nlive,
            "terminal_yield_quench": scenario.server.terminal_yield_quench,
            "speculative_overrides": {
                "shadow_guard": scenario.server.speculative_overrides.shadow_guard,
                "shadow_alpha": scenario.server.speculative_overrides.shadow_alpha,
                "shadow_min_evidence": scenario.server.speculative_overrides.shadow_min_evidence,
                "shadow_budget": scenario.server.speculative_overrides.shadow_budget,
                "shadow_credit_cap": scenario.server.speculative_overrides.shadow_credit_cap,
            },
        },
        "prompts": [
            {
                "id": prompt.id,
                "path": prompt.path,
                "sha256": prompt.sha256,
                "token_count": prompt.token_count,
                "license": prompt.license,
            }
            for prompt in scenario.prompts
        ],
        "requests": [
            {
                "id": request.id,
                "prompt_id": request.prompt_id,
                "start_offset_ms": request.start_offset_ms,
                "trigger": None
                if request.trigger is None
                else {
                    "kind": request.trigger.kind,
                    "minimum_requests": request.trigger.minimum_requests,
                },
                "output_budget": {"kind": "omitted"}
                if request.output_budget.kind == "omitted"
                else {
                    "kind": "explicit",
                    "tokens": request.output_budget.tokens,
                },
            }
            for request in scenario.requests
        ],
        "schedule": {
            "kind": scenario.schedule.kind,
            "case_matrix": [
                {"id": case.id, "request_ids": list(case.request_ids)}
                for case in scenario.schedule.case_matrix
            ],
        },
        "sampling": {
            "temperature": scenario.sampling.temperature,
            "top_p": scenario.sampling.top_p,
            "seed": scenario.sampling.seed,
        },
        "warmup_repetitions": scenario.warmup_repetitions,
        "measured_repetitions": scenario.measured_repetitions,
        "deadlines": {
            "connect_seconds": scenario.deadlines.connect_seconds,
            "read_seconds": scenario.deadlines.read_seconds,
            "overall_seconds": scenario.deadlines.overall_seconds,
            "server_seconds": scenario.deadlines.server_seconds,
        },
        "preconditions": {
            "server_restart_each_repetition": scenario.preconditions.server_restart_each_repetition,
            "cache_state": scenario.preconditions.cache_state,
            "warmup_server_is_separate": scenario.preconditions.warmup_server_is_separate,
            "cooldown_seconds": scenario.preconditions.cooldown_seconds,
            "prompt_reuse": scenario.preconditions.prompt_reuse,
        },
    }


__all__ = [
    "ActiveDecodeTrigger",
    "CalibrationManifest",
    "CalibrationPrompt",
    "Case",
    "Deadlines",
    "OutputBudget",
    "Preconditions",
    "Prompt",
    "Sampling",
    "Scenario",
    "ScenarioError",
    "ScenarioRequest",
    "Schedule",
    "ServerConfig",
    "SpeculativeOverrides",
    "load_calibration_manifest",
    "load_scenario",
    "normalize_scenario",
]
