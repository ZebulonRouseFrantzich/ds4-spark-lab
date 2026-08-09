"""Strict, private-safe target configuration loading."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import tomllib
from typing import Any, Mapping
from urllib.parse import urlsplit

from .common import SCHEMA_VERSION, TargetError, validate_object_keys


_TARGET_NAMES = frozenset({"spark", "local"})
_SSH_FIELDS = frozenset(
    {
        "name",
        "mode",
        "ssh_host",
        "workdir",
        "run_dir",
        "api_base_url",
        "model_path",
        "drafter_path",
    }
)
_LOCAL_FIELDS = frozenset({"name", "mode"})
_OPERATIONS = frozenset({"doctor", "sync", "build", "serve", "status", "logs", "stop", "smoke"})
_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", re.ASCII)
_PATH_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", re.ASCII)
_MIN_REMOTE_PATH_DEPTH = 4
_MAX_REMOTE_PATH_DEPTH = 32
_MAX_REMOTE_PATH_LENGTH = 4096
_FORBIDDEN_REMOTE_PATH_ROOTS = frozenset(
    {
        "bin",
        "boot",
        "cache",
        "dev",
        "etc",
        "home",
        "lib",
        "lib64",
        "lost+found",
        "opt",
        "proc",
        "root",
        "run",
        "sbin",
        "srv",
        "sys",
        "tmp",
        "usr",
        "var",
    }
)


def _config_error(code: str = "config_invalid") -> TargetError:
    return TargetError(code, "target configuration is invalid")


def _require_string(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise _config_error()
    if not value.isascii() or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise _config_error()
    return value


def _validate_alias(value: Any) -> str:
    alias = _require_string(value)
    if _ALIAS_RE.fullmatch(alias) is None:
        raise _config_error()
    return alias


def _validate_normalized_remote_path(value: Any) -> str:
    path = _require_string(value)
    if len(path) > _MAX_REMOTE_PATH_LENGTH or not path.startswith("/") or path == "/":
        raise _config_error()
    if path.endswith("/") or "//" in path:
        raise _config_error()
    components = path.split("/")[1:]
    if len(components) < _MIN_REMOTE_PATH_DEPTH or len(components) > _MAX_REMOTE_PATH_DEPTH:
        raise _config_error()
    for component in components:
        if component in {".", ".."} or _PATH_COMPONENT_RE.fullmatch(component) is None:
            raise _config_error()
    return path


def _validate_mutable_remote_path(value: Any) -> str:
    path = _validate_normalized_remote_path(value)
    if _components(path)[0] in _FORBIDDEN_REMOTE_PATH_ROOTS:
        raise _config_error()
    return path


def _validate_artifact_remote_path(value: Any) -> str:
    return _validate_normalized_remote_path(value)


def _validate_api_base_url(value: Any) -> str:
    url = _require_string(value)
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError):
        raise _config_error() from None
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or not 1 <= port <= 65535
        or parsed.path
        or parsed.query
        or parsed.fragment
        or url != f"http://127.0.0.1:{port}"
    ):
        raise _config_error()
    return url


def _components(path: str) -> tuple[str, ...]:
    return tuple(path.split("/")[1:])


def _overlaps(left: str, right: str) -> bool:
    left_parts = _components(left)
    right_parts = _components(right)
    shorter, longer = (left_parts, right_parts) if len(left_parts) <= len(right_parts) else (right_parts, left_parts)
    return longer[: len(shorter)] == shorter


def _validate_no_lexical_overlap(paths: tuple[str, ...]) -> None:
    for index, first in enumerate(paths):
        for second in paths[index + 1 :]:
            if _overlaps(first, second):
                raise _config_error("config_paths_overlap")


def _resolve_repo_root(repo_root: str | os.PathLike[str]) -> Path:
    try:
        resolved = Path(repo_root).resolve(strict=True)
    except (OSError, RuntimeError):
        raise TargetError("repo_root_invalid", "repository root is unavailable") from None
    if not resolved.is_dir():
        raise TargetError("repo_root_invalid", "repository root is unavailable")
    return resolved


def _local_run_dir() -> str:
    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        state = Path(state_home)
        if not state.is_absolute():
            raise TargetError("xdg_state_invalid", "local state location is unavailable")
    else:
        try:
            state = Path.home() / ".local" / "state"
        except (OSError, RuntimeError):
            raise TargetError("xdg_state_invalid", "local state location is unavailable") from None
    return str(state / "ds4-spark-lab" / "targetctl" / "local")


@dataclass(frozen=True, slots=True)
class TargetConfig:
    """An immutable validated target, with all private fields hidden in repr."""

    name: str
    mode: str
    ssh_host: str | None = field(default=None, repr=False)
    workdir: str | None = field(default=None, repr=False)
    run_dir: str | None = field(default=None, repr=False)
    api_base_url: str | None = field(default=None, repr=False)
    model_path: str | None = field(default=None, repr=False)
    drafter_path: str | None = field(default=None, repr=False)
    source_root: Path = field(default=Path("."), repr=False)

    @property
    def local_run_dir(self) -> Path:
        """Return the XDG-derived local state directory without logging it."""

        if self.mode != "local" or self.run_dir is None:
            raise TargetError("config_mode_invalid", "target mode is invalid")
        return Path(self.run_dir)

    def validate_for(self, operation: str) -> None:
        """Reject unknown operations before target-specific work begins."""

        if not isinstance(operation, str) or operation not in _OPERATIONS:
            raise TargetError("operation_invalid", "target operation is invalid")
        if self.mode == "local":
            if self.name != "local" or any(
                value is not None
                for value in (
                    self.ssh_host,
                    self.workdir,
                    self.api_base_url,
                    self.model_path,
                    self.drafter_path,
                )
            ) or self.run_dir is None:
                raise _config_error()
            return
        if self.name != "spark" or (
            self.ssh_host is None
            or self.workdir is None
            or self.run_dir is None
            or self.api_base_url is None
            or self.model_path is None
            or self.drafter_path is None
        ):
            raise _config_error()
        _validate_alias(self.ssh_host)
        paths = (
            _validate_mutable_remote_path(self.workdir),
            _validate_mutable_remote_path(self.run_dir),
            _validate_artifact_remote_path(self.model_path),
            _validate_artifact_remote_path(self.drafter_path),
        )
        _validate_no_lexical_overlap(paths)
        _validate_api_base_url(self.api_base_url)


def _read_toml(config_path: str | os.PathLike[str]) -> Mapping[str, Any]:
    try:
        with open(config_path, "rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        raise TargetError("config_read_failed", "target configuration is unavailable") from None
    if not isinstance(parsed, dict):
        raise _config_error()
    return parsed


def load_target(
    repo_root: str | os.PathLike[str], name: str, config_path: str | os.PathLike[str]
) -> TargetConfig:
    """Load exactly one validated named target from a strict TOML document."""

    if not isinstance(name, str) or name not in _TARGET_NAMES:
        raise TargetError("target_name_invalid", "target name is invalid")
    source_root = _resolve_repo_root(repo_root)
    document = _read_toml(config_path)
    validate_object_keys(document, allowed={"schema_version", "spark", "local"}, required={"schema_version"})
    schema = document["schema_version"]
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != SCHEMA_VERSION:
        raise TargetError("config_schema_invalid", "target configuration schema is invalid")
    section = document.get(name)
    if not isinstance(section, dict):
        raise _config_error()
    mode = section.get("mode")
    if mode == "local":
        validate_object_keys(section, allowed=_LOCAL_FIELDS, required=_LOCAL_FIELDS)
        if section["name"] != "local" or name != "local":
            raise _config_error()
        return TargetConfig(name="local", mode="local", run_dir=_local_run_dir(), source_root=source_root)
    if mode == "ssh":
        validate_object_keys(section, allowed=_SSH_FIELDS, required=_SSH_FIELDS)
        if section["name"] != "spark" or name != "spark":
            raise _config_error()
        ssh_host = _validate_alias(section["ssh_host"])
        workdir = _validate_mutable_remote_path(section["workdir"])
        run_dir = _validate_mutable_remote_path(section["run_dir"])
        model_path = _validate_artifact_remote_path(section["model_path"])
        drafter_path = _validate_artifact_remote_path(section["drafter_path"])
        _validate_no_lexical_overlap((workdir, run_dir, model_path, drafter_path))
        return TargetConfig(
            name="spark",
            mode="ssh",
            ssh_host=ssh_host,
            workdir=workdir,
            run_dir=run_dir,
            api_base_url=_validate_api_base_url(section["api_base_url"]),
            model_path=model_path,
            drafter_path=drafter_path,
            source_root=source_root,
        )
    raise _config_error()
