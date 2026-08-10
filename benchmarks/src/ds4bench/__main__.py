"""Portable JSON-only command line for the benchmark zipapp."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from typing import NoReturn, TextIO

from .execution import (
    ExecutionError,
    calibrate_prompts,
    run_case_from_files,
    verify_result_from_path,
)


class _StrictParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise ExecutionError("invalid_arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _StrictParser(prog="ds4bench.pyz", description="DS4 portable benchmark executor")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run-case", help="run one validated case repetition")
    run.add_argument("--scenario", required=True, metavar="PATH")
    run.add_argument("--repo-root", required=True, metavar="ROOT")
    run.add_argument("--endpoint", required=True, metavar="URL")
    run.add_argument("--model", required=True, metavar="ID")
    run.add_argument("--result-root", required=True, metavar="ROOT")
    run.add_argument("--metadata", required=True, metavar="PATH")
    run.add_argument("--source-manifest", required=True, metavar="PATH")
    run.add_argument("--case", required=True, metavar="ID")
    run.add_argument("--repetition", required=True, metavar="N")

    calibrate = commands.add_parser(
        "calibrate-prompts", help="measure an unmeasured prompt manifest"
    )
    calibrate.add_argument("--manifest", required=True, metavar="PATH")
    calibrate.add_argument("--repo-root", required=True, metavar="ROOT")
    calibrate.add_argument("--endpoint", required=True, metavar="URL")
    calibrate.add_argument("--model", required=True, metavar="ID")
    calibrate.add_argument("--output", required=True, metavar="PATH")

    verify = commands.add_parser("verify-result", help="verify one exact result bundle")
    verify.add_argument("path", metavar="PATH")
    return parser


def _unsigned_integer(value: object) -> int:
    if not isinstance(value, str) or not value or len(value) > 3 or not value.isascii() or not value.isdecimal():
        raise ExecutionError("invalid_repetition")
    result = int(value, 10)
    if result > 99:
        raise ExecutionError("invalid_repetition")
    return result


def _emit(stream: TextIO, value: dict[str, object]) -> None:
    stream.write(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    stream.flush()


def main(argv: Sequence[str] | None = None) -> int:
    """Execute one portable subcommand without echoing operator inputs."""

    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "run-case":
            repetition = _unsigned_integer(arguments.repetition)
            asyncio.run(
                run_case_from_files(
                    arguments.scenario,
                    arguments.repo_root,
                    arguments.endpoint,
                    arguments.model,
                    arguments.result_root,
                    arguments.metadata,
                    arguments.source_manifest,
                    arguments.case,
                    repetition,
                )
            )
            success: dict[str, object] = {
                "case_id": arguments.case,
                "command": "run-case",
                "repetition": repetition,
                "status": "ok",
            }
        elif arguments.command == "calibrate-prompts":
            asyncio.run(
                calibrate_prompts(
                    arguments.manifest,
                    arguments.repo_root,
                    arguments.endpoint,
                    arguments.model,
                    arguments.output,
                )
            )
            success = {"command": "calibrate-prompts", "status": "ok"}
        elif arguments.command == "verify-result":
            verify_result_from_path(arguments.path)
            success = {"command": "verify-result", "status": "ok"}
        else:
            raise ExecutionError("invalid_arguments")
    except ExecutionError as error:
        _emit(sys.stderr, {"code": error.code, "status": "error"})
        return 2
    except KeyboardInterrupt:
        _emit(sys.stderr, {"code": "interrupted", "status": "error"})
        return 130
    except Exception:
        _emit(sys.stderr, {"code": "internal_error", "status": "error"})
        return 2

    _emit(sys.stdout, success)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
