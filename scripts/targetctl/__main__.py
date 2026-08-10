"""Command line entry point for the private-safe target controller."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .benchmark import BENCHMARK_OPERATIONS, structured_benchmark_result
from .migration import MIGRATION_OPERATION, structured_migration_result
from .workflow import structured_result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="targetctl")
    parser.add_argument("operation", choices=("doctor", "sync", "build", "serve", "status", "logs", "stop", "smoke", "cleanup", "bundle", MIGRATION_OPERATION, *sorted(BENCHMARK_OPERATIONS)))
    parser.add_argument("--target", choices=("local", "spark"), default="spark")
    parser.add_argument("--allow-dirty")
    parser.add_argument("--jobs", type=int)
    parser.add_argument("--baseline")
    parser.add_argument("--candidate")
    args = parser.parse_args(argv)
    if args.allow_dirty is not None and args.operation not in {"build", "bundle"}:
        parser.error("--allow-dirty is only valid for build or bundle")
    if args.jobs is not None and args.operation not in {"build", "bundle"}:
        parser.error("--jobs is only valid for build or bundle")
    if args.operation == "compare":
        if args.baseline is None or args.candidate is None:
            parser.error("compare requires --baseline and --candidate")
    elif args.baseline is not None or args.candidate is not None:
        parser.error("--baseline and --candidate are only valid for compare")
    if args.operation == MIGRATION_OPERATION:
        result = structured_migration_result(Path.cwd(), args.target)
    elif args.operation in BENCHMARK_OPERATIONS:
        result = structured_benchmark_result(
            Path.cwd(),
            args.target,
            args.operation,
            baseline=args.baseline,
            candidate=args.candidate,
        )
    else:
        result = structured_result(Path.cwd(), args.target, args.operation, allow_dirty=args.allow_dirty, jobs=args.jobs)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result["status"] == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
