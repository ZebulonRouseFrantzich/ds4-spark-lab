"""Command line entry point for the private-safe target controller."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .workflow import structured_result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="targetctl")
    parser.add_argument("operation", choices=("doctor", "sync", "build", "serve", "status", "logs", "stop", "smoke", "cleanup", "bundle"))
    parser.add_argument("--target", choices=("local", "spark"), default="spark")
    parser.add_argument("--allow-dirty")
    parser.add_argument("--jobs", type=int)
    args = parser.parse_args(argv)
    if args.allow_dirty is not None and args.operation not in {"build", "bundle"}:
        parser.error("--allow-dirty is only valid for build or bundle")
    if args.jobs is not None and args.operation not in {"build", "bundle"}:
        parser.error("--jobs is only valid for build or bundle")
    result = structured_result(Path.cwd(), args.target, args.operation, allow_dirty=args.allow_dirty, jobs=args.jobs)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result["status"] == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
