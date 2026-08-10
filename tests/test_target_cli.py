from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.targetctl.__main__ import main
from scripts.targetctl.benchmark import BENCHMARK_OPERATIONS, SCENARIOS, SMOKE_SCENARIOS


class BenchmarkCliRoutingTests(unittest.TestCase):
    def test_each_benchmark_operation_routes_to_benchmark_dispatch(self) -> None:
        for operation in sorted(BENCHMARK_OPERATIONS - {"compare"}):
            with self.subTest(operation=operation), patch(
                "scripts.targetctl.__main__.structured_benchmark_result",
                return_value={"schema": 1, "operation": operation, "target": "local", "status": "succeeded"},
            ) as dispatched, patch("scripts.targetctl.__main__.structured_result") as phase_one:
                output = io.StringIO()
                with redirect_stdout(output):
                    status = main([operation, "--target", "local"])
            self.assertEqual(status, 0)
            dispatched.assert_called_once_with(Path.cwd(), "local", operation, baseline=None, candidate=None)
            phase_one.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["operation"], operation)

    def test_compare_requires_and_routes_both_paths_without_echoing_them(self) -> None:
        private_baseline = "/private/results/baseline"
        private_candidate = "/private/results/candidate"
        response = {"schema": 1, "operation": "compare", "target": "spark", "status": "succeeded", "comparison": {"schema_version": 1}}
        with patch("scripts.targetctl.__main__.structured_benchmark_result", return_value=response) as dispatched:
            output = io.StringIO()
            with redirect_stdout(output):
                status = main(["compare", "--baseline", private_baseline, "--candidate", private_candidate])
        self.assertEqual(status, 0)
        dispatched.assert_called_once_with(Path.cwd(), "spark", "compare", baseline=private_baseline, candidate=private_candidate)
        self.assertNotIn(private_baseline, output.getvalue())
        self.assertNotIn(private_candidate, output.getvalue())

    def test_compare_rejects_partial_arguments_before_dispatch(self) -> None:
        with patch("scripts.targetctl.__main__.structured_benchmark_result") as dispatched:
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(["compare", "--baseline", "baseline"])
        dispatched.assert_not_called()

    def test_benchmark_rejects_phase_one_build_flags(self) -> None:
        for option in ("--allow-dirty", "--jobs"):
            argv = ["bench-s1", option, "yes" if option == "--allow-dirty" else "1"]
            with self.subTest(option=option), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(argv)

    def test_phase_one_operation_still_uses_original_dispatch(self) -> None:
        response = {"schema": 1, "operation": "doctor", "target": "spark", "status": "succeeded"}
        with patch("scripts.targetctl.__main__.structured_result", return_value=response) as phase_one, patch("scripts.targetctl.__main__.structured_benchmark_result") as benchmark:
            with redirect_stdout(io.StringIO()):
                status = main(["doctor"])
        self.assertEqual(status, 0)
        phase_one.assert_called_once_with(Path.cwd(), "spark", "doctor", allow_dirty=None, jobs=None)
        benchmark.assert_not_called()

    def test_migration_routes_only_to_dedicated_dispatch(self) -> None:
        response = {
            "schema": 1,
            "operation": "migrate-state",
            "target": "spark",
            "status": "succeeded",
            "outcome": "not_found",
        }
        with patch(
            "scripts.targetctl.__main__.structured_migration_result",
            return_value=response,
        ) as migration, patch(
            "scripts.targetctl.__main__.structured_result"
        ) as phase_one, patch(
            "scripts.targetctl.__main__.structured_benchmark_result"
        ) as benchmark:
            output = io.StringIO()
            with redirect_stdout(output):
                status = main(["migrate-state"])
        self.assertEqual(status, 0)
        migration.assert_called_once_with(Path.cwd(), "spark")
        phase_one.assert_not_called()
        benchmark.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), response)


class BenchmarkRecipeContracts(unittest.TestCase):
    def test_only_implemented_phase_two_recipes_are_exposed(self) -> None:
        text = Path("Justfile").read_text(encoding="utf-8")
        for operation in (
            "bench-smoke",
            "bench-smoke-local",
            "bench-s1",
            "bench-s1-local-shipped",
            "bench-s1-local-plain",
            "bench-s1-local-paired",
            "bench-s2",
            "bench-s3",
            "bench-s5a",
            "bench-s5b",
            "bench-v1-baseline",
        ):
            self.assertIn(f'{operation} target="spark":', text)
            self.assertIn(f"uv run --frozen --project benchmarks python -m scripts.targetctl {operation} --target {{{{ quote(target) }}}}", text)
        self.assertIn("compare baseline candidate:", text)
        self.assertIn("uv run --frozen --project benchmarks python -m scripts.targetctl compare --baseline {{ quote(baseline) }} --candidate {{ quote(candidate) }}", text)
        self.assertEqual(
            SCENARIOS,
            {
                "bench-s1": Path("benchmarks/scenarios/s1.json"),
                "bench-s1-local-shipped": Path("benchmarks/scenarios/s1-target-shipped.json"),
                "bench-s1-local-plain": Path("benchmarks/scenarios/s1-target-plain.json"),
                "bench-s2": Path("benchmarks/scenarios/s2.json"),
                "bench-s3": Path("benchmarks/scenarios/s3.json"),
                "bench-s5a": Path("benchmarks/scenarios/s5a.json"),
                "bench-s5b": Path("benchmarks/scenarios/s5b.json"),
            },
        )
        self.assertEqual(
            SMOKE_SCENARIOS,
            {
                "bench-smoke": "bench-s1",
                "bench-smoke-local": "bench-s1-local-shipped",
            },
        )
        self.assertEqual(
            BENCHMARK_OPERATIONS,
            frozenset(
                {
                    "bench-smoke",
                    "bench-smoke-local",
                    "bench-s1",
                    "bench-s1-local-shipped",
                    "bench-s1-local-plain",
                    "bench-s1-local-paired",
                    "bench-s2",
                    "bench-s3",
                    "bench-s5a",
                    "bench-s5b",
                    "bench-v1-baseline",
                    "compare",
                }
            ),
        )

    def test_explicit_state_migration_recipe_is_exposed(self) -> None:
        text = Path("Justfile").read_text(encoding="utf-8")
        self.assertIn('target-migrate-state target="spark":', text)
        self.assertIn(
            "python3 -m scripts.targetctl migrate-state --target {{ quote(target) }}",
            text,
        )


if __name__ == "__main__":
    unittest.main()
