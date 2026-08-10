from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

from ds4bench.schema import (
    ScenarioError,
    load_calibration_manifest,
    load_scenario,
    normalize_scenario,
)


class ScenarioSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.repo_root = Path(self._temporary.name)
        self.artifact_root = self.repo_root / "benchmarks" / "prompts" / "artifacts"
        self.artifact_root.mkdir(parents=True)
        self._serial = 0

    def _prompt(self, prompt_id: str, token_count: int, content: bytes | None = None) -> dict[str, Any]:
        payload = content if content is not None else f"fixture:{prompt_id}\n".encode()
        relative = f"benchmarks/prompts/artifacts/{prompt_id}.txt"
        (self.repo_root / relative).write_bytes(payload)
        return {
            "id": prompt_id,
            "path": relative,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "token_count": token_count,
            "license": "CC0-1.0",
        }

    def _base_s5a(self) -> dict[str, Any]:
        prompt = self._prompt("deep", 100)
        return {
            "version": 1,
            "id": "S5A",
            "description": "explicit deep-output liability",
            "vantage": "controller_lan",
            "server": {
                "context_tokens": 1_000,
                "default_output_tokens": 393_216,
                "decode_policy": "shipped",
                "dspark_max_nlive": 1,
                "terminal_yield_quench": True,
                "speculative_overrides": {
                    "shadow_guard": None,
                    "shadow_alpha": None,
                    "shadow_min_evidence": None,
                    "shadow_budget": None,
                    "shadow_credit_cap": None,
                },
            },
            "prompts": [prompt],
            "requests": [
                {
                    "id": "deep-1",
                    "prompt_id": "deep",
                    "start_offset_ms": 0,
                    "trigger": None,
                    "output_budget": {"kind": "explicit", "tokens": 512},
                }
            ],
            "schedule": {
                "kind": "offsets",
                "case_matrix": [{"id": "deep", "request_ids": ["deep-1"]}],
            },
            "sampling": {"temperature": 0.0, "top_p": 1.0, "seed": 0},
            "warmup_repetitions": 1,
            "measured_repetitions": 5,
            "deadlines": {
                "connect_seconds": 5.0,
                "read_seconds": 30.0,
                "overall_seconds": 60.0,
                "server_seconds": 45.0,
            },
            "preconditions": {
                "server_restart_each_repetition": True,
                "cache_state": "cold",
                "warmup_server_is_separate": True,
                "cooldown_seconds": 0.0,
                "prompt_reuse": "forbid",
            },
        }

    def _s1(self) -> dict[str, Any]:
        data = self._base_s5a()
        data["id"] = "S1"
        data["description"] = "short and 32K concurrency matrix"
        data["prompts"] = [self._prompt("short", 20), self._prompt("long32k", 320)]
        requests: list[dict[str, Any]] = []
        cases: list[dict[str, Any]] = []
        for prompt_id in ("short", "long32k"):
            for concurrency in (1, 2, 4, 8, 12, 16):
                request_ids: list[str] = []
                for index in range(concurrency):
                    request_id = f"{prompt_id}-c{concurrency}-r{index + 1}"
                    request_ids.append(request_id)
                    requests.append(
                        {
                            "id": request_id,
                            "prompt_id": prompt_id,
                            "start_offset_ms": 0,
                            "trigger": None,
                            "output_budget": {"kind": "explicit", "tokens": 16},
                        }
                    )
                cases.append({"id": f"{prompt_id}-c{concurrency}", "request_ids": request_ids})
        data["requests"] = requests
        data["schedule"] = {"kind": "offsets", "case_matrix": cases}
        return data

    def _s1_local(self, policy: str = "shipped") -> dict[str, Any]:
        data = self._s1()
        data["description"] = f"target-local concurrency-1 {policy} control"
        data["vantage"] = "target_local"
        data["server"]["decode_policy"] = policy
        selected_ids = {"short-c1", "long32k-c1"}
        data["schedule"]["case_matrix"] = [
            case
            for case in data["schedule"]["case_matrix"]
            if case["id"] in selected_ids
        ]
        selected_requests = {
            request_id
            for case in data["schedule"]["case_matrix"]
            for request_id in case["request_ids"]
        }
        data["requests"] = [
            request for request in data["requests"] if request["id"] in selected_requests
        ]
        return data

    def _s2(self) -> dict[str, Any]:
        data = self._base_s5a()
        data["id"] = "S2"
        data["description"] = "fixed mixed-agent burst"
        role_counts = {"planner": 400, "coder": 300, "reviewer": 100, "advisor": 200}
        data["prompts"] = [self._prompt(f"{role}-prompt", count) for role, count in role_counts.items()]
        data["requests"] = [
            {
                "id": role,
                "prompt_id": f"{role}-prompt",
                "start_offset_ms": index * 100,
                "trigger": None,
                "output_budget": {"kind": "explicit", "tokens": 16},
            }
            for index, role in enumerate(("planner", "coder", "reviewer", "advisor"))
        ]
        data["schedule"] = {
            "kind": "offsets",
            "case_matrix": [
                {
                    "id": "mixed-burst",
                    "request_ids": ["planner", "coder", "reviewer", "advisor"],
                }
            ],
        }
        return data

    def _s3(self) -> dict[str, Any]:
        data = self._base_s5a()
        data["id"] = "S3"
        data["description"] = "long prefill injected during active decode"
        data["requests"] = [
            {
                "id": "active-1",
                "prompt_id": "deep",
                "start_offset_ms": 0,
                "trigger": None,
                "output_budget": {"kind": "explicit", "tokens": 128},
            },
            {
                "id": "active-2",
                "prompt_id": "deep",
                "start_offset_ms": 0,
                "trigger": None,
                "output_budget": {"kind": "explicit", "tokens": 128},
            },
            {
                "id": "long-injection",
                "prompt_id": "deep",
                "start_offset_ms": 100,
                "trigger": {"kind": "active_decode", "minimum_requests": 2},
                "output_budget": {"kind": "explicit", "tokens": 128},
            },
        ]
        data["schedule"] = {
            "kind": "active_decode_injection",
            "case_matrix": [
                {
                    "id": "two-active",
                    "request_ids": ["active-1", "active-2", "long-injection"],
                }
            ],
        }
        return data

    def _load(self, data: dict[str, Any]):
        self._serial += 1
        path = self.repo_root / f"scenario-{self._serial}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return load_scenario(path, self.repo_root)

    def _rejects(self, data: dict[str, Any], code: str | None = None) -> ScenarioError:
        with self.assertRaises(ScenarioError) as raised:
            self._load(data)
        if code is not None:
            self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_unknown_fields_are_rejected_at_every_nested_layer(self) -> None:
        mutations = (
            lambda value: value.__setitem__("extra", None),
            lambda value: value["server"].__setitem__("extra", None),
            lambda value: value["server"]["speculative_overrides"].__setitem__("extra", None),
            lambda value: value["prompts"][0].__setitem__("extra", None),
            lambda value: value["requests"][0].__setitem__("extra", None),
            lambda value: value["requests"][0]["output_budget"].__setitem__("extra", None),
            lambda value: value["schedule"].__setitem__("extra", None),
            lambda value: value["schedule"]["case_matrix"][0].__setitem__("extra", None),
            lambda value: value["sampling"].__setitem__("extra", None),
            lambda value: value["deadlines"].__setitem__("extra", None),
            lambda value: value["preconditions"].__setitem__("extra", None),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                data = self._base_s5a()
                mutate(data)
                self._rejects(data, "unknown_field")

        data = self._s3()
        data["requests"][2]["trigger"]["extra"] = None
        self._rejects(data, "unknown_field")

    def test_duplicate_json_fields_are_rejected(self) -> None:
        path = self.repo_root / "duplicate.json"
        path.write_text('{"version":1,"version":1}', encoding="utf-8")
        with self.assertRaises(ScenarioError) as raised:
            load_scenario(path, self.repo_root)
        self.assertEqual(raised.exception.code, "duplicate_field")

    def test_unsafe_and_noncanonical_prompt_paths_are_rejected(self) -> None:
        unsafe = (
            "/benchmarks/prompts/artifacts/deep.txt",
            "benchmarks/prompts/artifacts/../deep.txt",
            "benchmarks/prompts/artifacts//deep.txt",
            "benchmarks\\prompts\\artifacts\\deep.txt",
            "benchmarks/prompts/deep.txt",
        )
        for path in unsafe:
            with self.subTest(path=path):
                data = self._base_s5a()
                data["prompts"][0]["path"] = path
                self._rejects(data, "unsafe_prompt_path")

    def test_prompt_hash_must_be_lower_hex_and_match_artifact(self) -> None:
        data = self._base_s5a()
        data["prompts"][0]["sha256"] = data["prompts"][0]["sha256"].upper()
        self._rejects(data, "invalid_hash")

        data = self._base_s5a()
        data["prompts"][0]["sha256"] = "0" * 64
        self._rejects(data, "prompt_hash_mismatch")

    def test_output_budget_shapes_and_scenario_boundaries(self) -> None:
        data = self._base_s5a()
        data["requests"][0]["output_budget"] = {"kind": "explicit", "tokens": 0}
        self._rejects(data, "invalid_value")

        data = self._base_s5a()
        data["requests"][0]["output_budget"] = {"kind": "omitted"}
        self._rejects(data, "invalid_output_budget")

        data = self._base_s5a()
        data["requests"][0]["output_budget"]["tokens"] = 511
        self._rejects(data, "invalid_s5a")

        data = self._base_s5a()
        data["server"]["context_tokens"] = 600
        self._rejects(data, "impossible_token_budget")

    def test_s5b_accepts_intentional_default_liability_without_a_tokens_key(self) -> None:
        data = self._base_s5a()
        data["id"] = "S5B"
        data["description"] = "observe default output liability"
        data["server"]["context_tokens"] = 262_144
        data["prompts"][0]["token_count"] = 186_000
        data["requests"][0]["output_budget"] = {"kind": "omitted"}
        scenario = self._load(data)
        normalized_budget = normalize_scenario(scenario)["requests"][0]["output_budget"]
        self.assertEqual(normalized_budget, {"kind": "omitted"})
        self.assertNotIn("tokens", normalized_budget)

        no_excess = copy.deepcopy(data)
        no_excess["server"]["context_tokens"] = 524_288
        no_excess["prompts"][0]["token_count"] = 100
        self._rejects(no_excess, "invalid_s5b")

        fake_omission = copy.deepcopy(data)
        fake_omission["requests"][0]["output_budget"] = {"kind": "omitted", "tokens": None}
        self._rejects(fake_omission, "unknown_field")

    def test_frozen_shipped_and_plain_profiles_are_bounded(self) -> None:
        mutations = (
            ("default_output_tokens", 393_215),
            ("dspark_max_nlive", 2),
            ("terminal_yield_quench", False),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                data = self._base_s5a()
                data["server"][field] = value
                self._rejects(data, "invalid_server_profile")

        data = self._base_s5a()
        data["server"]["speculative_overrides"]["shadow_guard"] = True
        self._rejects(data, "invalid_server_profile")

        data = self._base_s5a()
        data["server"]["decode_policy"] = "plain"
        self._rejects(data, "invalid_server_profile")

        control = self._s1_local("plain")
        self.assertEqual(self._load(control).server.decode_policy, "plain")

        controller_plain = copy.deepcopy(control)
        controller_plain["vantage"] = "controller_lan"
        self._rejects(controller_plain, "invalid_server_profile")

    def test_s1_matrix_is_exact_and_sampling_identity_is_fixed(self) -> None:
        scenario = self._load(self._s1())
        self.assertEqual(len(scenario.schedule.case_matrix), 12)

        data = self._s1()
        data["schedule"]["case_matrix"].pop()
        self._rejects(data)

        for field, value in (("temperature", 0), ("top_p", 0.9), ("seed", 1)):
            with self.subTest(field=field):
                data = self._base_s5a()
                data["sampling"][field] = value
                self._rejects(data, "invalid_sampling")

    def test_target_local_s1_matrix_rejects_vantage_and_case_drift(self) -> None:
        full_local = self._s1()
        full_local["vantage"] = "target_local"
        self._rejects(full_local, "invalid_s1_matrix")

        extra_concurrency = self._s1_local()
        extra_request = copy.deepcopy(extra_concurrency["requests"][0])
        extra_request["id"] = "short-extra"
        extra_concurrency["requests"].append(extra_request)
        extra_concurrency["schedule"]["case_matrix"].append(
            {
                "id": "short-c2",
                "request_ids": [
                    extra_concurrency["requests"][0]["id"],
                    extra_request["id"],
                ],
            }
        )
        self._rejects(extra_concurrency, "invalid_s1_matrix")

        missing_prompt = self._s1_local()
        missing_prompt["prompts"] = [missing_prompt["prompts"][0]]
        missing_prompt["requests"] = [missing_prompt["requests"][0]]
        missing_prompt["schedule"]["case_matrix"] = [
            missing_prompt["schedule"]["case_matrix"][0]
        ]
        self._rejects(missing_prompt, "invalid_s1_matrix")

        controller_minimal = self._s1_local()
        controller_minimal["vantage"] = "controller_lan"
        self._rejects(controller_minimal, "invalid_s1_matrix")

    def test_real_canonical_scenario_family_loads_with_frozen_contract(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        scenario_root = repo_root / "benchmarks" / "scenarios"
        filenames = (
            "s1.json",
            "s2.json",
            "s3.json",
            "s5a.json",
            "s5b.json",
            "s1-target-shipped.json",
            "s1-target-plain.json",
        )
        scenarios = {
            filename: load_scenario(scenario_root / filename, repo_root)
            for filename in filenames
        }
        manifest = load_calibration_manifest(
            repo_root / "benchmarks" / "prompts" / "manifest.json",
            repo_root,
        )
        manifest_by_id = {prompt.id: prompt for prompt in manifest.prompts}

        for filename, scenario in scenarios.items():
            with self.subTest(filename=filename):
                path = scenario_root / filename
                raw = json.loads(path.read_bytes())
                canonical = (
                    json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode()
                self.assertEqual(path.read_bytes(), canonical)
                for prompt in scenario.prompts:
                    expected_prompt = manifest_by_id[prompt.id]
                    self.assertEqual(expected_prompt.status, "measured")
                    self.assertEqual(
                        (
                            prompt.path,
                            prompt.sha256,
                            prompt.token_count,
                            prompt.license,
                        ),
                        (
                            expected_prompt.path,
                            expected_prompt.sha256,
                            expected_prompt.token_count,
                            expected_prompt.license,
                        ),
                    )
                self.assertEqual(scenario.server.context_tokens, 262_144)
                self.assertEqual(scenario.server.default_output_tokens, 393_216)
                self.assertEqual(scenario.server.dspark_max_nlive, 1)
                self.assertTrue(scenario.server.terminal_yield_quench)
                self.assertEqual(
                    set(normalize_scenario(scenario)["server"]["speculative_overrides"].values()),
                    {None},
                )
                self.assertEqual(scenario.warmup_repetitions, 1)
                self.assertEqual(scenario.measured_repetitions, 5)
                self.assertEqual(
                    (scenario.sampling.temperature, scenario.sampling.top_p, scenario.sampling.seed),
                    (0.0, 1.0, 0),
                )
                self.assertTrue(scenario.preconditions.server_restart_each_repetition)
                self.assertEqual(scenario.preconditions.cache_state, "cold")
                self.assertTrue(scenario.preconditions.warmup_server_is_separate)
                self.assertEqual(scenario.preconditions.cooldown_seconds, 30.0)
                self.assertEqual(scenario.preconditions.prompt_reuse, "allow")

        primary_s1 = scenarios["s1.json"]
        self.assertEqual(primary_s1.id, "S1")
        self.assertEqual(primary_s1.vantage, "controller_lan")
        self.assertEqual(len(primary_s1.schedule.case_matrix), 12)
        primary_request_by_id = {request.id: request for request in primary_s1.requests}
        self.assertEqual(
            {
                (
                    primary_request_by_id[case.request_ids[0]].prompt_id,
                    len(case.request_ids),
                )
                for case in primary_s1.schedule.case_matrix
            },
            {
                (prompt_id, concurrency)
                for prompt_id in ("mixed_short", "mixed_medium")
                for concurrency in (1, 2, 4, 8, 12, 16)
            },
        )
        self.assertTrue(
            all(
                request.output_budget.kind == "explicit"
                and request.output_budget.tokens == 128
                for request in primary_s1.requests
            )
        )

        shipped_control = scenarios["s1-target-shipped.json"]
        plain_control = scenarios["s1-target-plain.json"]
        for scenario, policy in (
            (shipped_control, "shipped"),
            (plain_control, "plain"),
        ):
            with self.subTest(policy=policy):
                self.assertEqual((scenario.id, scenario.vantage), ("S1", "target_local"))
                self.assertEqual(scenario.server.decode_policy, policy)
                self.assertEqual(
                    {
                        (
                            {request.id: request for request in scenario.requests}[
                                case.request_ids[0]
                            ].prompt_id,
                            len(case.request_ids),
                        )
                        for case in scenario.schedule.case_matrix
                    },
                    {("mixed_short", 1), ("mixed_medium", 1)},
                )
                self.assertEqual(len(scenario.schedule.case_matrix), 2)
                self.assertTrue(
                    all(
                        request.output_budget.kind == "explicit"
                        and request.output_budget.tokens == 128
                        for request in scenario.requests
                    )
                )
        shipped_identity = normalize_scenario(shipped_control)
        plain_identity = normalize_scenario(plain_control)
        self.assertNotEqual(
            shipped_identity.pop("description"), plain_identity.pop("description")
        )
        plain_identity["server"]["decode_policy"] = "shipped"
        self.assertEqual(shipped_identity, plain_identity)

        s2 = scenarios["s2.json"]
        self.assertEqual(
            {request.id: request.prompt_id for request in s2.requests},
            {
                "planner": "repo_like_very_large",
                "coder": "repo_like_large",
                "reviewer": "repo_like_small",
                "advisor": "repo_like_medium",
            },
        )
        self.assertTrue(
            all(
                request.start_offset_ms == 0
                and request.output_budget.kind == "explicit"
                and request.output_budget.tokens == 512
                for request in s2.requests
            )
        )

        s3 = scenarios["s3.json"]
        s3_request_by_id = {request.id: request for request in s3.requests}
        for request_id in ("active-1", "active-2", "active-3"):
            request = s3_request_by_id[request_id]
            self.assertEqual(request.prompt_id, "mixed_medium")
            self.assertIsNone(request.trigger)
            self.assertEqual(request.output_budget.tokens, 1_024)
        injection = s3_request_by_id["cold-long-injection"]
        self.assertEqual(injection.prompt_id, "repo_like_very_large")
        self.assertIsNotNone(injection.trigger)
        self.assertEqual(injection.trigger.minimum_requests, 3)
        self.assertEqual(injection.output_budget.tokens, 512)

        for filename, budget_kind in (("s5a.json", "explicit"), ("s5b.json", "omitted")):
            scenario = scenarios[filename]
            with self.subTest(filename=filename):
                self.assertEqual(len(scenario.requests), 4)
                self.assertEqual(len(scenario.schedule.case_matrix), 1)
                self.assertEqual(len(scenario.schedule.case_matrix[0].request_ids), 4)
                self.assertTrue(
                    all(
                        request.prompt_id == "repo_like_very_large"
                        and request.start_offset_ms == 0
                        and request.output_budget.kind == budget_kind
                        for request in scenario.requests
                    )
                )
        self.assertTrue(
            all(request.output_budget.tokens == 512 for request in scenarios["s5a.json"].requests)
        )
        self.assertTrue(
            all(request.output_budget.tokens is None for request in scenarios["s5b.json"].requests)
        )

    def test_s2_has_exact_roles_offsets_and_prompt_size_order(self) -> None:
        scenario = self._load(self._s2())
        self.assertEqual({request.id for request in scenario.requests}, {"planner", "coder", "reviewer", "advisor"})

        data = self._s2()
        data["requests"][0]["id"] = "architect"
        data["schedule"]["case_matrix"][0]["request_ids"][0] = "architect"
        self._rejects(data, "invalid_s2")

        data = self._s2()
        data["requests"][0]["start_offset_ms"] = 200
        self._rejects(data, "invalid_s2")

        data = self._s2()
        data["prompts"][0]["token_count"] = 150
        self._rejects(data, "invalid_s2")

    def test_s3_requires_one_live_decode_trigger_and_sufficient_initial_requests(self) -> None:
        scenario = self._load(self._s3())
        triggered = [request for request in scenario.requests if request.trigger is not None]
        self.assertEqual([request.id for request in triggered], ["long-injection"])
        self.assertEqual(triggered[0].trigger.minimum_requests, 2)

        data = self._s3()
        data["schedule"]["kind"] = "offsets"
        self._rejects(data, "invalid_s3")

        data = self._s3()
        data["requests"][2]["trigger"]["minimum_requests"] = 3
        self._rejects(data, "invalid_s3")

        data = self._base_s5a()
        data["requests"][0]["trigger"] = {"kind": "active_decode", "minimum_requests": 1}
        self._rejects(data, "invalid_s5")

    def test_case_matrix_references_and_cardinality_are_strict(self) -> None:
        data = self._base_s5a()
        data["schedule"]["case_matrix"] = []
        self._rejects(data, "invalid_case_matrix")

        data = self._base_s5a()
        data["schedule"]["case_matrix"][0]["request_ids"] = ["missing"]
        self._rejects(data, "unknown_request")

        data = self._base_s5a()
        data["schedule"]["case_matrix"][0]["request_ids"] = ["deep-1", "deep-1"]
        self._rejects(data, "invalid_case_matrix")

    def test_deadline_and_precondition_cross_fields_are_validated(self) -> None:
        data = self._base_s5a()
        data["deadlines"]["read_seconds"] = 61.0
        self._rejects(data, "invalid_deadlines")

        data = self._base_s5a()
        data["deadlines"]["connect_seconds"] = 0.0
        self._rejects(data, "invalid_value")

        data = self._base_s5a()
        data["preconditions"]["server_restart_each_repetition"] = False
        self._rejects(data, "invalid_preconditions")

        data = self._base_s5a()
        data["preconditions"]["warmup_server_is_separate"] = False
        self._rejects(data, "invalid_preconditions")

        data = self._base_s5a()
        data["preconditions"]["cooldown_seconds"] = 3_601
        self._rejects(data, "invalid_value")

    def test_calibration_loader_alone_accepts_explicit_unmeasured_counts(self) -> None:
        prompt = self._prompt("uncalibrated", 1)
        prompt["token_count"] = None
        scenario = self._base_s5a()
        scenario["prompts"] = [copy.deepcopy(prompt)]
        scenario["requests"][0]["prompt_id"] = "uncalibrated"
        self._rejects(scenario, "invalid_type")

        prompt["status"] = "unmeasured"
        manifest_path = self.repo_root / "calibration.json"
        manifest_path.write_text(
            json.dumps({"version": 1, "prompts": [prompt]}),
            encoding="utf-8",
        )
        manifest = load_calibration_manifest(manifest_path, self.repo_root)
        self.assertEqual(manifest.prompts[0].status, "unmeasured")
        self.assertIsNone(manifest.prompts[0].token_count)

        invalid = copy.deepcopy(prompt)
        invalid["token_count"] = 1
        manifest_path.write_text(
            json.dumps({"version": 1, "prompts": [invalid]}),
            encoding="utf-8",
        )
        with self.assertRaises(ScenarioError) as raised:
            load_calibration_manifest(manifest_path, self.repo_root)
        self.assertEqual(raised.exception.code, "invalid_calibration_count")

    def test_normalization_is_deterministic_plain_data_and_dataclasses_are_immutable(self) -> None:
        data = self._base_s5a()
        first = self._load(data)
        second = self._load(copy.deepcopy(data))
        normalized_first = normalize_scenario(first)
        normalized_second = normalize_scenario(second)
        self.assertEqual(normalized_first, data)
        self.assertEqual(normalized_first, normalized_second)
        self.assertEqual(
            json.dumps(normalized_first, sort_keys=True, separators=(",", ":")),
            json.dumps(normalized_second, sort_keys=True, separators=(",", ":")),
        )
        self.assertIs(type(normalized_first), dict)
        self.assertIs(type(normalized_first["prompts"]), list)
        self.assertIs(type(normalized_first["schedule"]["case_matrix"][0]["request_ids"]), list)
        self.assertFalse(hasattr(first, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            first.id = "S1"


if __name__ == "__main__":
    unittest.main()
