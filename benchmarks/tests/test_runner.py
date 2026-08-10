from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import unittest
from collections.abc import Awaitable, Callable
from pathlib import Path

from ds4bench.artifacts import verify_result
from ds4bench.metrics import (
    SERVER_METRICS,
    ServerMetricsSampler,
    counter_deltas,
    delta_telemetry,
    observed_execution,
    parse_server_metrics,
    snapshot_telemetry,
)
from ds4bench.runner import ArtifactInputs, case_repetitions, run_case
from ds4bench.schema import Scenario, load_scenario


ChatHandler = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter, str], Awaitable[None]
]


class LocalRunnerServer:
    def __init__(self) -> None:
        self.chat_handler: ChatHandler | None = None
        self.metrics_status = 200
        self.metrics_payload = b"ds4_banks_live 0\n"
        self.received_at: dict[str, float] = {}
        self.hang_open = asyncio.Event()
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task[object]] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)

    @property
    def base_url(self) -> str:
        assert self._server is not None
        port = self._server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}"

    @property
    def chat_url(self) -> str:
        return self.base_url + "/v1/chat/completions"

    @property
    def metrics_url(self) -> str:
        return self.base_url + "/metrics"

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for writer in tuple(self._writers):
            writer.close()
        for task in tuple(self._tasks):
            if not task.done():
                task.cancel()
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        self._writers.add(writer)
        try:
            header = await reader.readuntil(b"\r\n\r\n")
            lines = header.split(b"\r\n")
            path = lines[0].decode("ascii").split()[1]
            content_length = 0
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if separator and name.lower() == b"content-length":
                    content_length = int(value.strip())
            body = await reader.readexactly(content_length)
            if path == "/metrics":
                await self._send_metrics(writer)
                return
            parsed = json.loads(body)
            prompt = parsed["messages"][0]["content"]
            assert isinstance(prompt, str)
            self.received_at[prompt] = asyncio.get_running_loop().time()
            if self.chat_handler is None:
                raise AssertionError("missing chat handler")
            await self.chat_handler(reader, writer, prompt)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, RuntimeError):
                pass
            self._writers.discard(writer)
            self._tasks.discard(task)

    async def _send_metrics(self, writer: asyncio.StreamWriter) -> None:
        reason = "OK" if self.metrics_status == 200 else "Unavailable"
        writer.write(
            (
                f"HTTP/1.1 {self.metrics_status} {reason}\r\n"
                "Content-Type: text/plain; version=0.0.4\r\n"
                f"Content-Length: {len(self.metrics_payload)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            + self.metrics_payload
        )
        await writer.drain()


async def send_sse_headers(writer: asyncio.StreamWriter) -> None:
    writer.write(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/event-stream\r\n"
        b"Connection: close\r\n\r\n"
    )
    await writer.drain()


async def send_model_token(writer: asyncio.StreamWriter, content: str) -> None:
    event = {"choices": [{"delta": {"content": content}}]}
    writer.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
    await writer.drain()


async def send_terminal(
    writer: asyncio.StreamWriter,
    *,
    prompt_tokens: int = 1,
    completion_tokens: int = 1,
) -> None:
    terminal = {
        "choices": [{"delta": {}, "finish_reason": "stop"}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
        },
    }
    writer.write(
        f"data: {json.dumps(terminal)}\n\ndata: [DONE]\n\n".encode("utf-8")
    )
    await writer.drain()


def source_manifest() -> dict[str, object]:
    available = lambda value: {"status": "available", "value": value}
    return {
        "schema_version": 1,
        "lab": {
            "url": "https://example.invalid/lab.git",
            "commit": "1" * 40,
            "clean": True,
            "source_snapshot_id": "snapshot-a",
            "applied_tree_hash": "1" * 64,
        },
        "engine": {
            "url": "https://example.invalid/engine.git",
            "commit": "2" * 40,
            "clean": True,
        },
        "integration": {
            "url": "https://example.invalid/integration.git",
            "commit": "3" * 40,
            "clean": True,
        },
        "userspace": {
            "flake_lock_sha256": "4" * 64,
            "nixpkgs_revision": "5" * 40,
            "python_version": "3.12.3",
            "uv_version": "0.8.0",
        },
        "controller": {"os": "Linux", "kernel": "fixture", "arch": "x86_64"},
        "target": {
            "os": available("Linux"),
            "kernel": available("fixture"),
            "arch": available("aarch64"),
            "hardware_vendor": available("NVIDIA"),
            "hardware_model": available("DGX Spark"),
            "soc": available("GB10"),
            "gpu": available("SM121"),
            "compute_capability": available("12.1"),
            "firmware": {"status": "unavailable", "value": None},
            "driver": available("fixture-driver"),
            "cuda": available("fixture-cuda"),
            "nvcc": available("fixture-nvcc"),
            "c_compiler": available("fixture-cc"),
            "cpp_compiler": available("fixture-cxx"),
            "clock_sync": available("synchronized"),
        },
        "build": {
            "build_id": "build-a",
            "binary_sha256": "6" * 64,
            "source_snapshot_id": "snapshot-a",
        },
        "weights": {
            "model_sha256": "8" * 64,
            "drafter_sha256": "9" * 64,
        },
    }


def metadata(
    scenario: Scenario,
    *,
    run_id: str,
    repetition: int,
    execution: dict[str, object] | None = None,
) -> dict[str, object]:
    normalized_server = {
        "context_tokens": scenario.server.context_tokens,
        "default_output_tokens": scenario.server.default_output_tokens,
        "decode_policy": scenario.server.decode_policy,
        "dspark_max_nlive": scenario.server.dspark_max_nlive,
        "terminal_yield_quench": scenario.server.terminal_yield_quench,
        "speculative_overrides": {
            "shadow_guard": None,
            "shadow_alpha": None,
            "shadow_min_evidence": None,
            "shadow_budget": None,
            "shadow_credit_cap": None,
        },
    }
    return {
        "schema_version": 1,
        "run_id": run_id,
        "scenario_id": scenario.id,
        "prompt_manifest_sha256": "d" * 64,
        "vantage": scenario.vantage,
        "clock_domain": "controller_monotonic",
        "started_utc": "2026-08-10T00:00:00Z",
        "configured_policy": normalized_server,
        "observed_execution": execution
        or {
            "status": "unavailable",
            "reason": "not_exposed_by_frozen_source",
        },
        "network": {
            "path": "direct_private_lan",
            "http_version": "HTTP/1.1",
            "tls": False,
            "link_speed_mbps": 1000,
            "mtu_bytes": 1500,
        },
        "warmup_repetitions": scenario.warmup_repetitions,
        "measured_repetitions": scenario.measured_repetitions,
        "pairing": {
            "pair_id": None,
            "block_id": None,
            "order": None,
            "repetition": repetition,
        },
        "runtime_bundle": None,
    }


def read_requests(result: Path) -> dict[str, dict[str, object]]:
    rows = [json.loads(line) for line in (result / "requests.jsonl").read_text().splitlines()]
    return {row["request_id"]: row for row in rows}


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo_root = Path(self.temporary.name)
        self.results = self.repo_root / "results"
        self.server = LocalRunnerServer()
        await self.server.start()

    async def asyncTearDown(self) -> None:
        await self.server.close()
        self.temporary.cleanup()

    def make_scenario(
        self,
        *,
        scenario_id: str,
        requests: list[dict[str, object]],
        cases: list[dict[str, object]],
        measured_repetitions: int = 1,
        server_seconds: float = 1.0,
    ) -> Scenario:
        prompt_root = self.repo_root / "benchmarks" / "prompts" / "artifacts"
        prompt_root.mkdir(parents=True, exist_ok=True)
        prompts: list[dict[str, object]] = []
        normalized_requests: list[dict[str, object]] = []
        for index, request in enumerate(requests):
            request_id = str(request["id"])
            prompt_id = f"prompt-{request_id}"
            content = str(request.get("content", request_id))
            relative = f"benchmarks/prompts/artifacts/{prompt_id}.txt"
            payload = content.encode("utf-8")
            (self.repo_root / relative).write_bytes(payload)
            prompts.append(
                {
                    "id": prompt_id,
                    "path": relative,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "token_count": index + 1,
                    "license": "CC0-1.0",
                }
            )
            normalized_requests.append(
                {
                    "id": request_id,
                    "prompt_id": prompt_id,
                    "start_offset_ms": request.get("start_offset_ms", 0),
                    "trigger": request.get("trigger"),
                    "output_budget": {"kind": "explicit", "tokens": 512},
                }
            )
        value = {
            "version": 1,
            "id": scenario_id,
            "description": "runner fixture",
            "vantage": "controller_lan",
            "server": {
                "context_tokens": 262144,
                "default_output_tokens": 393216,
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
            "prompts": prompts,
            "requests": normalized_requests,
            "schedule": {
                "kind": "active_decode_injection" if scenario_id == "S3" else "offsets",
                "case_matrix": cases,
            },
            "sampling": {"temperature": 0.0, "top_p": 1.0, "seed": 0},
            "warmup_repetitions": 1,
            "measured_repetitions": measured_repetitions,
            "deadlines": {
                "connect_seconds": 0.25,
                "read_seconds": 0.5,
                "overall_seconds": 2.0,
                "server_seconds": server_seconds,
            },
            "preconditions": {
                "server_restart_each_repetition": True,
                "cache_state": "cold",
                "warmup_server_is_separate": True,
                "cooldown_seconds": 0.0,
                "prompt_reuse": "allow",
            },
        }
        scenario_path = self.repo_root / f"{scenario_id}.json"
        scenario_path.write_text(json.dumps(value))
        return load_scenario(scenario_path, self.repo_root)

    def artifact_inputs(
        self, scenario: Scenario, *, run_id: str, repetition: int = 0
    ) -> ArtifactInputs:
        return ArtifactInputs(
            metadata(scenario, run_id=run_id, repetition=repetition),
            source_manifest(),
            server_log="server fixture\n",
            client_log="client fixture\n",
        )

    async def test_offsets_are_concurrent_and_slow_stream_does_not_block_fast(self) -> None:
        scenario = self.make_scenario(
            scenario_id="S5A",
            requests=[
                {"id": "slow", "content": "slow", "start_offset_ms": 0},
                {"id": "fast", "content": "fast", "start_offset_ms": 30},
            ],
            cases=[{"id": "offsets", "request_ids": ["slow", "fast"]}],
        )

        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            prompt: str,
        ) -> None:
            await send_sse_headers(writer)
            if prompt == "slow":
                await send_model_token(writer, "slow")
                await asyncio.sleep(0.15)
                await send_terminal(writer)
            else:
                await send_model_token(writer, "fast")
                await send_terminal(writer)

        self.server.chat_handler = handler
        result = await run_case(
            scenario,
            scenario.schedule.case_matrix[0],
            0,
            repo_root=self.repo_root,
            endpoint=self.server.chat_url,
            model="fixture-model",
            result_root=self.results,
            artifacts=self.artifact_inputs(scenario, run_id="offset-run"),
        )
        verified = verify_result(result)
        samples = read_requests(result)

        offset = self.server.received_at["fast"] - self.server.received_at["slow"]
        self.assertGreaterEqual(offset, 0.02)
        self.assertLess(offset, 0.10)
        self.assertLess(samples["fast"]["completion_ns"], samples["slow"]["completion_ns"])
        self.assertEqual(verified["run_id"], "offset-run")
        self.assertEqual(verified["result_state"], "success")

    async def test_s3_injects_only_while_minimum_initial_requests_are_live(self) -> None:
        scenario = self.make_scenario(
            scenario_id="S3",
            requests=[
                {"id": "initial-a", "content": "initial-a"},
                {"id": "initial-b", "content": "initial-b"},
                {
                    "id": "injection",
                    "content": "injection",
                    "trigger": {"kind": "active_decode", "minimum_requests": 2},
                },
            ],
            cases=[
                {
                    "id": "live-injection",
                    "request_ids": ["initial-a", "initial-b", "injection"],
                }
            ],
        )
        injection_seen = asyncio.Event()

        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            prompt: str,
        ) -> None:
            await send_sse_headers(writer)
            if prompt.startswith("initial"):
                await send_model_token(writer, prompt)
                await asyncio.wait_for(injection_seen.wait(), 0.5)
                await send_terminal(writer)
            else:
                injection_seen.set()
                await send_model_token(writer, "injected")
                await send_terminal(writer)

        self.server.chat_handler = handler
        result = await run_case(
            scenario,
            scenario.schedule.case_matrix[0],
            0,
            repo_root=self.repo_root,
            endpoint=self.server.chat_url,
            model="fixture-model",
            result_root=self.results,
            artifacts=self.artifact_inputs(scenario, run_id="s3-live"),
        )
        samples = read_requests(result)
        injection = samples["injection"]
        initials = [samples["initial-a"], samples["initial-b"]]

        self.assertIsNotNone(injection["send_ns"])
        self.assertGreaterEqual(
            injection["send_ns"], max(item["first_model_token_ns"] for item in initials)
        )
        self.assertLess(
            injection["send_ns"], min(item["completion_ns"] for item in initials)
        )
        self.assertEqual(verify_result(result)["result_state"], "success")

    async def test_s3_unmet_trigger_is_unsent_and_promotes_failure(self) -> None:
        scenario = self.make_scenario(
            scenario_id="S3",
            requests=[
                {"id": "initial", "content": "initial"},
                {
                    "id": "injection",
                    "content": "injection",
                    "trigger": {"kind": "active_decode", "minimum_requests": 1},
                },
            ],
            cases=[{"id": "no-trigger", "request_ids": ["initial", "injection"]}],
            server_seconds=0.12,
        )

        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _prompt: str,
        ) -> None:
            await send_sse_headers(writer)
            await send_terminal(writer, completion_tokens=0)

        self.server.chat_handler = handler
        result = await run_case(
            scenario,
            scenario.schedule.case_matrix[0],
            0,
            repo_root=self.repo_root,
            endpoint=self.server.chat_url,
            model="fixture-model",
            result_root=self.results,
            artifacts=self.artifact_inputs(scenario, run_id="s3-unmet"),
        )
        samples = read_requests(result)
        metadata_value = json.loads((result / "metadata.json").read_text())

        self.assertEqual(set(self.server.received_at), {"initial"})
        self.assertIsNone(samples["injection"]["send_ns"])
        self.assertEqual(samples["injection"]["finish_class"], "incomplete")
        self.assertEqual(metadata_value["primary_error"]["code"], "trigger_not_met")
        self.assertEqual(verify_result(result)["result_state"], "failed")

    async def test_external_cancellation_settles_http_error_and_open_stream(self) -> None:
        scenario = self.make_scenario(
            scenario_id="S5A",
            requests=[
                {"id": "error", "content": "error"},
                {"id": "hang", "content": "hang"},
            ],
            cases=[{"id": "cancel", "request_ids": ["error", "hang"]}],
        )

        async def handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            prompt: str,
        ) -> None:
            if prompt == "error":
                body = b'{"error":"fixture refusal"}'
                writer.write(
                    b"HTTP/1.1 503 Error\r\n"
                    b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + body
                )
                await writer.drain()
                return
            await send_sse_headers(writer)
            writer.write(b": stream-open\n\n")
            await writer.drain()
            self.server.hang_open.set()
            await reader.read()

        self.server.chat_handler = handler
        task = asyncio.create_task(
            run_case(
                scenario,
                scenario.schedule.case_matrix[0],
                0,
                repo_root=self.repo_root,
                endpoint=self.server.chat_url,
                model="fixture-model",
                result_root=self.results,
                artifacts=self.artifact_inputs(scenario, run_id="cancel-run"),
            )
        )
        await asyncio.wait_for(self.server.hang_open.wait(), 0.3)
        await asyncio.sleep(0.02)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        result = self.results / "cancel-run"
        samples = read_requests(result)
        self.assertEqual(set(samples), {"error", "hang"})
        self.assertEqual(samples["error"]["error_class"], "http_error")
        self.assertEqual(samples["hang"]["error_class"], "cancelled")
        self.assertEqual(verify_result(result)["result_state"], "failed")

    async def test_periodic_metrics_sampling_is_bounded_and_marks_failed_scrape(self) -> None:
        self.server.metrics_payload = b"ds4_banks_live 3\n"
        async with ServerMetricsSampler(
            self.server.metrics_url,
            run_id="metrics-run",
            clock_domain="controller_monotonic",
            interval_seconds=0.001,
            max_samples=2,
        ) as sampler:
            records = await sampler.periodic(asyncio.Event())
        self.assertEqual(len(records), len(SERVER_METRICS) * 2)
        banks = [item for item in records if item["metric"] == "banks_live"]
        self.assertEqual([item["value"] for item in banks], [3, 3])

        self.server.metrics_status = 503
        async with ServerMetricsSampler(
            self.server.metrics_url,
            run_id="metrics-unavailable",
            clock_domain="controller_monotonic",
            max_samples=1,
        ) as sampler:
            unavailable = snapshot_telemetry(
                await sampler.snapshot(),
                run_id="metrics-unavailable",
                clock_domain="controller_monotonic",
            )
        self.assertTrue(all(item["status"] == "unavailable" for item in unavailable))


class RunnerIdentityAndMetricsTests(unittest.TestCase):
    def test_all_case_repetition_ids_are_enumerated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prompt_root = root / "benchmarks" / "prompts" / "artifacts"
            prompt_root.mkdir(parents=True)
            requests = []
            prompts = []
            for request_id in ("a", "b"):
                payload = request_id.encode("ascii")
                path = f"benchmarks/prompts/artifacts/{request_id}.txt"
                (root / path).write_bytes(payload)
                prompts.append(
                    {
                        "id": request_id,
                        "path": path,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "token_count": 1,
                        "license": "CC0-1.0",
                    }
                )
                requests.append(
                    {
                        "id": request_id,
                        "prompt_id": request_id,
                        "start_offset_ms": 0,
                        "trigger": None,
                        "output_budget": {"kind": "explicit", "tokens": 512},
                    }
                )
            value = {
                "version": 1,
                "id": "S5A",
                "description": "identity fixture",
                "vantage": "controller_lan",
                "server": {
                    "context_tokens": 262144,
                    "default_output_tokens": 393216,
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
                "prompts": prompts,
                "requests": requests,
                "schedule": {
                    "kind": "offsets",
                    "case_matrix": [
                        {"id": "one", "request_ids": ["a"]},
                        {"id": "two", "request_ids": ["a", "b"]},
                    ],
                },
                "sampling": {"temperature": 0.0, "top_p": 1.0, "seed": 0},
                "warmup_repetitions": 1,
                "measured_repetitions": 3,
                "deadlines": {
                    "connect_seconds": 1.0,
                    "read_seconds": 1.0,
                    "overall_seconds": 4.0,
                    "server_seconds": 3.0,
                },
                "preconditions": {
                    "server_restart_each_repetition": True,
                    "cache_state": "cold",
                    "warmup_server_is_separate": True,
                    "cooldown_seconds": 0.0,
                    "prompt_reuse": "allow",
                },
            }
            path = root / "scenario.json"
            path.write_text(json.dumps(value))
            scenario = load_scenario(path, root)

        self.assertEqual(
            [(item.case_id, item.repetition) for item in case_repetitions(scenario)],
            [
                ("one", 0),
                ("one", 1),
                ("one", 2),
                ("two", 0),
                ("two", 1),
                ("two", 2),
            ],
        )

    def test_metric_deltas_and_absent_internal_signals_are_explicit(self) -> None:
        before = parse_server_metrics(
            """
# TYPE ds4_spec_drafts_total counter
ds4_spec_drafts_total 10
ds4_spec_hits_total 7
ds4_spec_quench_total 1
ds4_banks_live 2
ds4_tokens_prefilled_total{kind="computed"} 100
ds4_tokens_prefilled_total{kind="cached"} 50
ds4_tokens_decoded_total 20
ds4_graph_speculative_steps_total 999
""",
            timestamp_ns=10,
        )
        after = parse_server_metrics(
            """
ds4_spec_drafts_total 16
ds4_spec_hits_total 11
ds4_spec_quench_total 2
ds4_banks_live 3
ds4_tokens_prefilled_total{kind="computed"} 140
ds4_tokens_decoded_total 29
""",
            timestamp_ns=20,
        )
        delta = counter_deltas(before, after)
        records = {
            item["metric"]: item
            for item in delta_telemetry(
                delta,
                run_id="metrics-run",
                clock_domain="controller_monotonic",
            )
        }
        execution = observed_execution(delta)

        self.assertEqual(records["speculative_proposals_total"]["value"], 6)
        self.assertEqual(records["speculative_accepted_tokens_total"]["value"], 4)
        self.assertEqual(records["prefill_tokens_total"]["value"], 40)
        self.assertEqual(records["generated_tokens_total"]["value"], 9)
        self.assertEqual(records["banks_live"]["value"], 3)
        self.assertEqual(records["graph_speculative_steps_total"]["status"], "unavailable")
        self.assertEqual(records["plain_steps_total"]["status"], "unavailable")
        self.assertIsNone(execution["speculative_steps"])
        self.assertIsNone(execution["plain_steps"])
        self.assertIsNone(execution["verification_width_mean"])
        self.assertEqual(execution["proposals"], 6)

        reset = parse_server_metrics("ds4_spec_drafts_total 1\n", timestamp_ns=30)
        reset_delta = counter_deltas(after, reset)
        self.assertIsNone(reset_delta.values["speculative_proposals_total"])


if __name__ == "__main__":
    unittest.main()
