from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import httpx

from ds4bench.__main__ import main
from ds4bench.execution import ExecutionError, calibrate_prompts, run_case_from_files
from ds4bench.runtime_bundle import build_runtime_bundle
from ds4bench.stats import canonical_json_bytes


_ENDPOINT = "https://fixture.invalid:443/v1/chat/completions"
_MODEL = "fixture-model"


def _sse(*events: dict[str, object]) -> bytes:
    body = b"".join(
        b"data: " + json.dumps(event, separators=(",", ":")).encode("utf-8") + b"\n\n"
        for event in events
    )
    return body + b"data: [DONE]\n\n"


def _successful_sse(prompt_tokens: int) -> bytes:
    return _sse(
        {
            "choices": [{"delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 0},
        }
    )


class ExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addAsyncCleanup(self._cleanup)
        self.root = Path(self.temporary.name)
        self.artifact_root = self.root / "benchmarks" / "prompts" / "artifacts"
        self.artifact_root.mkdir(parents=True)
        self.output = self.root / "measured.json"

    async def _cleanup(self) -> None:
        self.temporary.cleanup()

    def _manifest(self) -> tuple[Path, dict[str, Path], dict[str, bytes]]:
        payloads = {
            "first": b"first deterministic prompt\n",
            "second": b"second deterministic prompt\n",
        }
        paths: dict[str, Path] = {}
        prompts: list[dict[str, object]] = []
        for prompt_id, payload in payloads.items():
            relative = f"benchmarks/prompts/artifacts/{prompt_id}.txt"
            path = self.root / relative
            path.write_bytes(payload)
            paths[prompt_id] = path
            prompts.append(
                {
                    "id": prompt_id,
                    "path": relative,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "token_count": None,
                    "license": "CC0-1.0",
                    "status": "unmeasured",
                }
            )
        manifest = self.root / "manifest.json"
        manifest.write_bytes(canonical_json_bytes({"version": 1, "prompts": prompts}))
        return manifest, paths, payloads

    async def test_calibration_success_is_canonical_deterministic_and_nonretrying(self) -> None:
        manifest, paths, payloads = self._manifest()
        observed: list[dict[str, object]] = []
        counts = {
            payloads["first"].decode(): 17,
            payloads["second"].decode(): 29,
        }

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            observed.append(body)
            prompt = body["messages"][0]["content"]
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=_successful_sse(counts[prompt]),
            )

        result = await calibrate_prompts(
            manifest,
            self.root,
            _ENDPOINT,
            _MODEL,
            self.output,
            transport=httpx.MockTransport(handler),
        )

        self.assertEqual(result, self.output)
        measured = json.loads(self.output.read_bytes())
        self.assertEqual(self.output.read_bytes(), canonical_json_bytes(measured))
        self.assertEqual(
            [(item["id"], item["status"], item["token_count"]) for item in measured["prompts"]],
            [("first", "measured", 17), ("second", "measured", 29)],
        )
        self.assertEqual(len(observed), 2)
        for request, payload in zip(observed, payloads.values(), strict=True):
            self.assertEqual(
                request,
                {
                    "model": _MODEL,
                    "messages": [{"role": "user", "content": payload.decode()}],
                    "temperature": 0.0,
                    "top_p": 1.0,
                    "seed": 0,
                    "stream": True,
                    "stream_options": {"include_usage": True},
                    "max_tokens": 1,
                },
            )
        self.assertEqual({key: path.read_bytes() for key, path in paths.items()}, payloads)

    async def test_calibration_rejects_missing_and_conflicting_usage(self) -> None:
        for kind in ("missing", "conflicting"):
            with self.subTest(kind=kind):
                manifest, _, _ = self._manifest()
                self.output.unlink(missing_ok=True)

                def handler(request: httpx.Request, *, response_kind: str = kind) -> httpx.Response:
                    del request
                    if response_kind == "missing":
                        content = _sse(
                            {
                                "choices": [{"delta": {}, "finish_reason": "stop"}],
                                "usage": {"completion_tokens": 0},
                            }
                        )
                    else:
                        content = _sse(
                            {
                                "choices": [],
                                "usage": {"prompt_tokens": 7, "completion_tokens": 0},
                            },
                            {
                                "choices": [{"delta": {}, "finish_reason": "stop"}],
                                "usage": {"prompt_tokens": 8, "completion_tokens": 0},
                            },
                        )
                    return httpx.Response(200, content=content)

                with self.assertRaises(ExecutionError) as raised:
                    await calibrate_prompts(
                        manifest,
                        self.root,
                        _ENDPOINT,
                        _MODEL,
                        self.output,
                        transport=httpx.MockTransport(handler),
                    )
                self.assertIn(
                    raised.exception.code,
                    {"calibration_usage_missing", "calibration_response_invalid"},
                )
                self.assertFalse(self.output.exists())

    async def test_partial_failure_preserves_existing_output_without_staging_residue(self) -> None:
        manifest, _, _ = self._manifest()
        sentinel = b"previous complete output\n"
        self.output.write_bytes(sentinel)
        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            del request
            request_count += 1
            if request_count == 1:
                return httpx.Response(200, content=_successful_sse(11))
            return httpx.Response(503, content=b"bounded failure")

        with self.assertRaises(ExecutionError):
            await calibrate_prompts(
                manifest,
                self.root,
                _ENDPOINT,
                _MODEL,
                self.output,
                transport=httpx.MockTransport(handler),
            )
        self.assertEqual(request_count, 2)
        self.assertEqual(self.output.read_bytes(), sentinel)
        self.assertEqual(
            [entry.name for entry in self.root.iterdir() if entry.name.startswith(".measured.json.tmp-")],
            [],
        )

    async def test_initial_and_inflight_prompt_tamper_never_promote_output(self) -> None:
        manifest, paths, _ = self._manifest()
        paths["first"].write_bytes(b"tampered before calibration\n")
        calls = 0

        def should_not_run(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            del request
            calls += 1
            return httpx.Response(200, content=_successful_sse(3))

        with self.assertRaisesRegex(ExecutionError, "calibration_manifest_invalid"):
            await calibrate_prompts(
                manifest,
                self.root,
                _ENDPOINT,
                _MODEL,
                self.output,
                transport=httpx.MockTransport(should_not_run),
            )
        self.assertEqual(calls, 0)
        self.assertFalse(self.output.exists())

        manifest, paths, _ = self._manifest()
        calls = 0

        def tamper_during_requests(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            del request
            calls += 1
            if calls == 1:
                paths["second"].write_bytes(b"tampered during calibration\n")
            return httpx.Response(200, content=_successful_sse(5 + calls))

        with self.assertRaisesRegex(ExecutionError, "calibration_input_changed"):
            await calibrate_prompts(
                manifest,
                self.root,
                _ENDPOINT,
                _MODEL,
                self.output,
                transport=httpx.MockTransport(tamper_during_requests),
            )
        self.assertEqual(calls, 2)
        self.assertFalse(self.output.exists())

    def _valid_s5a(self) -> Path:
        payload = b"scenario prompt\n"
        prompt = self.artifact_root / "scenario.txt"
        prompt.write_bytes(payload)
        value = {
            "version": 1,
            "id": "S5A",
            "description": "execution fixture",
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
            "prompts": [
                {
                    "id": "scenario-prompt",
                    "path": "benchmarks/prompts/artifacts/scenario.txt",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "token_count": 100,
                    "license": "CC0-1.0",
                }
            ],
            "requests": [
                {
                    "id": "deep-1",
                    "prompt_id": "scenario-prompt",
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
        scenario = self.root / "scenario.json"
        scenario.write_bytes(canonical_json_bytes(value))
        return scenario

    async def test_run_case_validates_scenario_case_and_metadata_before_network_or_output(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            del request
            calls += 1
            return httpx.Response(500)

        scenario = self.root / "invalid-scenario.json"
        scenario.write_bytes(canonical_json_bytes({}))
        result_root = self.root / "results"
        with self.assertRaisesRegex(ExecutionError, "scenario_invalid"):
            await run_case_from_files(
                scenario,
                self.root,
                _ENDPOINT,
                _MODEL,
                result_root,
                self.root / "missing-metadata.json",
                self.root / "missing-source.json",
                "deep",
                0,
                transport=httpx.MockTransport(handler),
            )
        self.assertEqual(calls, 0)
        self.assertFalse(result_root.exists())

        scenario = self._valid_s5a()
        with self.assertRaisesRegex(ExecutionError, "unknown_case"):
            await run_case_from_files(
                scenario,
                self.root,
                _ENDPOINT,
                _MODEL,
                result_root,
                self.root / "missing-metadata.json",
                self.root / "missing-source.json",
                "absent",
                0,
                transport=httpx.MockTransport(handler),
            )

        metadata = self.root / "metadata.json"
        source = self.root / "source.json"
        metadata.write_bytes(canonical_json_bytes({"bad": True}))
        source.write_bytes(canonical_json_bytes({}))
        with self.assertRaisesRegex(ExecutionError, "metadata_invalid"):
            await run_case_from_files(
                scenario,
                self.root,
                _ENDPOINT,
                _MODEL,
                result_root,
                metadata,
                source,
                "deep",
                0,
                transport=httpx.MockTransport(handler),
            )
        self.assertEqual(calls, 0)
        self.assertFalse(result_root.exists())

    def test_cli_errors_and_success_do_not_echo_private_inputs(self) -> None:
        private_path = str(self.root / "operator-private-value")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(
                [
                    "run-case",
                    "--scenario",
                    private_path,
                    "--repo-root",
                    str(self.root),
                    "--endpoint",
                    "http://private-endpoint.invalid:8000/v1/chat/completions",
                    "--model",
                    "private-model-id",
                    "--result-root",
                    str(self.root / "result"),
                    "--metadata",
                    private_path,
                    "--source-manifest",
                    private_path,
                    "--case",
                    "deep",
                    "--repetition",
                    "0",
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), "")
        error = json.loads(stderr.getvalue())
        self.assertEqual(error["status"], "error")
        self.assertNotIn(private_path, stderr.getvalue())
        self.assertNotIn("private-endpoint", stderr.getvalue())
        self.assertNotIn("private-model", stderr.getvalue())

        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch("ds4bench.__main__.verify_result_from_path", return_value={}), redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(["verify-result", private_path])
        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {"command": "verify-result", "status": "ok"},
        )
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(private_path, stdout.getvalue())


class ZipappExecutionSmokeTests(unittest.TestCase):
    def test_real_builder_replaces_stale_cached_project_before_system_help(self) -> None:
        system_python = Path("/usr/bin/python3")
        if not system_python.is_file():
            self.skipTest("system interpreter unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            source_package = Path(__file__).parents[1] / "src" / "ds4bench"
            shutil.copytree(source_package, project / "src" / "ds4bench")
            (project / "pyproject.toml").write_text(
                "[project]\n"
                "name='ds4bench'\n"
                "version='0.1.0'\n"
                "requires-python='>=3.12'\n",
                encoding="utf-8",
            )
            lock = project / "uv.lock"
            lock.write_text(
                'version = 1\nrevision = 3\nrequires-python = ">=3.12"\n\n'
                "[[package]]\n"
                'name = "ds4bench"\n'
                'version = "0.1.0"\n'
                'source = { editable = "." }\n'
                'dependencies = [{ name = "httpx" }]\n\n'
                "[[package]]\n"
                'name = "httpx"\n'
                'version = "0.0.0"\n'
                'source = { registry = "https://pypi.org/simple" }\n'
                "wheels = [\n"
                '  { url = "https://files.pythonhosted.org/httpx-0.0.0-py3-none-any.whl", hash = "sha256:'
                + "a" * 64
                + '" },\n]\n',
                encoding="utf-8",
            )

            cached_site = root / "cached-site"
            cached_site.mkdir()
            _write_distribution(
                cached_site,
                "ds4bench",
                "0.1.0",
                {"ds4bench/__init__.py": b'__version__ = "0.1.0"\n'},
            )
            _write_distribution(
                cached_site,
                "httpx",
                "0.0.0",
                {"httpx/__init__.py": b""},
            )

            def stale_uv(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                environment = kwargs["env"]
                self.assertIsInstance(environment, dict)
                venv = Path(environment["UV_PROJECT_ENVIRONMENT"])
                installed = venv / "lib" / "python3.12" / "site-packages"
                installed.parent.mkdir(parents=True)
                shutil.copytree(cached_site, installed)
                return subprocess.CompletedProcess(argv, 0)

            with patch("ds4bench.runtime_bundle.subprocess.run", side_effect=stale_uv):
                runtime = build_runtime_bundle(
                    project,
                    root / "runtime",
                    uv_executable="/controller/uv",
                    python_executable=system_python,
                )
            completed = subprocess.run(
                [str(system_python), "-I", str(runtime.bundle_path), "--help"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            help_text = completed.stdout.decode("utf-8")
            self.assertIn("run-case", help_text)
            self.assertIn("calibrate-prompts", help_text)
            self.assertIn("verify-result", help_text)


def _record_hash(payload: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
    return "sha256=" + encoded.decode("ascii")


def _write_distribution(
    site: Path,
    name: str,
    version: str,
    package_files: dict[str, bytes],
) -> None:
    normalized = name.replace("-", "_")
    dist_info = f"{normalized}-{version}.dist-info"
    files = dict(package_files)
    files.update(
        {
            f"{dist_info}/METADATA": (
                "Metadata-Version: 2.4\n"
                f"Name: {name}\n"
                f"Version: {version}\n"
                "License-Expression: MIT\n"
                "License-File: licenses/LICENSE.txt\n\n"
            ).encode(),
            f"{dist_info}/WHEEL": (
                "Wheel-Version: 1.0\n"
                "Generator: execution-fixture\n"
                "Root-Is-Purelib: true\n"
                "Tag: py3-none-any\n\n"
            ).encode(),
            f"{dist_info}/licenses/LICENSE.txt": b"fixture license\n",
        }
    )
    for relative, payload in files.items():
        destination = site / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for relative in sorted(files):
        payload = files[relative]
        writer.writerow((relative, _record_hash(payload), str(len(payload))))
    record_relative = f"{dist_info}/RECORD"
    writer.writerow((record_relative, "", ""))
    (site / record_relative).write_text(record.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
