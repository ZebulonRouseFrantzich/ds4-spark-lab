from __future__ import annotations

import asyncio
import json
import unittest
from collections.abc import Awaitable, Callable

import httpx

from ds4bench.client import (
    OpenAIChatClient,
    RequestCancelled,
    run_request,
    settle_request,
)
from ds4bench.schema import Deadlines, OutputBudget, Sampling, ScenarioRequest
from ds4bench.stats import RAW_REQUEST_FIELDS, validate_request_sample


class OneChunkAsyncStream(httpx.AsyncByteStream):
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.closed = False

    async def __aiter__(self):
        yield self.content

    async def aclose(self) -> None:
        self.closed = True




Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter, dict[str, object]], Awaitable[None]]


class LocalByteStreamServer:
    def __init__(self) -> None:
        self.handler: Handler | None = None
        self.requests: list[dict[str, object]] = []
        self.connection_closed = asyncio.Event()
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task[object]] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)

    @property
    def endpoint(self) -> str:
        assert self._server is not None
        socket = self._server.sockets[0]
        port = socket.getsockname()[1]
        return f"http://127.0.0.1:{port}/v1/chat/completions"

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for writer in tuple(self._writers):
            writer.close()
        for writer in tuple(self._writers):
            try:
                await writer.wait_closed()
            except (ConnectionError, RuntimeError):
                pass
        remaining = [task for task in self._tasks if not task.done()]
        if remaining:
            await asyncio.gather(*remaining, return_exceptions=True)

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        self._writers.add(writer)
        try:
            header_bytes = await reader.readuntil(b"\r\n\r\n")
            content_length = 0
            for line in header_bytes.split(b"\r\n")[1:]:
                name, separator, value = line.partition(b":")
                if separator and name.lower() == b"content-length":
                    content_length = int(value.strip())
            body = await reader.readexactly(content_length)
            parsed = json.loads(body)
            assert isinstance(parsed, dict)
            self.requests.append(parsed)
            if self.handler is None:
                raise AssertionError("missing handler")
            await self.handler(reader, writer, parsed)
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


async def send_headers(
    writer: asyncio.StreamWriter,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> None:
    reason = "OK" if status == 200 else "Error"
    values = {
        "Content-Type": "text/event-stream",
        "Connection": "close",
        **(headers or {}),
    }
    wire = f"HTTP/1.1 {status} {reason}\r\n" + "".join(
        f"{name}: {value}\r\n" for name, value in values.items()
    ) + "\r\n"
    writer.write(wire.encode("ascii"))
    await writer.drain()


async def send_success(writer: asyncio.StreamWriter, content: str = "ok") -> None:
    await send_headers(writer)
    payloads = (
        {"choices": [{"delta": {"content": content}, "finish_reason": None}]},
        {
            "choices": [{"delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 1},
        },
    )
    for payload in payloads:
        writer.write(f"data: {json.dumps(payload)}\n\n".encode("utf-8"))
        await writer.drain()
    writer.write(b"data: [DONE]\n\n")
    await writer.drain()


def make_request(
    request_id: str = "request-1", *, kind: str = "explicit", tokens: int | None = 8
) -> ScenarioRequest:
    return ScenarioRequest(
        id=request_id,
        prompt_id="prompt-1",
        start_offset_ms=7,
        trigger=None,
        output_budget=OutputBudget(kind=kind, tokens=tokens),
    )


def deadlines(
    *, connect: float = 0.25, read: float = 0.25, overall: float = 1.0
) -> Deadlines:
    return Deadlines(
        connect_seconds=connect,
        read_seconds=read,
        overall_seconds=overall,
        server_seconds=2.0,
    )


SAMPLING = Sampling(temperature=0.0, top_p=1.0, seed=0)


class OpenAIChatClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = LocalByteStreamServer()
        await self.server.start()

    async def asyncTearDown(self) -> None:
        await self.server.close()

    async def call(
        self,
        client: OpenAIChatClient,
        request: ScenarioRequest | None = None,
        *,
        prompt: str = "fixture",
    ):
        try:
            sample = await run_request(
                client,
                request or make_request(),
                scenario_run_id="run-1",
                repetition=2,
                prompt=prompt,
                model="fixture-model",
                sampling=SAMPLING,
                clock_domain="controller-monotonic",
            )
        except RequestCancelled as exc:
            validate_request_sample(exc.sample.to_dict())
            raise
        validate_request_sample(sample.to_dict())
        return sample

    async def test_split_stream_records_byte_delta_finish_usage_and_all_fields(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_headers(writer)
            writer.write(b": response-open\r\n\r\n")
            await writer.drain()
            await asyncio.sleep(0.02)
            events = [
                {"choices": [{"delta": {"content": "caf\u00e9"}}]},
                {"choices": [{"delta": {"reasoning_content": "consider"}}]},
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {"function": {"arguments": "{\"path\":"}}
                                ]
                            }
                        }
                    ]
                },
                {
                    "choices": [{"delta": {}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 19, "completion_tokens": 3},
                },
            ]
            first = f"data: {json.dumps(events[0], ensure_ascii=False)}\r\n\r\n".encode(
                "utf-8"
            )
            encoded_character = "\u00e9".encode("utf-8")
            split = first.index(encoded_character) + 1
            writer.write(first[:split])
            await writer.drain()
            await asyncio.sleep(0.005)
            writer.write(first[split:])
            await writer.drain()
            for event in events[1:]:
                writer.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
                await writer.drain()
            writer.write(b"data: [DONE]\n\n")
            await writer.drain()

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint,
            concurrency=2,
            deadlines=deadlines(),
        ) as client:
            sample = await self.call(client)

        self.assertIsNone(sample.error_class)
        self.assertEqual(sample.status_code, 200)
        self.assertEqual(sample.finish_class, "stop")
        self.assertEqual(sample.prompt_tokens, 19)
        self.assertEqual(sample.generated_tokens, 3)
        self.assertEqual(len(sample.token_event_timestamps_ns), 3)
        self.assertEqual(len(sample.itl_ns), 2)
        self.assertEqual(
            sample.itl_ns,
            tuple(
                later - earlier
                for earlier, later in zip(
                    sample.token_event_timestamps_ns,
                    sample.token_event_timestamps_ns[1:],
                )
            ),
        )
        self.assertEqual(sample.first_model_token_ns, sample.token_event_timestamps_ns[0])
        self.assertLess(sample.send_ns, sample.http_accept_ns)
        self.assertLess(sample.http_accept_ns, sample.first_byte_ns)
        self.assertLess(sample.first_byte_ns, sample.first_model_token_ns)
        self.assertLessEqual(sample.first_model_token_ns, sample.completion_ns)
        self.assertEqual(sample.scheduled_offset_ns, 7_000_000)
        self.assertEqual(sample.output_budget_kind, "explicit")
        self.assertEqual(sample.output_budget_value, 8)
        self.assertEqual(sample.retry_count, 0)
        self.assertEqual(sample.timing_granularity, "body_chunk")
        self.assertEqual(set(sample.to_dict()), RAW_REQUEST_FIELDS)
        request_body = self.server.requests[0]
        self.assertEqual(request_body["max_tokens"], 8)
        self.assertEqual(request_body["stream_options"], {"include_usage": True})

    async def test_omitted_output_budget_is_truly_absent(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_success(writer)

        self.server.handler = handler
        request = make_request(kind="omitted", tokens=None)
        async with OpenAIChatClient(
            self.server.endpoint, concurrency=1, deadlines=deadlines()
        ) as client:
            sample = await self.call(client, request)
        self.assertIsNone(sample.error_class)
        self.assertNotIn("max_tokens", self.server.requests[0])
        self.assertIsNone(sample.output_budget_value)

    async def test_non_2xx_body_is_preserved_bounded_and_redacted(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_headers(writer, status=429, headers={"Retry-After": "3"})
            writer.write(
                json.dumps(
                    {
                        "error": "capacity refused",
                        "token": "private-value",
                        "detail": "http://192.168.1.8/private",
                        "padding": "x" * 1024,
                    }
                ).encode("utf-8")
            )
            await writer.drain()

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint,
            concurrency=1,
            deadlines=deadlines(),
            max_error_body_bytes=256,
        ) as client:
            sample = await self.call(client)

        self.assertEqual(sample.error_class, "http_error")
        self.assertEqual(sample.finish_class, "error")
        self.assertEqual(sample.status_code, 429)
        self.assertEqual(sample.retry_after, "3")
        self.assertEqual(sample.retry_count, 0)
        self.assertIn("capacity refused", sample.redacted_error_body)
        self.assertIn("[REDACTED]", sample.redacted_error_body)
        self.assertNotIn("private-value", sample.redacted_error_body)
        self.assertNotIn("192.168", sample.redacted_error_body)
        self.assertNotIn("http://", sample.redacted_error_body)
        self.assertTrue(sample.redacted_error_body.endswith("[TRUNCATED]"))
        self.assertLessEqual(len(sample.redacted_error_body.encode("utf-8")), 256)

    async def test_malformed_sse_is_a_safe_fixed_error(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_headers(writer)
            writer.write(b"data: \xff\n\n")
            await writer.drain()

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint, concurrency=1, deadlines=deadlines()
        ) as client:
            sample = await self.call(client)
        self.assertEqual(sample.error_class, "invalid_utf8")
        self.assertIsNone(sample.redacted_error_body)

    async def test_malformed_event_json_is_rejected(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_headers(writer)
            writer.write(b"data: {not-json}\n\n")
            await writer.drain()

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint, concurrency=1, deadlines=deadlines()
        ) as client:
            sample = await self.call(client)
        self.assertEqual(sample.error_class, "malformed_sse")
        self.assertEqual(sample.finish_class, "error")

    async def test_idle_read_timeout_is_distinct_from_overall_timeout(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_headers(writer)
            writer.write(b": first-byte\n\n")
            await writer.drain()
            await asyncio.sleep(0.2)

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint,
            concurrency=1,
            deadlines=deadlines(read=0.03, overall=0.3),
        ) as client:
            sample = await self.call(client)
        self.assertEqual(sample.error_class, "read_timeout")
        self.assertIsNotNone(sample.first_byte_ns)

    async def test_overall_timeout_fires_while_bytes_keep_arriving(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_headers(writer)
            try:
                for _ in range(20):
                    writer.write(b": heartbeat\n\n")
                    await writer.drain()
                    await asyncio.sleep(0.015)
            except ConnectionError:
                pass

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint,
            concurrency=1,
            deadlines=deadlines(read=0.05, overall=0.06),
        ) as client:
            sample = await self.call(client)
        self.assertEqual(sample.error_class, "overall_timeout")

    async def test_slow_request_does_not_serialize_an_unrelated_request(self) -> None:
        slow_started = asyncio.Event()

        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            body: dict[str, object],
        ) -> None:
            messages = body["messages"]
            assert isinstance(messages, list)
            marker = messages[0]["content"]
            if marker == "slow":
                await send_headers(writer)
                slow_started.set()
                await asyncio.sleep(0.15)
                writer.write(
                    b'data: {"choices":[{"delta":{"content":"slow"}}]}\n\n'
                    b'data: {"choices":[{"delta":{},"finish_reason":"stop"}],'
                    b'"usage":{"prompt_tokens":1,"completion_tokens":1}}\n\n'
                    b"data: [DONE]\n\n"
                )
                await writer.drain()
            else:
                await send_success(writer, "fast")

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint,
            concurrency=2,
            deadlines=deadlines(read=0.4, overall=0.8),
        ) as client:
            slow = asyncio.create_task(self.call(client, make_request("slow"), prompt="slow"))
            await asyncio.wait_for(slow_started.wait(), 0.2)
            fast = asyncio.create_task(self.call(client, make_request("fast"), prompt="fast"))
            fast_sample = await asyncio.wait_for(fast, 0.2)
            slow_sample = await asyncio.wait_for(slow, 0.4)

        self.assertIsNone(fast_sample.error_class)
        self.assertIsNone(slow_sample.error_class)
        self.assertLess(fast_sample.completion_ns, slow_sample.completion_ns)

    async def test_cancellation_propagates_after_closing_and_can_be_settled(self) -> None:
        stream_open = asyncio.Event()
        async def handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            body: dict[str, object],
        ) -> None:
            messages = body["messages"]
            assert isinstance(messages, list)
            if messages[0]["content"] == "fast":
                await send_success(writer)
                return
            await send_headers(writer)
            writer.write(b": open\n\n")
            await writer.drain()
            stream_open.set()
            if await reader.read() == b"":
                self.server.connection_closed.set()

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint,
            concurrency=1,
            deadlines=deadlines(read=0.8, overall=1.0),
        ) as client:
            task = asyncio.create_task(self.call(client, prompt="hang"))
            await asyncio.wait_for(stream_open.wait(), 0.2)
            task.cancel()
            with self.assertRaises(RequestCancelled) as raised:
                await task
            self.assertEqual(raised.exception.sample.error_class, "cancelled")
            self.assertEqual(str(raised.exception), "request_cancelled")
            validate_request_sample(raised.exception.sample.to_dict())
            await asyncio.wait_for(self.server.connection_closed.wait(), 0.2)

            fast = await asyncio.wait_for(
                self.call(client, make_request("fast"), prompt="fast"), 0.2
            )
            self.assertIsNone(fast.error_class)

            stream_open = asyncio.Event()
            self.server.connection_closed = asyncio.Event()
            settled_task = asyncio.create_task(
                settle_request(
                    client,
                    make_request("settled"),
                    scenario_run_id="run-1",
                    repetition=2,
                    prompt="hang-again",
                    model="fixture-model",
                    sampling=SAMPLING,
                    clock_domain="controller-monotonic",
                )
            )
            await asyncio.wait_for(stream_open.wait(), 0.2)
            settled_task.cancel()
            settled = await asyncio.wait_for(settled_task, 0.2)
            self.assertEqual(settled.error_class, "cancelled")
            self.assertEqual(settled.finish_class, "cancelled")
            validate_request_sample(settled.to_dict())
            await asyncio.wait_for(self.server.connection_closed.wait(), 0.2)

    async def test_exception_mapping_is_url_safe_and_never_retries(self) -> None:
        endpoint = "http://private.example.invalid:8123/v1/chat/completions"
        attempts = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            raise httpx.ConnectError(
                f"connection to {request.url} failed", request=request
            )

        async with OpenAIChatClient(
            endpoint,
            concurrency=1,
            deadlines=deadlines(),
            transport=httpx.MockTransport(handler),
        ) as client:
            sample = await self.call(client)

        serialized = json.dumps(sample.to_dict())
        self.assertEqual(attempts, 1)
        self.assertEqual(sample.error_class, "connection_error")
        self.assertIsNone(sample.redacted_error_body)
        self.assertNotIn(endpoint, serialized)
        self.assertNotIn("private.example.invalid", serialized)

    async def test_done_cannot_hide_incomplete_utf8_in_same_body_chunk(self) -> None:
        event = {
            "choices": [{"delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }
        wire = (
            f"data: {json.dumps(event)}\n\ndata: [DONE]\n\n".encode("utf-8")
            + b"\xc3"
        )
        stream = OneChunkAsyncStream(wire)

        async def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=stream,
            )

        async with OpenAIChatClient(
            "http://fixture.invalid/v1/chat/completions",
            concurrency=1,
            deadlines=deadlines(),
            transport=httpx.MockTransport(handler),
        ) as client:
            sample = await self.call(client)

        self.assertTrue(stream.closed)
        self.assertEqual(sample.finish_class, "error")
        self.assertEqual(sample.error_class, "invalid_utf8")

    async def test_tool_call_name_delta_is_a_model_token_event(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_headers(writer)
            events = (
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "id": "call-1",
                                        "type": "function",
                                        "function": {
                                            "name": "lookup",
                                            "arguments": "",
                                        },
                                    }
                                ]
                            }
                        }
                    ]
                },
                {
                    "choices": [
                        {"delta": {}, "finish_reason": "tool_calls"}
                    ],
                    "usage": {"prompt_tokens": 2, "completion_tokens": 1},
                },
            )
            for event in events:
                writer.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
            writer.write(b"data: [DONE]\n\n")
            await writer.drain()

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint, concurrency=1, deadlines=deadlines()
        ) as client:
            sample = await self.call(client)

        self.assertEqual(sample.finish_class, "tool_calls")
        self.assertEqual(len(sample.token_event_timestamps_ns), 1)

    async def test_conflicting_usage_events_are_malformed(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_headers(writer)
            events = (
                {
                    "choices": [],
                    "usage": {"prompt_tokens": 2, "completion_tokens": 1},
                },
                {
                    "choices": [
                        {"delta": {}, "finish_reason": "stop"}
                    ],
                    "usage": {"prompt_tokens": 2, "completion_tokens": 2},
                },
            )
            for event in events:
                writer.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
            writer.write(b"data: [DONE]\n\n")
            await writer.drain()

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint, concurrency=1, deadlines=deadlines()
        ) as client:
            sample = await self.call(client)

        self.assertEqual(sample.finish_class, "error")
        self.assertEqual(sample.error_class, "malformed_sse")

    async def test_run_identity_matches_stats_slug_before_network(self) -> None:
        async with OpenAIChatClient(
            self.server.endpoint, concurrency=1, deadlines=deadlines()
        ) as client:
            with self.assertRaisesRegex(ValueError, "scenario_run_id"):
                await run_request(
                    client,
                    make_request(),
                    scenario_run_id="run/private",
                    repetition=0,
                    prompt="fixture",
                    model="fixture-model",
                    sampling=SAMPLING,
                    clock_domain="controller-monotonic",
                )

        self.assertEqual(self.server.requests, [])

    async def test_done_marker_is_required_even_after_finish_and_usage(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_headers(writer)
            event = {
                "choices": [{"delta": {"content": "partial"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 4, "completion_tokens": 1},
            }
            writer.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
            await writer.drain()

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint, concurrency=1, deadlines=deadlines()
        ) as client:
            sample = await self.call(client)
        self.assertIsNone(sample.error_class)
        self.assertEqual(sample.finish_class, "incomplete")
        self.assertEqual(sample.generated_tokens, 1)
        self.assertEqual(len(sample.token_event_timestamps_ns), 1)

    async def test_first_model_token_callback_runs_once_and_is_failure_isolated(self) -> None:
        async def handler(
            _reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            _body: dict[str, object],
        ) -> None:
            await send_headers(writer)
            for content in ("first", "second"):
                event = {"choices": [{"delta": {"content": content}}]}
                writer.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
                await writer.drain()
                await asyncio.sleep(0)
            terminal = {
                "choices": [{"delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2},
            }
            writer.write(
                f"data: {json.dumps(terminal)}\n\ndata: [DONE]\n\n".encode("utf-8")
            )
            await writer.drain()

        observed: list[int] = []

        def callback(timestamp_ns: int) -> None:
            observed.append(timestamp_ns)
            raise RuntimeError("observer failures are not request failures")

        self.server.handler = handler
        async with OpenAIChatClient(
            self.server.endpoint, concurrency=2, deadlines=deadlines()
        ) as client:
            sample = await run_request(
                client,
                make_request(),
                scenario_run_id="run-1",
                repetition=2,
                prompt="fixture",
                model="fixture-model",
                sampling=SAMPLING,
                clock_domain="controller-monotonic",
                on_first_model_token=callback,
            )
            await asyncio.sleep(0)

        self.assertEqual(observed, [sample.first_model_token_ns])
        self.assertEqual(sample.finish_class, "stop")
        self.assertIsNone(sample.error_class)



if __name__ == "__main__":
    unittest.main()
