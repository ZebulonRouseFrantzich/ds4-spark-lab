"""Process and SSH transport boundary for targetctl.

The module has no target-specific shell interpolation.  Remote commands are a fixed
argv, rendered once with :func:`shlex.join`; request data travels exclusively on
standard input to the controller-owned helper.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import selectors
import signal
import shlex
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Collection, Mapping, Sequence

from .common import PROTOCOL_VERSION, TargetError

MAX_HELPER_INPUT_BYTES = 1024 * 1024
MAX_HELPER_OUTPUT_BYTES = 1024 * 1024
MAX_HELPER_ERROR_CODE_LENGTH = 64
MAX_RSYNC_FILTER_BYTES = 16 * 1024 * 1024
MAX_EXTENSION_ERROR_CODES = 16
_BASE_HELPER_ERROR_CODES = frozenset({
    "entry_changed",
    "internal_error",
    "invalid_entries",
    "invalid_entry",
    "invalid_path",
    "invalid_payload",
    "invalid_report",
    "invalid_request",
    "lock_busy",
    "lock_failed",
    "lock_release_failed",
    "lock_token_mismatch",
    "marker_exists",
    "marker_mismatch",
    "missing_path",
    "path_overlap",
    "protocol_mismatch",
    "report_too_large",
    "request_too_large",
    "root_create_failed",
    "symlink_path",
    "unmarked_populated_root",
    "unknown_action",
    "unsafe_entry",
    "unsafe_lock",
    "unsafe_path",
    "unsafe_root",
    "unsafe_state",
    "unsupported_entry",
})
_SAFE_ENV_KEYS = frozenset({"LANG", "LC_ALL", "PATH", "TMPDIR", "XDG_RUNTIME_DIR", "TARGETCTL_HELPER_DIGEST", "TARGETCTL_HELPER_DEFERRED"})
_BASE_ENV = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
SSH_OPTIONS = (
    "BatchMode=yes",
    "ForwardAgent=no",
    "IdentityAgent=none",
    "ForwardX11=no",
    "ForwardX11Trusted=no",
    "RequestTTY=no",
    "PermitLocalCommand=no",
    "RemoteCommand=none",
    "ClearAllForwardings=yes",
    "ControlMaster=no",
    "ControlPath=none",
    "ControlPersist=no",
)

# This is deliberately an argv fragment, not a user-configurable transport
# setting.  Source synchronization needs rsync's receiver-side deletion, but
# must not inherit an operator's SSH forwarding or multiplexing defaults.
RSYNC_OPTIONS = (
    "--archive",
    "--no-owner",
    "--no-group",
    "--no-links",
    "--no-devices",
    "--no-specials",
    "--one-file-system",
    "--delete",
    "--delete-excluded",
    "--human-readable",
)


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    timed_out: bool
    duration_ns: int
    stdout: bytes
    stderr: bytes


Runner = Callable[[Sequence[str], bytes | None, float | None, str, Mapping[str, str], int], CommandResult]


def _error(code: str, message: str = "target command failed") -> TargetError:
    return TargetError(code, message)


def _is_safe_helper_error_code(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_HELPER_ERROR_CODE_LENGTH
        and value.isascii()
        and all(character.islower() or character.isdigit() or character == "_" for character in value)
    )


def _allowed_helper_error_codes(allowed_error_codes: Collection[str] | None) -> frozenset[str]:
    """Return bounded controller-owned error codes for this helper invocation."""
    if allowed_error_codes is None:
        return _BASE_HELPER_ERROR_CODES
    if (
        isinstance(allowed_error_codes, (str, bytes, bytearray))
        or not isinstance(allowed_error_codes, Collection)
        or len(allowed_error_codes) > MAX_EXTENSION_ERROR_CODES
        or not all(_is_safe_helper_error_code(code) for code in allowed_error_codes)
    ):
        raise _error("invalid_request", "invalid helper request")
    return _BASE_HELPER_ERROR_CODES | frozenset(allowed_error_codes)


def _validate_env(overrides: Mapping[str, str] | None = None, *, helper_digest: str | None = None, deferred: bool = False) -> dict[str, str]:
    env = dict(_BASE_ENV)
    if overrides is not None:
        if not isinstance(overrides, Mapping):
            raise _error("invalid_environment", "invalid command environment")
        for key, value in overrides.items():
            if key not in _SAFE_ENV_KEYS or not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value or "\n" in value or "\r" in value:
                raise _error("invalid_environment", "invalid command environment")
            env[key] = value
    if helper_digest is not None:
        env["TARGETCTL_HELPER_DIGEST"] = helper_digest
    if deferred:
        env["TARGETCTL_HELPER_DEFERRED"] = "1"
    return env


def _bounded_process(argv: Sequence[str], input_bytes: bytes | None, timeout: float | None, cwd: str, env: Mapping[str, str], max_output_bytes: int) -> CommandResult:
    if not argv or any(not isinstance(argument, str) or "\x00" in argument for argument in argv):
        raise _error("invalid_command", "invalid command")
    if input_bytes is not None and len(input_bytes) > MAX_HELPER_INPUT_BYTES:
        raise _error("request_too_large", "helper request is too large")

    # Account for process creation and every pipe operation.  In particular,
    # writing a request before draining output can deadlock when a helper fills
    # stdout before it starts consuming stdin.
    start = time.monotonic_ns()
    deadline = None if timeout is None else time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=dict(env),
            shell=False,
            start_new_session=True,
        )
    except OSError:
        raise _error("command_start_failed", "target command could not start") from None

    completed = False
    try:
        def terminate_process_tree() -> None:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    return
                except ProcessLookupError:
                    return
                except OSError:
                    pass
            try:
                process.kill()
            except OSError:
                pass

        with selectors.DefaultSelector() as selector:
            assert process.stdout is not None and process.stderr is not None
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, "stdout" if stream is process.stdout else "stderr")

            input_view: memoryview | None = None
            input_offset = 0
            if process.stdin is not None:
                os.set_blocking(process.stdin.fileno(), False)
                if input_bytes:
                    input_view = memoryview(input_bytes)
                    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    process.stdin.close()

            def unregister_and_close(stream: Any) -> None:
                try:
                    selector.unregister(stream)
                except (KeyError, OSError, ValueError):
                    pass
                try:
                    stream.close()
                except OSError:
                    pass

            streams = {"stdout": bytearray(), "stderr": bytearray()}
            timed_out = False
            overflow = False
            while selector.get_map() or process.poll() is None:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    timed_out = True
                    break
                if not selector.get_map():
                    try:
                        process.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                    continue
                for key, events in selector.select(remaining):
                    stream = key.fileobj
                    if events & selectors.EVENT_READ:
                        output = streams[key.data]
                        try:
                            chunk = os.read(stream.fileno(), min(65536, max_output_bytes - len(output) + 1))
                        except BlockingIOError:
                            continue
                        except OSError:
                            unregister_and_close(stream)
                            continue
                        if not chunk:
                            unregister_and_close(stream)
                            continue
                        if len(output) + len(chunk) > max_output_bytes:
                            overflow = True
                            break
                        output.extend(chunk)
                    elif events & selectors.EVENT_WRITE:
                        assert input_view is not None
                        try:
                            written = os.write(stream.fileno(), input_view[input_offset:input_offset + 65536])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            unregister_and_close(stream)
                            continue
                        except OSError:
                            unregister_and_close(stream)
                            continue
                        if written:
                            input_offset += written
                        if written == 0 or input_offset == len(input_view):
                            unregister_and_close(stream)
                if overflow:
                    break

            if timed_out or overflow:
                terminate_process_tree()
                process.wait()
                completed = True
                return CommandResult(-1, timed_out, time.monotonic_ns() - start, b"", b"")

        process.wait()
        completed = True
        return CommandResult(process.returncode, False, time.monotonic_ns() - start, bytes(streams["stdout"]), bytes(streams["stderr"]))
    finally:
        if not completed:
            terminate_process_tree()
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass


def _strict_json(data: bytes) -> Any:
    def duplicate_free(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=duplicate_free)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _error("invalid_helper_response", "helper returned an invalid response") from None


def helper_source(extension_source: str | bytes | None = None) -> bytes:
    """Return complete isolated-helper source, with optional controller-owned actions."""
    try:
        base = Path(__file__).with_name("remote.py").read_bytes()
    except OSError:
        raise _error("helper_unavailable", "helper source is unavailable") from None
    if extension_source is None:
        extension = b""
    elif isinstance(extension_source, str):
        extension = extension_source.encode("utf-8")
    elif isinstance(extension_source, bytes):
        extension = extension_source
    else:
        raise _error("invalid_extension", "invalid helper extension")
    if b"\x00" in extension or len(base) + len(extension) > MAX_HELPER_INPUT_BYTES:
        raise _error("invalid_extension", "invalid helper extension")
    # remote.py defers main while this source is installed, allowing an extension
    # to call register_action before the controller appends its encoded request.
    return base + b"\n" + extension + b"\n"


def _helper_digest(source: bytes) -> str:
    """Return the versioned identity of controller-owned helper code."""
    return hashlib.sha256(b"targetctl-helper-source-v1\x00" + source).hexdigest()


class _HelperTransport:
    def _execute(self, argv: Sequence[str], input_bytes: bytes, *, timeout: float | None, cwd: str, env: Mapping[str, str]) -> CommandResult:
        raise NotImplementedError

    def run_helper(
        self,
        action: str,
        payload: Mapping[str, Any],
        *,
        extension_source: str | bytes | None = None,
        allowed_error_codes: Collection[str] | None = None,
        timeout: float | None = 30.0,
    ) -> Any:
        if not isinstance(action, str) or not action or not isinstance(payload, Mapping):
            raise _error("invalid_request", "invalid helper request")
        allowed_codes = _allowed_helper_error_codes(allowed_error_codes)
        request = {"protocol_version": PROTOCOL_VERSION, "action": action, "payload": dict(payload)}
        try:
            request_bytes = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        except (TypeError, ValueError):
            raise _error("invalid_request", "invalid helper request") from None
        source = helper_source(extension_source)
        program = source + b"run(base64.b64decode(" + repr(base64.b64encode(request_bytes)).encode("ascii") + b"))\n"
        digest = _helper_digest(source)
        result = self._execute_helper(program, digest, timeout)
        if result.timed_out:
            raise _error("helper_timeout", "target helper timed out")
        if result.exit_code != 0 or len(result.stdout) > MAX_HELPER_OUTPUT_BYTES or len(result.stderr) > MAX_HELPER_OUTPUT_BYTES:
            raise _error("helper_execution_failed", "target helper failed")
        response = _strict_json(result.stdout)
        if not isinstance(response, dict) or set(response) not in ({"protocol_version", "helper_sha256", "ok", "result"}, {"protocol_version", "helper_sha256", "ok", "error"}):
            raise _error("invalid_helper_response", "helper returned an invalid response")
        if response.get("protocol_version") != PROTOCOL_VERSION or not isinstance(response.get("helper_sha256"), str) or not hmac.compare_digest(response["helper_sha256"], digest):
            raise _error("helper_integrity_failed", "helper protocol verification failed")
        if response.get("ok") is True:
            return response["result"]
        error = response.get("error")
        if (
            response.get("ok") is not False
            or not isinstance(error, dict)
            or set(error) != {"code", "message"}
            or not isinstance(error["code"], str)
            or not isinstance(error["message"], str)
            or error["code"] not in allowed_codes
        ):
            raise _error("invalid_helper_response", "helper returned an invalid response")
        raise _error(error["code"], "target helper rejected the request")

    def _execute_helper(self, program: bytes, digest: str, timeout: float | None) -> CommandResult:
        raise NotImplementedError


class LocalTransport(_HelperTransport):
    """Local process boundary used by local target operations."""
    def __init__(self, *, runner: Runner | None = None, max_output_bytes: int = MAX_HELPER_OUTPUT_BYTES) -> None:
        self._runner = runner
        self._max_output_bytes = max_output_bytes

    def _execute(self, argv: Sequence[str], input_bytes: bytes, *, timeout: float | None, cwd: str, env: Mapping[str, str]) -> CommandResult:
        if self._runner is not None:
            return self._runner(argv, input_bytes, timeout, cwd, env, self._max_output_bytes)
        return _bounded_process(argv, input_bytes, timeout, cwd, env, self._max_output_bytes)

    def run(self, argv: Sequence[str], *, input_bytes: bytes | None = None, timeout: float | None = None, cwd: str = "/", env: Mapping[str, str] | None = None) -> CommandResult:
        return self._execute(argv, input_bytes or b"", timeout=timeout, cwd=cwd, env=_validate_env(env))

    def _execute_helper(self, program: bytes, digest: str, timeout: float | None) -> CommandResult:
        return self._execute((sys.executable, "-I", "-S", "-"), program, timeout=timeout, cwd="/", env=_validate_env(helper_digest=digest, deferred=True))


def _validated_ssh_config(value: str | Path) -> Path:
    """Return a current-user SSH config after descriptor-based metadata checks."""
    try:
        path = Path(value)
        if not path.is_absolute():
            raise OSError
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise OSError
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except (OSError, RuntimeError, TypeError, ValueError):
        raise _error("ssh_config_invalid", "SSH configuration is unavailable") from None
    try:
        opened = os.fstat(fd)
    except OSError:
        raise _error("ssh_config_invalid", "SSH configuration is unavailable") from None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if (
        (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise _error("ssh_config_invalid", "SSH configuration is unavailable")
    return path


class SSHForward:
    """Operation-owned loopback bridge backed by one ``ssh -W`` per client.

    OpenSSH's configured forward directives stay disabled by
    ``ClearAllForwardings=yes``.  The controller listener is a normal loopback
    socket and each accepted connection is carried over SSH's fixed stdio
    forwarding mode, so private configuration can still provide host routing
    and identity without activating any configured listener.
    """

    _BACKLOG = 8
    _MAX_WORKERS = 8
    _BUFFER_BYTES = 64 * 1024
    _POLL_SECONDS = 0.1

    def __init__(self, transport: "SSHTransport", *, target_port: int, timeout: float = 30.0) -> None:
        if (
            not isinstance(transport, SSHTransport)
            or not isinstance(target_port, int)
            or isinstance(target_port, bool)
            or not 1 <= target_port <= 65535
            or not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < timeout <= 600
        ):
            raise _error("invalid_forward_request", "SSH forward request is invalid")
        self._transport = transport
        self._target_port = target_port
        self._timeout = float(timeout)
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._workers: set[threading.Thread] = set()
        self._processes: set[subprocess.Popen[bytes]] = set()
        self._clients: set[socket.socket] = set()
        self.local_port = 0

    def _argv(self) -> tuple[str, ...]:
        config_args = () if self._transport._ssh_config is None else ("-F", os.fspath(self._transport._ssh_config))
        connect_timeout = max(1, int(self._timeout))
        return (
            self._transport._ssh_binary,
            *config_args,
            *(part for option in (*SSH_OPTIONS, f"ConnectTimeout={connect_timeout}", "ConnectionAttempts=1") for part in ("-o", option)),
            "-W",
            f"127.0.0.1:{self._target_port}",
            "--",
            self._transport.ssh_host,
        )

    @property
    def argv(self) -> tuple[str, ...]:
        """The fixed forwarding-free SSH argv, primarily for deterministic tests."""
        return self._argv()

    @staticmethod
    def _selector_events(selector: selectors.BaseSelector, fileobj: Any, events: int, data: str) -> None:
        try:
            selector.get_key(fileobj)
        except KeyError:
            if events:
                selector.register(fileobj, events, data)
        else:
            if events:
                selector.modify(fileobj, events, data)
            else:
                selector.unregister(fileobj)

    def _stop_process(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
                process.wait(timeout=min(2.0, self._timeout))
            except (OSError, subprocess.TimeoutExpired):
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except OSError:
                    pass
        try:
            process.wait(timeout=min(2.0, self._timeout))
        except (OSError, subprocess.TimeoutExpired):
            pass
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def _pump(self, client: socket.socket, process: subprocess.Popen[bytes]) -> None:
        if process.stdin is None or process.stdout is None:
            return
        selector = selectors.DefaultSelector()
        to_ssh = bytearray()
        to_client = bytearray()
        client_readable = True
        ssh_readable = True
        stdin_open = True
        deadline = time.monotonic() + self._timeout
        client.setblocking(False)
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        try:
            while not self._stop.is_set():
                if not client_readable and not to_ssh and stdin_open:
                    self._selector_events(selector, process.stdin, 0, "ssh-write")
                    try:
                        process.stdin.close()
                    except OSError:
                        pass
                    stdin_open = False
                if not ssh_readable and not to_client:
                    try:
                        client.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                if not client_readable and not to_ssh and not ssh_readable and not to_client:
                    break
                now = time.monotonic()
                if now >= deadline:
                    break
                client_events = 0
                if client_readable and len(to_ssh) < self._BUFFER_BYTES:
                    client_events |= selectors.EVENT_READ
                if to_client:
                    client_events |= selectors.EVENT_WRITE
                self._selector_events(selector, client, client_events, "client")
                self._selector_events(
                    selector,
                    process.stdout,
                    selectors.EVENT_READ if ssh_readable and len(to_client) < self._BUFFER_BYTES else 0,
                    "ssh-read",
                )
                if stdin_open:
                    self._selector_events(
                        selector,
                        process.stdin,
                        selectors.EVENT_WRITE if to_ssh else 0,
                        "ssh-write",
                    )
                try:
                    events = selector.select(min(self._POLL_SECONDS, deadline - now))
                except OSError:
                    break
                for key, mask in events:
                    if key.data == "client":
                        if mask & selectors.EVENT_READ:
                            try:
                                chunk = client.recv(min(16384, self._BUFFER_BYTES - len(to_ssh)))
                            except BlockingIOError:
                                chunk = None
                            except OSError:
                                chunk = b""
                            if chunk:
                                to_ssh.extend(chunk)
                                deadline = time.monotonic() + self._timeout
                            elif chunk == b"":
                                client_readable = False
                        if mask & selectors.EVENT_WRITE and to_client:
                            try:
                                sent = client.send(to_client)
                            except BlockingIOError:
                                sent = 0
                            except OSError:
                                return
                            if sent:
                                del to_client[:sent]
                                deadline = time.monotonic() + self._timeout
                    elif key.data == "ssh-read":
                        try:
                            chunk = os.read(process.stdout.fileno(), min(16384, self._BUFFER_BYTES - len(to_client)))
                        except BlockingIOError:
                            chunk = None
                        except OSError:
                            chunk = b""
                        if chunk:
                            to_client.extend(chunk)
                            deadline = time.monotonic() + self._timeout
                        elif chunk == b"":
                            ssh_readable = False
                    elif key.data == "ssh-write" and to_ssh:
                        try:
                            sent = os.write(process.stdin.fileno(), to_ssh)
                        except BlockingIOError:
                            sent = 0
                        except (BrokenPipeError, OSError):
                            sent = 0
                            to_ssh.clear()
                            self._selector_events(selector, process.stdin, 0, "ssh-write")
                            try:
                                process.stdin.close()
                            except OSError:
                                pass
                            stdin_open = False
                        if sent:
                            del to_ssh[:sent]
                            deadline = time.monotonic() + self._timeout
        finally:
            selector.close()

    def _bridge_connection(self, client: socket.socket) -> None:
        process: subprocess.Popen[bytes] | None = None
        try:
            if self._stop.is_set():
                return
            try:
                process = subprocess.Popen(
                    self._argv(),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    cwd="/",
                    env=_validate_env(),
                    shell=False,
                    start_new_session=True,
                    bufsize=0,
                )
            except OSError:
                return
            with self._lock:
                self._processes.add(process)
            if self._stop.is_set():
                return
            try:
                self._pump(client, process)
            except (OSError, ValueError):
                pass
        finally:
            if process is not None:
                self._stop_process(process)
            try:
                client.close()
            except OSError:
                pass
            current = threading.current_thread()
            with self._lock:
                self._clients.discard(client)
                if process is not None:
                    self._processes.discard(process)
                self._workers.discard(current)

    def _accept_connections(self) -> None:
        while not self._stop.is_set():
            listener = self._listener
            if listener is None:
                return
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            client.settimeout(self._timeout)
            with self._lock:
                if self._stop.is_set() or len(self._workers) >= self._MAX_WORKERS:
                    client.close()
                    continue
                worker = threading.Thread(target=self._bridge_connection, args=(client,), name="targetctl-ssh-bridge", daemon=True)
                self._clients.add(client)
                self._workers.add(worker)
            try:
                worker.start()
            except RuntimeError:
                with self._lock:
                    self._clients.discard(client)
                    self._workers.discard(worker)
                client.close()

    def __enter__(self) -> "SSHForward":
        if self._listener is not None:
            raise _error("forward_start_failed", "SSH forward could not start")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            listener.bind(("127.0.0.1", 0))
            listener.listen(self._BACKLOG)
            listener.settimeout(self._POLL_SECONDS)
            self.local_port = int(listener.getsockname()[1])
            self._listener = listener
            self._stop.clear()
            thread = threading.Thread(target=self._accept_connections, name="targetctl-ssh-accept", daemon=True)
            self._accept_thread = thread
            thread.start()
            return self
        except BaseException:
            try:
                listener.close()
            except OSError:
                pass
            self._listener = None
            self.local_port = 0
            raise

    def close(self) -> None:
        self._stop.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        with self._lock:
            clients = tuple(self._clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
        accept_thread = self._accept_thread
        self._accept_thread = None
        if accept_thread is not None and accept_thread is not threading.current_thread():
            accept_thread.join(timeout=2.0)
        with self._lock:
            workers = tuple(self._workers)
        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=min(5.0, self._timeout))
        with self._lock:
            remaining = tuple(self._processes)
        for process in remaining:
            self._stop_process(process)
        self.local_port = 0

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


class SSHTransport(_HelperTransport):
    """SSH transport with forwarding, agent, X11, tty, and control sharing disabled."""
    def __init__(
        self,
        ssh_host: str,
        *,
        runner: Runner | None = None,
        ssh_binary: str = "ssh",
        ssh_config: str | Path | None = None,
        max_output_bytes: int = MAX_HELPER_OUTPUT_BYTES,
    ) -> None:
        if not _valid_ssh_alias(ssh_host):
            raise _error("invalid_ssh_host", "invalid SSH host alias")
        self.ssh_host = ssh_host
        self._runner = runner
        self._ssh_binary = ssh_binary
        self._ssh_config = _validated_ssh_config(ssh_config) if ssh_config is not None else None
        self._max_output_bytes = max_output_bytes

    def _execute(self, argv: Sequence[str], input_bytes: bytes, *, timeout: float | None, cwd: str, env: Mapping[str, str]) -> CommandResult:
        if self._runner is not None:
            return self._runner(argv, input_bytes, timeout, cwd, env, self._max_output_bytes)
        return _bounded_process(argv, input_bytes, timeout, cwd, env, self._max_output_bytes)

    def _execute_helper(self, program: bytes, digest: str, timeout: float | None) -> CommandResult:
        remote_env = _validate_env(helper_digest=digest, deferred=True)
        remote_argv = ("/usr/bin/env", "-i", *(f"{key}={value}" for key, value in remote_env.items()), "/usr/bin/python3", "-I", "-S", "-")
        # OpenSSH concatenates every operand after the host into one remote-shell
        # command.  Send exactly one quoted operand so `-c` receives the complete
        # fixed wrapper, including the cwd invariant, as its script.
        inner_command = f"cd -- / && exec {shlex.join(remote_argv)}"
        remote_command = shlex.join(("/bin/sh", "-c", inner_command))
        config_args = () if self._ssh_config is None else ("-F", os.fspath(self._ssh_config))
        argv = (
            self._ssh_binary,
            *config_args,
            *(part for option in SSH_OPTIONS for part in ("-o", option)),
            "--",
            self.ssh_host,
            remote_command,
        )
        return self._execute(argv, program, timeout=timeout, cwd="/", env=_validate_env())

    def guarded_rsync(
        self,
        source_root: Path,
        remote_workdir: str,
        *,
        receiver: str,
        filters: Collection[str] = (),
        filter_file: Path | None = None,
        timeout: float | None = 300.0,
    ) -> None:
        """Mirror a staged inventory through a descriptor-validating receiver."""

        try:
            source = Path(source_root).resolve(strict=True)
        except (OSError, RuntimeError):
            raise _error("source_root_invalid", "source root is unavailable") from None
        if not source.is_dir() or not _valid_rsync_root(remote_workdir) or not _valid_rsync_root(receiver):
            raise _error("invalid_rsync_request", "source synchronization request is invalid")
        if not isinstance(filters, Collection) or len(filters) > 128:
            raise _error("invalid_rsync_request", "source synchronization request is invalid")
        checked_filters: list[str] = []
        for item in filters:
            if not isinstance(item, str) or not item.isascii() or not item or "\x00" in item or "\n" in item:
                raise _error("invalid_rsync_request", "source synchronization request is invalid")
            checked_filters.append(item)
        merge_filter: tuple[str, ...] = ()
        if filter_file is not None:
            try:
                item = Path(filter_file)
                details = os.stat(item, follow_symlinks=False)
                if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_RSYNC_FILTER_BYTES:
                    raise OSError
                with open(item, "rb") as handle:
                    content = handle.read(MAX_RSYNC_FILTER_BYTES + 1)
                if len(content) != details.st_size or not content.isascii() or b"\x00" in content:
                    raise OSError
                merge_filter = (f"--filter=merge {item}",)
            except (OSError, RuntimeError):
                raise _error("invalid_rsync_request", "source synchronization request is invalid") from None
        config_args = () if self._ssh_config is None else ("-F", os.fspath(self._ssh_config))
        ssh_command = shlex.join((self._ssh_binary, *config_args, *(part for option in SSH_OPTIONS for part in ("-o", option))))
        argv = (
            "/usr/bin/rsync",
            *RSYNC_OPTIONS,
            f"--rsync-path={receiver}",
            "--filter=H /.targetctl-owner-v1-work.json",
            "--filter=P /.targetctl-owner-v1-work.json",
            *(f"--filter={item}" for item in checked_filters),
            *merge_filter,
            "-e",
            ssh_command,
            f"{source}/",
            f"{self.ssh_host}:{remote_workdir}/",
        )
        result = self._execute(argv, b"", timeout=timeout, cwd="/", env=_validate_env())
        if result.timed_out:
            raise _error("rsync_timeout", "source synchronization timed out")
        if result.exit_code != 0:
            raise _error("rsync_failed", "source synchronization failed")


def _valid_rsync_root(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 4096 or not value.startswith("/") or value.endswith("/"):
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    parts = value.split("/")[1:]
    return bool(parts) and all(
        part not in {"", ".", ".."} and all(character.isalnum() or character in "._+-@%=" for character in part)
        for part in parts
    )


def _valid_ssh_alias(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 253 or not value[0].isalnum():
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return all(character.isalnum() or character in "._-" for character in value)


def select_transport(config: Any, *, repo_root: Path | None = None, runner: Runner | None = None) -> LocalTransport | SSHTransport:
    """Select the concrete transport from a validated TargetConfig-like object."""
    mode = getattr(config, "mode", None)
    if mode == "local":
        return LocalTransport(runner=runner)
    if mode == "ssh":
        return SSHTransport(
            getattr(config, "ssh_host", None),
            runner=runner,
            ssh_config=Path.home() / ".ssh" / "config",
        )
    raise _error("invalid_target_mode", "invalid target mode")


transport_for = select_transport
