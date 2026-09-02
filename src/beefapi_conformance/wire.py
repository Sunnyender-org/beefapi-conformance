"""Wire-level capture: a recording reverse proxy and SSE stream health.

Real clients always stream. A cell only counts as conformant when every
completion request observed on the wire terminated with the protocol's
terminal event, not merely when the client printed the expected text.
"""

from __future__ import annotations

import http.server
import json
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

CLEAN_TERMINALS = {"message_stop", "response.completed"}
ERROR_TERMINALS = {"error", "response.failed", "response.incomplete"}
COMPLETION_PATHS = ("/messages", "/responses", "/chat/completions")
HOP_HEADERS = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authorization",
    "te",
    "transfer-encoding",
    "upgrade",
}
MAX_RECORDED_EVENTS = 2000


def parse_sse(raw: str) -> list[tuple[str, str]]:
    """Split an SSE body into (event_name, data) pairs."""
    events: list[tuple[str, str]] = []
    name = ""
    data: list[str] = []
    for line in raw.splitlines() + [""]:
        if line.startswith("event:"):
            name = line[len("event:") :].strip()
        elif line.startswith("data:"):
            data.append(line[len("data:") :].strip())
        elif not line.strip() and (name or data):
            events.append((name, "\n".join(data)))
            name = ""
            data = []
    return events


def termination(event_names: list[str], saw_done: bool) -> str:
    """Classify how an SSE stream ended: clean, error_event, or early."""
    if saw_done or any(name in CLEAN_TERMINALS for name in event_names):
        return "clean"
    if any(name in ERROR_TERMINALS for name in event_names):
        return "error_event"
    return "early"


def sse_text(protocol: str | None, events: list[tuple[str, str]]) -> str:
    """Assemble assistant text from streamed deltas for one protocol."""
    parts: list[str] = []
    for name, data in events:
        if data == "[DONE]":
            continue
        try:
            payload = json.loads(data) if data else {}
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if protocol == "messages" and name == "content_block_delta":
            delta = payload.get("delta", {})
            if isinstance(delta, dict) and isinstance(delta.get("text"), str):
                parts.append(delta["text"])
        elif protocol == "chat":
            for choice in payload.get("choices", []) or []:
                delta = choice.get("delta", {}) if isinstance(choice, dict) else {}
                if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                    parts.append(delta["content"])
        elif protocol == "responses" and name == "response.output_text.delta":
            if isinstance(payload.get("delta"), str):
                parts.append(payload["delta"])
    return "".join(parts)


def _tool_names(tools: object) -> list[str]:
    names: list[str] = []
    for tool in tools if isinstance(tools, list) else []:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function")
        name = (
            tool.get("name")
            or (function.get("name") if isinstance(function, dict) else None)
            or tool.get("type")
        )
        if isinstance(name, str):
            names.append(name)
    return names


_BASE64_MIN = 256


def compact_media(value: object) -> object:
    """Replace long base64-looking strings with a size placeholder so captured
    fixtures stay reviewable and never embed screenshots or documents."""
    if isinstance(value, dict):
        return {key: compact_media(item) for key, item in value.items()}
    if isinstance(value, list):
        return [compact_media(item) for item in value]
    if (
        isinstance(value, str)
        and len(value) >= _BASE64_MIN
        and re.fullmatch(r"[A-Za-z0-9+/=\s]+", value)
    ):
        return f"<base64 {len(value)} chars>"
    return value


def summarize_request(body: bytes) -> dict[str, object]:
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    turns = payload.get("messages", payload.get("input"))
    return {
        "model": payload.get("model"),
        "stream": bool(payload.get("stream")),
        "tool_names": _tool_names(payload.get("tools")),
        "message_count": len(turns) if isinstance(turns, list) else None,
        "has_system": bool(payload.get("system") or payload.get("instructions")),
    }


@dataclass
class Exchange:
    method: str
    path: str
    status: int | None
    request: dict[str, object]
    sse: bool
    event_names: list[str] = field(default_factory=list)
    saw_done: bool = False
    terminated: str = "not_stream"
    duration_ms: int = 0
    first_byte_ms: int | None = None
    max_gap_ms: int = 0
    response_bytes: int = 0
    error: str = ""
    request_body: object | None = None
    response_body: str | None = None

    @property
    def is_completion(self) -> bool:
        path = self.path.split("?", 1)[0]
        return any(path.endswith(suffix) for suffix in COMPLETION_PATHS)

    def summary(self) -> dict[str, object]:
        names = self.event_names
        return {
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "request": self.request,
            "sse": self.sse,
            "event_count": len(names),
            "events_head": names[:5],
            "events_tail": names[-3:] if len(names) > 5 else [],
            "terminated": self.terminated,
            "duration_ms": self.duration_ms,
            "first_byte_ms": self.first_byte_ms,
            "max_gap_ms": self.max_gap_ms,
            "response_bytes": self.response_bytes,
            "error": self.error,
        }


class _SseCapture:
    """Incrementally track SSE event names and the chat [DONE] sentinel."""

    def __init__(self) -> None:
        self.event_names: list[str] = []
        self.saw_done = False
        self._buffer = b""

    def feed(self, chunk: bytes) -> None:
        self._buffer += chunk
        while True:
            for separator in (b"\n\n", b"\r\n\r\n"):
                index = self._buffer.find(separator)
                if index >= 0:
                    block = self._buffer[:index]
                    self._buffer = self._buffer[index + len(separator) :]
                    self._block(block)
                    break
            else:
                return

    def _block(self, block: bytes) -> None:
        name = ""
        for line in block.splitlines():
            if line.startswith(b"event:"):
                name = line[len(b"event:") :].strip().decode("utf-8", "replace")
            elif line.startswith(b"data:") and b"[DONE]" in line:
                self.saw_done = True
        if name and len(self.event_names) < MAX_RECORDED_EVENTS:
            self.event_names.append(name)


class RecordingProxy:
    """Local reverse proxy that forwards to the real route and records wire
    behavior without altering payloads."""

    def __init__(
        self, upstream: str, timeout_seconds: int = 600, capture_bodies: bool = False
    ) -> None:
        self.upstream = upstream.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.capture_bodies = capture_bodies
        self._exchanges: list[Exchange] = []
        self._lock = threading.Lock()
        proxy = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: object) -> None:
                return

            def _proxy(self) -> None:
                proxy._handle(self)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _proxy

        class Server(http.server.ThreadingHTTPServer):
            def handle_error(self, request: object, client_address: object) -> None:
                # Clients may reset connections mid-request (observed with
                # codex exec); that is wire behavior, not a harness crash.
                return

        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=5)

    def exchanges(self) -> list[Exchange]:
        with self._lock:
            return list(self._exchanges)

    def _record(self, exchange: Exchange) -> None:
        with self._lock:
            self._exchanges.append(exchange)

    def _handle(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        started = time.monotonic()
        length = int(handler.headers.get("content-length", "0") or 0)
        body = handler.rfile.read(length) if length else b""
        exchange = Exchange(
            method=handler.command,
            path=handler.path,
            status=None,
            request=summarize_request(body),
            sse=False,
        )
        if self.capture_bodies and body:
            try:
                exchange.request_body = compact_media(json.loads(body))
            except (json.JSONDecodeError, UnicodeDecodeError):
                exchange.request_body = f"<non-json {len(body)} bytes>"
        headers = {
            key: value
            for key, value in handler.headers.items()
            if key.lower() not in HOP_HEADERS
        }
        headers["accept-encoding"] = "identity"
        request = urllib.request.Request(
            self.upstream + handler.path,
            data=body or None,
            headers=headers,
            method=handler.command,
        )
        try:
            response = urllib.request.urlopen(request, timeout=self.timeout_seconds)
        except urllib.error.HTTPError as exc:
            response = exc
        except (OSError, TimeoutError) as exc:
            exchange.terminated = "proxy_error"
            exchange.error = str(exc)
            exchange.duration_ms = int((time.monotonic() - started) * 1000)
            self._record(exchange)
            payload = json.dumps({"error": {"message": f"upstream: {exc}"}}).encode()
            handler.send_response(502)
            handler.send_header("content-type", "application/json")
            handler.send_header("content-length", str(len(payload)))
            handler.end_headers()
            handler.wfile.write(payload)
            return
        try:
            self._forward(handler, response, exchange, started)
        finally:
            response.close()
            exchange.duration_ms = int((time.monotonic() - started) * 1000)
            self._record(exchange)

    def _forward(
        self,
        handler: http.server.BaseHTTPRequestHandler,
        response: object,
        exchange: Exchange,
        started: float,
    ) -> None:
        status = int(getattr(response, "status", None) or getattr(response, "code", 0))
        exchange.status = status
        content_type = response.headers.get("content-type", "")
        exchange.sse = "text/event-stream" in content_type
        handler.send_response_only(status)
        for key, value in response.headers.items():
            if key.lower() not in HOP_HEADERS:
                handler.send_header(key, value)
        if not exchange.sse:
            data = response.read()
            exchange.response_bytes = len(data)
            if self.capture_bodies:
                exchange.response_body = data.decode("utf-8", "replace")[:65536]
            handler.send_header("content-length", str(len(data)))
            handler.end_headers()
            try:
                handler.wfile.write(data)
            except OSError as exc:
                exchange.error = f"client: {exc}"
            return
        handler.send_header("transfer-encoding", "chunked")
        handler.end_headers()
        capture = _SseCapture()
        raw: list[bytes] = []
        last_read = time.monotonic()
        try:
            while True:
                chunk = response.read1(8192)
                now = time.monotonic()
                if exchange.first_byte_ms is None and chunk:
                    exchange.first_byte_ms = int((now - started) * 1000)
                exchange.max_gap_ms = max(
                    exchange.max_gap_ms, int((now - last_read) * 1000)
                )
                last_read = now
                if not chunk:
                    break
                exchange.response_bytes += len(chunk)
                capture.feed(chunk)
                if self.capture_bodies and sum(map(len, raw)) < 262144:
                    raw.append(chunk)
                handler.wfile.write(f"{len(chunk):x}\r\n".encode())
                handler.wfile.write(chunk)
                handler.wfile.write(b"\r\n")
                handler.wfile.flush()
            handler.wfile.write(b"0\r\n\r\n")
        except OSError as exc:
            exchange.error = str(exc)
        exchange.event_names = capture.event_names
        exchange.saw_done = capture.saw_done
        exchange.terminated = termination(capture.event_names, capture.saw_done)
        if self.capture_bodies:
            exchange.response_body = b"".join(raw).decode("utf-8", "replace")


def _is_web_search_tool(name: str) -> bool:
    """Match web search tool names across clients: web_search, WebSearch,
    web_search_20250305, and similar variants."""
    return "websearch" in re.sub(r"[^a-z0-9]", "", name.lower())


def wire_summary(exchanges: list[Exchange]) -> dict[str, object]:
    return {
        "request_count": len(exchanges),
        "completion_request_count": sum(1 for item in exchanges if item.is_completion),
        "exchanges": [item.summary() for item in exchanges],
    }


def crosstalk(answers: dict[str, str]) -> list[str]:
    """Given nonce -> response text, report any response that leaked another
    request's nonce. This is the direct detector for stream interleaving."""
    problems = []
    for nonce, text in answers.items():
        leaked = sorted(other for other in answers if other != nonce and other in text)
        if leaked:
            problems.append(f"response for {nonce} also contained {', '.join(leaked)}")
    return problems


def latency_stats(durations_ms: list[int]) -> dict[str, int]:
    if not durations_ms:
        return {}
    ordered = sorted(durations_ms)

    def percentile(p: float) -> int:
        index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * p)))
        return ordered[index]

    return {
        "count": len(ordered),
        "min_ms": ordered[0],
        "p50_ms": percentile(0.5),
        "p95_ms": percentile(0.95),
        "max_ms": ordered[-1],
    }


def wire_verdict(
    exchanges: list[Exchange],
    expectations: tuple[str, ...] = (),
    concurrency: int = 1,
) -> dict[str, object]:
    """Grade captured traffic: streams must terminate cleanly and declared
    expectations (tool loop depth, web search declaration) must hold."""
    problems: list[str] = []
    completions = [item for item in exchanges if item.is_completion]
    for item in completions:
        label = f"{item.method} {item.path}"
        if item.status is not None and item.status >= 400:
            problems.append(f"{label} returned HTTP {item.status}")
        elif item.terminated == "early":
            problems.append(f"{label} stream ended without a terminal event")
        elif item.terminated == "error_event":
            problems.append(f"{label} stream terminated with an error event")
        elif item.terminated == "proxy_error":
            problems.append(f"{label} upstream connection failed: {item.error}")
    minimum = 2 * max(1, concurrency)
    if "multi_request" in expectations and len(completions) < minimum:
        problems.append(
            f"expected a native tool loop with >={minimum} completion requests, saw {len(completions)}"
        )
    if "web_search_requested" in expectations and not any(
        _is_web_search_tool(name)
        for item in completions
        for name in item.request.get("tool_names", [])
        if isinstance(name, str)
    ):
        problems.append("no completion request declared a web search tool")
    return {
        "status": "fail" if problems else "pass",
        "detail": "; ".join(problems),
    }
