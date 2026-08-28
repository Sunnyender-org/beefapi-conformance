#!/usr/bin/env python3
"""Certify an upstream model route through BeefAPI without exposing credentials."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


DEFAULT_TIMEOUT = 180
PASS = "pass"
FAIL = "fail"
SKIP = "skip"
UNSUPPORTED = "unsupported"


@dataclass
class CheckResult:
    name: str
    layer: str
    status: str
    required: bool
    duration_ms: int
    first_event_ms: int | None = None
    first_text_ms: int | None = None
    http_status: int | None = None
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compact_error(value: Any, limit: int = 600) -> str:
    text = str(value or "").replace("\n", " ").strip()
    text = re.sub(r"sk-[A-Za-z0-9_-]{8,}", "sk-***", text)
    text = re.sub(r"Bearer\s+[^\s\"']+", "Bearer ***", text, flags=re.I)
    return text[:limit]


class HTTPClient:
    def __init__(self, base_url: str, api_key: str, timeout: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def post(self, path: str, payload: dict[str, Any], anthropic: bool = False) -> tuple[int, Any, dict[str, int]]:
        started = time.monotonic()
        data = json.dumps(payload, separators=(",", ":")).encode()
        headers = {"content-type": "application/json", "authorization": f"Bearer {self.api_key}"}
        if anthropic:
            headers.update({"x-api-key": self.api_key, "anthropic-version": "2023-06-01"})
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method="POST")
        first_event_ms: int | None = None
        first_text_ms: int | None = None
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = response.status
                if payload.get("stream"):
                    events: list[dict[str, Any]] = []
                    for raw_line in response:
                        line = raw_line.decode("utf-8", "replace").strip()
                        if not line.startswith("data:"):
                            continue
                        data_text = line[5:].strip()
                        if not data_text or data_text == "[DONE]":
                            continue
                        if first_event_ms is None:
                            first_event_ms = int((time.monotonic() - started) * 1000)
                        try:
                            event = json.loads(data_text)
                        except json.JSONDecodeError:
                            event = {"raw": data_text[:300]}
                        events.append(event)
                        if first_text_ms is None and event_has_text(event):
                            first_text_ms = int((time.monotonic() - started) * 1000)
                    body: Any = events
                else:
                    raw = response.read()
                    first_event_ms = int((time.monotonic() - started) * 1000)
                    body = json.loads(raw or b"{}")
                    if event_has_text(body):
                        first_text_ms = first_event_ms
                timing = {
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "first_event_ms": first_event_ms or -1,
                    "first_text_ms": first_text_ms or -1,
                }
                return status, body, timing
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = {"error": raw}
            return exc.code, body, {
                "duration_ms": int((time.monotonic() - started) * 1000),
                "first_event_ms": -1,
                "first_text_ms": -1,
            }


def event_has_text(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(event_has_text(item) for item in value)
    if not isinstance(value, dict):
        return False
    event_type = value.get("type")
    if event_type in {"response.output_text.delta", "content_block_delta"}:
        delta = value.get("delta")
        if isinstance(delta, str):
            return bool(delta)
        if isinstance(delta, dict):
            return bool(delta.get("text"))
    for key in ("text", "output_text", "content", "output"):
        if key in value and event_has_text(value[key]):
            return True
    return False


def response_terminal(events: Any) -> str:
    if not isinstance(events, list):
        return "json"
    for event in reversed(events):
        if isinstance(event, dict) and event.get("type") in {"response.completed", "response.failed", "error"}:
            return str(event.get("type"))
    return "missing"


def response_output(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict) and isinstance(body.get("output"), list):
        return [item for item in body["output"] if isinstance(item, dict)]
    if isinstance(body, list):
        completed = next(
            (event for event in reversed(body) if isinstance(event, dict) and event.get("type") == "response.completed"),
            None,
        )
        response = completed.get("response") if completed else None
        if isinstance(response, dict) and isinstance(response.get("output"), list):
            return [item for item in response["output"] if isinstance(item, dict)]
        return [event.get("item") for event in body if isinstance(event, dict) and isinstance(event.get("item"), dict)]
    return []


def anthropic_content(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict) and isinstance(body.get("content"), list):
        return [item for item in body["content"] if isinstance(item, dict)]
    if isinstance(body, list):
        blocks: dict[int, dict[str, Any]] = {}
        for event in body:
            if not isinstance(event, dict):
                continue
            index = event.get("index")
            if event.get("type") == "content_block_start" and isinstance(index, int):
                block = event.get("content_block")
                if isinstance(block, dict):
                    blocks[index] = dict(block)
            if event.get("type") == "content_block_delta" and isinstance(index, int):
                delta = event.get("delta")
                if isinstance(delta, dict) and delta.get("type") == "input_json_delta":
                    blocks.setdefault(index, {}).setdefault("_partial_json", "")
                    blocks[index]["_partial_json"] += str(delta.get("partial_json", ""))
        for block in blocks.values():
            partial = block.pop("_partial_json", "")
            if partial:
                try:
                    block["input"] = json.loads(partial)
                except json.JSONDecodeError:
                    block["input"] = {"raw": partial}
        return [blocks[index] for index in sorted(blocks)]
    return []


class Certifier:
    def __init__(self, args: argparse.Namespace, api_key: str) -> None:
        self.args = args
        self.http = HTTPClient(args.base_url, api_key, args.timeout)
        self.api_key = api_key
        self.results: list[CheckResult] = [CheckResult(
            name="channel_route_pin",
            layer="configuration",
            status=PASS if args.pin_channel else (SKIP if args.channel_id == "unknown" else FAIL),
            required=args.channel_id != "unknown",
            duration_ms=0,
            detail="" if args.pin_channel or args.channel_id == "unknown" else "channel id is report-only without --pin-channel",
            evidence={"strategy": "admin_key_suffix" if args.pin_channel else "none"},
        )]

    def record_http(
        self,
        name: str,
        layer: str,
        required: bool,
        call: Callable[[], tuple[int, Any, dict[str, int]]],
        validator: Callable[[int, Any], tuple[str, str, dict[str, Any]]],
    ) -> tuple[int, Any] | None:
        try:
            status, body, timing = call()
            result_status, detail, evidence = validator(status, body)
            self.results.append(CheckResult(
                name=name,
                layer=layer,
                status=result_status,
                required=required,
                duration_ms=timing["duration_ms"],
                first_event_ms=None if timing["first_event_ms"] < 0 else timing["first_event_ms"],
                first_text_ms=None if timing["first_text_ms"] < 0 else timing["first_text_ms"],
                http_status=status,
                detail=compact_error(detail),
                evidence=evidence,
            ))
            return status, body
        except Exception as exc:  # noqa: BLE001 - certification must preserve every failure
            self.results.append(CheckResult(name, layer, FAIL, required, 0, detail=compact_error(exc)))
            return None

    def run_api(self) -> None:
        self._responses_text(False)
        self._responses_text(True)
        self._responses_tool_roundtrip(namespace=False)
        self._responses_tool_roundtrip(namespace=True)
        self._responses_image_generation_surface()
        if self.args.web_search:
            self._responses_web_search()
        self._messages_text(False)
        self._messages_text(True)
        self._messages_tool_roundtrip()
        self._messages_count_tokens()

    def _responses_text(self, stream: bool) -> None:
        payload = {"model": self.args.model, "input": "Reply exactly CERT_RESPONSES_OK", "stream": stream, "store": False}

        def validate(status: int, body: Any) -> tuple[str, str, dict[str, Any]]:
            terminal = response_terminal(body)
            ok = status == 200 and (not stream or terminal == "response.completed") and event_has_text(body)
            return (PASS if ok else FAIL, "" if ok else body, {"terminal": terminal})

        self.record_http(
            f"responses_{'stream' if stream else 'nonstream'}_text", "responses", True,
            lambda: self.http.post("/v1/responses", payload), validate,
        )

    def _responses_tool_roundtrip(self, namespace: bool) -> None:
        fn = {
            "type": "function",
            "name": "cert_marker",
            "description": "Return the supplied marker",
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {"marker": {"type": "string"}},
                "required": ["marker"],
                "additionalProperties": False,
            },
        }
        tool: dict[str, Any] = fn
        if namespace:
            tool = {"type": "namespace", "name": "cert", "description": "Certification tools", "tools": [fn]}
        first_payload = {
            "model": self.args.model,
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "Call cert_marker with marker ROUNDTRIP_233. Do not answer directly."}]}],
            "tools": [tool],
            "tool_choice": "required",
            "stream": False,
            "store": False,
        }
        label = "responses_namespace_roundtrip" if namespace else "responses_function_roundtrip"

        def run() -> tuple[int, Any, dict[str, int]]:
            status, first, timing = self.http.post("/v1/responses", first_payload)
            if status != 200:
                return status, first, timing
            calls = [item for item in response_output(first) if item.get("type") == "function_call"]
            if not calls:
                return 422, {"error": "model returned no function_call", "body": first}, timing
            call = calls[0]
            history: list[dict[str, Any]] = list(first_payload["input"])
            history.append(call)
            history.append({"type": "function_call_output", "call_id": call.get("call_id"), "output": "ROUNDTRIP_233_OK"})
            second_payload = {
                "model": self.args.model,
                "input": history,
                "tools": [tool],
                "tool_choice": "auto",
                "stream": False,
                "store": False,
            }
            status2, second, timing2 = self.http.post("/v1/responses", second_payload)
            timing2["duration_ms"] += timing["duration_ms"]
            return status2, {"first_call": call, "second": second}, timing2

        def validate(status: int, body: Any) -> tuple[str, str, dict[str, Any]]:
            call = body.get("first_call", {}) if isinstance(body, dict) else {}
            second = body.get("second", {}) if isinstance(body, dict) else body
            name_ok = call.get("name") == "cert_marker" and (not namespace or call.get("namespace") == "cert")
            ok = status == 200 and name_ok and event_has_text(second)
            return PASS if ok else FAIL, "" if ok else body, {"call_name": call.get("name"), "namespace": call.get("namespace")}

        self.record_http(label, "responses", True, run, validate)

    def _responses_image_generation_surface(self) -> None:
        payload = {
            "model": self.args.model,
            "input": "Reply exactly CERT_IMAGE_TOOL_SURFACE_OK without calling tools.",
            "tools": [{"type": "image_generation", "quality": "low"}],
            "tool_choice": "none",
            "stream": True,
            "store": False,
        }

        def validate(status: int, body: Any) -> tuple[str, str, dict[str, Any]]:
            ok = status == 200 and response_terminal(body) == "response.completed"
            detail = "" if ok else body
            return PASS if ok else UNSUPPORTED, detail, {"codex_tool_surface": "image_generation"}

        self.record_http("responses_codex_image_generation_surface", "responses", True,
                         lambda: self.http.post("/v1/responses", payload), validate)

    def _responses_web_search(self) -> None:
        payload = {
            "model": self.args.model,
            "input": "Use web search to find the current UTC date, then answer in one sentence.",
            "tools": [{"type": "web_search"}],
            "tool_choice": "required",
            "stream": True,
            "store": False,
        }

        def validate(status: int, body: Any) -> tuple[str, str, dict[str, Any]]:
            terminal = response_terminal(body)
            ok = status == 200 and terminal == "response.completed" and event_has_text(body)
            return PASS if ok else FAIL, "" if ok else body, {"terminal": terminal}

        self.record_http("responses_web_search", "responses", False,
                         lambda: self.http.post("/v1/responses", payload), validate)

    def _messages_text(self, stream: bool) -> None:
        payload = {
            "model": self.args.model,
            "max_tokens": 128,
            "messages": [{"role": "user", "content": "Reply exactly CERT_MESSAGES_OK"}],
            "stream": stream,
        }

        def validate(status: int, body: Any) -> tuple[str, str, dict[str, Any]]:
            event_types = [event.get("type") for event in body if isinstance(event, dict)] if isinstance(body, list) else []
            terminal_ok = not stream or "message_stop" in event_types
            ok = status == 200 and terminal_ok and event_has_text(body)
            return PASS if ok else FAIL, "" if ok else body, {"terminal": "message_stop" if terminal_ok and stream else "json"}

        self.record_http(
            f"messages_{'stream' if stream else 'nonstream'}_text", "messages", True,
            lambda: self.http.post("/v1/messages", payload, anthropic=True), validate,
        )

    def _messages_tool_roundtrip(self) -> None:
        tool = {
            "name": "cert_marker",
            "description": "Return the supplied marker",
            "input_schema": {
                "type": "object",
                "properties": {"marker": {"type": "string"}},
                "required": ["marker"],
            },
        }
        first_payload = {
            "model": self.args.model,
            "max_tokens": 256,
            "messages": [{"role": "user", "content": "Call cert_marker with marker ROUNDTRIP_233."}],
            "tools": [tool],
            "tool_choice": {"type": "tool", "name": "cert_marker"},
            "stream": False,
        }

        def run() -> tuple[int, Any, dict[str, int]]:
            status, first, timing = self.http.post("/v1/messages", first_payload, anthropic=True)
            if status != 200:
                return status, first, timing
            calls = [item for item in anthropic_content(first) if item.get("type") == "tool_use"]
            if not calls:
                return 422, {"error": "model returned no tool_use", "body": first}, timing
            call = calls[0]
            messages = list(first_payload["messages"])
            messages.append({"role": "assistant", "content": first.get("content", [])})
            messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": call.get("id"), "content": "ROUNDTRIP_233_OK"}]})
            second_payload = {"model": self.args.model, "max_tokens": 256, "messages": messages, "tools": [tool], "stream": False}
            status2, second, timing2 = self.http.post("/v1/messages", second_payload, anthropic=True)
            timing2["duration_ms"] += timing["duration_ms"]
            return status2, {"first_call": call, "second": second}, timing2

        def validate(status: int, body: Any) -> tuple[str, str, dict[str, Any]]:
            call = body.get("first_call", {}) if isinstance(body, dict) else {}
            second = body.get("second", {}) if isinstance(body, dict) else body
            ok = status == 200 and call.get("name") == "cert_marker" and event_has_text(second)
            return PASS if ok else FAIL, "" if ok else body, {"tool_name": call.get("name")}

        self.record_http("messages_tool_roundtrip", "messages", True, run, validate)

    def _messages_count_tokens(self) -> None:
        payload = {"model": self.args.model, "messages": [{"role": "user", "content": "count these tokens"}]}

        def validate(status: int, body: Any) -> tuple[str, str, dict[str, Any]]:
            count = body.get("input_tokens") if isinstance(body, dict) else None
            ok = status == 200 and isinstance(count, int) and count > 0
            return PASS if ok else FAIL, "" if ok else body, {"input_tokens": count}

        self.record_http("messages_count_tokens", "messages", True,
                         lambda: self.http.post("/v1/messages/count_tokens", payload, anthropic=True), validate)

    def run_clients(self) -> None:
        self._run_codex_client()
        self._run_claude_client()

    def _run_command(
        self,
        name: str,
        layer: str,
        command: list[str],
        env: dict[str, str],
        cwd: Path,
        required: bool = True,
        required_markers: tuple[str, ...] = (),
    ) -> tuple[subprocess.CompletedProcess[str] | None, int]:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                text=True,
                capture_output=True,
                timeout=self.args.client_timeout,
                check=False,
            )
            duration = int((time.monotonic() - started) * 1000)
            output = compact_error((completed.stdout + "\n" + completed.stderr).strip(), 1200)
            missing_markers = [marker for marker in required_markers if marker not in completed.stdout]
            ok = completed.returncode == 0 and not missing_markers
            failure_detail = output
            if completed.returncode == 0 and missing_markers:
                failure_detail = "missing output markers: " + ", ".join(missing_markers)
            self.results.append(CheckResult(
                name=name,
                layer=layer,
                status=PASS if ok else FAIL,
                required=required,
                duration_ms=duration,
                detail="" if ok else failure_detail,
                evidence={
                    "returncode": completed.returncode,
                    "required_markers": list(required_markers),
                    "output_tail": output[-500:] if ok else "",
                },
            ))
            return completed, duration
        except Exception as exc:  # noqa: BLE001
            duration = int((time.monotonic() - started) * 1000)
            self.results.append(CheckResult(name, layer, FAIL, required, duration, detail=compact_error(exc)))
            return None, duration

    def _run_codex_client(self) -> None:
        binary = shutil.which(self.args.codex_bin)
        if not binary:
            self.results.append(CheckResult("codex_cli_multiturn", "codex_client", SKIP, True, 0, detail="codex binary not found"))
            return
        with tempfile.TemporaryDirectory(prefix="beefapi-cert-codex-") as tmp:
            root = Path(tmp)
            codex_home = root / "codex-home"
            workspace = root / "workspace"
            codex_home.mkdir()
            workspace.mkdir()
            (workspace / "marker.txt").write_text("CERT_CODEX_FILE_OK\n", encoding="utf-8")
            (codex_home / "config.toml").write_text(
                "\n".join([
                    'model_provider = "beefapi_cert"',
                    f'model = {json.dumps(self.args.model)}',
                    'disable_response_storage = true',
                    '[model_providers.beefapi_cert]',
                    'name = "beefapi-cert"',
                    f'base_url = {json.dumps(self.args.base_url.rstrip("/") + "/v1")}',
                    'wire_api = "responses"',
                    'requires_openai_auth = true',
                    'supports_websockets = false',
                    "",
                ]),
                encoding="utf-8",
            )
            (codex_home / "auth.json").write_text(json.dumps({"OPENAI_API_KEY": self.api_key}), encoding="utf-8")
            env = codex_child_env(codex_home)
            command = [binary, "exec", "--json", "--sandbox", "read-only", "--ignore-rules", "--skip-git-repo-check", "-C", str(workspace),
                       "Read marker.txt using a shell command, then reply exactly CERT_CODEX_CLIENT_OK."]
            completed, _ = self._run_command(
                "codex_cli_turn_1", "codex_client", command, env, workspace,
                required_markers=("CERT_CODEX_CLIENT_OK", "command_execution", "CERT_CODEX_FILE_OK"),
            )
            if not completed or self.results[-1].status != PASS:
                for turn in range(2, self.args.client_turns + 1):
                    self.results.append(CheckResult(f"codex_cli_turn_{turn}", "codex_client", SKIP, True, 0, detail="turn 1 failed"))
                return
            thread_id = extract_codex_thread_id(completed.stdout)
            if not thread_id:
                self.results.append(CheckResult("codex_cli_resume_contract", "codex_client", FAIL, True, 0, detail="thread id missing from Codex JSONL"))
                return
            for turn in range(2, self.args.client_turns + 1):
                prompt = f"This is certification turn {turn}. Run pwd once, then reply exactly CERT_CODEX_TURN_{turn}_OK."
                resume = [binary, "exec", "resume", "--json", "--skip-git-repo-check", "--ignore-rules", thread_id, prompt]
                completed, _ = self._run_command(
                    f"codex_cli_turn_{turn}", "codex_client", resume, env, workspace,
                    required_markers=(f"CERT_CODEX_TURN_{turn}_OK", "command_execution"),
                )
                if not completed or self.results[-1].status != PASS:
                    for remaining in range(turn + 1, self.args.client_turns + 1):
                        self.results.append(CheckResult(f"codex_cli_turn_{remaining}", "codex_client", SKIP, True, 0, detail=f"turn {turn} failed"))
                    break

    def _run_claude_client(self) -> None:
        binary = shutil.which(self.args.claude_bin)
        if not binary:
            self.results.append(CheckResult("claude_code_multiturn", "claude_client", SKIP, True, 0, detail="claude binary not found"))
            return
        with tempfile.TemporaryDirectory(prefix="beefapi-cert-claude-") as tmp:
            root = Path(tmp)
            config_dir = root / "claude-config"
            workspace = root / "workspace"
            config_dir.mkdir()
            workspace.mkdir()
            (workspace / "marker.txt").write_text("CERT_CLAUDE_FILE_OK\n", encoding="utf-8")
            env = os.environ.copy()
            env.pop("ANTHROPIC_API_KEY", None)
            env.update({
                "ANTHROPIC_BASE_URL": self.args.base_url.rstrip("/"),
                "ANTHROPIC_AUTH_TOKEN": self.api_key,
                "ANTHROPIC_MODEL": self.args.model,
                "CLAUDE_CONFIG_DIR": str(config_dir),
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "CLAUDE_CODE_DISABLE_TERMINAL_TITLE": "1",
            })
            session_id = str(uuid.uuid4())
            base = [binary, "--print", "--output-format", "stream-json", "--verbose", "--model", self.args.model,
                    "--permission-mode", "bypassPermissions", "--allowedTools", "Bash", "--session-id", session_id]
            command = base + ["Use Bash to read marker.txt, then reply exactly CERT_CLAUDE_CLIENT_OK."]
            completed, _ = self._run_command(
                "claude_code_turn_1", "claude_client", command, env, workspace,
                required_markers=("CERT_CLAUDE_CLIENT_OK", "CERT_CLAUDE_FILE_OK"),
            )
            if not completed or self.results[-1].status != PASS:
                for turn in range(2, self.args.client_turns + 1):
                    self.results.append(CheckResult(f"claude_code_turn_{turn}", "claude_client", SKIP, True, 0, detail="turn 1 failed"))
                return
            for turn in range(2, self.args.client_turns + 1):
                prompt = f"This is certification turn {turn}. Use Bash to run pwd once, then reply exactly CERT_CLAUDE_TURN_{turn}_OK."
                resume = [binary, "--print", "--output-format", "stream-json", "--verbose", "--model", self.args.model,
                          "--permission-mode", "bypassPermissions", "--allowedTools", "Bash", "--resume", session_id, prompt]
                completed, _ = self._run_command(
                    f"claude_code_turn_{turn}", "claude_client", resume, env, workspace,
                    required_markers=(f"CERT_CLAUDE_TURN_{turn}_OK",),
                )
                if not completed or self.results[-1].status != PASS:
                    for remaining in range(turn + 1, self.args.client_turns + 1):
                        self.results.append(CheckResult(f"claude_code_turn_{remaining}", "claude_client", SKIP, True, 0, detail=f"turn {turn} failed"))
                    break


def extract_codex_thread_id(output: str) -> str | None:
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "thread.started" and isinstance(event.get("thread_id"), str):
            return event["thread_id"]
        if isinstance(event.get("thread"), dict) and isinstance(event["thread"].get("id"), str):
            return event["thread"]["id"]
    return None


def codex_child_env(codex_home: Path, source: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(source or os.environ)
    for key in (
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_API_BASE",
        "OPENAI_AUTH_TOKEN",
        "OPENAI_ORG_ID",
        "OPENAI_ORGANIZATION",
        "CODEX_API_KEY",
    ):
        env.pop(key, None)
    env["CODEX_HOME"] = str(codex_home)
    return env


def classify(results: list[CheckResult], clients_requested: bool) -> str:
    required = [result for result in results if result.required]
    if any(result.status == FAIL and result.layer in {"responses", "messages"} for result in required):
        return "blocked"
    if any(result.status in {FAIL, UNSUPPORTED} for result in required):
        return "limited"
    required_layers = {result.layer for result in required if result.status == PASS}
    complete_layers = {"responses", "messages", "codex_client", "claude_client"}
    if not clients_requested or not complete_layers.issubset(required_layers) or any(result.status == SKIP for result in required):
        return "experimental"
    return "certified"


def percentile(values: list[int], p: float) -> int | None:
    values = sorted(value for value in values if value >= 0)
    if not values:
        return None
    index = min(len(values) - 1, max(0, round((len(values) - 1) * p)))
    return values[index]


def build_report(args: argparse.Namespace, results: list[CheckResult]) -> dict[str, Any]:
    classification = classify(results, clients_requested=args.profile in {"clients", "all"})
    return {
        "schema_version": 1,
        "generated_at": now_iso(),
        "target": {
            "channel_id": args.channel_id,
            "base_url": args.base_url,
            "model": args.model,
            "profile": args.profile,
            "client_turns": args.client_turns,
            "channel_pin": "admin_key_suffix" if args.pin_channel else "none",
            "client_versions": {
                "codex": command_version(args.codex_bin),
                "claude": command_version(args.claude_bin),
            },
        },
        "classification": classification,
        "summary": {
            "pass": sum(result.status == PASS for result in results),
            "fail": sum(result.status == FAIL for result in results),
            "unsupported": sum(result.status == UNSUPPORTED for result in results),
            "skip": sum(result.status == SKIP for result in results),
            "first_text_p50_ms": percentile([result.first_text_ms for result in results if result.first_text_ms is not None], 0.50),
            "first_text_p95_ms": percentile([result.first_text_ms for result in results if result.first_text_ms is not None], 0.95),
        },
        "checks": [asdict(result) for result in results],
    }


def command_version(binary: str) -> str | None:
    resolved = shutil.which(binary)
    if not resolved:
        return None
    try:
        completed = subprocess.run([resolved, "--version"], text=True, capture_output=True, timeout=10, check=False)
    except Exception:  # noqa: BLE001
        return None
    return compact_error((completed.stdout or completed.stderr).strip(), 120) or None


def render_markdown(report: dict[str, Any]) -> str:
    target = report["target"]
    lines = [
        "# BeefAPI Provider Certification",
        "",
        f"- Classification: **{report['classification']}**",
        f"- Channel: `{target['channel_id']}`",
        f"- Model: `{target['model']}`",
        f"- Base URL: `{target['base_url']}`",
        f"- Generated: `{report['generated_at']}`",
        "",
        "| Check | Layer | Required | Status | HTTP | First text | Total | Detail |",
        "|---|---|---:|---|---:|---:|---:|---|",
    ]
    for check in report["checks"]:
        detail = compact_error(check.get("detail", ""), 180).replace("|", "\\|")
        lines.append(
            f"| `{check['name']}` | {check['layer']} | {'yes' if check['required'] else 'no'} | "
            f"**{check['status']}** | {check.get('http_status') or '-'} | "
            f"{check.get('first_text_ms') if check.get('first_text_ms') is not None else '-'} ms | "
            f"{check['duration_ms']} ms | {detail} |"
        )
    lines.extend(["", "Credentials are read from the configured environment variable and are never written to this report.", ""])
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Certify a BeefAPI provider/channel route")
    parser.add_argument("--base-url", default="https://beefapi.com")
    parser.add_argument("--model", required=True)
    parser.add_argument("--channel-id", default="unknown")
    parser.add_argument("--pin-channel", action="store_true", help="append channel id to an admin test key")
    parser.add_argument("--key-env", default="BEEFAPI_PROVIDER_TEST_KEY")
    parser.add_argument("--profile", choices=("api", "clients", "all"), default="all")
    parser.add_argument("--client-turns", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--client-timeout", type=int, default=900)
    parser.add_argument("--web-search", action="store_true")
    parser.add_argument("--codex-bin", default="codex")
    parser.add_argument("--claude-bin", default="claude")
    parser.add_argument("--output-dir", type=Path, default=Path(".tmp/provider-certifier"))
    return parser.parse_args(argv)


def pin_channel_key(api_key: str, channel_id: str) -> str:
    match = re.search(r"-(\d+)$", api_key)
    if match:
        existing_channel = match.group(1)
        if existing_channel != channel_id:
            raise ValueError(
                f"credential is already pinned to channel {existing_channel}; requested channel {channel_id}"
            )
        return api_key
    return f"{api_key}-{channel_id}"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.client_turns < 1 or args.client_turns > 20:
        raise SystemExit("--client-turns must be between 1 and 20")
    api_key = os.environ.get(args.key_env, "").strip()
    if not api_key:
        raise SystemExit(f"missing credential environment variable: {args.key_env}")
    if args.pin_channel:
        if args.channel_id == "unknown" or not str(args.channel_id).isdigit():
            raise SystemExit("--pin-channel requires a numeric --channel-id")
        try:
            api_key = pin_channel_key(api_key, str(args.channel_id))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    certifier = Certifier(args, api_key)
    if args.profile in {"api", "all"}:
        certifier.run_api()
    if args.profile in {"clients", "all"}:
        certifier.run_clients()
    report = build_report(args, certifier.results)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "certification.json"
    markdown_path = args.output_dir / "certification.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({
        "classification": report["classification"],
        "summary": report["summary"],
        "json": str(json_path),
        "markdown": str(markdown_path),
    }, ensure_ascii=False))
    return 0 if report["classification"] == "certified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
