from __future__ import annotations

import http.server
import json
import os
import re
import tempfile
import threading
import unittest
import urllib.request
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from beefapi_conformance.clients import ClientCommand, assistant_text, resolve_binary
from beefapi_conformance.inventory import build_live_inventory
from beefapi_conformance.manifest import Inventory, load_inventory
from beefapi_conformance.matrix import compile_matrix
from beefapi_conformance.model import (
    Client,
    ContractError,
    MatrixCell,
    Model,
    Route,
    Scenario,
    Turn,
)
from beefapi_conformance.redact import redact
from beefapi_conformance.report import build_report
from beefapi_conformance.runner import (
    _beefapi_token_log_evidence,
    _request_token,
    _usage_log_payload,
    run_cell,
)
from beefapi_conformance.wire import (
    RecordingProxy,
    crosstalk,
    latency_stats,
    parse_sse,
    sse_text,
    termination,
    wire_verdict,
)

ROOT = Path(__file__).resolve().parents[1]

MESSAGES_SSE_CLEAN = (
    'event: message_start\ndata: {"type":"message_start"}\n\n'
    "event: content_block_delta\n"
    'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"BEEFAPI_MESSAGES_STREAM_OK"}}\n\n'
    'event: message_stop\ndata: {"type":"message_stop"}\n\n'
)
MESSAGES_SSE_EARLY = (
    'event: message_start\ndata: {"type":"message_start"}\n\n'
    "event: content_block_delta\n"
    'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"BEEFAPI_MESSAGES_STREAM_OK"}}\n\n'
)


def messages_sse(text: str) -> str:
    return (
        'event: message_start\ndata: {"type":"message_start"}\n\n'
        "event: content_block_delta\n"
        "data: "
        + json.dumps(
            {
                "type": "content_block_delta",
                "delta": {"type": "text_delta", "text": text},
            }
        )
        + "\n\n"
        'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    )


def sse_server(
    body: str | None = None, *, crosstalk: bool = False
) -> http.server.ThreadingHTTPServer:
    """Serve a fixed SSE body, or (when body is None) echo the nonce found in
    the prompt. crosstalk=True simulates a router that mixes users' streams
    by appending the previous request's nonce to every answer."""
    fixed = body.encode() if body is not None else None
    seen: list[str] = []
    lock = threading.Lock()
    nonce_pattern = re.compile(r"BEEFAPI-NONCE-[A-Z0-9]+-\d+")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", "0") or 0)
            request = self.rfile.read(length)
            if fixed is not None:
                payload = fixed
            else:
                match = nonce_pattern.search(request.decode("utf-8", "replace"))
                nonce = match.group(0) if match else "NO-NONCE"
                with lock:
                    leaked = seen[-1] if crosstalk and seen else ""
                    seen.append(nonce)
                payload = messages_sse(f"{nonce} {leaked}".strip()).encode()
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class FakeResponse:
    def __init__(self, body: dict, headers: dict[str, str] | None = None):
        self.body = json.dumps(body).encode()
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


class ContractTests(unittest.TestCase):
    def inventory(self) -> Inventory:
        return load_inventory(
            ROOT,
            ROOT / "manifests/routes.example.json",
            ROOT / "manifests/models.example.json",
        )

    def test_inventory_loads_and_matrix_covers_all_clients_at_release(self):
        inventory = self.inventory()
        cells = compile_matrix(inventory, "release")
        covered = {cell.client.id for cell in cells}
        self.assertEqual({item.id for item in inventory.clients}, covered)

    def test_nightly_native_scenarios_cover_real_failure_modes(self):
        cells = compile_matrix(self.inventory(), "nightly", clients={"codex-cli"})
        self.assertEqual(
            {
                "text-turn",
                "long-stream",
                "tool-loop",
                "web-search",
                "concurrent-users",
                "session-resume",
            },
            {item.scenario.id for item in cells},
        )

    def test_pr_protocol_scenarios_are_streaming(self):
        cells = compile_matrix(self.inventory(), "pr", clients={"raw-http"})
        self.assertTrue(cells)
        self.assertTrue(all(cell.scenario.stream for cell in cells))

    def test_manifest_rejects_literal_secret(self):
        source = json.loads((ROOT / "manifests/routes.example.json").read_text())
        source["routes"][0]["token_env"] = "sk-secret-value"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "routes.json"
            path.write_text(json.dumps(source))
            with self.assertRaisesRegex(ContractError, "environment variable"):
                load_inventory(ROOT, path, ROOT / "manifests/models.example.json")

    def test_http_payload_rejects_persisted_credentials(self):
        base = {
            "id": "secret-payload",
            "name": "Secret payload",
            "tier": "pr",
            "kind": "http",
            "protocol": "messages",
            "http_endpoint": "/v1/messages",
            "required_capabilities": ["messages"],
            "turns": [{"prompt": "hello", "marker": "hello", "expected_events": []}],
        }
        for payload in (
            {"Authorization": "Bearer persisted-secret"},
            {"metadata": {"cookie": "session=secret"}},
            {"messages": [{"role": "user", "content": "sk-abcdef123456"}]},
        ):
            with (
                self.subTest(payload=payload),
                self.assertRaisesRegex(ContractError, "credential"),
            ):
                Scenario.parse({**base, "http_payload": payload})

    def test_scenario_wire_fields_are_validated(self):
        base = {
            "id": "case",
            "name": "Case",
            "tier": "pr",
            "kind": "client",
            "required_capabilities": ["text"],
            "turns": [{"prompt": "p", "marker": "m", "expected_events": []}],
        }
        with self.assertRaisesRegex(ContractError, "expect_wire"):
            Scenario.parse({**base, "expect_wire": ["unknown_check"]})
        with self.assertRaisesRegex(ContractError, "stream"):
            Scenario.parse({**base, "stream": True})
        with self.assertRaisesRegex(ContractError, "marker or expected events"):
            Scenario.parse(
                {
                    **base,
                    "turns": [{"prompt": "p", "marker": "", "expected_events": []}],
                }
            )
        with self.assertRaisesRegex(ContractError, "nonce"):
            Scenario.parse({**base, "concurrency": 4})
        with self.assertRaisesRegex(ContractError, "exactly one turn"):
            Scenario.parse(
                {
                    **base,
                    "concurrency": 2,
                    "turns": [
                        {"prompt": "{{nonce}}", "marker": "m", "expected_events": []},
                        {"prompt": "{{nonce}}", "marker": "m", "expected_events": []},
                    ],
                }
            )
        with self.assertRaisesRegex(ContractError, "max_slowdown"):
            Scenario.parse({**base, "max_slowdown": 3.0})

    def test_redaction_covers_explicit_and_pattern_secrets(self):
        output = redact(
            "Bearer sk-abcdef123456 api_key=plain-secret", ("plain-secret",)
        )
        self.assertNotIn("abcdef", output)
        self.assertNotIn("plain-secret", output)

    def test_workbuddy_bundled_binary_is_discoverable_when_installed(self):
        workbuddy = next(
            item for item in self.inventory().clients if item.id == "workbuddy-cli"
        )
        app_binary = Path(
            "/Applications/WorkBuddy.app/Contents/Resources/app.asar.unpacked/cli/bin/codebuddy"
        )
        if app_binary.exists():
            self.assertEqual(str(app_binary), resolve_binary(workbuddy))

    def test_live_inventory_uses_sanitized_channel_snapshot(self):
        routes, models = build_live_inventory(
            channels=[
                {
                    "id": 252,
                    "type": 62,
                    "status": 1,
                    "models": "grok-4.6,hidden-model",
                    "test_model": "grok-4.6",
                },
                {"id": 57, "type": 57, "status": 1, "models": "gpt-5.4"},
            ],
            public_models={"grok-4.6"},
            base_url="https://beefapi.example",
            token_env="TEST_TOKEN",
            group="cursor-acceptance",
        )
        self.assertEqual(1, len(routes["routes"]))
        route = routes["routes"][0]
        self.assertEqual(252, route["channel_id"])
        self.assertTrue(route["pin_channel"])
        self.assertEqual("beefapi_token_log", route["evidence_provider"])
        self.assertEqual(["grok-4.6"], [item["id"] for item in models["models"]])

    def test_live_inventory_gates_agent_v1_web_capability_on_channel_policy(self):
        routes, _ = build_live_inventory(
            channels=[
                {
                    "id": 301,
                    "type": 64,
                    "status": 1,
                    "models": "claude-opus-5",
                    "cursor_agent_v1_native_web_search": False,
                },
                {
                    "id": 302,
                    "type": 64,
                    "status": 1,
                    "models": "claude-opus-5",
                    "cursor_agent_v1_native_web_search": True,
                },
            ],
            public_models={"claude-opus-5"},
            base_url="https://beefapi.example",
            token_env="TEST_TOKEN",
            group="cursor-agent-v1-acceptance",
        )
        by_id = {route["channel_id"]: route for route in routes["routes"]}
        self.assertNotIn("tool.web", by_id[301]["capabilities"])
        self.assertIn("tool.web", by_id[302]["capabilities"])

    def test_live_inventory_rejects_stale_channel_test_model(self):
        with self.assertRaisesRegex(ContractError, "not in its public model inventory"):
            build_live_inventory(
                channels=[
                    {
                        "id": 271,
                        "type": 62,
                        "status": 1,
                        "models": "claude-sonnet-4-6,retired-model",
                        "test_model": "retired-model",
                    }
                ],
                public_models={"claude-sonnet-4-6"},
                base_url="https://beefapi.example",
                token_env="TEST_TOKEN",
                group="cursor-acceptance",
            )

    def test_representative_matrix_covers_routes_models_and_deep_cases(self):
        routes, models = build_live_inventory(
            channels=[
                {
                    "id": 252,
                    "type": 62,
                    "status": 1,
                    "models": "grok-4.6,composer-2.5",
                    "test_model": "grok-4.6",
                },
                {
                    "id": 272,
                    "type": 62,
                    "status": 1,
                    "models": "glm-5.2",
                    "test_model": "glm-5.2",
                },
            ],
            public_models={"grok-4.6", "composer-2.5", "glm-5.2"},
            base_url="https://beefapi.example",
            token_env="TEST_TOKEN",
            group="cursor-acceptance",
        )
        with tempfile.TemporaryDirectory() as tmp:
            routes_path = Path(tmp) / "routes.json"
            models_path = Path(tmp) / "models.json"
            routes_path.write_text(json.dumps(routes))
            models_path.write_text(json.dumps(models))
            inventory = load_inventory(ROOT, routes_path, models_path)
        cells = compile_matrix(inventory, "release", coverage="representative")
        raw_stream = {
            (cell.route.id, cell.model.id)
            for cell in cells
            if cell.client.id == "raw-http" and cell.scenario.id == "responses-stream"
        }
        self.assertEqual(
            {
                (route.id, model.id)
                for route in inventory.routes
                for model in inventory.models
                if route.id in model.routes
            },
            raw_stream,
        )
        deep = {
            "tool-loop",
            "session-resume",
            "web-search",
            "long-stream",
            "concurrent-users",
        }
        for route in inventory.routes:
            route_cells = [cell for cell in cells if cell.route.id == route.id]
            self.assertEqual(
                deep,
                {cell.scenario.id for cell in route_cells if cell.scenario.id in deep},
            )
        for model in inventory.models:
            self.assertTrue(
                any(
                    cell.model.id == model.id
                    and cell.client.adapter != "raw-http"
                    and cell.scenario.id == "text-turn"
                    for cell in cells
                )
            )


class WireTests(unittest.TestCase):
    def test_parse_sse_and_termination(self):
        events = parse_sse(MESSAGES_SSE_CLEAN)
        names = [name for name, _ in events]
        self.assertEqual(
            ["message_start", "content_block_delta", "message_stop"], names
        )
        self.assertEqual("clean", termination(names, saw_done=False))
        self.assertEqual(
            "early",
            termination(["message_start", "content_block_delta"], saw_done=False),
        )
        self.assertEqual("clean", termination([], saw_done=True))
        self.assertEqual(
            "error_event", termination(["response.failed"], saw_done=False)
        )

    def test_sse_text_assembles_deltas_per_protocol(self):
        self.assertEqual(
            "BEEFAPI_MESSAGES_STREAM_OK",
            sse_text("messages", parse_sse(MESSAGES_SSE_CLEAN)),
        )
        chat = 'data: {"choices":[{"delta":{"content":"CHAT_OK"}}]}\n\ndata: [DONE]\n\n'
        self.assertEqual("CHAT_OK", sse_text("chat", parse_sse(chat)))
        responses = (
            "event: response.output_text.delta\n"
            'data: {"type":"response.output_text.delta","delta":"RESP_OK"}\n\n'
            'event: response.completed\ndata: {"type":"response.completed"}\n\n'
        )
        self.assertEqual("RESP_OK", sse_text("responses", parse_sse(responses)))

    def test_crosstalk_and_latency_helpers(self):
        clean = {"N-1": "N-1 done", "N-2": "N-2 done"}
        self.assertEqual([], crosstalk(clean))
        leaked = crosstalk({"N-1": "N-1 done", "N-2": "N-2 and also N-1"})
        self.assertEqual(1, len(leaked))
        self.assertIn("N-2", leaked[0])
        self.assertIn("N-1", leaked[0])
        stats = latency_stats([100, 300, 200, 900, 250])
        self.assertEqual(5, stats["count"])
        self.assertEqual(250, stats["p50_ms"])
        self.assertEqual(900, stats["p95_ms"])
        self.assertEqual({}, latency_stats([]))

    def test_wire_verdict_scales_tool_loop_depth_with_concurrency(self):
        upstream = sse_server(MESSAGES_SSE_CLEAN)
        proxy = RecordingProxy(f"http://127.0.0.1:{upstream.server_port}")
        try:
            for _ in range(3):
                request = urllib.request.Request(
                    proxy.base_url + "/v1/messages",
                    data=json.dumps({"model": "m", "stream": True}).encode(),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=10) as response:
                    response.read()
            exchanges = proxy.exchanges()
            self.assertEqual(
                "pass", wire_verdict(exchanges, ("multi_request",), 1)["status"]
            )
            self.assertEqual(
                "fail", wire_verdict(exchanges, ("multi_request",), 2)["status"]
            )
        finally:
            proxy.stop()
            upstream.shutdown()
            upstream.server_close()

    def test_proxy_records_clean_stream_and_request_summary(self):
        upstream = sse_server(MESSAGES_SSE_CLEAN)
        proxy = RecordingProxy(f"http://127.0.0.1:{upstream.server_port}")
        try:
            request = urllib.request.Request(
                # Real Claude Code appends a query string; completion matching
                # and web-search detection must survive both that and the
                # client-style WebSearch tool name.
                proxy.base_url + "/v1/messages?beta=true",
                data=json.dumps(
                    {
                        "model": "m",
                        "stream": True,
                        "messages": [{"role": "user", "content": "hi"}],
                        "tools": [{"name": "Bash"}, {"name": "WebSearch"}],
                    }
                ).encode(),
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                body = response.read().decode()
            self.assertIn("message_stop", body)
            exchanges = proxy.exchanges()
            self.assertEqual(1, len(exchanges))
            exchange = exchanges[0]
            self.assertTrue(exchange.sse)
            self.assertTrue(exchange.is_completion)
            self.assertEqual("clean", exchange.terminated)
            self.assertEqual(["Bash", "WebSearch"], exchange.request["tool_names"])
            verdict = wire_verdict(exchanges, ("web_search_requested",))
            self.assertEqual("pass", verdict["status"], verdict)
        finally:
            proxy.stop()
            upstream.shutdown()
            upstream.server_close()

    def test_proxy_flags_early_terminated_stream(self):
        upstream = sse_server(MESSAGES_SSE_EARLY)
        proxy = RecordingProxy(f"http://127.0.0.1:{upstream.server_port}")
        try:
            request = urllib.request.Request(
                proxy.base_url + "/v1/messages",
                data=json.dumps({"model": "m", "stream": True}).encode(),
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
            verdict = wire_verdict(proxy.exchanges())
            self.assertEqual("fail", verdict["status"])
            self.assertIn("without a terminal event", verdict["detail"])
        finally:
            proxy.stop()
            upstream.shutdown()
            upstream.server_close()

    def test_wire_verdict_enforces_tool_loop_depth(self):
        upstream = sse_server(MESSAGES_SSE_CLEAN)
        proxy = RecordingProxy(f"http://127.0.0.1:{upstream.server_port}")
        try:
            request = urllib.request.Request(
                proxy.base_url + "/v1/messages",
                data=json.dumps({"model": "m", "stream": True}).encode(),
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
            verdict = wire_verdict(proxy.exchanges(), ("multi_request",))
            self.assertEqual("fail", verdict["status"])
            self.assertIn(">=2 completion requests", verdict["detail"])
        finally:
            proxy.stop()
            upstream.shutdown()
            upstream.server_close()


class CommandTests(unittest.TestCase):
    def cell(self, adapter: str, capabilities: frozenset[str] | None = None):
        capabilities = capabilities or frozenset({"text", "session.resume"})
        client = Client(
            "client",
            "Client",
            adapter,
            ("binary",),
            ("--version",),
            capabilities,
            frozenset({"darwin"}),
        )
        route = Route(
            "route",
            "Route",
            "gateway_token",
            "https://example.invalid",
            None,
            "TOKEN",
            frozenset({"client"}),
            frozenset({"responses"}),
            capabilities,
            None,
        )
        model = Model(
            "model",
            "Model",
            frozenset({"route"}),
            frozenset({"client"}),
            capabilities,
            {},
        )
        scenario = Scenario(
            "scenario",
            "Scenario",
            "pr",
            "client",
            None,
            capabilities,
            10,
            False,
            (Turn("prompt", "marker", ()),),
        )
        return MatrixCell(client, route, model, scenario)

    def test_codex_config_references_env_without_persisting_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = ClientCommand(
                self.cell("codex"),
                "/bin/echo",
                Path(tmp),
                "sk-private-value",
                "https://gateway",
            )
            command.prepare()
            config = (Path(tmp) / "client-home/config.toml").read_text()
            self.assertIn('env_key = "BEEFAPI_CONFORMANCE_TOKEN"', config)
            self.assertNotIn("sk-private-value", config)
            self.assertNotIn("web_search", config)

    def test_codex_web_scenario_enables_native_search(self):
        cell = self.cell("codex", frozenset({"text", "tool.web"}))
        with tempfile.TemporaryDirectory() as tmp:
            command = ClientCommand(
                cell, "/bin/echo", Path(tmp), "token", "https://gateway"
            )
            command.prepare()
            config = (Path(tmp) / "client-home/config.toml").read_text()
            self.assertIn("web_search = true", config)
            self.assertNotIn("--search", command.command("hello", 1))

    def test_grok_keeps_default_tool_surface_and_env_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = ClientCommand(
                self.cell("grok-build"),
                "/bin/echo",
                Path(tmp),
                "sk-private-value",
                "https://gateway",
            )
            command.prepare()
            config = (Path(tmp) / "client-home/config.toml").read_text()
            self.assertIn('env_key = "BEEFAPI_CONFORMANCE_TOKEN"', config)
            self.assertNotIn("sk-private-value", config)
            env = command.environment()
            self.assertEqual("sk-private-value", env["BEEFAPI_CONFORMANCE_TOKEN"])
            self.assertNotIn("XAI_API_KEY", env)
            grok_command = command.command("hello", 1)
            self.assertIn("streaming-messages-json", grok_command)
            self.assertNotIn("--tools", grok_command)

    def test_workbuddy_command_uses_headless_stream_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = ClientCommand(
                self.cell("workbuddy"), "codebuddy", Path(tmp), None, None
            )
            first = command.command("hello", 1)
            second = command.command("again", 2)
            self.assertIn("--print", first)
            self.assertIn("stream-json", first)
            self.assertIn("--session-id", first)
            self.assertIn("--resume", second)

    def test_codex_resume_requires_thread_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = ClientCommand(
                self.cell("codex"), "/bin/echo", Path(tmp), "token", "https://gateway"
            )
            with self.assertRaisesRegex(RuntimeError, "thread id"):
                command.command("again", 2)
            command.resume_id = "thread-id"
            self.assertIn("thread-id", command.command("again", 2))

    def test_assistant_text_does_not_accept_echoed_user_prompt(self):
        output = "\n".join(
            [
                json.dumps(
                    {
                        "type": "user",
                        "message": {"role": "user", "content": "SECRET_MARKER"},
                    }
                ),
                json.dumps({"type": "result", "result": "different answer"}),
            ]
        )
        self.assertNotIn("SECRET_MARKER", assistant_text("workbuddy", output))


class EvidenceTests(unittest.TestCase):
    def cell(self) -> MatrixCell:
        base = CommandTests().cell("codex")
        route = replace(
            base.route,
            channel_id=252,
            pin_channel=True,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
        )
        return MatrixCell(base.client, route, base.model, base.scenario)

    def log(self, request_id: str, state: str = "final") -> dict:
        return {
            "created_at": 200,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": request_id,
            "prompt_tokens": 10,
            "completion_tokens": 2,
            "quota": 3,
            "use_time": 1,
            "other": json.dumps(
                {
                    "usage_receipt_id": f"receipt-{request_id}",
                    "usage_receipt_provider": "cursor-sdk-bridge",
                    "usage_receipt_state": state,
                }
            ),
        }

    def test_channel_pin_is_explicit_and_conflict_safe(self):
        cell = self.cell()
        self.assertEqual("test-token-252", _request_token(cell, "test-token"))
        self.assertEqual("test-token-252", _request_token(cell, "test-token-252"))
        with self.assertRaisesRegex(RuntimeError, "already pinned to channel 271"):
            _request_token(cell, "test-token-271")

    def test_usage_log_payload_requires_final_receipt(self):
        cell = self.cell()
        payload = _usage_log_payload(cell, self.log("req-252"), "commit-sha")
        self.assertEqual("pass", payload["status"])
        self.assertEqual(252, payload["route"]["channel_id"])
        provisional = _usage_log_payload(
            cell, self.log("req-252", state="provisional"), "commit-sha"
        )
        self.assertEqual("fail", provisional["status"])

    def test_token_log_evidence_waits_for_final_receipt(self):
        cell = self.cell()
        responses = [
            FakeResponse(
                {"success": True, "data": [self.log("req-252", "provisional")]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {"success": True, "data": [self.log("req-252")]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        with (
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            patch("time.sleep"),
        ):
            payload = _beefapi_token_log_evidence(
                cell, "token", 200, set(), {"req-252"}
            )
        self.assertEqual("pass", payload["status"])
        self.assertEqual(2, urlopen.call_count)

    def test_tool_loop_accepts_multiple_final_request_ids(self):
        cell = self.cell()
        response = FakeResponse(
            {"success": True, "data": [self.log("tool-call"), self.log("tool-result")]},
            {"X-New-Api-Commit": "commit-sha"},
        )
        with patch("urllib.request.urlopen", return_value=response):
            payload = _beefapi_token_log_evidence(
                cell, "token", 200, set(), {"tool-call", "tool-result"}
            )
        self.assertEqual("pass", payload["status"])
        self.assertEqual(2, len(payload["requests"]))

    def test_web_search_scenario_requires_observed_search_call(self):
        base = self.cell()
        cell = MatrixCell(
            base.client,
            base.route,
            base.model,
            replace(base.scenario, id="web-search"),
        )
        response = FakeResponse(
            {"success": True, "data": [self.log("req-search")]},
            {"X-New-Api-Commit": "commit-sha"},
        )
        with (
            patch("urllib.request.urlopen", return_value=response),
            patch("time.sleep"),
        ):
            payload = _beefapi_token_log_evidence(
                cell, "token", 200, set(), {"req-search"}
            )
        self.assertEqual("fail", payload["status"])
        self.assertIn("no observed search call", payload["detail"])


class RunnerTests(unittest.TestCase):
    def test_mock_client_runs_and_report_passes(self):
        binary = str(ROOT / "tests/fixtures/mock_agent.py")
        client = Client(
            "mock",
            "Mock",
            "mock",
            (binary,),
            ("--version",),
            frozenset({"text", "tool.shell"}),
            frozenset({"darwin"}),
        )
        route = Route(
            "mock-route",
            "Mock",
            "managed_session",
            None,
            None,
            None,
            frozenset({"mock"}),
            frozenset({"mock"}),
            frozenset({"text", "tool.shell"}),
            None,
        )
        model = Model(
            "mock-model",
            "Mock",
            frozenset({"mock-route"}),
            frozenset({"mock"}),
            frozenset({"text", "tool.shell"}),
            {},
        )
        scenario = Scenario(
            "mock-scenario",
            "Mock",
            "pr",
            "client",
            None,
            frozenset({"tool.shell"}),
            10,
            True,
            (
                Turn(
                    "BEEFAPI_CONFORMANCE_TOOL_OK",
                    "BEEFAPI_CONFORMANCE_TOOL_OK",
                    ("BEEFAPI_CONFORMANCE_FILE_OK",),
                ),
            ),
        )
        cell = MatrixCell(client, route, model, scenario)
        result = run_cell(cell, allow_local_tools=True)
        self.assertEqual("pass", result.status, result)
        self.assertEqual("passed", build_report([result])["classification"])
        skipped = run_cell(cell, allow_local_tools=False)
        self.assertEqual("skip", skipped.status)
        self.assertIn("--allow-local-tools", skipped.detail)

    def http_cell(self, port: int, stream: bool = True) -> MatrixCell:
        client = Client(
            "raw-http",
            "HTTP",
            "raw-http",
            ("python3",),
            ("--version",),
            frozenset({"text", "stream", "messages"}),
            frozenset({"darwin"}),
        )
        route = Route(
            "route",
            "Route",
            "gateway_token",
            f"http://127.0.0.1:{port}",
            None,
            "RAW_HTTP_TEST_TOKEN",
            frozenset({"raw-http"}),
            frozenset({"messages"}),
            frozenset({"text", "stream", "messages"}),
            None,
        )
        model = Model(
            "model",
            "Model",
            frozenset({"route"}),
            frozenset({"raw-http"}),
            frozenset({"text", "stream", "messages"}),
            {},
        )
        scenario = Scenario(
            "messages-stream",
            "Messages stream",
            "pr",
            "http",
            "messages",
            frozenset({"text", "stream", "messages"}),
            10,
            False,
            (
                Turn(
                    "Reply exactly BEEFAPI_MESSAGES_STREAM_OK.",
                    "BEEFAPI_MESSAGES_STREAM_OK",
                    (),
                ),
            ),
            "/v1/messages",
            None,
            stream,
        )
        return MatrixCell(client, route, model, scenario)

    def test_raw_http_streaming_cell_passes_on_clean_stream(self):
        server = sse_server(MESSAGES_SSE_CLEAN)
        os.environ["RAW_HTTP_TEST_TOKEN"] = "plain-test-token"
        try:
            result = run_cell(self.http_cell(server.server_port))
            self.assertEqual("pass", result.status, result)
            self.assertNotIn("plain-test-token", json.dumps(result.evidence))
        finally:
            os.environ.pop("RAW_HTTP_TEST_TOKEN", None)
            server.shutdown()
            server.server_close()

    def test_raw_http_streaming_cell_fails_on_early_termination(self):
        server = sse_server(MESSAGES_SSE_EARLY)
        os.environ["RAW_HTTP_TEST_TOKEN"] = "plain-test-token"
        try:
            result = run_cell(self.http_cell(server.server_port))
            self.assertEqual("fail", result.status)
            self.assertIn(
                "stream terminated early", json.dumps(result.turns[0].missing_events)
            )
        finally:
            os.environ.pop("RAW_HTTP_TEST_TOKEN", None)
            server.shutdown()
            server.server_close()

    def concurrent_cell(self, port: int, users: int = 6) -> MatrixCell:
        base = self.http_cell(port)
        scenario = replace(
            base.scenario,
            id="messages-concurrent",
            concurrency=users,
            max_slowdown=50.0,
            turns=(Turn("Reply exactly {{nonce}}.", "{{nonce}}", ()),),
        )
        return MatrixCell(base.client, base.route, base.model, scenario)

    def test_concurrent_http_cell_passes_and_records_load_evidence(self):
        server = sse_server()
        os.environ["RAW_HTTP_TEST_TOKEN"] = "plain-test-token"
        try:
            result = run_cell(self.concurrent_cell(server.server_port))
            self.assertEqual("pass", result.status, result)
            self.assertEqual(6, len(result.turns))
            self.assertEqual(6, len({turn.marker for turn in result.turns}))
            load = result.evidence["concurrency"]
            self.assertEqual(6, load["users"])
            self.assertEqual(6, load["passed"])
            self.assertEqual([], load["crosstalk"])
            self.assertEqual(6, load["latency"]["count"])
            self.assertEqual(200, load["baseline_status"])
        finally:
            os.environ.pop("RAW_HTTP_TEST_TOKEN", None)
            server.shutdown()
            server.server_close()

    def test_concurrent_http_cell_fails_on_crosstalk(self):
        server = sse_server(crosstalk=True)
        os.environ["RAW_HTTP_TEST_TOKEN"] = "plain-test-token"
        try:
            result = run_cell(self.concurrent_cell(server.server_port))
            self.assertEqual("fail", result.status)
            self.assertIn("leaked across users", result.detail)
            self.assertTrue(result.evidence["concurrency"]["crosstalk"])
        finally:
            os.environ.pop("RAW_HTTP_TEST_TOKEN", None)
            server.shutdown()
            server.server_close()

    def test_concurrent_mock_client_isolates_workspaces_and_nonces(self):
        binary = str(ROOT / "tests/fixtures/mock_agent.py")
        client = Client(
            "mock",
            "Mock",
            "mock",
            (binary,),
            ("--version",),
            frozenset({"text", "stream"}),
            frozenset({"darwin"}),
        )
        route = Route(
            "mock-route",
            "Mock",
            "managed_session",
            None,
            None,
            None,
            frozenset({"mock"}),
            frozenset({"mock"}),
            frozenset({"text", "stream"}),
            None,
        )
        model = Model(
            "mock-model",
            "Mock",
            frozenset({"mock-route"}),
            frozenset({"mock"}),
            frozenset({"text", "stream"}),
            {},
        )
        scenario = Scenario(
            "concurrent-users",
            "Concurrent",
            "pr",
            "client",
            None,
            frozenset({"text"}),
            10,
            False,
            (Turn("{{nonce}}", "{{nonce}}", ()),),
            concurrency=3,
        )
        result = run_cell(MatrixCell(client, route, model, scenario))
        self.assertEqual("pass", result.status, result)
        self.assertEqual(3, len(result.turns))
        self.assertEqual(3, result.evidence["concurrency"]["passed"])
        self.assertEqual([], result.evidence["concurrency"]["crosstalk"])

    def test_release_tier_fails_closed_without_server_evidence(self):
        server = sse_server(MESSAGES_SSE_CLEAN)
        os.environ["RAW_HTTP_TEST_TOKEN"] = "plain-test-token"
        try:
            result = run_cell(
                self.http_cell(server.server_port), require_server_evidence=True
            )
            self.assertEqual("fail", result.status)
            self.assertIn("requires passing server evidence", result.detail)
        finally:
            os.environ.pop("RAW_HTTP_TEST_TOKEN", None)
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
