from __future__ import annotations

import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from beefapi_conformance.clients import ClientCommand, assistant_text, resolve_binary
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
from beefapi_conformance.runner import run_cell

ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def inventory(self) -> Inventory:
        return load_inventory(
            ROOT,
            ROOT / "manifests/routes.example.json",
            ROOT / "manifests/models.example.json",
        )

    def test_inventory_loads_workbuddy_as_first_class_client(self):
        inventory = self.inventory()
        workbuddy = next(
            item for item in inventory.clients if item.id == "workbuddy-cli"
        )
        self.assertEqual("workbuddy", workbuddy.adapter)
        self.assertIn("session.resume", workbuddy.capabilities)
        self.assertIn("acp", workbuddy.capabilities)

    def test_matrix_excludes_incompatible_client_route_pairs(self):
        cells = compile_matrix(self.inventory(), "release")
        self.assertTrue(any(item.client.id == "workbuddy-cli" for item in cells))
        self.assertFalse(
            any(
                item.client.id == "workbuddy-cli"
                and item.route.id == "beefapi-cursor-native"
                for item in cells
            )
        )

    def test_lower_tier_is_included_in_nightly(self):
        cells = compile_matrix(self.inventory(), "nightly", clients={"codex-cli"})
        scenarios = {item.scenario.id for item in cells}
        self.assertEqual(
            {"text-turn", "local-tool-read", "session-resume", "native-web-search"},
            scenarios,
        )

    def test_manifest_rejects_literal_secret(self):
        source = json.loads((ROOT / "manifests/routes.example.json").read_text())
        source["routes"][0]["token_env"] = "sk-secret-value"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "routes.json"
            path.write_text(json.dumps(source))
            with self.assertRaisesRegex(ContractError, "environment variable"):
                load_inventory(ROOT, path, ROOT / "manifests/models.example.json")

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


class CommandTests(unittest.TestCase):
    def cell(self, adapter: str) -> MatrixCell:
        client = Client(
            "client",
            "Client",
            adapter,
            ("binary",),
            ("--version",),
            frozenset({"text", "session.resume"}),
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
            frozenset({"text", "session.resume"}),
            None,
        )
        model = Model(
            "model",
            "Model",
            frozenset({"route"}),
            frozenset({"client"}),
            frozenset({"text", "session.resume"}),
            {},
        )
        scenario = Scenario(
            "scenario",
            "Scenario",
            "pr",
            "client",
            None,
            frozenset({"text"}),
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

    def test_grok_config_uses_env_key_without_copying_credentials(self):
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
            self.assertIn("[compat.claude]", config)
            self.assertIn("mcps = false", config)
            self.assertIn('ignore = ["~/.agents/skills"]', config)
            self.assertIn("disabled = [", config)
            self.assertIn("[plugins]", config)
            self.assertNotIn("sk-private-value", config)
            env = command.environment()
            self.assertEqual("sk-private-value", env["BEEFAPI_CONFORMANCE_TOKEN"])
            self.assertNotIn("XAI_API_KEY", env)
            grok_command = command.command("hello", 1)
            self.assertIn("streaming-messages-json", grok_command)

    def test_grok_messages_stream_extracts_assistant_text(self):
        output = "\n".join(
            [
                json.dumps(
                    {"type": "user", "message": {"role": "user", "content": "ECHOED"}}
                ),
                json.dumps(
                    {
                        "type": "assistant",
                        "message": {
                            "role": "assistant",
                            "content": [{"type": "text", "text": "GROK_STREAM_OK"}],
                        },
                    }
                ),
                json.dumps({"type": "result", "result": "GROK_STREAM_OK"}),
            ]
        )
        text = assistant_text("grok-build", output)
        self.assertIn("GROK_STREAM_OK", text)
        self.assertNotIn("ECHOED", text)

    def test_codex_resume_pins_read_only_sandbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = ClientCommand(
                self.cell("codex"), "/bin/echo", Path(tmp), "token", "https://gateway"
            )
            command.resume_id = "thread-id"
            resume = command.command("again", 2)
            self.assertIn('sandbox_mode="read-only"', resume)


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
        result = run_cell(
            MatrixCell(client, route, model, scenario), allow_local_tools=True
        )
        self.assertEqual("pass", result.status, result)
        self.assertEqual("passed", build_report([result])["classification"])

    def test_local_tool_requires_explicit_opt_in(self):
        inventory = load_inventory(
            ROOT,
            ROOT / "manifests/routes.example.json",
            ROOT / "manifests/models.example.json",
        )
        cell = next(
            item
            for item in compile_matrix(inventory, "merge")
            if item.scenario.id == "local-tool-read"
        )
        result = run_cell(cell, allow_local_tools=False)
        self.assertEqual("skip", result.status)
        self.assertIn("--allow-local-tools", result.detail)

    def test_raw_http_responses_is_a_real_matrix_surface(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                request = json.loads(self.rfile.read(length))
                body = json.dumps(
                    {"id": "resp-test", "output_text": request["input"].split()[-1]}
                ).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = Client(
                "raw-http",
                "HTTP",
                "raw-http",
                ("python3",),
                ("--version",),
                frozenset({"text", "responses"}),
                frozenset({"darwin"}),
            )
            route = Route(
                "route",
                "Route",
                "gateway_token",
                f"http://127.0.0.1:{server.server_port}",
                None,
                "RAW_HTTP_TEST_TOKEN",
                frozenset({"raw-http"}),
                frozenset({"responses"}),
                frozenset({"text", "responses"}),
                None,
            )
            model = Model(
                "model",
                "Model",
                frozenset({"route"}),
                frozenset({"raw-http"}),
                frozenset({"text", "responses"}),
                {},
            )
            scenario = Scenario(
                "responses",
                "Responses",
                "pr",
                "http",
                "responses",
                frozenset({"text", "responses"}),
                10,
                False,
                (Turn("Reply BEEFAPI_RESPONSES_OK", "BEEFAPI_RESPONSES_OK", ()),),
                "/v1/responses",
            )
            os.environ["RAW_HTTP_TEST_TOKEN"] = "plain-test-token"
            result = run_cell(MatrixCell(client, route, model, scenario))
            self.assertEqual("pass", result.status, result)
            self.assertNotIn("plain-test-token", json.dumps(result.evidence))
            release_result = run_cell(
                MatrixCell(client, route, model, scenario),
                require_server_evidence=True,
            )
            self.assertEqual("fail", release_result.status)
            self.assertIn("requires passing server evidence", release_result.detail)
            route_with_evidence = Route(
                route.id,
                route.name,
                route.auth_mode,
                route.base_url,
                route.base_url_env,
                route.token_env,
                route.clients,
                route.protocols,
                route.capabilities,
                "RAW_HTTP_EVIDENCE_COMMAND",
            )
            evidence_payload = {
                "status": "pass",
                "commit": "abc123",
                "route": "route",
                "terminal": "completed",
                "receipt": "plain-test-token",
                "usage": {"input_tokens": 1},
            }
            os.environ["RAW_HTTP_EVIDENCE_COMMAND"] = json.dumps(
                [
                    sys.executable,
                    "-c",
                    f"print({json.dumps(json.dumps(evidence_payload))})",
                ]
            )
            evidenced_result = run_cell(
                MatrixCell(client, route_with_evidence, model, scenario),
                require_server_evidence=True,
            )
            self.assertEqual("pass", evidenced_result.status, evidenced_result)
            self.assertNotIn("plain-test-token", json.dumps(evidenced_result.evidence))
        finally:
            os.environ.pop("RAW_HTTP_TEST_TOKEN", None)
            os.environ.pop("RAW_HTTP_EVIDENCE_COMMAND", None)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
