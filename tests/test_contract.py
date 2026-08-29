from __future__ import annotations

import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from beefapi_conformance.clients import ClientCommand, assistant_text, resolve_binary
from beefapi_conformance.inventory import build_live_inventory
from beefapi_conformance.manifest import Inventory, load_inventory
from beefapi_conformance.matrix import compile_matrix
from beefapi_conformance.model import (
    CellResult,
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
    _evidence_fence,
    _matching_usage_log,
    _matching_usage_logs,
    _request_token,
    _usage_log_payload,
    finalize_batch_server_evidence,
    prepare_batch_server_evidence,
    run_cell,
)

ROOT = Path(__file__).resolve().parents[1]


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

    def test_http_payload_rejects_persisted_credentials(self):
        base = {
            "id": "secret-payload",
            "name": "Secret payload",
            "tier": "pr",
            "kind": "http",
            "protocol": "messages",
            "http_endpoint": "/v1/messages",
            "required_capabilities": ["messages"],
            "turns": [
                {
                    "prompt": "hello",
                    "marker": "hello",
                    "expected_events": [],
                }
            ],
        }
        for payload in (
            {"Authorization": "Bearer persisted-secret"},
            {"metadata": {"cookie": "session=secret"}},
            {"metadata": {"access_token": "secret"}},
            {"metadata": {"refreshToken": "secret"}},
            {"metadata": {"id-token": "secret"}},
            {"metadata": {"clientSecret": "secret"}},
            {"metadata": {"password": "secret"}},
            {"metadata": {"bearer_token": "secret"}},
            {"messages": [{"role": "user", "content": "sk-abcdef123456"}]},
            {"messages": [{"role": "user", "content": "Bearer abcdef123456"}]},
        ):
            with (
                self.subTest(payload=payload),
                self.assertRaisesRegex(ContractError, "credential"),
            ):
                Scenario.parse({**base, "http_payload": payload})

    def test_production_refresh_reads_native_search_from_channel_setting(self):
        script = (ROOT / "scripts/refresh_production_config.sh").read_text()
        self.assertIn("btrim(setting)", script)
        self.assertIn("setting::jsonb", script)
        self.assertNotIn("btrim(other)", script)

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

    def test_live_inventory_includes_cursor_agent_v1_as_a_distinct_route(self):
        routes, models = build_live_inventory(
            channels=[
                {
                    "id": 301,
                    "type": 64,
                    "status": 1,
                    "models": "claude-opus-5",
                    "test_model": "claude-opus-5",
                }
            ],
            public_models={"claude-opus-5"},
            base_url="https://beefapi.example",
            token_env="TEST_TOKEN",
            group="cursor-agent-v1-acceptance",
        )

        self.assertEqual(1, len(routes["routes"]))
        route = routes["routes"][0]
        self.assertEqual("cursor-agent-v1-channel-301", route["id"])
        self.assertEqual(64, route["channel_type"])
        self.assertEqual(301, route["channel_id"])
        self.assertIn("messages.trailing_system", route["capabilities"])
        self.assertIn("client.trailing_system", route["capabilities"])
        self.assertEqual(["claude-opus-5"], [item["id"] for item in models["models"]])

    def test_trailing_system_scenarios_compile_only_for_cursor_agent_v1(self):
        routes, models = build_live_inventory(
            channels=[
                {
                    "id": 271,
                    "type": 62,
                    "status": 1,
                    "models": "claude-opus-5",
                    "test_model": "claude-opus-5",
                },
                {
                    "id": 301,
                    "type": 64,
                    "status": 1,
                    "models": "claude-opus-5",
                    "test_model": "claude-opus-5",
                },
            ],
            public_models={"claude-opus-5"},
            base_url="https://beefapi.example",
            token_env="TEST_TOKEN",
            group="cursor-agent-v1-acceptance",
        )
        with tempfile.TemporaryDirectory() as tmp:
            routes_path = Path(tmp) / "routes.json"
            models_path = Path(tmp) / "models.json"
            routes_path.write_text(json.dumps(routes))
            models_path.write_text(json.dumps(models))
            inventory = load_inventory(ROOT, routes_path, models_path)

        cells = compile_matrix(inventory, "release", coverage="full")
        trailing_cells = [
            cell
            for cell in cells
            if cell.scenario.id
            in {"messages-trailing-system", "claude-code-dynamic-system"}
        ]
        self.assertTrue(trailing_cells)
        self.assertEqual(
            {"cursor-agent-v1-channel-301"},
            {cell.route.id for cell in trailing_cells},
        )
        self.assertTrue(
            any(
                cell.client.id == "raw-http"
                and cell.scenario.id == "messages-trailing-system"
                for cell in trailing_cells
            )
        )
        self.assertTrue(
            any(
                cell.client.id == "claude-code"
                and cell.scenario.id == "claude-code-dynamic-system"
                for cell in trailing_cells
            )
        )

    def test_cursor_agent_v1_web_capability_follows_sanitized_channel_policy(self):
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

    def test_representative_matrix_covers_routes_models_clients_and_deep_cases(self):
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
        raw_responses = {
            (cell.route.id, cell.model.id)
            for cell in cells
            if cell.client.id == "raw-http" and cell.scenario.id == "responses-text"
        }
        self.assertEqual(
            {
                (route.id, model.id)
                for route in inventory.routes
                for model in inventory.models
                if route.id in model.routes
            },
            raw_responses,
        )
        for route in inventory.routes:
            route_cells = [cell for cell in cells if cell.route.id == route.id]
            self.assertTrue(
                {"responses-text", "messages-text", "chat-text"}.issubset(
                    {
                        cell.scenario.id
                        for cell in route_cells
                        if cell.client.id == "raw-http"
                    }
                )
            )
            for client_id in ("claude-code", "codex-cli", "grok-build"):
                self.assertTrue(
                    any(
                        cell.client.id == client_id
                        and cell.model.id == route.test_model
                        and cell.scenario.id == "text-turn"
                        for cell in route_cells
                    )
                )
            self.assertEqual(
                {"local-tool-read", "session-resume", "native-web-search"},
                {
                    cell.scenario.id
                    for cell in route_cells
                    if cell.scenario.id
                    in {"local-tool-read", "session-resume", "native-web-search"}
                },
            )
        for model in inventory.models:
            self.assertTrue(
                any(
                    cell.model.id == model.id
                    and cell.client.id != "raw-http"
                    and cell.scenario.id == "text-turn"
                    for cell in cells
                )
            )

    def test_production_shaped_representative_matrix_stays_bounded(self):
        channels = [
            {
                "id": 250 + route_index,
                "type": 62,
                "status": 1,
                "models": ",".join(
                    f"route-{route_index}-model-{model_index}"
                    for model_index in range(4)
                ),
                "test_model": f"route-{route_index}-model-0",
            }
            for route_index in range(6)
        ]
        public_models = {
            f"route-{route_index}-model-{model_index}"
            for route_index in range(6)
            for model_index in range(4)
        }
        routes, models = build_live_inventory(
            channels,
            public_models,
            "https://beefapi.example",
            "TEST_TOKEN",
            "cursor-acceptance",
        )
        with tempfile.TemporaryDirectory() as tmp:
            routes_path = Path(tmp) / "routes.json"
            models_path = Path(tmp) / "models.json"
            routes_path.write_text(json.dumps(routes))
            models_path.write_text(json.dumps(models))
            inventory = load_inventory(ROOT, routes_path, models_path)
        cells = compile_matrix(inventory, "nightly", coverage="representative")
        self.assertLessEqual(len(cells), 150)

    def test_channel_pin_is_explicit_and_conflict_safe(self):
        cell = CommandTests().cell("codex")
        route = replace(cell.route, channel_id=252, pin_channel=True)
        pinned = MatrixCell(cell.client, route, cell.model, cell.scenario)
        self.assertEqual("test-token-252", _request_token(pinned, "test-token"))
        self.assertEqual("test-token-252", _request_token(pinned, "test-token-252"))
        with self.assertRaisesRegex(RuntimeError, "already pinned to channel 271"):
            _request_token(pinned, "test-token-271")

    def test_token_log_evidence_requires_exact_route_and_final_receipt(self):
        cell = CommandTests().cell("codex")
        route = replace(
            cell.route,
            id="cursor-channel-252",
            channel_id=252,
            pin_channel=True,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
        )
        cell = MatrixCell(cell.client, route, cell.model, cell.scenario)
        log = {
            "created_at": 200,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": "req-252",
            "prompt_tokens": 10,
            "completion_tokens": 2,
            "quota": 3,
            "use_time": 1,
            "other": json.dumps(
                {
                    "usage_receipt_id": "cursor-sdk-bridge:receipt",
                    "usage_receipt_provider": "cursor-sdk-bridge",
                    "usage_receipt_state": "final",
                }
            ),
        }
        self.assertIs(log, _matching_usage_log(cell, [log], 200))
        self.assertIsNone(_matching_usage_log(cell, [log], 200, {"req-252"}))
        payload = _usage_log_payload(cell, log, "commit-sha")
        self.assertEqual("pass", payload["status"])
        self.assertEqual(252, payload["route"]["channel_id"])
        self.assertEqual("final", payload["receipt"]["state"])

    def test_token_log_matching_rejects_empty_and_ambiguous_request_ids(self):
        cell = CommandTests().cell("codex")
        route = replace(
            cell.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
        )
        cell = MatrixCell(cell.client, route, cell.model, cell.scenario)
        base = {
            "created_at": 200,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
        }
        self.assertEqual(
            [], _matching_usage_logs(cell, [{**base, "request_id": ""}], 200)
        )
        matches = _matching_usage_logs(
            cell,
            [
                {**base, "request_id": "req-a"},
                {**base, "request_id": "req-b"},
            ],
            200,
        )
        self.assertEqual(["req-a", "req-b"], [item["request_id"] for item in matches])
        exact = _matching_usage_logs(
            cell,
            matches,
            200,
            expected_request_id="req-b",
        )
        self.assertEqual(["req-b"], [item["request_id"] for item in exact])

    def test_native_tool_loop_accepts_multiple_final_request_ids(self):
        cell = CommandTests().cell("codex")
        route = replace(
            cell.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
        )
        cell = MatrixCell(cell.client, route, cell.model, cell.scenario)
        logs = []
        for request_id in ("tool-call", "tool-result"):
            logs.append(
                {
                    "created_at": 200,
                    "type": 2,
                    "model_name": "model",
                    "channel": 252,
                    "group": "cursor-acceptance",
                    "request_id": request_id,
                    "other": json.dumps(
                        {
                            "usage_receipt_id": request_id,
                            "usage_receipt_provider": "cursor-sdk-bridge",
                            "usage_receipt_state": "final",
                        }
                    ),
                }
            )
        response = FakeResponse(
            {"success": True, "data": logs},
            {"X-New-Api-Commit": "commit-sha"},
        )
        with patch("urllib.request.urlopen", return_value=response):
            payload = _beefapi_token_log_evidence(cell, "token", 200, set())
        self.assertEqual("pass", payload["status"])
        self.assertEqual(2, len(payload["requests"]))

    def test_token_log_evidence_waits_for_final_receipt(self):
        cell = CommandTests().cell("codex")
        route = replace(
            cell.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
        )
        cell = MatrixCell(cell.client, route, cell.model, cell.scenario)
        base_log = {
            "created_at": 200,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": "req-252",
        }
        provisional = {
            **base_log,
            "other": json.dumps(
                {
                    "usage_receipt_id": "receipt",
                    "usage_receipt_state": "provisional",
                }
            ),
        }
        final = {
            **base_log,
            "other": json.dumps(
                {
                    "usage_receipt_id": "receipt",
                    "usage_receipt_provider": "cursor-sdk-bridge",
                    "usage_receipt_state": "final",
                }
            ),
        }
        responses = [
            FakeResponse(
                {"success": True, "data": [provisional]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {"success": True, "data": [final]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        with (
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            patch("time.sleep"),
        ):
            payload = _beefapi_token_log_evidence(
                cell,
                "token",
                200,
                set(),
                "req-252",
            )
        self.assertEqual("pass", payload["status"])
        self.assertEqual(2, urlopen.call_count)

    def test_token_log_fence_requires_success_true(self):
        cell = CommandTests().cell("codex")
        route = replace(cell.route, evidence_provider="beefapi_token_log")
        cell = MatrixCell(cell.client, route, cell.model, cell.scenario)
        with patch(
            "urllib.request.urlopen",
            return_value=FakeResponse({"success": False, "data": []}),
        ):
            self.assertIsNone(_evidence_fence(cell, "token"))

    def test_batch_evidence_uses_two_log_reads_for_multiple_cells(self):
        native = CommandTests().cell("codex")
        raw = CommandTests().cell("raw-http")
        route = replace(
            native.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        native = MatrixCell(native.client, route, native.model, native.scenario)
        raw = MatrixCell(raw.client, route, raw.model, raw.scenario)
        native = MatrixCell(
            replace(native.client, id="codex-cli"),
            native.route,
            native.model,
            native.scenario,
        )
        raw = MatrixCell(
            replace(raw.client, id="raw-http"), raw.route, raw.model, raw.scenario
        )
        receipt = {
            "usage_receipt_provider": "cursor-sdk-bridge",
            "usage_receipt_state": "final",
        }
        old_log = {
            "created_at": 100,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": "old",
            "other": json.dumps({**receipt, "usage_receipt_id": "old"}),
        }
        native_log = {
            **old_log,
            "created_at": 200,
            "request_id": "native-new",
            "other": json.dumps({**receipt, "usage_receipt_id": "native"}),
        }
        raw_log = {
            **old_log,
            "created_at": 201,
            "request_id": "raw-new",
            "other": json.dumps({**receipt, "usage_receipt_id": "raw"}),
        }
        responses = [
            FakeResponse(
                {"success": True, "data": [old_log]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {"success": True, "data": [raw_log, native_log, old_log]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        results = [
            CellResult(
                native.id,
                "pass",
                "client",
                "now",
                1,
                route.id,
                native.model.id,
                native.scenario.id,
                [],
                {
                    "server_evidence": {"status": "deferred"},
                    "_server_window": {
                        "started_epoch": 199,
                        "finished_epoch": 200,
                    },
                },
            ),
            CellResult(
                raw.id,
                "pass",
                "client",
                "now",
                1,
                route.id,
                raw.model.id,
                raw.scenario.id,
                [],
                {
                    "server_evidence": {"status": "deferred"},
                    "_response_request_id": "raw-new",
                    "_server_window": {
                        "started_epoch": 201,
                        "finished_epoch": 201,
                    },
                },
            ),
        ]
        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
        ):
            sessions = prepare_batch_server_evidence([native, raw])
            finalize_batch_server_evidence([native, raw], results, sessions)
        self.assertEqual(2, urlopen.call_count)
        self.assertEqual(["pass", "pass"], [item.status for item in results])
        self.assertTrue(
            all(
                item.evidence["server_evidence"]["status"] == "pass" for item in results
            )
        )

    def test_batch_evidence_keeps_native_tool_logs_in_their_time_window(self):
        first = CommandTests().cell("codex")
        second = CommandTests().cell("grok-build")
        route = replace(
            first.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        first = MatrixCell(
            replace(first.client, id="codex-cli"),
            route,
            first.model,
            first.scenario,
        )
        second = MatrixCell(
            replace(second.client, id="grok-build"),
            route,
            second.model,
            second.scenario,
        )
        receipt = {
            "usage_receipt_provider": "cursor-sdk-bridge",
            "usage_receipt_state": "final",
        }

        def log(request_id: str, created_at: int):
            return {
                "created_at": created_at,
                "type": 2,
                "model_name": "model",
                "channel": 252,
                "group": "cursor-acceptance",
                "request_id": request_id,
                "other": json.dumps({**receipt, "usage_receipt_id": request_id}),
            }

        old = log("old", 100)
        responses = [
            FakeResponse(
                {"success": True, "data": [old]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {
                    "success": True,
                    "data": [
                        log("second-only", 211),
                        log("first-followup", 200),
                        log("first-tool", 199),
                        {
                            **log("first-provisional", 199),
                            "other": json.dumps(
                                {
                                    "usage_receipt_id": "first-provisional",
                                    "usage_receipt_state": "provisional",
                                }
                            ),
                        },
                        old,
                    ],
                },
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        results = [
            CellResult(
                first.id,
                "pass",
                "client",
                "now",
                1,
                route.id,
                first.model.id,
                first.scenario.id,
                [],
                {
                    "server_evidence": {"status": "deferred"},
                    "_server_window": {
                        "started_epoch": 199,
                        "finished_epoch": 200,
                    },
                },
            ),
            CellResult(
                second.id,
                "pass",
                "client",
                "now",
                1,
                route.id,
                second.model.id,
                second.scenario.id,
                [],
                {
                    "server_evidence": {"status": "deferred"},
                    "_server_window": {
                        "started_epoch": 210,
                        "finished_epoch": 211,
                    },
                },
            ),
        ]
        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses),
        ):
            sessions = prepare_batch_server_evidence([first, second])
            finalize_batch_server_evidence([first, second], results, sessions)
        first_ids = {
            item["terminal"]["request_id"]
            for item in results[0].evidence["server_evidence"]["requests"]
        }
        second_id = results[1].evidence["server_evidence"]["terminal"]["request_id"]
        self.assertEqual({"first-tool", "first-followup"}, first_ids)
        self.assertEqual(1, results[0].evidence["server_evidence"]["provisional_count"])
        self.assertEqual("second-only", second_id)
        self.assertNotIn(second_id, first_ids)


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
    def test_raw_http_messages_can_replay_trailing_system_context(self):
        received: list[dict] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                request = json.loads(self.rfile.read(length))
                received.append(request)
                roles = [message.get("role") for message in request.get("messages", [])]
                system = request.get("system", "")
                is_claude_code = (
                    "x-anthropic-billing-header: cc_version=" in system
                    and "cc_entrypoint=sdk-cli;" in system
                )
                status = 200 if roles == ["user", "system"] and is_claude_code else 400
                body = json.dumps(
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": "BEEFAPI_TRAILING_SYSTEM_OK",
                            }
                        ]
                    }
                ).encode()
                self.send_response(status)
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
                frozenset({"text", "messages"}),
                frozenset({"darwin"}),
            )
            route = Route(
                "cursor-agent-v1-channel-301",
                "Cursor Agent v1",
                "gateway_token",
                f"http://127.0.0.1:{server.server_port}",
                None,
                "RAW_HTTP_TEST_TOKEN",
                frozenset({"raw-http"}),
                frozenset({"messages"}),
                frozenset({"text", "messages"}),
                None,
            )
            model = Model(
                "claude-opus-5",
                "Claude Opus 5",
                frozenset({route.id}),
                frozenset({client.id}),
                frozenset({"text", "messages"}),
                {},
            )
            scenario = Scenario.parse(
                {
                    "id": "messages-trailing-system",
                    "name": "Claude Code dynamic system context after user",
                    "tier": "pr",
                    "kind": "http",
                    "protocol": "messages",
                    "http_endpoint": "/v1/messages",
                    "required_capabilities": ["messages", "text"],
                    "timeout_seconds": 10,
                    "requires_local_tools": False,
                    "http_payload": {
                        "model": "{{model}}",
                        "max_tokens": 128,
                        "system": "x-anthropic-billing-header: cc_version=2.1.233; cc_entrypoint=sdk-cli;",
                        "messages": [
                            {"role": "user", "content": "{{prompt}}"},
                            {
                                "role": "system",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Available agent types and skills",
                                    }
                                ],
                            },
                        ],
                    },
                    "turns": [
                        {
                            "prompt": "Reply exactly BEEFAPI_TRAILING_SYSTEM_OK.",
                            "marker": "BEEFAPI_TRAILING_SYSTEM_OK",
                            "expected_events": [],
                        }
                    ],
                }
            )
            os.environ["RAW_HTTP_TEST_TOKEN"] = "plain-test-token"
            result = run_cell(MatrixCell(client, route, model, scenario))
            self.assertEqual("pass", result.status, result)
            self.assertEqual(
                ["user", "system"],
                [message["role"] for message in received[0]["messages"]],
            )
        finally:
            os.environ.pop("RAW_HTTP_TEST_TOKEN", None)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

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
        cell = MatrixCell(
            replace(
                cell.client,
                binary_candidates=(str(ROOT / "tests/fixtures/mock_agent.py"),),
            ),
            cell.route,
            cell.model,
            cell.scenario,
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
