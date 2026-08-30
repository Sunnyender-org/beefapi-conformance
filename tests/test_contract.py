from __future__ import annotations

import errno
import http.server
import json
import os
import sys
import tempfile
import threading
import tomllib
import unittest
from argparse import Namespace
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from portable import MOCK_AGENT, git_bash_windows, mock_agent_candidates

from beefapi_conformance.cli import (
    _build_run_report,
    _write_run_checkpoint,
    command_run,
)
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
from beefapi_conformance.report import build_report, write_report
from beefapi_conformance.runner import (
    AGENT_V1_RESPONSE_ID,
    _beefapi_token_log_evidence,
    _evidence_fence,
    _matching_usage_log,
    _matching_usage_logs,
    _request_token,
    _usage_log_payload,
    finalize_batch_server_evidence,
    native_window_schedule_gap,
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

    def test_agent_v1_request_id_extraction_requires_response_id_field(self):
        request_id = "202608291253521598208738268d9d67sN73Cgw"
        public_id = f"resp_bf_agentv1_u1_c301_{request_id}"
        self.assertEqual(
            [request_id],
            AGENT_V1_RESPONSE_ID.findall(json.dumps({"id": public_id})),
        )
        self.assertEqual([], AGENT_V1_RESPONSE_ID.findall(public_id))

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

    def test_native_web_search_requires_positive_observed_search_evidence(self):
        base = CommandTests().cell("codex")
        cell = MatrixCell(
            base.client,
            replace(base.route, channel_type=64),
            base.model,
            replace(base.scenario, id="native-web-search"),
        )
        log = {
            "type": 2,
            "request_id": "req-search",
            "other": json.dumps(
                {
                    "usage_receipt_id": "cursor-agent-v1:receipt",
                    "usage_receipt_provider": "cursor-agent-v1",
                    "usage_receipt_state": "final",
                }
            ),
        }
        missing = _usage_log_payload(cell, log, "commit-sha")
        self.assertEqual("fail", missing["status"])
        self.assertIn("no observed search call", missing["detail"])

        log["other"] = json.dumps(
            {
                "usage_receipt_id": "cursor-agent-v1:receipt",
                "usage_receipt_provider": "cursor-agent-v1",
                "usage_receipt_state": "final",
                "cursor_agent_v1_hosted_search_call_count": 1,
            }
        )
        count_only = _usage_log_payload(cell, log, "commit-sha")
        self.assertEqual("fail", count_only["status"])
        self.assertRegex(count_only["detail"], "progress|citation")

        log["other"] = json.dumps(
            {
                "usage_receipt_id": "cursor-agent-v1:receipt",
                "usage_receipt_provider": "cursor-agent-v1",
                "usage_receipt_state": "final",
                "cursor_agent_v1_hosted_search_call_count": 1,
                "cursor_agent_v1_hosted_search_citation_count": 2,
                "cursor_agent_v1_hosted_search_progress_events": 3,
            }
        )
        present = _usage_log_payload(cell, log, "commit-sha")
        self.assertEqual("pass", present["status"])
        self.assertEqual(1, present["usage"]["web_search_call_count"])
        self.assertEqual(2, present["usage"]["citation_count"])
        self.assertNotIn("cursor-agent-v1:receipt", json.dumps(present))

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
                    "_response_request_ids": [
                        "first-tool",
                        "first-followup",
                        "first-provisional",
                    ],
                    "_server_window": {
                        "started_epoch": 199,
                        "finished_epoch": 198,
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
                    "_response_request_ids": ["second-only"],
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
        from beefapi_conformance.cursor_agent_v1 import correlate_id

        first_ids = {
            item["terminal"]["http_request_id_hash"]
            for item in results[0].evidence["server_evidence"]["requests"]
        }
        second_id = results[1].evidence["server_evidence"]["terminal"][
            "http_request_id_hash"
        ]
        self.assertEqual(
            {correlate_id("first-tool"), correlate_id("first-followup")}, first_ids
        )
        self.assertEqual(1, results[0].evidence["server_evidence"]["provisional_count"])
        self.assertEqual(correlate_id("second-only"), second_id)
        self.assertNotIn(second_id, first_ids)
        self.assertNotIn(
            "first-tool", json.dumps(results[0].evidence["server_evidence"])
        )

    def test_batch_evidence_rereads_empty_snapshot_until_final_receipt(self):
        native = CommandTests().cell("codex")
        route = replace(
            native.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        native = MatrixCell(
            replace(native.client, id="codex-cli"),
            route,
            native.model,
            native.scenario,
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
        final_log = {
            **old_log,
            "created_at": 200,
            "request_id": "native-new",
            "other": json.dumps({**receipt, "usage_receipt_id": "native"}),
        }
        result = CellResult(
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
        )
        responses = [
            FakeResponse(
                {"success": True, "data": [old_log]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {"success": True, "data": []},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {"success": True, "data": [old_log, final_log]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            patch("time.sleep") as slept,
        ):
            sessions = prepare_batch_server_evidence([native])
            finalize_batch_server_evidence([native], [result], sessions)
        self.assertEqual("pass", result.status, result.detail)
        self.assertEqual("pass", result.evidence["server_evidence"]["status"])
        self.assertEqual(3, urlopen.call_count)
        self.assertGreaterEqual(slept.call_count, 1)

    def test_batch_evidence_duplicate_request_id_does_not_pass(self):
        raw = CommandTests().cell("raw-http")
        route = replace(
            raw.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        raw = MatrixCell(
            replace(raw.client, id="raw-http"), route, raw.model, raw.scenario
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

        def log(request_id: str, receipt_id: str):
            return {
                **old_log,
                "created_at": 201,
                "request_id": request_id,
                "other": json.dumps({**receipt, "usage_receipt_id": receipt_id}),
            }

        result = CellResult(
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
        )
        responses = [
            FakeResponse(
                {"success": True, "data": [old_log]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {
                    "success": True,
                    "data": [
                        old_log,
                        log("raw-new", "raw-a"),
                        log("raw-new", "raw-b"),
                    ],
                },
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            patch("time.sleep") as slept,
        ):
            sessions = prepare_batch_server_evidence([raw])
            finalize_batch_server_evidence([raw], [result], sessions)
        self.assertEqual("fail", result.status)
        self.assertEqual("fail", result.evidence["server_evidence"]["status"])
        self.assertEqual(2, urlopen.call_count)
        slept.assert_not_called()
        self.assertEqual(
            2, result.evidence["server_evidence"].get("consume_match_count")
        )
        self.assertNotIn("raw-new", json.dumps(result.evidence["server_evidence"]))

    def test_batch_snapshot_does_not_stitch_partial_session_reads(self):
        cell_a = CommandTests().cell("raw-http")
        cell_b = CommandTests().cell("raw-http")
        receipt = {
            "usage_receipt_provider": "cursor-sdk-bridge",
            "usage_receipt_state": "final",
        }
        route_a = replace(
            cell_a.route,
            id="route-a",
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
            base_url="https://a.example",
        )
        route_b = replace(
            cell_b.route,
            id="route-b",
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
            base_url="https://b.example",
        )
        cell_a = MatrixCell(
            replace(cell_a.client, id="raw-http-a"),
            route_a,
            cell_a.model,
            cell_a.scenario,
        )
        cell_b = MatrixCell(
            replace(cell_b.client, id="raw-http-b"),
            route_b,
            cell_b.model,
            cell_b.scenario,
        )

        def log(request_id: str, created_at: int = 200):
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
        result_a = CellResult(
            cell_a.id,
            "pass",
            "client",
            "now",
            1,
            route_a.id,
            cell_a.model.id,
            cell_a.scenario.id,
            [],
            {
                "server_evidence": {"status": "deferred"},
                "_response_request_id": "req-a",
            },
        )
        result_b = CellResult(
            cell_b.id,
            "pass",
            "client",
            "now",
            1,
            route_b.id,
            cell_b.model.id,
            cell_b.scenario.id,
            [],
            {
                "server_evidence": {"status": "deferred"},
                "_response_request_id": "req-b",
            },
        )
        calls = {"a": 0, "b": 0}

        def fake_urlopen(request, timeout=0):
            host = "a" if "a.example" in request.full_url else "b"
            calls[host] += 1
            headers = {"X-New-Api-Commit": "commit-sha"}
            if host == "a":
                if calls[host] <= 2:
                    return FakeResponse({"success": True, "data": [old]}, headers)
                return FakeResponse(
                    {"success": True, "data": [old, log("req-a")]}, headers
                )
            if calls[host] == 1:
                return FakeResponse({"success": True, "data": [old]}, headers)
            if calls[host] == 2:
                return FakeResponse(
                    {"success": True, "data": [old, log("req-b")]}, headers
                )
            raise OSError("session b token-log unavailable")

        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
            patch("time.sleep"),
        ):
            sessions = prepare_batch_server_evidence([cell_a, cell_b])
            finalize_batch_server_evidence(
                [cell_a, cell_b], [result_a, result_b], sessions
            )
        self.assertEqual("fail", result_a.status)
        self.assertNotEqual(["pass", "pass"], [result_a.status, result_b.status])

    def test_batch_conflict_stays_failed_after_later_clean_snapshot(self):
        first = CommandTests().cell("raw-http")
        second = CommandTests().cell("raw-http")
        route = replace(
            first.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        first = MatrixCell(
            replace(first.client, id="raw-x"), route, first.model, first.scenario
        )
        second = MatrixCell(
            replace(second.client, id="raw-y"), route, second.model, second.scenario
        )
        receipt = {
            "usage_receipt_provider": "cursor-sdk-bridge",
            "usage_receipt_state": "final",
        }

        def log(request_id: str, extra: str = ""):
            return {
                "created_at": 200,
                "type": 2,
                "model_name": "model",
                "channel": 252,
                "group": "cursor-acceptance",
                "request_id": request_id,
                "other": json.dumps(
                    {**receipt, "usage_receipt_id": request_id + extra}
                ),
            }

        old = {**log("old"), "created_at": 100}
        result_x = CellResult(
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
                "_response_request_id": "req-x",
            },
        )
        result_y = CellResult(
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
                "_response_request_id": "req-y",
            },
        )
        responses = [
            FakeResponse(
                {"success": True, "data": [old]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {
                    "success": True,
                    "data": [old, log("req-x", "-a"), log("req-x", "-b")],
                },
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {
                    "success": True,
                    "data": [old, log("req-x"), log("req-y")],
                },
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses),
            patch("time.sleep"),
        ):
            sessions = prepare_batch_server_evidence([first, second])
            finalize_batch_server_evidence(
                [first, second], [result_x, result_y], sessions
            )
        self.assertEqual("fail", result_x.status)
        self.assertEqual("pass", result_y.status, result_y.detail)

    def test_native_exact_ids_require_every_id_not_turn_count(self):
        native = CommandTests().cell("codex")
        route = replace(
            native.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        native = MatrixCell(
            replace(native.client, id="codex-cli"),
            route,
            native.model,
            native.scenario,
        )
        receipt = {
            "usage_receipt_provider": "cursor-sdk-bridge",
            "usage_receipt_state": "final",
        }
        old = {
            "created_at": 100,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": "old",
            "other": json.dumps({**receipt, "usage_receipt_id": "old"}),
        }
        only_a = {
            **old,
            "created_at": 200,
            "request_id": "req-a",
            "other": json.dumps({**receipt, "usage_receipt_id": "a"}),
        }
        result = CellResult(
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
                "_response_request_ids": ["req-a", "req-b"],
                "_server_window": {"started_epoch": 199, "finished_epoch": 200},
            },
        )
        seen = {"n": 0}

        def fake_urlopen(request, timeout=0):
            seen["n"] += 1
            data = [old] if seen["n"] == 1 else [old, only_a]
            return FakeResponse(
                {"success": True, "data": data},
                {"X-New-Api-Commit": "commit-sha"},
            )

        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
            patch("time.sleep"),
        ):
            sessions = prepare_batch_server_evidence([native])
            finalize_batch_server_evidence([native], [result], sessions)
        self.assertEqual("fail", result.status)

    def test_window_cell_cannot_steal_later_exact_request_id(self):
        window_cell = CommandTests().cell("codex")
        exact_cell = CommandTests().cell("raw-http")
        route = replace(
            window_cell.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        window_cell = MatrixCell(
            replace(window_cell.client, id="codex-cli"),
            route,
            window_cell.model,
            window_cell.scenario,
        )
        exact_cell = MatrixCell(
            replace(exact_cell.client, id="raw-http"),
            route,
            exact_cell.model,
            exact_cell.scenario,
        )
        receipt = {
            "usage_receipt_provider": "cursor-sdk-bridge",
            "usage_receipt_state": "final",
        }
        old = {
            "created_at": 100,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": "old",
            "other": json.dumps({**receipt, "usage_receipt_id": "old"}),
        }
        shared = {
            **old,
            "created_at": 200,
            "request_id": "req-b",
            "other": json.dumps({**receipt, "usage_receipt_id": "b"}),
        }
        window_result = CellResult(
            window_cell.id,
            "pass",
            "client",
            "now",
            1,
            route.id,
            window_cell.model.id,
            window_cell.scenario.id,
            [],
            {
                "server_evidence": {"status": "deferred"},
                "_server_window": {"started_epoch": 200, "finished_epoch": 200},
            },
        )
        exact_result = CellResult(
            exact_cell.id,
            "pass",
            "client",
            "now",
            1,
            route.id,
            exact_cell.model.id,
            exact_cell.scenario.id,
            [],
            {
                "server_evidence": {"status": "deferred"},
                "_response_request_id": "req-b",
                "_server_window": {"started_epoch": 200, "finished_epoch": 200},
            },
        )
        seen = {"n": 0}

        def fake_urlopen(request, timeout=0):
            seen["n"] += 1
            data = [old] if seen["n"] == 1 else [old, shared]
            return FakeResponse(
                {"success": True, "data": data},
                {"X-New-Api-Commit": "commit-sha"},
            )

        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
            patch("time.sleep"),
        ):
            sessions = prepare_batch_server_evidence([window_cell, exact_cell])
            finalize_batch_server_evidence(
                [window_cell, exact_cell],
                [window_result, exact_result],
                sessions,
            )
        self.assertEqual("fail", window_result.status)
        self.assertEqual("pass", exact_result.status, exact_result.detail)

    def test_batch_empty_then_provisional_then_final_passes(self):
        native = CommandTests().cell("codex")
        route = replace(
            native.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        native = MatrixCell(
            replace(native.client, id="codex-cli"),
            route,
            native.model,
            native.scenario,
        )
        receipt = {
            "usage_receipt_provider": "cursor-sdk-bridge",
            "usage_receipt_state": "final",
        }
        old = {
            "created_at": 100,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": "old",
            "other": json.dumps({**receipt, "usage_receipt_id": "old"}),
        }
        provisional = {
            **old,
            "created_at": 200,
            "request_id": "native-new",
            "other": json.dumps(
                {
                    "usage_receipt_id": "native",
                    "usage_receipt_state": "provisional",
                }
            ),
        }
        final = {
            **old,
            "created_at": 200,
            "request_id": "native-new",
            "other": json.dumps({**receipt, "usage_receipt_id": "native"}),
        }
        result = CellResult(
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
                "_server_window": {"started_epoch": 199, "finished_epoch": 200},
            },
        )
        responses = [
            FakeResponse(
                {"success": True, "data": [old]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {"success": True, "data": []},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {"success": True, "data": [old, provisional]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {"success": True, "data": [old, final]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses),
            patch("time.sleep"),
        ):
            sessions = prepare_batch_server_evidence([native])
            finalize_batch_server_evidence([native], [result], sessions)
        self.assertEqual("pass", result.status, result.detail)

    def test_batch_rejects_cross_route_model_and_token_logs(self):
        native = CommandTests().cell("codex")
        route = replace(
            native.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        native = MatrixCell(
            replace(native.client, id="codex-cli"),
            route,
            native.model,
            native.scenario,
        )
        receipt = {
            "usage_receipt_provider": "cursor-sdk-bridge",
            "usage_receipt_state": "final",
        }
        old = {
            "created_at": 100,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": "old",
            "other": json.dumps({**receipt, "usage_receipt_id": "old"}),
        }
        wrong_model = {
            **old,
            "created_at": 200,
            "model_name": "other-model",
            "request_id": "native-new",
        }
        wrong_channel = {
            **old,
            "created_at": 200,
            "channel": 999,
            "request_id": "native-new",
        }
        result = CellResult(
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
                "_response_request_id": "native-new",
                "_server_window": {"started_epoch": 199, "finished_epoch": 200},
            },
        )
        for alien in (wrong_model, wrong_channel):
            with self.subTest(
                channel=alien.get("channel"), model=alien.get("model_name")
            ):
                target = CellResult(
                    result.cell_id,
                    "pass",
                    "client",
                    "now",
                    1,
                    result.route_id,
                    result.model_id,
                    result.scenario_id,
                    [],
                    {
                        "server_evidence": {"status": "deferred"},
                        "_response_request_id": "native-new",
                        "_server_window": {
                            "started_epoch": 199,
                            "finished_epoch": 200,
                        },
                    },
                )
                counter = {"n": 0}

                def fake_urlopen(request, timeout=0, snapshot=alien, state=counter):
                    state["n"] += 1
                    data = [old] if state["n"] == 1 else [old, snapshot]
                    return FakeResponse(
                        {"success": True, "data": data},
                        {"X-New-Api-Commit": "commit-sha"},
                    )

                with (
                    patch.dict(os.environ, {"TOKEN": "token"}),
                    patch("urllib.request.urlopen", side_effect=fake_urlopen),
                    patch("time.sleep"),
                ):
                    sessions = prepare_batch_server_evidence([native])
                    finalize_batch_server_evidence([native], [target], sessions)
                self.assertEqual("fail", target.status)

    def test_raw_http_without_request_id_does_not_claim_neighbor_logs(self):
        raw = CommandTests().cell("raw-http")
        route = replace(
            raw.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        raw = MatrixCell(
            replace(raw.client, id="raw-http"), route, raw.model, raw.scenario
        )
        receipt = {
            "usage_receipt_provider": "cursor-sdk-bridge",
            "usage_receipt_state": "final",
        }
        neighbor = {
            "created_at": 200,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": "neighbor-final",
            "other": json.dumps({**receipt, "usage_receipt_id": "neighbor"}),
        }
        result = CellResult(
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
                "_server_window": {"started_epoch": 199, "finished_epoch": 201},
            },
        )
        responses = [
            FakeResponse(
                {"success": True, "data": []},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {"success": True, "data": [neighbor]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses),
            patch("time.sleep"),
        ):
            sessions = prepare_batch_server_evidence([raw])
            finalize_batch_server_evidence([raw], [result], sessions)
        self.assertEqual("fail", result.status)
        self.assertIn(
            "X-Oneapi-Request-Id", result.evidence["server_evidence"].get("detail", "")
        )

    def test_batch_error_redacts_opaque_token_and_raw_request_id(self):
        canary_token = "OPAQUE-CANARY-TOKEN-9f3a7c"
        canary_id = "req-canary-freeform-id-xyz"
        raw = CommandTests().cell("raw-http")
        route = replace(
            raw.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
        )
        raw = MatrixCell(
            replace(raw.client, id="raw-http"), route, raw.model, raw.scenario
        )
        result = CellResult(
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
                "_response_request_id": canary_id,
            },
        )
        seen = {"n": 0}

        def fake_urlopen(request, timeout=0):
            seen["n"] += 1
            if seen["n"] == 1:
                return FakeResponse(
                    {"success": True, "data": []},
                    {"X-New-Api-Commit": "commit-sha"},
                )
            raise RuntimeError(
                f"gateway rejected token={canary_token} request_id={canary_id}"
            )

        with (
            patch.dict(os.environ, {"TOKEN": canary_token}),
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
            patch("time.sleep"),
        ):
            sessions = prepare_batch_server_evidence([raw])
            finalize_batch_server_evidence([raw], [result], sessions)
        evidence = json.dumps(result.evidence)
        self.assertEqual("fail", result.status)
        self.assertNotIn(canary_token, evidence)
        self.assertNotIn(canary_id, evidence)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report"
            report = _build_run_report([result], "release", [raw])
            write_report(report, output)
            _write_run_checkpoint([result], "release", [raw], output)
            dumped = (output / "conformance.json").read_text(encoding="utf-8")
        self.assertNotIn(canary_token, dumped)
        self.assertNotIn(canary_id, dumped)
        self.assertNotIn(canary_token, json.dumps(report))

    def test_type64_exact_ids_each_require_final_receipt(self):
        native = CommandTests().cell("codex")
        route = replace(
            native.route,
            channel_id=252,
            group="cursor-acceptance",
            evidence_provider="beefapi_token_log",
            release_evidence_required=True,
            channel_type=64,
        )
        native = MatrixCell(
            replace(native.client, id="codex-cli"),
            route,
            native.model,
            native.scenario,
        )
        receipt = {
            "usage_receipt_provider": "cursor-agent-v1",
            "usage_receipt_state": "final",
        }
        old = {
            "created_at": 100,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": "old",
            "other": json.dumps({**receipt, "usage_receipt_id": "old"}),
        }
        final_a = {
            **old,
            "created_at": 200,
            "request_id": "req-a",
            "other": json.dumps({**receipt, "usage_receipt_id": "a"}),
        }
        provisional_b = {
            **old,
            "created_at": 200,
            "request_id": "req-b",
            "other": json.dumps(
                {
                    "usage_receipt_id": "b",
                    "usage_receipt_provider": "cursor-agent-v1",
                    "usage_receipt_state": "provisional",
                }
            ),
        }
        result = CellResult(
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
                "_response_request_ids": ["req-a", "req-b"],
                "_server_window": {"started_epoch": 199, "finished_epoch": 200},
            },
        )
        seen = {"n": 0}

        def fake_urlopen(request, timeout=0):
            seen["n"] += 1
            data = [old] if seen["n"] == 1 else [old, final_a, provisional_b]
            return FakeResponse(
                {"success": True, "data": data},
                {"X-New-Api-Commit": "commit-sha"},
            )

        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
            patch("time.sleep"),
        ):
            sessions = prepare_batch_server_evidence([native])
            finalize_batch_server_evidence([native], [result], sessions)
        self.assertEqual("fail", result.status)

    def test_overlapping_native_windows_both_fail(self):
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
        shared = {
            "created_at": 200,
            "type": 2,
            "model_name": "model",
            "channel": 252,
            "group": "cursor-acceptance",
            "request_id": "shared-window",
            "other": json.dumps({**receipt, "usage_receipt_id": "shared"}),
        }
        old = {**shared, "created_at": 100, "request_id": "old"}
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
                    "_server_window": {"started_epoch": 200, "finished_epoch": 200},
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
                    "_server_window": {"started_epoch": 200, "finished_epoch": 200},
                },
            ),
        ]
        responses = [
            FakeResponse(
                {"success": True, "data": [old]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            FakeResponse(
                {"success": True, "data": [old, shared]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        with (
            patch.dict(os.environ, {"TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses),
            patch("time.sleep"),
        ):
            sessions = prepare_batch_server_evidence([first, second])
            finalize_batch_server_evidence([first, second], results, sessions)
        self.assertEqual(["fail", "fail"], [item.status for item in results])
        self.assertIn(
            "ambiguous", results[0].evidence["server_evidence"].get("detail", "")
        )

    def test_native_window_schedule_gap_only_for_shared_evidence_natives(self):
        native = CommandTests().cell("codex")
        other = CommandTests().cell("codex")
        raw = CommandTests().cell("raw-http")
        route = replace(
            native.route,
            evidence_provider="beefapi_token_log",
            token_env="TOKEN",
            base_url="https://example.invalid",
        )
        other_route = replace(route, token_env="OTHER_TOKEN")
        first = MatrixCell(
            replace(native.client, id="codex-a"), route, native.model, native.scenario
        )
        second = MatrixCell(
            replace(other.client, id="codex-b"), route, other.model, other.scenario
        )
        raw_cell = MatrixCell(
            replace(raw.client, id="raw-http"), route, raw.model, raw.scenario
        )
        other_token = MatrixCell(
            replace(native.client, id="codex-c"),
            other_route,
            native.model,
            native.scenario,
        )
        self.assertTrue(native_window_schedule_gap(first, second))
        self.assertFalse(native_window_schedule_gap(first, raw_cell))
        self.assertFalse(native_window_schedule_gap(first, other_token))


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
            models = tomllib.loads(config)["models"]
            self.assertEqual(models["default"], models["session_summary"])
            env = command.environment()
            self.assertEqual("sk-private-value", env["BEEFAPI_CONFORMANCE_TOKEN"])
            self.assertNotIn("XAI_API_KEY", env)
            grok_command = command.command("hello", 1)
            self.assertIn("streaming-messages-json", grok_command)

    def test_grok_title_uses_selected_client_alias_not_builtin_default(self):
        cell = self.cell("grok-build")
        cell = replace(
            cell, model=replace(cell.model, aliases={cell.client.id: "custom-alias"})
        )
        with tempfile.TemporaryDirectory() as tmp:
            command = ClientCommand(
                cell, "/bin/echo", Path(tmp), "local-only", "http://localhost"
            )
            command.prepare()
            config = tomllib.loads((Path(tmp) / "client-home/config.toml").read_text())
            self.assertEqual(config["models"]["session_summary"], "custom-alias")
            self.assertEqual(config["model"]["custom-alias"]["model"], "custom-alias")

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
                        "role": "assistant",
                        "type": "message",
                        "content": [
                            {
                                "type": "text",
                                "text": "BEEFAPI_TRAILING_SYSTEM_OK",
                            }
                        ],
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
        client = Client(
            "mock",
            "Mock",
            "mock",
            mock_agent_candidates(),
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
                binary_candidates=mock_agent_candidates(),
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

    def test_workspace_teardown_failure_keeps_cell_result(self):
        client = Client(
            "mock",
            "Mock",
            "mock",
            mock_agent_candidates(),
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
        with (
            patch(
                "beefapi_conformance.runner.shutil.rmtree",
                side_effect=OSError(errno.ENOTEMPTY, "Directory not empty"),
            ),
            patch("beefapi_conformance.runner.time.sleep"),
        ):
            result = run_cell(
                MatrixCell(client, route, model, scenario), allow_local_tools=True
            )
        self.assertEqual("fail", result.status)
        self.assertIn("infrastructure", result.detail)
        self.assertEqual(1, len(result.turns))
        self.assertEqual("pass", result.turns[0].status)
        self.assertEqual(
            "workspace_cleanup_failed",
            result.evidence["infrastructure"]["teardown"],
        )
        self.assertEqual(errno.ENOTEMPTY, result.evidence["infrastructure"]["errno"])

    def _mock_tool_cell(self):
        client = Client(
            "mock",
            "Mock",
            "mock",
            mock_agent_candidates(),
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
        return MatrixCell(client, route, model, scenario)

    def test_transient_teardown_winerror32_then_success_keeps_pass(self):
        locked = OSError(errno.EACCES, "being used by another process")
        locked.winerror = 32
        with (
            patch(
                "beefapi_conformance.runner.shutil.rmtree",
                side_effect=[locked, None],
            ),
            patch("beefapi_conformance.runner.time.sleep") as slept,
        ):
            result = run_cell(self._mock_tool_cell(), allow_local_tools=True)
        self.assertEqual("pass", result.status, result.detail)
        self.assertNotIn("infrastructure", result.evidence)
        slept.assert_called()

    def test_transient_teardown_access_and_enotempty_then_success_keeps_pass(self):
        access = OSError(errno.EACCES, "Access is denied")
        access.winerror = 5
        empty = OSError(errno.ENOTEMPTY, "Directory not empty")
        empty.winerror = 145
        for err in (access, empty):
            with self.subTest(winerror=getattr(err, "winerror", None)):
                with (
                    patch(
                        "beefapi_conformance.runner.shutil.rmtree",
                        side_effect=[err, None],
                    ),
                    patch("beefapi_conformance.runner.time.sleep"),
                ):
                    result = run_cell(self._mock_tool_cell(), allow_local_tools=True)
                self.assertEqual("pass", result.status, result.detail)
                self.assertNotIn("infrastructure", result.evidence)

    def test_persistent_teardown_failure_preserves_failed_cell(self):
        locked = OSError(errno.EACCES, "being used by another process")
        locked.winerror = 32
        with (
            patch(
                "beefapi_conformance.runner.shutil.rmtree",
                side_effect=locked,
            ),
            patch("beefapi_conformance.runner.time.sleep"),
        ):
            result = run_cell(self._mock_tool_cell(), allow_local_tools=True)
        self.assertEqual("fail", result.status)
        self.assertEqual("pass", result.turns[0].status)
        self.assertEqual(32, result.evidence["infrastructure"]["winerror"])
        self.assertEqual(
            "workspace_cleanup_failed",
            result.evidence["infrastructure"]["teardown"],
        )

    def test_cli_checkpoint_redacts_private_ids_and_marks_unfinished(self):
        canary_token = "OPAQUE-CANARY-TOKEN-9f3a7c"
        cell = CommandTests().cell("mock")
        result = CellResult(
            cell.id,
            "pass",
            "client",
            "now",
            1,
            cell.route.id,
            cell.model.id,
            cell.scenario.id,
            [],
            {
                "_response_request_ids": ["req-raw-secret"],
                "_replay_attempts": [{"_http_request_id": "req-raw-secret"}],
                "server_evidence": {
                    "status": "deferred",
                    "detail": f"leaked {canary_token} req-raw-secret",
                },
            },
            f"leaked {canary_token}",
        )
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report"
            args = Namespace(
                tier="pr",
                allow_local_tools=False,
                require_server_evidence=True,
                max_cells=10,
                fail_fast=False,
                output=str(output),
            )
            with (
                patch.dict(os.environ, {"TOKEN": canary_token}),
                patch("beefapi_conformance.cli._matrix", return_value=[cell]),
                patch("beefapi_conformance.cli.run_cell", return_value=result),
                patch(
                    "beefapi_conformance.cli.prepare_batch_server_evidence",
                    return_value={
                        ("https://example.invalid", "TOKEN"): {"token": canary_token}
                    },
                ),
                patch(
                    "beefapi_conformance.cli.finalize_batch_server_evidence",
                    side_effect=RuntimeError("token-log unavailable"),
                ),
                self.assertRaises(RuntimeError),
            ):
                command_run(args)
            dumped = (output / "conformance.json").read_text(encoding="utf-8")
            payload = json.loads(dumped)
            self.assertTrue(payload["unfinished"])
            self.assertEqual("failed", payload["classification"])
            self.assertNotIn("req-raw-secret", dumped)
            self.assertNotIn(canary_token, dumped)
            self.assertNotIn("_replay_attempts", dumped)
            self.assertNotIn("_http_request_id", dumped)
            self.assertNotIn("_response_request_ids", dumped)

    def test_cli_checkpoint_is_unfinished_and_not_a_final_pass(self):
        cell = CommandTests().cell("mock")
        result = CellResult(
            cell.id,
            "pass",
            "client",
            "now",
            1,
            cell.route.id,
            cell.model.id,
            cell.scenario.id,
            [],
            {"server_evidence": {"status": "deferred"}},
        )
        writes: list[dict] = []

        def capture(report, output_dir):
            writes.append(json.loads(json.dumps(report)))
            write_report(report, output_dir)

        with tempfile.TemporaryDirectory() as tmp:
            args = Namespace(
                tier="pr",
                allow_local_tools=False,
                require_server_evidence=False,
                max_cells=10,
                fail_fast=False,
                output=str(Path(tmp) / "report"),
            )
            with (
                patch("beefapi_conformance.cli._matrix", return_value=[cell]),
                patch("beefapi_conformance.cli.run_cell", return_value=result),
                patch("beefapi_conformance.cli.write_report", side_effect=capture),
            ):
                code = command_run(args)
        self.assertEqual(0, code)
        self.assertGreaterEqual(len(writes), 2)
        checkpoint = writes[0]
        final = writes[-1]
        self.assertTrue(checkpoint["unfinished"])
        self.assertEqual("failed", checkpoint["classification"])
        self.assertNotEqual("passed", checkpoint["classification"])
        self.assertFalse(final.get("unfinished"))
        self.assertEqual("passed", final["classification"])

    def test_cli_sleeps_between_native_window_cells_sharing_evidence(self):
        native = CommandTests().cell("codex")
        route = replace(
            native.route,
            evidence_provider="beefapi_token_log",
            token_env="TOKEN",
            base_url="https://example.invalid",
        )
        first = MatrixCell(
            replace(native.client, id="codex-a"), route, native.model, native.scenario
        )
        second = MatrixCell(
            replace(native.client, id="codex-b"), route, native.model, native.scenario
        )
        raw = CommandTests().cell("raw-http")
        raw_cell = MatrixCell(
            replace(raw.client, id="raw-http"), route, raw.model, raw.scenario
        )

        def fake_run(cell, **_kwargs):
            return CellResult(
                cell.id,
                "pass",
                "client",
                "now",
                1,
                cell.route.id,
                cell.model.id,
                cell.scenario.id,
                [],
                {"server_evidence": {"status": "deferred"}},
            )

        with tempfile.TemporaryDirectory() as tmp:
            args = Namespace(
                tier="pr",
                allow_local_tools=False,
                require_server_evidence=True,
                max_cells=10,
                fail_fast=False,
                output=str(Path(tmp) / "report"),
            )
            with (
                patch("beefapi_conformance.cli._matrix", return_value=[first, second]),
                patch("beefapi_conformance.cli.run_cell", side_effect=fake_run),
                patch(
                    "beefapi_conformance.cli.prepare_batch_server_evidence",
                    return_value={
                        ("https://example.invalid", "TOKEN"): {
                            "token": "t",
                            "fence": set(),
                            "commit": "x",
                        }
                    },
                ),
                patch("beefapi_conformance.cli.finalize_batch_server_evidence"),
                patch("beefapi_conformance.cli.time.sleep") as slept,
            ):
                command_run(args)
            slept.assert_called_with(1)
            with (
                patch(
                    "beefapi_conformance.cli._matrix", return_value=[first, raw_cell]
                ),
                patch("beefapi_conformance.cli.run_cell", side_effect=fake_run),
                patch(
                    "beefapi_conformance.cli.prepare_batch_server_evidence",
                    return_value={
                        ("https://example.invalid", "TOKEN"): {
                            "token": "t",
                            "fence": set(),
                            "commit": "x",
                        }
                    },
                ),
                patch("beefapi_conformance.cli.finalize_batch_server_evidence"),
                patch("beefapi_conformance.cli.time.sleep") as slept_raw,
            ):
                command_run(args)
            slept_raw.assert_not_called()

    def test_raw_http_marker_in_error_or_tool_input_is_not_a_pass(self):
        marker = "BEEFAPI_ASSISTANT_BODY_OK"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                self.rfile.read(length)
                payload = {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01Leak",
                            "name": "lookup",
                            "input": {"q": marker},
                        },
                        {"type": "text", "text": "nope"},
                    ],
                    "error": {"message": marker},
                    "stop_reason": "tool_use",
                }
                body = json.dumps(payload).encode()
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
                frozenset({"text", "messages"}),
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
                frozenset({"messages"}),
                frozenset({"text", "messages"}),
                None,
            )
            model = Model(
                "model",
                "Model",
                frozenset({route.id}),
                frozenset({client.id}),
                frozenset({"text", "messages"}),
                {},
            )
            scenario = Scenario.parse(
                {
                    "id": "messages-text",
                    "name": "Messages",
                    "tier": "pr",
                    "kind": "http",
                    "protocol": "messages",
                    "http_endpoint": "/v1/messages",
                    "required_capabilities": ["messages"],
                    "turns": [
                        {
                            "prompt": f"Reply exactly {marker}.",
                            "marker": marker,
                            "expected_events": [],
                        }
                    ],
                }
            )
            os.environ["RAW_HTTP_TEST_TOKEN"] = "plain-test-token"
            result = run_cell(MatrixCell(client, route, model, scenario))
            self.assertEqual("fail", result.status)
        finally:
            os.environ.pop("RAW_HTTP_TEST_TOKEN", None)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_raw_http_assistant_body_marker_still_passes(self):
        marker = "BEEFAPI_ASSISTANT_BODY_OK"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                self.rfile.read(length)
                payload = {
                    "role": "assistant",
                    "content": [{"type": "text", "text": marker}],
                    "stop_reason": "end_turn",
                }
                body = json.dumps(payload).encode()
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
                frozenset({"text", "messages"}),
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
                frozenset({"messages"}),
                frozenset({"text", "messages"}),
                None,
            )
            model = Model(
                "model",
                "Model",
                frozenset({route.id}),
                frozenset({client.id}),
                frozenset({"text", "messages"}),
                {},
            )
            scenario = Scenario.parse(
                {
                    "id": "messages-text",
                    "name": "Messages",
                    "tier": "pr",
                    "kind": "http",
                    "protocol": "messages",
                    "http_endpoint": "/v1/messages",
                    "required_capabilities": ["messages"],
                    "turns": [
                        {
                            "prompt": f"Reply exactly {marker}.",
                            "marker": marker,
                            "expected_events": [],
                        }
                    ],
                }
            )
            os.environ["RAW_HTTP_TEST_TOKEN"] = "plain-test-token"
            result = run_cell(MatrixCell(client, route, model, scenario))
            self.assertEqual("pass", result.status, result.detail)
        finally:
            os.environ.pop("RAW_HTTP_TEST_TOKEN", None)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class PortableHelperTests(unittest.TestCase):
    def test_mock_agent_candidates_remain_executable_alternatives(self):
        candidates = mock_agent_candidates()
        self.assertEqual((str(MOCK_AGENT),), candidates)
        self.assertTrue(Path(candidates[0]).is_file())

    def test_mock_command_uses_interpreter_plus_script_path(self):
        base = CommandTests().cell("mock")
        cell = MatrixCell(
            replace(base.client, binary_candidates=mock_agent_candidates()),
            base.route,
            base.model,
            base.scenario,
        )
        with tempfile.TemporaryDirectory() as tmp:
            command = ClientCommand(
                cell, mock_agent_candidates()[0], Path(tmp), None, None
            )
            argv = command.command("prompt", 1)
        self.assertEqual(
            [sys.executable, str(MOCK_AGENT), "prompt"],
            argv,
        )

    def test_windows_bash_resolver_uses_git_bash_not_wsl_stub(self):
        def is_file(path):
            text = str(path).replace("/", "\\")
            if "system32" in text.lower():
                return True
            return text.endswith(r"Git\bin\bash.exe")

        with (
            patch("portable.os.path.isfile", is_file),
            patch.dict(os.environ, {"ProgramFiles": r"C:\Program Files"}, clear=False),
        ):
            found = git_bash_windows()
        self.assertTrue(found.replace("\\", "/").endswith("Git/bin/bash.exe"))
        self.assertNotIn("system32", found.lower())
        self.assertNotEqual("bash", found)


if __name__ == "__main__":
    unittest.main()
