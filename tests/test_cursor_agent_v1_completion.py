from __future__ import annotations

import http.server
import json
import os
import subprocess
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from beefapi_conformance.clients import ClientCommand
from beefapi_conformance.cursor_agent_v1 import (
    CLASSIFIER_CANARY,
    CLASSIFIER_COMMAND,
    apply_completion_gates,
    correlate_id,
    evaluate_classifier,
    evaluate_disconnect,
    evaluate_hosted_search,
    evaluate_http_status,
    evaluate_idempotent_retries,
    evaluate_mcp_mode,
    evaluate_receipt_uniqueness,
    evaluate_stream_progress,
    evaluate_tool_catalog,
    evaluate_usage_quality,
    load_completion_inventory,
    missing_critical_executions,
    redact_correlation_ids,
    sanitize_report_value,
)
from beefapi_conformance.inventory import build_live_inventory
from beefapi_conformance.manifest import load_inventory
from beefapi_conformance.matrix import compile_matrix
from beefapi_conformance.model import (
    CellResult,
    ContractError,
    MatrixCell,
    Scenario,
    Turn,
    TurnResult,
)
from beefapi_conformance.report import build_report
from beefapi_conformance.runner import (
    _bind_replay_server_evidence,
    _evaluate_single_stage_receipts,
    _usage_log_payload,
    bind_replay_attempt_receipts,
    finalize_batch_server_evidence,
    prepare_batch_server_evidence,
    run_cell,
)
from beefapi_conformance.tool_replay import (
    ToolUse,
    covering_tool_results,
    evaluate_live_tool_ids,
    evaluate_mcp_spans,
    evaluate_none_terminal,
    evaluate_replay_identity,
    execute_tool_replay,
    mixed_followup_text,
    parse_assistant_message,
    parse_tool_uses,
    sleep_deltas,
    stage_a_payload,
    stage_b_payload,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads(
    (ROOT / "tests/fixtures/cursor_agent_v1/evidence.json").read_text(encoding="utf-8")
)


class _FakeTokenLogResponse:
    def __init__(self, body: dict, headers: dict[str, str] | None = None):
        self.body = json.dumps(body).encode()
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


def _type64_inventory(*, native_web: bool = True):
    routes, models = build_live_inventory(
        channels=[
            {
                "id": 301,
                "type": 64,
                "status": 1,
                "models": "claude-opus-5",
                "test_model": "claude-opus-5",
                "cursor_agent_v1_native_web_search": native_web,
            }
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
        return load_inventory(ROOT, routes_path, models_path)


def _cell_result(
    cell: MatrixCell,
    status: str,
    *,
    detail: str = "",
    evidence: dict | None = None,
) -> CellResult:
    payload = dict(evidence or {})
    payload.setdefault(
        "completion",
        {
            "family": "cursor-agent-v1",
            "item": cell.scenario.id,
            "weight": "critical",
            "required_release": True,
        },
    )
    return CellResult(
        cell.id,
        status,
        "client",
        "now",
        1,
        cell.route.id,
        cell.model.id,
        cell.scenario.id,
        [],
        payload,
        detail,
    )


class InventoryTests(unittest.TestCase):
    def test_completion_inventory_maps_critical_and_major_weights(self):
        inventory = load_completion_inventory()
        weights = {item.id: item.weight for item in inventory.items}
        self.assertEqual("critical", weights["usage-quality"])
        self.assertEqual("critical", weights["catalog-canary"])
        self.assertEqual("critical", weights["tool-retry-23s"])
        self.assertEqual("critical", weights["tool-retry-3m"])
        self.assertEqual("critical", weights["covering-set"])
        self.assertEqual("critical", weights["mixed-tool-result-text"])
        self.assertEqual("critical", weights["hosted-web-search"])
        self.assertEqual("critical", weights["thinking-progress"])
        self.assertEqual("critical", weights["claude-classifier"])
        self.assertEqual("critical", weights["disconnect"])
        self.assertEqual("major", weights["text-turn"])
        self.assertTrue(
            any(item.gate == "receipt_uniqueness" for item in inventory.items)
        )

    def test_type64_release_plan_includes_every_advertised_critical_scenario(self):
        inventory = _type64_inventory()
        cells = compile_matrix(inventory, "release", coverage="representative")
        self.assertEqual([], missing_critical_executions(cells))
        planned = {cell.scenario.id for cell in cells}
        required = {
            item.scenario
            for item in load_completion_inventory().critical_scenario_items()
            if item.scenario
            and item.capabilities.issubset(inventory.routes[0].capabilities)
        }
        self.assertTrue(required.issubset(planned), required - planned)

    def test_web_search_is_not_required_when_type64_does_not_advertise_it(self):
        inventory = _type64_inventory(native_web=False)
        cells = compile_matrix(inventory, "release", coverage="representative")
        self.assertEqual([], missing_critical_executions(cells))
        self.assertFalse(any(cell.scenario.id == "native-web-search" for cell in cells))

    def test_representative_requires_codex_grok_and_workbuddy_applicable_cells(self):
        type64 = _type64_inventory()
        cells = compile_matrix(type64, "release", coverage="representative")
        for client_id in ("codex-cli", "grok-build", "claude-code"):
            for scenario_id in ("text-turn", "local-tool-read", "session-resume"):
                self.assertTrue(
                    any(
                        cell.client.id == client_id and cell.scenario.id == scenario_id
                        for cell in cells
                    ),
                    f"{client_id}/{scenario_id}",
                )
        example = load_inventory(
            ROOT,
            ROOT / "manifests/routes.example.json",
            ROOT / "manifests/models.example.json",
        )
        example_cells = compile_matrix(example, "release", coverage="representative")
        for scenario_id in ("text-turn", "local-tool-read", "session-resume"):
            self.assertTrue(
                any(
                    cell.client.id == "workbuddy-cli"
                    and cell.scenario.id == scenario_id
                    for cell in example_cells
                ),
                scenario_id,
            )


class UsageQualityTests(unittest.TestCase):
    def test_measured_zero_usage_is_false_green(self):
        payload = FIXTURES["usage_false_green_measured_zero"]
        result = evaluate_usage_quality(payload, channel_type=64)
        self.assertEqual("fail", result.status)
        self.assertIn("measured zero", result.detail)

    def test_unknown_observed_and_estimated_billing_pass(self):
        payload = FIXTURES["usage_valid_unknown_and_estimate"]
        self.assertEqual(
            "pass", evaluate_usage_quality(payload, channel_type=64).status
        )

    def test_runner_encodes_type64_zeros_as_unknown_not_measured(self):
        inventory = _type64_inventory()
        cell = next(
            item
            for item in compile_matrix(inventory, "release")
            if item.scenario.id == "cursor-v1-usage-quality"
        )
        log = {
            "type": 2,
            "request_id": "req-usage",
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "quota": 0,
            "use_time": 0,
            "other": json.dumps(
                {
                    "usage_receipt_id": "cursor-agent-v1:receipt",
                    "usage_receipt_provider": "cursor-agent-v1",
                    "usage_receipt_state": "final",
                    "cache_tokens": 0,
                }
            ),
        }
        payload = _usage_log_payload(cell, log, "commit-sha")
        observed = payload["usage"]["observed_usage"]["prompt_tokens"]
        estimate = payload["usage"]["billing_estimate"]["prompt_tokens"]
        self.assertEqual("unknown", observed["quality"])
        self.assertIsNone(observed["value"])
        self.assertEqual("estimated", estimate["quality"])
        self.assertEqual(
            "pass", evaluate_usage_quality(payload, channel_type=64).status
        )
        self.assertNotEqual(0, observed.get("value", "missing"))


class CatalogAndToolResultTests(unittest.TestCase):
    def test_catalog_rejects_hidden_native_tools_and_missing_caller_tools(self):
        leaked = evaluate_tool_catalog(["Bash", "Read", "ReadFile", "Shell"])
        self.assertEqual("fail", leaked.status)
        self.assertIn("leaked", leaked.detail)
        missing = evaluate_tool_catalog(["beefapi_conformance_canary"])
        self.assertEqual("fail", missing.status)
        present = evaluate_tool_catalog(["Bash", "Read", "beefapi_conformance_canary"])
        self.assertEqual("pass", present.status)

    def test_covering_and_mixed_tool_results_must_not_4xx(self):
        self.assertEqual("fail", evaluate_http_status(400).status)
        self.assertEqual("fail", evaluate_http_status(409).status)
        self.assertEqual("pass", evaluate_http_status(200).status)

    def test_identical_retries_at_23s_and_3m_must_stay_idempotent(self):
        self.assertEqual(
            "fail",
            evaluate_idempotent_retries(FIXTURES["retry_false_green"]).status,
        )
        self.assertEqual(
            "pass", evaluate_idempotent_retries(FIXTURES["retry_valid"]).status
        )

    def test_http_covering_set_4xx_fails_the_cell(self):
        result = self._run_parked_http(
            "cursor-v1-covering-set-tool-result",
            stage_b_status=400,
            stage_b_marker="NO",
            tool_count=2,
        )
        self.assertEqual("fail", result.status)
        self.assertEqual(400, result.turns[0].returncode)

    def test_http_covering_set_2xx_passes_without_server_evidence(self):
        result = self._run_parked_http(
            "cursor-v1-covering-set-tool-result",
            stage_b_status=200,
            stage_b_marker="BEEFAPI_CURSOR_V1_COVERING_OK",
            tool_count=2,
        )
        self.assertEqual("pass", result.status, result.detail)
        self.assertEqual(2, len(result.evidence["tool_replay"]["tool_use_id_hashes"]))
        dumped = json.dumps(build_report([result], tier="pr"))
        self.assertNotIn("toolu_01ParkedA", dumped)
        self.assertNotIn("toolu_01ParkedB", dumped)
        self.assertNotIn("_http_request_id", dumped)
        self.assertNotIn("_response_request_ids", dumped)

    def test_covering_set_without_a_real_batch_is_blocked(self):
        result = self._run_parked_http(
            "cursor-v1-covering-set-tool-result",
            stage_b_status=200,
            stage_b_marker="BEEFAPI_CURSOR_V1_COVERING_OK",
            tool_count=1,
        )
        self.assertEqual("blocked", result.status)
        self.assertIn("parked", result.detail)

    def test_mixed_tool_result_uses_parked_id(self):
        result = self._run_parked_http(
            "cursor-v1-mixed-tool-result-text",
            stage_b_status=200,
            stage_b_marker="BEEFAPI_CURSOR_V1_MIXED_OK",
            tool_count=1,
        )
        self.assertEqual("pass", result.status, result.detail)

    def test_stage_b_tool_use_or_tool_payload_marker_is_not_a_pass(self):
        marker = "BEEFAPI_CURSOR_V1_MIXED_OK"
        tool_use = self._run_parked_http(
            "cursor-v1-mixed-tool-result-text",
            stage_b_status=200,
            stage_b_marker=marker,
            tool_count=1,
            stage_b_body={
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01Again",
                        "name": "beefapi_conformance_canary",
                        "input": {"marker": marker},
                    }
                ],
                "stop_reason": "tool_use",
            },
        )
        self.assertEqual("fail", tool_use.status)
        self.assertIn("tool_use", tool_use.detail)
        echoed = self._run_parked_http(
            "cursor-v1-mixed-tool-result-text",
            stage_b_status=200,
            stage_b_marker=marker,
            tool_count=1,
            stage_b_body={
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01ParkedA",
                        "content": marker,
                    }
                ],
                "stop_reason": "end_turn",
            },
        )
        self.assertEqual("fail", echoed.status)
        self.assertIn("marker", echoed.detail)

    def test_stage_b_end_turn_assistant_text_still_passes(self):
        result = self._run_parked_http(
            "cursor-v1-mixed-tool-result-text",
            stage_b_status=200,
            stage_b_marker="BEEFAPI_CURSOR_V1_MIXED_OK",
            tool_count=1,
            stage_b_body={
                "role": "assistant",
                "content": [{"type": "text", "text": "BEEFAPI_CURSOR_V1_MIXED_OK"}],
                "stop_reason": "end_turn",
            },
        )
        self.assertEqual("pass", result.status, result.detail)

    def test_custom_tool_rejects_marker_only_and_requires_round_trip(self):
        marker_only = self._run_parked_http(
            "cursor-v1-custom-tool-canary",
            stage_b_status=200,
            stage_b_marker="BEEFAPI_CURSOR_V1_CUSTOM_OK",
            tool_count=0,
            stage_a_text="BEEFAPI_CURSOR_V1_CUSTOM_OK",
        )
        self.assertEqual("fail", marker_only.status)
        self.assertIn("marker-only", marker_only.detail)
        round_trip = self._run_parked_http(
            "cursor-v1-custom-tool-canary",
            stage_b_status=200,
            stage_b_marker="BEEFAPI_CURSOR_V1_CUSTOM_OK",
            tool_count=1,
        )
        self.assertEqual("pass", round_trip.status, round_trip.detail)

    def test_static_synthetic_tool_ids_are_rejected_from_manifests(self):
        with self.assertRaisesRegex(ContractError, "static synthetic tool_use"):
            Scenario.parse(
                {
                    "id": "bad-static",
                    "name": "Bad",
                    "tier": "pr",
                    "kind": "http",
                    "protocol": "messages",
                    "http_endpoint": "/v1/messages",
                    "required_capabilities": ["messages"],
                    "http_payload": {
                        "messages": [
                            {
                                "role": "assistant",
                                "content": [
                                    {
                                        "type": "tool_use",
                                        "id": "toolu_conformance_retry_23s",
                                        "name": "beefapi_conformance_canary",
                                        "input": {},
                                    }
                                ],
                            }
                        ]
                    },
                    "turns": [{"prompt": "x", "marker": "x", "expected_events": []}],
                }
            )

    def _run_parked_http(
        self,
        scenario_id: str,
        *,
        stage_b_status: int,
        stage_b_marker: str,
        tool_count: int,
        stage_a_text: str = "",
        stage_b_body: dict | None = None,
    ):
        return self._run_http_scenario(
            scenario_id,
            status=stage_b_status,
            marker=stage_b_marker,
            tool_count=tool_count,
            stage_a_text=stage_a_text,
            stage_b_body=stage_b_body,
        )

    def _run_http_scenario(
        self,
        scenario_id: str,
        *,
        status: int,
        marker: str,
        tool_count: int = 2,
        stage_a_text: str = "",
        stage_b_body: dict | None = None,
    ):
        inventory = _type64_inventory()
        cell = next(
            item
            for item in compile_matrix(inventory, "release")
            if item.scenario.id == scenario_id and item.client.adapter == "raw-http"
        )

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                request = json.loads(self.rfile.read(length))
                messages = request.get("messages", [])
                has_tool_result = any(
                    isinstance(message.get("content"), list)
                    and any(
                        isinstance(block, dict) and block.get("type") == "tool_result"
                        for block in message.get("content")
                    )
                    for message in messages
                    if isinstance(message, dict)
                )
                if not has_tool_result:
                    content: list[dict] = []
                    if stage_a_text:
                        content.append({"type": "text", "text": stage_a_text})
                    names = [
                        "beefapi_conformance_canary",
                        "beefapi_conformance_canary_b",
                    ]
                    for index in range(tool_count):
                        content.append(
                            {
                                "type": "tool_use",
                                "id": f"toolu_01Parked{chr(65 + index)}",
                                "name": names[index % 2],
                                "input": {"marker": chr(65 + index)},
                            }
                        )
                    payload = {
                        "role": "assistant",
                        "content": content,
                        "stop_reason": "tool_use" if tool_count else "end_turn",
                    }
                    code = 200
                else:
                    payload = stage_b_body or {
                        "role": "assistant",
                        "content": [{"type": "text", "text": marker}],
                        "stop_reason": "end_turn",
                    }
                    code = status
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("content-type", "application/json")
                self.send_header("X-Oneapi-Request-Id", f"req-{id(request)}")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            route = replace(
                cell.route,
                base_url=f"http://127.0.0.1:{server.server_port}",
                release_evidence_required=False,
                evidence_provider=None,
            )
            os.environ["TEST_TOKEN"] = "plain-test-token"
            return run_cell(MatrixCell(cell.client, route, cell.model, cell.scenario))
        finally:
            os.environ.pop("TEST_TOKEN", None)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class ToolReplayDriverTests(unittest.TestCase):
    def test_parse_tool_use_and_build_replay_payload_from_returned_ids(self):
        output = json.dumps(
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01LiveParked",
                        "name": "beefapi_conformance_canary",
                        "input": {"marker": "M"},
                    }
                ],
                "stop_reason": "tool_use",
            }
        )
        uses = parse_tool_uses(output)
        self.assertEqual(["toolu_01LiveParked"], [item.id for item in uses])
        self.assertEqual("pass", evaluate_live_tool_ids(uses).status)
        self.assertEqual(
            "fail",
            evaluate_live_tool_ids(
                [
                    ToolUse(
                        id="toolu_conformance_retry_23s",
                        name="beefapi_conformance_canary",
                        input={},
                        raw={},
                    )
                ]
            ).status,
        )
        assistant = parse_assistant_message(output)
        spec = {"mode": "retry"}
        stage_a = stage_a_payload(spec, "claude-opus-5", "call the canary")
        self.assertEqual(
            {"type": "tool", "name": "beefapi_conformance_canary"},
            stage_a["tool_choice"],
        )
        stage_b = stage_b_payload(
            stage_a,
            assistant,
            uses,
            spec,
            "follow-up",
            "BEEFAPI_CURSOR_V1_RETRY_23S_OK",
        )
        self.assertEqual(assistant, stage_b["messages"][1])
        result_block = stage_b["messages"][2]["content"][0]
        self.assertEqual("toolu_01LiveParked", result_block["tool_use_id"])
        self.assertEqual("BEEFAPI_CURSOR_V1_RETRY_23S_OK", result_block["content"])

    def test_mixed_stage_b_followup_consumes_tool_result_instead_of_must_call(self):
        marker = "BEEFAPI_CURSOR_V1_MIXED_OK"
        prompt = (
            "You must call beefapi_conformance_canary. After the tool result "
            "plus this follow-up text, reply exactly "
            f"{marker}."
        )
        uses = [
            ToolUse(
                id="toolu_01LiveParked",
                name="beefapi_conformance_canary",
                input={"marker": "M"},
                raw={
                    "type": "tool_use",
                    "id": "toolu_01LiveParked",
                    "name": "beefapi_conformance_canary",
                    "input": {"marker": "M"},
                },
            )
        ]
        stage_a = stage_a_payload({"mode": "mixed"}, "claude-opus-5", prompt)
        stage_b = stage_b_payload(
            stage_a,
            {"role": "assistant", "content": [uses[0].raw]},
            uses,
            {"mode": "mixed"},
            prompt,
            marker,
        )
        self.assertEqual({"type": "none"}, stage_b["tool_choice"])
        user_content = stage_b["messages"][2]["content"]
        self.assertEqual("tool_result", user_content[0]["type"])
        self.assertEqual("toolu_01LiveParked", user_content[0]["tool_use_id"])
        self.assertEqual("text", user_content[1]["type"])
        self.assertEqual(mixed_followup_text(marker), user_content[1]["text"])
        self.assertIn(marker, user_content[1]["text"])
        self.assertNotEqual(prompt, user_content[1]["text"])
        self.assertNotIn("must call", user_content[1]["text"].lower())
        self.assertEqual(prompt, stage_b["messages"][0]["content"])

    def test_covering_set_uses_only_parked_run_ids(self):
        self.assertEqual([], covering_tool_results([], marker="X"))
        uses = [
            ToolUse(
                id="toolu_01ParkedA",
                name="beefapi_conformance_canary",
                input={},
                raw={},
            ),
            ToolUse(
                id="toolu_01ParkedB",
                name="beefapi_conformance_canary_b",
                input={},
                raw={},
            ),
        ]
        results = covering_tool_results(uses, marker="OK")
        self.assertEqual(
            ["toolu_01ParkedA", "toolu_01ParkedB"],
            [item["tool_use_id"] for item in results],
        )
        self.assertFalse(
            any("historical_routed" in item["tool_use_id"] for item in results)
        )
        self.assertEqual(
            "fail",
            evaluate_live_tool_ids(
                [
                    ToolUse(
                        id="toolu_historical_routed_deadbeef",
                        name="beefapi_conformance_canary",
                        input={},
                        raw={},
                    )
                ]
            ).status,
        )

    def test_mcp_spans_must_correlate_to_returned_tool_ids(self):
        uses = [
            ToolUse(id="toolu_01Alpha", name="beefapi_mcp_alpha", input={}, raw={}),
            ToolUse(id="toolu_01Beta", name="beefapi_mcp_beta", input={}, raw={}),
        ]
        self.assertEqual(
            "fail",
            evaluate_mcp_spans(
                "serial",
                [{"start": 0, "end": 4}, {"start": 5, "end": 9}],
                uses,
            ).status,
        )
        self.assertEqual(
            "pass",
            evaluate_mcp_spans(
                "serial",
                [
                    {"tool_use_id": "toolu_01Alpha", "start": 0, "end": 4},
                    {"tool_use_id": "toolu_01Beta", "start": 4, "end": 8},
                ],
                uses,
            ).status,
        )

    def test_absolute_offsets_sleep_deltas_not_the_raw_offsets(self):
        self.assertEqual([23, 157], sleep_deltas((23, 180)))
        slept: list[float] = []
        calls: list[dict] = []

        def exchange(payload: dict):
            calls.append(payload)
            if len(payload["messages"]) == 1:
                body = json.dumps(
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "toolu_01ReplayLive",
                                "name": "beefapi_conformance_canary",
                                "input": {"marker": "R"},
                            }
                        ],
                        "stop_reason": "tool_use",
                    }
                )
                return 200, body, f"http-a-{len(calls)}", {}
            body = json.dumps(
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "BEEFAPI_CURSOR_V1_RETRY_23S_OK"}
                    ],
                    "stop_reason": "end_turn",
                }
            )
            return 200, body, f"http-b-{len(calls)}", {}

        result = execute_tool_replay(
            spec={"mode": "retry", "min_tool_uses": 1},
            model="claude-opus-5",
            prompt="call canary",
            marker="BEEFAPI_CURSOR_V1_RETRY_23S_OK",
            offsets=(23, 180),
            exchange=exchange,
            sleeper=slept.append,
        )
        self.assertEqual("pass", result.status, result.detail)
        self.assertEqual([23, 157], slept)
        self.assertEqual(
            [0, 0, 23, 180],
            [item["offset_seconds"] for item in result.attempts],
        )
        self.assertEqual(
            ["a", "b", "c", "c"], [item["stage"] for item in result.attempts]
        )
        self.assertEqual(4, len(calls))
        self.assertEqual(calls[1], calls[2])
        self.assertEqual(calls[1], calls[3])
        http_ids = [item["http_request_id_hash"] for item in result.attempts]
        self.assertEqual(len(http_ids), len(set(http_ids)))
        self.assertNotIn("toolu_01ReplayLive", json.dumps(result.evidence))
        self.assertTrue(all(item.get("_http_request_id") for item in result.attempts))

    def test_stage_b_none_terminal_requires_end_turn_and_assistant_text(self):
        marker = "BEEFAPI_CURSOR_V1_RETRY_23S_OK"
        self.assertEqual(
            "fail",
            evaluate_none_terminal(
                json.dumps(
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "toolu_01Again",
                                "name": "beefapi_conformance_canary",
                                "input": {"marker": marker},
                            }
                        ],
                        "stop_reason": "tool_use",
                    }
                ),
                marker,
            ).status,
        )
        self.assertEqual(
            "fail",
            evaluate_none_terminal(
                json.dumps(
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "toolu_01ParkedA",
                                "content": marker,
                            }
                        ],
                        "stop_reason": "end_turn",
                    }
                ),
                marker,
            ).status,
        )
        self.assertEqual(
            "fail",
            evaluate_none_terminal(
                json.dumps(
                    {
                        "role": "assistant",
                        "content": [{"type": "text", "text": marker}],
                        "stop_reason": "max_tokens",
                    }
                ),
                marker,
            ).status,
        )
        self.assertEqual(
            "pass",
            evaluate_none_terminal(
                json.dumps(
                    {
                        "role": "assistant",
                        "content": [{"type": "text", "text": marker}],
                        "stop_reason": "end_turn",
                    }
                ),
                marker,
            ).status,
        )
        self.assertEqual(
            "fail",
            evaluate_none_terminal(
                json.dumps(
                    {
                        "role": "user",
                        "content": [{"type": "text", "text": marker}],
                        "stop_reason": "end_turn",
                    }
                ),
                marker,
            ).status,
        )
        self.assertEqual(
            "fail",
            evaluate_none_terminal(
                json.dumps(
                    {
                        "role": "assistant",
                        "content": [{"type": "tool_use"}],
                        "stop_reason": "end_turn",
                    }
                ),
                marker,
            ).status,
        )

        def exchange_with(stage_b_body: dict):
            calls: list[dict] = []

            def exchange(payload: dict):
                calls.append(payload)
                if len(payload["messages"]) == 1:
                    body = json.dumps(
                        {
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "tool_use",
                                    "id": "toolu_01ReplayLive",
                                    "name": "beefapi_conformance_canary",
                                    "input": {"marker": "R"},
                                }
                            ],
                            "stop_reason": "tool_use",
                        }
                    )
                    return 200, body, "http-a", {}
                return 200, json.dumps(stage_b_body), "http-b", {}

            result = execute_tool_replay(
                spec={"mode": "retry", "min_tool_uses": 1},
                model="claude-opus-5",
                prompt="You must call beefapi_conformance_canary.",
                marker=marker,
                exchange=exchange,
            )
            return result, calls

        tool_use, calls = exchange_with(
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01Again",
                        "name": "beefapi_conformance_canary",
                        "input": {"marker": marker},
                    }
                ],
                "stop_reason": "tool_use",
            }
        )
        self.assertEqual("fail", tool_use.status)
        self.assertIn("tool_use", tool_use.detail)
        self.assertEqual({"type": "none"}, calls[1]["tool_choice"])
        echoed, _calls = exchange_with(
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01ReplayLive",
                        "content": marker,
                    }
                ],
                "stop_reason": "end_turn",
            }
        )
        self.assertEqual("fail", echoed.status)
        self.assertNotIn("pass", echoed.status)
        clean, _calls = exchange_with(
            {
                "role": "assistant",
                "content": [{"type": "text", "text": marker}],
                "stop_reason": "end_turn",
            }
        )
        self.assertEqual("pass", clean.status, clean.detail)

    def test_replay_receipt_drift_is_not_idempotent(self):
        self.assertEqual(
            "fail",
            evaluate_idempotent_retries(
                [
                    {
                        "stage": "b",
                        "offset_seconds": 0,
                        "http_status": 200,
                        "request_hash": "abc",
                        "http_request_id_hash": "h1",
                        "receipt_hash": "rec-1",
                        "terminal_hash": "term",
                    },
                    {
                        "stage": "c",
                        "offset_seconds": 23,
                        "http_status": 200,
                        "request_hash": "abc",
                        "http_request_id_hash": "h2",
                        "receipt_hash": "rec-2",
                        "terminal_hash": "term",
                    },
                ]
            ).status,
        )

    def _retry_cell(self):
        inventory = _type64_inventory()
        return next(
            item
            for item in compile_matrix(inventory, "release")
            if item.scenario.id == "cursor-v1-tool-result-retry-23s"
            and item.client.adapter == "raw-http"
        )

    def _consume_log(self, cell, request_id: str, receipt_id: str):
        return {
            "created_at": 200,
            "type": 2,
            "model_name": cell.model.id,
            "channel": cell.route.channel_id,
            "group": cell.route.group,
            "request_id": request_id,
            "other": json.dumps(
                {
                    "usage_receipt_id": receipt_id,
                    "usage_receipt_provider": "cursor-agent-v1",
                    "usage_receipt_state": "final",
                }
            ),
        }

    def _attempts(self, req_b: str, req_c: str) -> list[dict]:
        return [
            {
                "stage": "b",
                "offset_seconds": 0,
                "http_status": 200,
                "request_hash": "abc",
                "http_request_id_hash": correlate_id(req_b),
                "_http_request_id": req_b,
                "receipt_hash": "",
                "terminal_hash": "term",
            },
            {
                "stage": "c",
                "offset_seconds": 23,
                "http_status": 200,
                "request_hash": "abc",
                "http_request_id_hash": correlate_id(req_c),
                "_http_request_id": req_c,
                "receipt_hash": "",
                "terminal_hash": "term",
            },
        ]

    def test_stage_b_one_consume_log_stage_c_zero_passes(self):
        cell = self._retry_cell()
        attempts = self._attempts("req-b-exact", "req-c-exact")
        attempts.append(self._generation_a())
        logs = [
            self._consume_log(cell, "req-a", "cursor-agent-v1:receipt-a"),
            self._consume_log(cell, "req-b-exact", "cursor-agent-v1:receipt-shared"),
        ]
        bind_replay_attempt_receipts(cell, attempts, logs, "commit-sha", 0, set())
        self.assertEqual(1, attempts[0]["consume_match_count"])
        self.assertEqual(0, attempts[1]["consume_match_count"])
        shared = correlate_id("cursor-agent-v1:receipt-shared")
        self.assertEqual(shared, attempts[0]["receipt_hash"])
        self.assertEqual("", attempts[1]["receipt_hash"])
        self.assertTrue(attempts[1]["replay_without_consume"])
        self.assertTrue(attempts[1]["no_new_charge"])
        self.assertNotIn("_bound_payload", attempts[1])
        self.assertEqual(
            "pass",
            evaluate_replay_identity(attempts, require_receipts=True).status,
        )

    def test_stage_c_consume_log_or_copied_receipt_fails_release(self):
        cell = self._retry_cell()
        same_receipt = self._attempts("req-b-exact", "req-c-exact")
        bind_replay_attempt_receipts(
            cell,
            same_receipt,
            [
                self._consume_log(
                    cell, "req-b-exact", "cursor-agent-v1:receipt-shared"
                ),
                self._consume_log(
                    cell, "req-c-exact", "cursor-agent-v1:receipt-shared"
                ),
            ],
            "commit-sha",
            0,
            set(),
        )
        self.assertEqual(1, same_receipt[1]["consume_match_count"])
        self.assertEqual("", same_receipt[1]["receipt_hash"])
        self.assertFalse(same_receipt[1]["replay_without_consume"])
        self.assertEqual(
            "fail",
            evaluate_replay_identity(same_receipt, require_receipts=True).status,
        )
        copied = self._attempts("req-b-exact", "req-c-exact")
        copied[0]["consume_match_count"] = 1
        copied[0]["receipt_hash"] = correlate_id("cursor-agent-v1:receipt-shared")
        copied[1]["consume_match_count"] = 0
        copied[1]["receipt_hash"] = copied[0]["receipt_hash"]
        copied[1]["replay_without_consume"] = True
        copied[1]["no_new_charge"] = True
        self.assertEqual(
            "fail",
            evaluate_replay_identity(copied, require_receipts=True).status,
        )
        self.assertIn(
            "copied usage receipt",
            evaluate_replay_identity(copied, require_receipts=True).detail,
        )

    def test_release_fails_when_stage_b_is_missing_or_ambiguous(self):
        cell = self._retry_cell()
        missing = self._attempts("req-b-missing", "req-c-exact")
        bind_replay_attempt_receipts(
            cell,
            missing,
            [self._consume_log(cell, "req-unrelated", "cursor-agent-v1:receipt-other")],
            "commit-sha",
            0,
            set(),
        )
        self.assertEqual(0, missing[0]["consume_match_count"])
        self.assertEqual(0, missing[1]["consume_match_count"])
        self.assertEqual(
            "fail",
            evaluate_replay_identity(missing, require_receipts=True).status,
        )
        self.assertIn(
            "stage B",
            evaluate_replay_identity(missing, require_receipts=True).detail,
        )
        ambiguous = self._attempts("req-b-dup", "req-c-exact")
        bind_replay_attempt_receipts(
            cell,
            ambiguous,
            [
                self._consume_log(cell, "req-b-dup", "cursor-agent-v1:receipt-shared"),
                self._consume_log(cell, "req-b-dup", "cursor-agent-v1:receipt-other"),
            ],
            "commit-sha",
            0,
            set(),
        )
        self.assertEqual(2, ambiguous[0]["consume_match_count"])
        self.assertEqual(0, ambiguous[1]["consume_match_count"])
        self.assertEqual(
            "fail",
            evaluate_replay_identity(ambiguous, require_receipts=True).status,
        )

    def test_local_tests_may_omit_receipts_but_release_cannot(self):
        attempts = self._attempts("req-b-exact", "req-c-exact")
        self.assertEqual(
            "pass", evaluate_replay_identity(attempts, require_receipts=False).status
        )
        self.assertEqual(
            "fail", evaluate_replay_identity(attempts, require_receipts=True).status
        )
        self.assertIn(
            "stage B",
            evaluate_replay_identity(attempts, require_receipts=True).detail,
        )

    def test_single_stage_receipts_fail_without_stage_b(self):
        self.assertEqual(
            "fail",
            _evaluate_single_stage_receipts(
                [{"stage": "a", "consume_match_count": 1, "receipt_hash": "rec"}]
            ).status,
        )
        self.assertEqual("fail", _evaluate_single_stage_receipts([]).status)
        self.assertEqual(
            "fail",
            _evaluate_single_stage_receipts(
                [{"stage": "b", "consume_match_count": 1, "receipt_hash": "rec"}]
            ).status,
        )

    def test_optional_response_receipt_header_hash_must_equal_stage_b(self):
        shared = correlate_id("cursor-agent-v1:receipt-shared")
        matching = self._attempts("req-b-exact", "req-c-exact")
        matching[0]["consume_match_count"] = 1
        matching[0]["receipt_hash"] = shared
        matching[0]["receipt_state"] = "final"
        matching[0]["response_receipt_hash"] = shared
        matching[1]["consume_match_count"] = 0
        matching[1]["receipt_hash"] = ""
        matching[1]["response_receipt_hash"] = shared
        matching[1]["replay_without_consume"] = True
        matching[1]["no_new_charge"] = True
        matching.append(
            {
                **self._generation_a(),
                "consume_match_count": 1,
                "receipt_hash": correlate_id("cursor-agent-v1:receipt-a"),
                "receipt_state": "final",
            }
        )
        self.assertEqual(
            "pass",
            evaluate_replay_identity(matching, require_receipts=True).status,
        )
        drifted = [dict(item) for item in matching]
        drifted[1]["response_receipt_hash"] = correlate_id("other-receipt")
        self.assertEqual(
            "fail",
            evaluate_replay_identity(drifted, require_receipts=True).status,
        )

    def test_bind_replay_resolves_base_url_from_env(self):
        cell = self._retry_cell()
        route = replace(cell.route, base_url=None, base_url_env="TEST_BASE_URL")
        cell = MatrixCell(cell.client, route, cell.model, cell.scenario)
        attempts = self._attempts("req-b-exact", "req-c-exact")
        attempts.append(self._generation_a())
        seen_urls: list[str] = []

        def fake_urlopen(request, timeout=0):
            seen_urls.append(request.full_url)
            return _FakeTokenLogResponse(
                {
                    "success": True,
                    "data": [
                        self._consume_log(cell, "req-a", "cursor-agent-v1:receipt-a"),
                        self._consume_log(
                            cell, "req-b-exact", "cursor-agent-v1:receipt-shared"
                        ),
                    ],
                },
                {"X-New-Api-Commit": "commit-sha"},
            )

        with (
            patch.dict(os.environ, {"TEST_BASE_URL": "https://env-only.example"}),
            patch("urllib.request.urlopen", side_effect=fake_urlopen),
        ):
            payload = _bind_replay_server_evidence(cell, attempts, "token", 0, set())
        self.assertEqual("pass", payload.get("status"), payload)
        self.assertTrue(any("https://env-only.example" in url for url in seen_urls))
        self.assertEqual(1, attempts[0]["consume_match_count"])
        self.assertEqual(0, attempts[1]["consume_match_count"])
        self.assertTrue(attempts[1]["replay_without_consume"])

    def test_deferred_batch_correlates_raw_ids_then_scrubs_them(self):
        cell = self._retry_cell()
        attempts = self._attempts("req-b-exact", "req-c-exact")
        attempts.append(self._generation_a())
        receipt = "cursor-agent-v1:receipt-shared"
        old = self._consume_log(cell, "old", "old-receipt")
        old["created_at"] = 100
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
                "http_status": 200,
                "server_evidence": {"status": "deferred"},
                "_response_request_ids": ["req-a", "req-b-exact", "req-c-exact"],
                "_replay_attempts": attempts,
                "tool_replay": {"mode": "retry", "tool_use_id_hashes": []},
            },
        )
        responses = [
            _FakeTokenLogResponse(
                {"success": True, "data": [old]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            _FakeTokenLogResponse(
                {
                    "success": True,
                    "data": [
                        self._consume_log(cell, "req-a", "cursor-agent-v1:receipt-a"),
                        self._consume_log(cell, "req-b-exact", receipt),
                        old,
                    ],
                },
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        with (
            patch.dict(os.environ, {cell.route.token_env or "TEST_TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses),
        ):
            sessions = prepare_batch_server_evidence([cell])
            finalize_batch_server_evidence([cell], [result], sessions)
        self.assertEqual("pass", result.status, result.detail)
        self.assertEqual(1, attempts[0]["consume_match_count"])
        self.assertEqual(0, attempts[1]["consume_match_count"])
        self.assertEqual("", attempts[1]["receipt_hash"])
        self.assertTrue(attempts[1]["replay_without_consume"])
        self.assertTrue(attempts[1]["no_new_charge"])
        replay = result.evidence["server_evidence"]["replay"]["stage_c"]
        self.assertEqual(0, replay[0]["consume_match_count"])
        self.assertTrue(replay[0]["no_new_charge"])
        self.assertNotIn("_response_request_ids", result.evidence)
        self.assertNotIn("_replay_attempts", result.evidence)
        self.assertNotIn("_http_request_id", json.dumps(attempts))
        dumped = json.dumps(build_report([result]))
        self.assertNotIn("req-b-exact", dumped)
        self.assertNotIn("req-c-exact", dumped)
        self.assertNotIn(receipt, dumped)
        self.assertIn(correlate_id(receipt), dumped)

    def test_deferred_batch_rereads_empty_snapshot_until_stage_b_final(self):
        cell = self._retry_cell()
        attempts = [self._generation_a(), *self._attempts("req-b-exact", "req-c-exact")]
        receipt = "cursor-agent-v1:receipt-shared"
        old = self._consume_log(cell, "old", "old-receipt")
        old["created_at"] = 100
        provisional = self._consume_log(cell, "req-b-exact", receipt)
        provisional["other"] = json.dumps(
            {
                "usage_receipt_id": receipt,
                "usage_receipt_provider": "cursor-agent-v1",
                "usage_receipt_state": "provisional",
            }
        )
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
                "http_status": 200,
                "server_evidence": {"status": "deferred"},
                "_response_request_ids": ["req-a", "req-b-exact", "req-c-exact"],
                "_replay_attempts": attempts,
                "tool_replay": {"mode": "retry", "tool_use_id_hashes": []},
            },
        )
        responses = [
            _FakeTokenLogResponse(
                {"success": True, "data": [old]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            _FakeTokenLogResponse(
                {"success": True, "data": []},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            _FakeTokenLogResponse(
                {"success": True, "data": [old, provisional]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            _FakeTokenLogResponse(
                {
                    "success": True,
                    "data": [
                        old,
                        self._consume_log(cell, "req-a", "cursor-agent-v1:initial-a"),
                        self._consume_log(cell, "req-b-exact", receipt),
                    ],
                },
                {"X-New-Api-Commit": "commit-sha"},
            ),
        ]
        with (
            patch.dict(os.environ, {cell.route.token_env or "TEST_TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            patch("time.sleep") as slept,
        ):
            sessions = prepare_batch_server_evidence([cell])
            finalize_batch_server_evidence([cell], [result], sessions)
        self.assertEqual("pass", result.status, result.detail)
        self.assertGreaterEqual(urlopen.call_count, 3)
        self.assertGreaterEqual(slept.call_count, 1)
        self.assertEqual(1, attempts[0]["consume_match_count"])
        self.assertEqual("final", attempts[0]["receipt_state"])
        self.assertEqual(1, result.evidence["server_evidence"]["consume_match_count"])
        self.assertEqual("final", result.evidence["server_evidence"]["receipt_state"])
        self.assertNotIn("req-b-exact", json.dumps(build_report([result])))

    def test_deferred_batch_conflict_consume_logs_fail_without_passing(self):
        cell = self._retry_cell()
        attempts = self._attempts("req-b-exact", "req-c-exact")
        old = self._consume_log(cell, "old", "old-receipt")
        old["created_at"] = 100
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
                "http_status": 200,
                "server_evidence": {"status": "deferred"},
                "_response_request_ids": ["req-a", "req-b-exact", "req-c-exact"],
                "_replay_attempts": attempts,
                "tool_replay": {"mode": "retry", "tool_use_id_hashes": []},
            },
        )
        conflict = _FakeTokenLogResponse(
            {
                "success": True,
                "data": [
                    old,
                    self._consume_log(cell, "req-b-exact", "cursor-agent-v1:receipt-a"),
                    self._consume_log(cell, "req-b-exact", "cursor-agent-v1:receipt-b"),
                ],
            },
            {"X-New-Api-Commit": "commit-sha"},
        )
        responses = [
            _FakeTokenLogResponse(
                {"success": True, "data": [old]},
                {"X-New-Api-Commit": "commit-sha"},
            ),
            conflict,
        ]
        with (
            patch.dict(os.environ, {cell.route.token_env or "TEST_TOKEN": "token"}),
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            patch("time.sleep") as slept,
        ):
            sessions = prepare_batch_server_evidence([cell])
            finalize_batch_server_evidence([cell], [result], sessions)
        self.assertEqual("fail", result.status)
        self.assertEqual(2, urlopen.call_count)
        slept.assert_not_called()
        evidence = result.evidence["server_evidence"]
        self.assertEqual("fail", evidence["status"])
        self.assertEqual(2, evidence["consume_match_count"])
        dumped = json.dumps(build_report([result]))
        self.assertNotIn("req-b-exact", dumped)
        self.assertNotIn("cursor-agent-v1:receipt-a", dumped)
        self.assertIn("consume_match_count", dumped)

    def test_bind_replay_conflict_keeps_match_count_and_does_not_reread(self):
        cell = self._retry_cell()
        attempts = self._attempts("req-b-exact", "req-c-exact")
        response = _FakeTokenLogResponse(
            {
                "success": True,
                "data": [
                    self._consume_log(cell, "req-b-exact", "cursor-agent-v1:receipt-a"),
                    self._consume_log(cell, "req-b-exact", "cursor-agent-v1:receipt-b"),
                ],
            },
            {"X-New-Api-Commit": "commit-sha"},
        )
        with (
            patch("urllib.request.urlopen", return_value=response) as urlopen,
            patch("time.sleep") as slept,
        ):
            payload = _bind_replay_server_evidence(cell, attempts, "token", 0, set())
        self.assertEqual("fail", payload.get("status"), payload)
        self.assertEqual(2, payload.get("consume_match_count"))
        self.assertEqual(1, urlopen.call_count)
        slept.assert_not_called()
        self.assertNotIn("req-b-exact", json.dumps(payload))
        self.assertNotIn("cursor-agent-v1:receipt-a", json.dumps(payload))

    def _generation_a(self):
        return {
            "stage": "a",
            "offset_seconds": 0,
            "_http_request_id": "req-a",
            "http_request_id_hash": correlate_id("req-a"),
        }


class ServerToolStreamAndClassifierTests(unittest.TestCase):
    def test_hosted_web_search_requires_progress_count_citations_not_client_search(
        self,
    ):
        client_search = json.dumps(
            {"type": "tool_use", "name": "WebSearch", "input": {"query": "example"}}
        )
        self.assertEqual(
            "fail",
            evaluate_hosted_search(
                web_search_call_count=1,
                citation_count=1,
                progress_event_count=1,
                client_output=client_search,
            ).status,
        )
        self.assertEqual(
            "fail",
            evaluate_hosted_search(
                web_search_call_count=1,
                citation_count=0,
                progress_event_count=1,
            ).status,
        )
        self.assertEqual(
            "pass",
            evaluate_hosted_search(
                web_search_call_count=1,
                citation_count=2,
                progress_event_count=3,
            ).status,
        )

    def test_mcp_serial_and_parallel_contracts(self):
        serial = [
            {"server": "alpha", "start": 0, "end": 10},
            {"server": "beta", "start": 10, "end": 20},
        ]
        parallel = [
            {"server": "alpha", "start": 0, "end": 10},
            {"server": "beta", "start": 2, "end": 8},
        ]
        self.assertEqual("pass", evaluate_mcp_mode("serial", serial).status)
        self.assertEqual("fail", evaluate_mcp_mode("serial", parallel).status)
        self.assertEqual("pass", evaluate_mcp_mode("parallel", parallel).status)
        self.assertEqual("fail", evaluate_mcp_mode("parallel", serial).status)

    def test_thinking_stream_requires_first_byte_and_keepalive(self):
        self.assertEqual("fail", evaluate_stream_progress({}).status)
        self.assertEqual(
            "fail",
            evaluate_stream_progress(
                {"first_byte_ms": 12, "keepalive_count": 0}
            ).status,
        )
        self.assertEqual(
            "pass",
            evaluate_stream_progress(
                {"first_byte_ms": 12, "keepalive_count": 1, "progress_event_count": 0}
            ).status,
        )

    def test_thinking_http_stream_records_keepalive_and_first_byte(self):
        inventory = _type64_inventory()
        cell = next(
            item
            for item in compile_matrix(inventory, "release")
            if item.scenario.id == "cursor-v1-thinking-progress"
        )

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                self.rfile.read(length)
                body = (
                    b"event: ping\n\n"
                    b'data: {"type":"thinking"}\n\n'
                    b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"BEEFAPI_CURSOR_V1_THINKING_OK"}}\n\n'
                    b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
                )
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            route = replace(
                cell.route,
                base_url=f"http://127.0.0.1:{server.server_port}",
                release_evidence_required=False,
                evidence_provider=None,
            )
            os.environ["TEST_TOKEN"] = "plain-test-token"
            result = run_cell(MatrixCell(cell.client, route, cell.model, cell.scenario))
            self.assertEqual("pass", result.status, result.detail)
            self.assertIsNotNone(result.evidence["stream"]["first_byte_ms"])
            self.assertGreater(result.evidence["stream"]["keepalive_count"], 0)
        finally:
            os.environ.pop("TEST_TOKEN", None)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_classifier_rejects_every_non_auto_permission_mode(self):
        for mode in (None, "default", "manual", "bypassPermissions", "acceptEdits"):
            with self.subTest(mode=mode):
                result = evaluate_classifier(
                    '{"type":"classifier","mode":"auto"}',
                    {"classifier": {"invoked": True}},
                    permission_mode=mode,
                )
                self.assertEqual("fail", result.status)
                self.assertIn("explicit auto", result.detail)

    def test_classifier_rejects_prose_errors_and_invented_receipts(self):
        for output in (
            "classifier invoked; auto-mode active",
            "Error: auto_mode classifier unavailable",
            '{"type":"classifier","mode":"auto"}',
            '{"permissionMode":"default"}',
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {
                                "type": "text",
                                "text": '{"type":"classifier","mode":"auto"}',
                            }
                        ]
                    },
                }
            ),
        ):
            with self.subTest(output=output):
                self.assertEqual(
                    "fail",
                    evaluate_classifier(
                        output, {"classifier": {"invoked": True}}, "auto"
                    ).status,
                )

    def test_classifier_checks_correlated_canary_but_does_not_infer_invocation(self):
        events = [
            {"type": "system", "subtype": "init", "permissionMode": "auto"},
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "name": "Bash",
                            "id": "canary-call",
                            "input": {"command": CLASSIFIER_COMMAND},
                        }
                    ]
                },
            },
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "canary-call",
                            "content": CLASSIFIER_CANARY + "\n",
                            "is_error": False,
                        }
                    ]
                },
            },
        ]

        def evaluate():
            return evaluate_classifier(
                "\n".join(json.dumps(event) for event in events),
                {"classifier": {"invoked": True}},
                "auto",
            )

        result = evaluate()
        self.assertEqual("fail", result.status)
        self.assertIn("direct classifier invocation proof", result.detail)
        self.assertIn("inferred only", result.detail)
        tool_result = events[2]["message"]["content"][0]
        for key, value in (
            ("tool_use_id", "different-call"),
            ("is_error", True),
            ("content", "Error: " + CLASSIFIER_CANARY),
        ):
            original = tool_result[key]
            tool_result[key] = value
            self.assertIn("canary execution was not observed", evaluate().detail)
            tool_result[key] = original
        events[0]["permissionMode"] = "default"
        self.assertIn("did not report active auto", evaluate().detail)

    def test_classifier_scenario_uses_claude_auto_without_allow_rule(self):
        inventory = _type64_inventory()
        cell = next(
            item
            for item in compile_matrix(inventory, "release")
            if item.scenario.id == "cursor-v1-claude-classifier"
        )
        with tempfile.TemporaryDirectory() as tmp:
            command = ClientCommand(
                cell, "claude", Path(tmp), "token", "https://example.invalid"
            )
            args = command.command("hello", 1)
            self.assertIn("--permission-mode", args)
            self.assertEqual("auto", args[args.index("--permission-mode") + 1])
            self.assertNotIn("bypassPermissions", args)
            self.assertNotIn("--allowedTools", args)
            self.assertEqual("Bash", args[args.index("--tools") + 1])
            self.assertEqual(
                {"autoMode": {"classifyAllShell": True}},
                json.loads(args[args.index("--settings") + 1]),
            )
            self.assertTrue(cell.scenario.requires_local_tools)
            self.assertIn("tool.shell", cell.scenario.required_capabilities)
            self.assertIn(CLASSIFIER_COMMAND, cell.scenario.turns[0].prompt)
            self.assertEqual(
                ("tool_use", "tool_result"), cell.scenario.turns[0].expected_events
            )

    def test_classifier_canary_command_runs_only_in_temporary_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                ["bash", "-c", CLASSIFIER_COMMAND],
                cwd=tmp,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(CLASSIFIER_CANARY + "\n", completed.stdout)
            self.assertEqual(
                (CLASSIFIER_CANARY + "\n").encode(),
                (Path(tmp) / "classifier-canary.txt").read_bytes(),
            )

    def test_classifier_scenario_requires_local_tool_opt_in(self):
        cell = next(
            item
            for item in compile_matrix(_type64_inventory(), "release")
            if item.scenario.id == "cursor-v1-claude-classifier"
        )
        with (
            patch("beefapi_conformance.runner.resolve_binary", return_value="claude"),
            patch("beefapi_conformance.runner._version", return_value="2.1.233"),
            patch("beefapi_conformance.runner.subprocess.run") as execute,
        ):
            result = run_cell(cell, defer_server_evidence=True)
        self.assertEqual("skip", result.status)
        self.assertIn("--allow-local-tools", result.detail)
        execute.assert_not_called()


class LifecycleAndReportTests(unittest.TestCase):
    def test_disconnect_requires_abort_and_unique_receipt(self):
        self.assertEqual(
            "fail",
            evaluate_disconnect(
                [
                    {"aborted": False, "http_status": 200, "receipt_hash": "a"},
                    {"aborted": False, "http_status": 200, "receipt_hash": "b"},
                ]
            ).status,
        )
        self.assertEqual(
            "fail",
            evaluate_disconnect(
                [
                    {"aborted": True, "http_status": None, "receipt_hash": "same"},
                    {"aborted": False, "http_status": 200, "receipt_hash": "same"},
                ]
            ).status,
        )
        self.assertEqual(
            "pass",
            evaluate_disconnect(
                [
                    {"aborted": True, "http_status": None, "receipt_hash": "one"},
                    {"aborted": False, "http_status": 200, "receipt_hash": "two"},
                ]
            ).status,
        )

    def test_receipt_uniqueness_ignores_shared_http_request_hashes(self):
        http_hash = correlate_id("shared-http-request")
        first = CellResult(
            "a/cell",
            "pass",
            "client",
            "now",
            1,
            "route",
            "model",
            "one",
            [],
            {
                "server_evidence": {
                    "terminal": {
                        "http_request_id_hash": http_hash,
                        "status": "completed",
                    },
                    "receipt": {"id_hash": correlate_id("receipt-a"), "state": "final"},
                }
            },
        )
        second = CellResult(
            "b/cell",
            "pass",
            "client",
            "now",
            1,
            "route",
            "model",
            "two",
            [],
            {
                "server_evidence": {
                    "terminal": {
                        "http_request_id_hash": http_hash,
                        "status": "completed",
                    },
                    "receipt": {"id_hash": correlate_id("receipt-b"), "state": "final"},
                }
            },
        )
        self.assertEqual([], evaluate_receipt_uniqueness([first, second]))
        self.assertEqual(["pass", "pass"], [first.status, second.status])

    def test_receipt_uniqueness_fails_colliding_pass_cells(self):
        hashed = correlate_id("shared-receipt")
        first = CellResult(
            "a/cell",
            "pass",
            "client",
            "now",
            1,
            "route",
            "model",
            "one",
            [],
            {"server_evidence": {"receipt": {"id_hash": hashed, "state": "final"}}},
        )
        second = CellResult(
            "b/cell",
            "pass",
            "client",
            "now",
            1,
            "route",
            "model",
            "two",
            [],
            {"server_evidence": {"receipt": {"id_hash": hashed, "state": "final"}}},
        )
        collisions = evaluate_receipt_uniqueness([first, second])
        self.assertEqual([hashed], collisions)
        self.assertEqual("fail", second.status)

    def test_required_release_skip_fails_but_ordinary_missing_binary_stays_skip(self):
        inventory = _type64_inventory()
        catalog = next(
            item
            for item in compile_matrix(inventory, "release")
            if item.scenario.id == "cursor-v1-tool-catalog-canary"
        )
        text = MatrixCell(
            catalog.client,
            catalog.route,
            catalog.model,
            Scenario(
                "text-turn",
                "Text",
                "pr",
                "client",
                None,
                frozenset({"text"}),
                10,
                False,
                (Turn("p", "m", ()),),
            ),
        )
        skipped_critical = _cell_result(
            catalog, "skip", detail="client binary not found"
        )
        skipped_ordinary = CellResult(
            text.id,
            "skip",
            "client",
            "now",
            1,
            text.route.id,
            text.model.id,
            text.scenario.id,
            [],
            {},
            "client binary not found",
        )
        gated = apply_completion_gates(
            [skipped_critical, skipped_ordinary], tier="release"
        )
        self.assertEqual("fail", gated[0].status)
        self.assertIn("skipped or unexecuted", gated[0].detail)
        self.assertEqual("skip", gated[1].status)
        pr_critical = _cell_result(catalog, "skip", detail="client binary not found")
        pr_ordinary = CellResult(
            text.id,
            "skip",
            "client",
            "now",
            1,
            text.route.id,
            text.model.id,
            text.scenario.id,
            [],
            {},
            "client binary not found",
        )
        report = build_report([pr_critical, pr_ordinary], tier="pr")
        self.assertEqual("not_run", report["classification"])

    def test_release_classification_fails_if_critical_capability_is_unexecuted(self):
        inventory = _type64_inventory()
        planned = compile_matrix(inventory, "release", coverage="representative")
        usage = next(
            item for item in planned if item.scenario.id == "cursor-v1-usage-quality"
        )
        passed = _cell_result(usage, "pass")
        report = build_report([passed], tier="release", planned_cells=planned)
        self.assertEqual("failed", report["classification"])
        self.assertTrue(report["gates"]["unexecuted_critical"])

    def test_report_persists_hashed_ids_not_raw_request_or_receipt_ids(self):
        raw_request = "202608291253521598208738268d9d67sN73Cgw"
        raw_receipt = "cursor-agent-v1:receipt-secret"
        public_id = f"resp_bf_agentv1_u1_c301_{raw_request}"
        hashed = correlate_id(raw_request)
        result = CellResult(
            "cell",
            "pass",
            "client",
            "now",
            1,
            "route",
            "model",
            "scenario",
            [],
            {
                "server_evidence": {
                    "terminal": {"request_id": raw_request, "status": "completed"},
                    "receipt": {"id": raw_receipt, "state": "final"},
                }
            },
        )
        report = build_report([result], tier="pr")
        dumped = json.dumps(report)
        self.assertNotIn(raw_request, dumped)
        self.assertNotIn(raw_receipt, dumped)
        self.assertIn(correlate_id(raw_request), dumped)
        self.assertIn(correlate_id(raw_receipt), dumped)
        self.assertEqual(hashed, correlate_id(raw_request))
        self.assertNotIn(raw_request, redact_correlation_ids(public_id))
        sanitized = sanitize_report_value({"request_id": raw_request})
        self.assertEqual(hashed, sanitized["request_id"])

    def test_final_json_contains_no_raw_request_tool_or_receipt_ids(self):
        raw_request = "req-raw-secret-abcdef123"
        raw_tool = "toolu_01LiveParkedSecret"
        raw_receipt = "cursor-agent-v1:receipt-secret"
        result = CellResult(
            "cell",
            "pass",
            "client",
            "now",
            1,
            "route",
            "model",
            "scenario",
            [
                TurnResult(
                    1,
                    "pass",
                    1,
                    200,
                    "marker",
                    [],
                    f"output {raw_tool} {raw_receipt}",
                )
            ],
            {
                "_response_request_ids": [raw_request],
                "_replay_attempts": [{"_http_request_id": raw_request}],
                "server_evidence": {
                    "terminal": {"request_id": raw_request, "status": "completed"},
                    "receipt": {"id": raw_receipt, "state": "final"},
                },
                "tool_replay": {"tool_use_id_hashes": [correlate_id(raw_tool)]},
            },
        )
        dumped = json.dumps(build_report([result], tier="pr"))
        self.assertNotIn(raw_request, dumped)
        self.assertNotIn(raw_receipt, dumped)
        self.assertNotIn("_response_request_ids", dumped)
        self.assertNotIn("_http_request_id", dumped)
        self.assertIn(correlate_id(raw_request), dumped)
        self.assertIn(correlate_id(raw_receipt), dumped)
        self.assertNotIn(raw_tool, dumped)


if __name__ == "__main__":
    unittest.main()
