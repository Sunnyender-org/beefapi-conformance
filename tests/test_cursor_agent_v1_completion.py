from __future__ import annotations

import http.server
import json
import os
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from beefapi_conformance.clients import ClientCommand
from beefapi_conformance.cursor_agent_v1 import (
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
    MatrixCell,
    Scenario,
    Turn,
)
from beefapi_conformance.report import build_report
from beefapi_conformance.runner import _usage_log_payload, run_cell

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads(
    (ROOT / "tests/fixtures/cursor_agent_v1/evidence.json").read_text(encoding="utf-8")
)


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
        result = self._run_http_scenario(
            "cursor-v1-covering-set-tool-result", status=400, marker="NO"
        )
        self.assertEqual("fail", result.status)
        self.assertEqual(400, result.turns[0].returncode)

    def test_http_covering_set_2xx_passes_without_server_evidence(self):
        result = self._run_http_scenario(
            "cursor-v1-covering-set-tool-result",
            status=200,
            marker="BEEFAPI_CURSOR_V1_COVERING_OK",
        )
        self.assertEqual("pass", result.status, result.detail)

    def _run_http_scenario(self, scenario_id: str, *, status: int, marker: str):
        inventory = _type64_inventory()
        cell = next(
            item
            for item in compile_matrix(inventory, "release")
            if item.scenario.id == scenario_id and item.client.adapter == "raw-http"
        )

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                self.rfile.read(length)
                body = json.dumps(
                    {"content": [{"type": "text", "text": marker}]}
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
                    b'data: {"content":[{"type":"text","text":"BEEFAPI_CURSOR_V1_THINKING_OK"}]}\n\n'
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

    def test_classifier_rejects_bypass_permissions(self):
        self.assertEqual(
            "fail",
            evaluate_classifier("", permission_mode="bypassPermissions").status,
        )
        self.assertEqual(
            "pass",
            evaluate_classifier(
                '{"type":"classifier","mode":"auto"}', permission_mode="default"
            ).status,
        )

    def test_classifier_scenario_uses_claude_default_permission_mode(self):
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
            self.assertEqual("default", args[args.index("--permission-mode") + 1])
            self.assertNotIn("bypassPermissions", args)


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


if __name__ == "__main__":
    unittest.main()
