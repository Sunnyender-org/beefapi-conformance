from __future__ import annotations

import copy
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

from beefapi_conformance.cursor_agent_v1 import correlate_id
from beefapi_conformance.model import CellResult, MatrixCell
from beefapi_conformance.report import build_report, write_report
from beefapi_conformance.runner import (
    _batch_session_key,
    _bind_replay_server_evidence,
    _evaluate_single_stage_receipts,
    _replay_no_new_charge_evidence,
    bind_replay_attempt_receipts,
    finalize_batch_server_evidence,
)
from beefapi_conformance.tool_replay import (
    evaluate_generation_receipts,
    evaluate_replay_identity,
    generation_receipt_gap,
)
from tests import test_cursor_agent_v1_completion as fixtures


class GenerationReceiptTests(unittest.TestCase):
    def setUp(self):
        self.helper = fixtures.ToolReplayDriverTests()
        self.cell = self.helper._retry_cell()
        self.attempts = [
            self.helper._generation_a(),
            *self.helper._attempts("req-b", "req-c"),
        ]
        self.logs = [
            self.helper._consume_log(self.cell, "req-a", "cursor-agent-v1:receipt-a"),
            self.helper._consume_log(self.cell, "req-b", "cursor-agent-v1:receipt-b"),
        ]

    def bind(self, logs=None):
        bind_replay_attempt_receipts(
            self.cell,
            self.attempts,
            self.logs if logs is None else logs,
            "commit",
            0,
            set(),
        )

    def test_ab_final_distinct_and_c_zero_preserves_retry_and_nonretry_gates(self):
        self.bind()
        self.assertTrue(_evaluate_single_stage_receipts(self.attempts).ok)
        self.assertTrue(
            evaluate_replay_identity(self.attempts, require_receipts=True).ok
        )
        self.assertEqual("ok", generation_receipt_gap(self.attempts))
        self.assertEqual([1, 1, 0], [a["consume_match_count"] for a in self.attempts])
        self.assertNotEqual(
            self.attempts[0]["receipt_hash"], self.attempts[1]["receipt_hash"]
        )

    def test_ab_missing_provisional_duplicate_or_shared_receipt_cannot_pass(self):
        self.bind()
        valid = copy.deepcopy(self.attempts)
        for stage in (0, 1):
            for fields in (
                {"consume_match_count": 0, "receipt_hash": ""},
                {"receipt_state": "provisional"},
                {"consume_match_count": 2},
                {"receipt_hash": valid[1 - stage]["receipt_hash"]},
                {"http_request_id_hash": ""},
                {"response_receipt_hash": correlate_id("wrong-header")},
            ):
                with self.subTest(stage=stage, fields=fields):
                    changed = copy.deepcopy(valid)
                    changed[stage].update(fields)
                    self.assertFalse(_evaluate_single_stage_receipts(changed).ok)
                    self.assertFalse(
                        evaluate_replay_identity(changed, require_receipts=True).ok
                    )
        self.assertFalse(evaluate_generation_receipts(valid[1:]).ok)
        self.assertFalse(evaluate_generation_receipts([*valid, valid[0]]).ok)

    def test_binding_does_not_borrow_b_receipt_for_missing_a(self):
        self.bind(self.logs[1:])
        self.assertEqual(0, self.attempts[0]["consume_match_count"])
        self.assertEqual("", self.attempts[0]["receipt_hash"])
        self.assertEqual("missing", generation_receipt_gap(self.attempts))
        self.assertFalse(evaluate_generation_receipts(self.attempts).ok)

    def test_c_new_consume_or_missing_exact_id_still_fails(self):
        self.bind()
        self.attempts[2]["http_request_id_hash"] = ""
        self.assertFalse(
            evaluate_replay_identity(self.attempts, require_receipts=True).ok
        )
        self.attempts[2]["http_request_id_hash"] = correlate_id("req-c")
        self.attempts[2].pop("_http_request_id")
        self.bind()
        self.assertIsNone(self.attempts[2]["consume_match_count"])
        self.assertFalse(self.attempts[2]["no_new_charge"])
        self.assertFalse(
            evaluate_replay_identity(self.attempts, require_receipts=True).ok
        )

    def test_nonbatch_c_consume_conflict_cannot_produce_pass_evidence(self):
        logs = [
            *self.logs,
            self.helper._consume_log(self.cell, "req-c", "cursor-agent-v1:receipt-c"),
        ]
        with (
            patch(
                "beefapi_conformance.runner._fetch_token_logs",
                return_value=(logs, "commit"),
            ) as fetch,
            patch("time.sleep") as sleep,
        ):
            payload = _bind_replay_server_evidence(
                self.cell, self.attempts, "offline", 0, set()
            )
        self.assertEqual("fail", payload["status"])
        self.assertIn("stage C", payload["detail"])
        self.assertEqual(1, fetch.call_count)
        sleep.assert_not_called()
        self.attempts[2]["http_request_id_hash"] = correlate_id("req-c")
        self.bind(
            [
                *self.logs,
                self.helper._consume_log(
                    self.cell, "req-c", "cursor-agent-v1:receipt-c"
                ),
            ]
        )
        self.assertFalse(
            evaluate_replay_identity(self.attempts, require_receipts=True).ok
        )

    def test_nonbatch_waits_for_a_final_without_rewriting_b(self):
        provisional = copy.deepcopy(self.logs[0])
        other = json.loads(provisional["other"])
        other["usage_receipt_state"] = "provisional"
        provisional["other"] = json.dumps(other)
        with (
            patch(
                "beefapi_conformance.runner._fetch_token_logs",
                side_effect=[
                    (self.logs[1:], "commit"),
                    ([provisional, self.logs[1]], "commit"),
                    (self.logs, "commit"),
                ],
            ) as fetch,
            patch("time.sleep"),
        ):
            payload = _bind_replay_server_evidence(
                self.cell, self.attempts, "offline", 0, set()
            )
        self.assertEqual(3, fetch.call_count)
        self.assertEqual("pass", payload["status"])
        self.assertEqual(
            [1, 1, 0], [a["consume_match_count"] for a in payload["replay"]["stages"]]
        )

    def test_batch_retry_and_nonretry_require_a_and_b(self):
        for offsets in ((23,), ()):
            for include_a in (True, False):
                with self.subTest(offsets=offsets, include_a=include_a):
                    cell = MatrixCell(
                        self.cell.client,
                        self.cell.route,
                        self.cell.model,
                        replace(self.cell.scenario, retry_offsets_seconds=offsets),
                    )
                    attempts = copy.deepcopy(
                        self.attempts if offsets else self.attempts[:2]
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
                            "_response_request_ids": [
                                a["_http_request_id"] for a in attempts
                            ],
                            "_replay_attempts": attempts,
                            "tool_replay": {
                                "mode": "retry" if offsets else "custom",
                                "tool_use_id_hashes": [],
                            },
                        },
                    )
                    sessions = {
                        _batch_session_key(cell): {"token": "offline", "fence": set()}
                    }
                    with patch(
                        "beefapi_conformance.runner._fetch_token_logs",
                        return_value=(
                            self.logs if include_a else self.logs[1:],
                            "commit",
                        ),
                    ):
                        finalize_batch_server_evidence([cell], [result], sessions)
                    self.assertEqual("pass" if include_a else "fail", result.status)
                    proof = result.evidence["server_evidence"]["replay"]["stages"]
                    self.assertEqual("a", proof[0]["stage"])
                    dumped = json.dumps(build_report([result]))
                    for raw in (
                        "req-a",
                        "req-b",
                        "req-c",
                        "cursor-agent-v1:receipt-a",
                        "cursor-agent-v1:receipt-b",
                        "_http_request_id",
                    ):
                        self.assertNotIn(raw, dumped)

    def test_segment_proof_is_allowlisted_not_raw_attempt_dump(self):
        self.bind()
        self.attempts[0]["_secret"] = "do-not-persist"
        proof = _replay_no_new_charge_evidence(self.attempts)
        dumped = json.dumps(proof)
        self.assertNotIn("do-not-persist", dumped)
        self.assertNotIn("req-a", dumped)
        self.assertNotIn("_bound_payload", dumped)
        self.assertIn(correlate_id("req-a"), dumped)
        self.assertIn(correlate_id("cursor-agent-v1:receipt-a"), dumped)


class UnfinishedJUnitTests(unittest.TestCase):
    def test_unfinished_adds_fixed_failure_and_preserves_client_cases(self):
        for count in (0, 1):
            for unfinished in (False, True):
                with (
                    self.subTest(count=count, unfinished=unfinished),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    rows = [
                        {"cell_id": "client-case", "duration_ms": 1, "status": "pass"}
                    ] * count
                    report = {
                        "results": rows,
                        "unfinished": unfinished,
                        "detail": "opaque-secret raw-request-id",
                    }
                    write_report(report, Path(tmp))
                    suite = ElementTree.parse(Path(tmp) / "junit.xml").getroot()
                    self.assertEqual(count + int(unfinished), int(suite.get("tests")))
                    failures = suite.findall("testcase/failure")
                    self.assertEqual(int(unfinished), len(failures))
                    if unfinished:
                        self.assertEqual(
                            "conformance run did not complete",
                            failures[0].get("message"),
                        )
                    if count:
                        self.assertIsNone(
                            suite.find("testcase[@name='client-case']/failure")
                        )
                    self.assertNotIn(
                        "opaque-secret", (Path(tmp) / "junit.xml").read_text()
                    )
                    self.assertEqual("pass", rows[0]["status"] if count else "pass")
