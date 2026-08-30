import json
import unittest

from beefapi_conformance.cursor_agent_v1 import redact_correlation_ids
from beefapi_conformance.model import CellResult, TurnResult
from beefapi_conformance.report import build_report
from beefapi_conformance.runner import _http_response_text, _set_batch_evidence_failure
from beefapi_conformance.tool_replay import evaluate_none_terminal


class FinalEvidenceBoundaries(unittest.TestCase):
    def test_non_assistant_message_is_not_a_response(self):
        for role in ("user", "system", None):
            with self.subTest(role=role):
                body = {
                    "type": "message",
                    "content": [{"type": "text", "text": "MARKER"}],
                    "stop_reason": "end_turn",
                }
                if role is not None:
                    body["role"] = role
                raw = json.dumps(body)
                self.assertEqual(_http_response_text("messages", raw), "")
                self.assertFalse(evaluate_none_terminal(raw, "MARKER").ok)

    def test_messages_real_text_delta_is_visible(self):
        stream = 'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"MARKER"}}\n\n'
        self.assertEqual(_http_response_text("messages", stream), "MARKER")
        self.assertEqual(
            _http_response_text(
                "messages", stream.replace("text_delta", "input_json_delta")
            ),
            "",
        )

    def test_failed_evidence_scrubs_ids_before_dropping_private_fields(self):
        raw_id = "opaque-request-canary-for-final-report"
        result = CellResult(
            "cell",
            "pass",
            "test",
            "now",
            1,
            "route",
            "model",
            "scenario",
            [TurnResult(1, "pass", 1, 0, "ok", [], "request failed: " + raw_id)],
            {"_response_request_ids": [raw_id]},
        )
        _set_batch_evidence_failure(result, "missing evidence for " + raw_id)
        serialized = json.dumps(build_report([result]))
        self.assertNotIn(raw_id, serialized)

    def test_relay_request_id_in_client_warning_is_hashed(self):
        raw_id = "20260830031257986234308268d9d6jIRn0kG4"
        self.assertNotIn(
            raw_id, redact_correlation_ids("warning (request id: " + raw_id + ")")
        )


if __name__ == "__main__":
    unittest.main()
