import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from beefapi_conformance.cursor_agent_v1 import (
    correlate_id,
    evaluate_hosted_search,
    evaluate_public_artifacts,
)


class ClaudeSearchChildTests(unittest.TestCase):
    def test_real_claude_cell_cannot_pass_on_counts_without_client_trace(self):
        cell = SimpleNamespace(
            client=SimpleNamespace(id="claude-code"),
            route=SimpleNamespace(channel_type=64),
            scenario=SimpleNamespace(
                id="native-web-search",
                evidence_requirements=(),
                retry_offsets_seconds=(),
                mcp_mode=None,
            ),
        )
        evidence = {
            "usage": {
                "web_search_call_count": 1,
                "citation_count": 2,
                "progress_event_count": 3,
            }
        }
        for output in ("", "Web Search did 1 search", "unparsed output"):
            self.assertEqual(
                "fail",
                evaluate_public_artifacts(
                    cell, output=output, evidence=evidence
                ).status,
            )
        cell.client.id = "raw-http"
        self.assertEqual(
            "pass", evaluate_public_artifacts(cell, evidence=evidence).status
        )

    def evidence(self):
        return {
            "caller_tool_id_hash": correlate_id("toolu_fixture"),
            "result_tool_id_hash": correlate_id("toolu_fixture"),
            "http_request_id_hash": correlate_id("child-http"),
            "channel_type": 64,
            "tool_type": "web_search_20250305",
            "max_uses": 8,
            "stop_reason": "end_turn",
            "result_is_error": False,
        }

    def evaluate(self, child):
        return evaluate_hosted_search(
            web_search_call_count=1,
            citation_count=2,
            progress_event_count=2,
            client_output=json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "name": "WebSearch",
                                "id": "toolu_fixture",
                                "input": {"query": "fixture"},
                            }
                        ],
                    },
                }
            ),
            child_search=child,
        ).status

    def test_wrapper_requires_correlated_cursor_child(self):
        self.assertEqual("pass", self.evaluate(self.evidence()))
        self.assertEqual("fail", self.evaluate(None))
        for field, value in (
            ("caller_tool_id_hash", "unhashed"),
            ("result_tool_id_hash", correlate_id("other-tool")),
            ("http_request_id_hash", ""),
            ("channel_type", 60),
            ("tool_type", "function"),
            ("max_uses", 0),
            ("max_uses", True),
            ("result_is_error", True),
            ("stop_reason", "tool_use"),
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    "fail", self.evaluate({**self.evidence(), field: value})
                )

    def test_fixture_stream_has_real_input_and_text_deltas(self):
        path = (
            Path(__file__).resolve().parents[1] / "scripts/smoke_claude_search_child.py"
        )
        spec = importlib.util.spec_from_file_location("search_fixture", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        output = module.stream(
            {
                "id": "fixture",
                "stop_reason": "tool_use",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_fixture",
                        "name": "WebSearch",
                        "input": {"query": "fixture"},
                    },
                    {"type": "text", "text": "fixture"},
                ],
            }
        ).decode()
        events = [
            json.loads(line[6:])
            for line in output.splitlines()
            if line.startswith("data: ")
        ]
        deltas = [
            event["delta"] for event in events if event["type"] == "content_block_delta"
        ]
        self.assertEqual({"query": "fixture"}, json.loads(deltas[0]["partial_json"]))
        self.assertEqual("fixture", deltas[1]["text"])
        self.assertEqual("message_stop", events[-1]["type"])
        self.assertTrue(
            module.parent_result_matches(
                "success", {"result_is_error": False, "result_contains_fixture": True}
            )
        )
        self.assertTrue(
            module.parent_result_matches(
                "empty", {"result_is_error": False, "result_contains_fixture": False}
            )
        )
        self.assertTrue(
            module.parent_result_matches(
                "http-error",
                {"result_is_error": True, "result_contains_fixture": False},
            )
        )
        self.assertFalse(
            module.parent_result_matches(
                "success", {"result_is_error": True, "result_contains_fixture": True}
            )
        )
        self.assertFalse(
            module.parent_result_matches(
                "empty", {"result_is_error": True, "result_contains_fixture": False}
            )
        )
        self.assertFalse(
            module.parent_result_matches(
                "http-error",
                {"result_is_error": False, "result_contains_fixture": False},
            )
        )


if __name__ == "__main__":
    unittest.main()
