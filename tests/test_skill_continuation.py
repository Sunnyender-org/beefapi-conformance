import json
import tempfile
import unittest
from pathlib import Path

from beefapi_conformance.clients import codex_final_text
from beefapi_conformance.manifest import load_inventory
from beefapi_conformance.matrix import compile_matrix
from beefapi_conformance.skill_fixture import (
    PNG,
    image_skill_problems,
    install_image_skill,
)
from beefapi_conformance.wire import (
    Exchange,
    _SseCapture,
    summarize_request,
    wire_verdict,
)

ROOT = Path(__file__).resolve().parents[1]


class SkillContinuationTests(unittest.TestCase):
    def test_unsupported_tool_call_fails_even_after_clean_terminal(self):
        for kind, expected in [("function_call_output", "fail"), ("message", "pass")]:
            with self.subTest(kind=kind):
                body = json.dumps(
                    {"input": [{"type": kind, "output": "unsupported call: read"}]}
                ).encode()
                exchange = Exchange(
                    "POST",
                    "/v1/responses",
                    200,
                    summarize_request(body),
                    True,
                    terminated="clean",
                )
                self.assertEqual(wire_verdict([exchange])["status"], expected)

    def test_empty_completed_is_not_wire_success(self):
        capture = _SseCapture()
        raw = b'data: {"type":"response.completed","response":{"output":[],"usage":{"output_tokens":0}}}\n\n'
        for byte in raw:
            capture.feed(bytes([byte]))
        self.assertTrue(capture.empty_completed)
        exchange = Exchange(
            "POST",
            "/v1/responses",
            200,
            {},
            True,
            terminated="clean",
            empty_completed=capture.empty_completed,
        )
        self.assertEqual(wire_verdict([exchange])["status"], "fail")

    def test_tool_only_and_streamed_text_are_not_empty(self):
        for event in [
            {"type": "response.output_text.delta", "delta": "done"},
            {
                "type": "response.output_item.done",
                "item": {"type": "function_call", "name": "write_stdin"},
            },
        ]:
            capture = _SseCapture()
            capture.feed(("data: " + json.dumps(event) + "\n\n").encode())
            capture.feed(
                b'data: {"type":"response.completed","response":{"output":[],"usage":{"output_tokens":0}}}\n\n'
            )
            self.assertFalse(capture.empty_completed)

    def test_parse_error_and_missing_poll_fail_even_after_clean_terminal(self):
        body = json.dumps(
            {
                "input": [
                    {
                        "type": "function_call_output",
                        "output": "failed to parse function arguments: invalid type: floating point",
                    }
                ]
            }
        ).encode()
        exchange = Exchange(
            "POST",
            "/v1/responses",
            200,
            summarize_request(body),
            True,
            terminated="clean",
        )
        self.assertEqual(wire_verdict([exchange])["status"], "fail")
        exchange.request = {}
        self.assertEqual(wire_verdict([exchange], ("shell_poll",))["status"], "fail")
        exchange.called_tools = ["write_stdin"]
        self.assertEqual(wire_verdict([exchange], ("shell_poll",))["status"], "pass")

    def test_commentary_and_successful_file_check_are_not_final_reply(self):
        events = [
            {
                "type": "item.completed",
                "item": {
                    "type": "agent_message",
                    "text": "BEEFAPI_IMAGE_SKILL_OK will follow",
                },
            },
            {
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "aggregated_output": "Wrote result.png",
                    "exit_code": 0,
                },
            },
            {"type": "turn.completed", "usage": {"output_tokens": 0}},
        ]
        self.assertEqual(codex_final_text("\n".join(map(json.dumps, events))), "")
        events.insert(
            -1,
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": "BEEFAPI_IMAGE_SKILL_OK"},
            },
        )
        self.assertEqual(
            codex_final_text("\n".join(map(json.dumps, events))),
            "BEEFAPI_IMAGE_SKILL_OK",
        )

    def test_fixture_checks_bytes_and_exactly_one_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            install_image_skill(home)
            self.assertEqual(len(image_skill_problems(home)), 2)
            (home / "result.png").write_bytes(PNG)
            (home / "generation-count.txt").write_text("1\n")
            self.assertEqual(image_skill_problems(home), [])
            (home / "generation-count.txt").write_text("1\n1\n")
            self.assertIn("single_generation", image_skill_problems(home))
            self.assertIn(
                "time.sleep(12)",
                (home / "skills/conformance-image/generate.py").read_text(),
            )

    def test_scenario_is_codex_only_and_retained_in_representative_matrix(self):
        inventory = load_inventory(
            ROOT,
            ROOT / "manifests/routes.example.json",
            ROOT / "manifests/models.example.json",
        )
        cells = compile_matrix(
            inventory,
            "merge",
            scenarios={"codex-image-skill-continuation"},
            coverage="representative",
        )
        self.assertTrue(cells)
        self.assertEqual({c.client.adapter for c in cells}, {"codex"})
        self.assertTrue(all(c.scenario.requires_local_tools for c in cells))


if __name__ == "__main__":
    unittest.main()
