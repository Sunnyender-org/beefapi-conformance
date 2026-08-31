import json
import tempfile
import unittest
from pathlib import Path

from beefapi_conformance.natural_tools import FILES, missing_evidence, prepare


class NaturalToolsTests(unittest.TestCase):
    def output(self, result):
        return "\n".join(
            json.dumps(e)
            for e in [
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "tool_use", "id": "local-read", "name": "Read"}
                        ]
                    },
                },
                {
                    "type": "user",
                    "message": {"content": "READONLY-CEDAR-42 INDEX-MAPLE-73"},
                },
                {"type": "result", "is_error": False, "result": result},
            ]
        )

    def test_tool_success_followed_by_empty_final_is_failure(self):
        self.assertTrue(missing_evidence(self.output("")))

    def test_earlier_assistant_claim_cannot_replace_final(self):
        output = (
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "text", "text": "repo-audit document-index"}
                        ]
                    },
                }
            )
            + "\n"
            + self.output("")
        )
        self.assertIn("final answer: repo-audit", missing_evidence(output))

    def test_grounded_answer_after_real_tools_passes(self):
        self.assertEqual(
            [],
            missing_evidence(
                self.output("repo-audit is read-only; document-index writes an index.")
            ),
        )

    def test_fixture_exists_only_in_owned_workspace(self):
        with tempfile.TemporaryDirectory() as root:
            prepare(Path(root))
            for name, text in FILES.items():
                self.assertEqual(text, (Path(root) / name).read_text())
