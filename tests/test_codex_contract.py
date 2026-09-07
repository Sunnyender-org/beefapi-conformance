import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from beefapi_conformance.manifest import load_inventory
from beefapi_conformance.matrix import compile_matrix
from beefapi_conformance.responses_contract import exercise


def outcome(output, status=200):
    return SimpleNamespace(
        status_code=status,
        output=output,
        stream_detail="",
        duration_ms=1,
        request_id="fixture",
    )


def completed(items):
    return outcome(
        "event: response.completed\ndata: "
        + json.dumps(
            {
                "type": "response.completed",
                "response": {"status": "completed", "output": items},
            }
        )
        + "\n\n"
    )


class CodexContractTests(unittest.TestCase):
    def test_plain_completed_is_not_compaction(self):
        for kind in ["compact-json", "compact-stream"]:

            def send(p, endpoint, stream):
                if stream:
                    return completed(
                        [
                            {
                                "type": "message",
                                "content": [{"type": "output_text", "text": "hello"}],
                            }
                        ]
                    )
                return outcome(
                    json.dumps({"output": [{"type": "message", "content": []}]})
                )

            _, problems = exercise(kind, "fixture", send)
            self.assertIn("exactly one", problems[0])

    def test_namespace_loss_fails(self):
        _, problems = exercise(
            "namespace",
            "fixture",
            lambda *_: completed(
                [
                    {
                        "type": "function_call",
                        "name": "functions__lookup",
                        "call_id": "a",
                        "arguments": "{}",
                    }
                ]
            ),
        )
        self.assertIn("kind/name", problems[0])

    def test_function_does_not_pass_as_custom(self):
        _, problems = exercise(
            "custom",
            "fixture",
            lambda *_: completed(
                [
                    {
                        "type": "function_call",
                        "name": "write_raw",
                        "call_id": "a",
                        "arguments": "{}",
                    }
                ]
            ),
        )
        self.assertIn("kind/name", problems[0])

    def test_unknown_state_must_fail_explicitly(self):
        _, problems = exercise(
            "foreign-compaction", "fixture", lambda *_: completed([])
        )
        self.assertTrue(problems)
        _, problems = exercise(
            "foreign-compaction",
            "fixture",
            lambda *_: outcome('{"error":{"code":"invalid_compaction"}}', 400),
        )
        self.assertFalse(problems)

    def test_custom_roundtrip_uses_actual_call_id_and_result(self):
        calls = []

        def send(payload, *_):
            calls.append(payload)
            if len(calls) == 1:
                text = (
                    payload["input"][0]["content"]
                    .split("this exact input:\n")[1]
                    .split(". Do not")[0]
                )
                return completed(
                    [
                        {
                            "type": "custom_tool_call",
                            "name": "write_raw",
                            "input": text,
                            "call_id": "unique-call",
                        }
                    ]
                )
            result = payload["input"][-2]
            self.assertEqual(result["call_id"], "unique-call")
            self.assertEqual(result["type"], "custom_tool_call_output")
            return completed(
                [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": result["output"]}],
                    }
                ]
            )

        _, problems = exercise("custom", "fixture", send)
        self.assertFalse(problems)
        self.assertEqual(len(calls), 2)

    def test_required_contracts_survive_representative_sampling(self):
        root = Path(__file__).resolve().parents[1]
        inv = load_inventory(
            root,
            root / "manifests/routes.example.json",
            root / "manifests/models.example.json",
        )
        full = compile_matrix(inv, "release")
        sampled = compile_matrix(inv, "release", coverage="representative")
        wanted = {c.id for c in full if c.scenario.responses_contract}
        self.assertTrue(wanted)
        self.assertTrue(wanted <= {c.id for c in sampled})


class ReportComparisonTests(unittest.TestCase):
    def test_missing_and_skipped_cells_are_not_success(self):
        from beefapi_conformance.report import compare_reports

        old = {
            "results": [
                {"cell_id": "a", "status": "pass"},
                {"cell_id": "b", "status": "pass"},
            ]
        }
        new = {"results": [{"cell_id": "a", "status": "skip"}]}
        result = compare_reports(old, new)
        self.assertEqual(
            {x["after"] for x in result["regressions"]}, {"skip", "missing"}
        )


class RejectionEvidenceTests(unittest.TestCase):
    def test_rejection_needs_correlated_zero_quota_error(self):
        from beefapi_conformance.runner import _matching_usage_logs, _usage_log_payload

        root = Path(__file__).resolve().parents[1]
        inv = load_inventory(
            root,
            root / "manifests/routes.example.json",
            root / "manifests/models.example.json",
        )
        cell = next(
            c
            for c in compile_matrix(inv, "merge")
            if c.scenario.responses_contract == "foreign-compaction"
        )
        error = {
            "request_id": "r1",
            "type": 5,
            "quota": 0,
            "model_name": cell.model.id,
            "created_at": 100,
        }
        self.assertEqual(
            _matching_usage_logs(cell, [error], 100, set(), {"r1"}), [error]
        )
        self.assertEqual(_usage_log_payload(cell, error, "commit")["status"], "pass")
        self.assertEqual(
            _usage_log_payload(cell, dict(error, quota=1), "commit")["status"], "fail"
        )
