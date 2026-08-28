import importlib.util
import json
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("certify.py")
SPEC = importlib.util.spec_from_file_location("provider_certify", MODULE_PATH)
assert SPEC and SPEC.loader
certify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = certify
SPEC.loader.exec_module(certify)


class ProviderCertifierTests(unittest.TestCase):
    def test_extract_codex_thread_id(self):
        output = "\n".join([
            json.dumps({"type": "thread.started", "thread_id": "thread-233"}),
            json.dumps({"type": "turn.completed"}),
        ])
        self.assertEqual("thread-233", certify.extract_codex_thread_id(output))

    def test_response_output_from_completed_sse(self):
        events = [{
            "type": "response.completed",
            "response": {"output": [{"type": "function_call", "name": "cert_marker"}]},
        }]
        self.assertEqual("cert_marker", certify.response_output(events)[0]["name"])

    def test_anthropic_partial_tool_json(self):
        events = [
            {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "tool-1", "name": "cert_marker"}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": '{"marker":'}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": '"ok"}'}},
        ]
        block = certify.anthropic_content(events)[0]
        self.assertEqual({"marker": "ok"}, block["input"])

    def test_required_unsupported_is_limited(self):
        results = [
            certify.CheckResult("responses", "responses", certify.PASS, True, 1),
            certify.CheckResult("image", "responses", certify.UNSUPPORTED, True, 1),
        ]
        self.assertEqual("limited", certify.classify(results, clients_requested=True))

    def test_api_failure_is_blocked(self):
        results = [certify.CheckResult("messages", "messages", certify.FAIL, True, 1)]
        self.assertEqual("blocked", certify.classify(results, clients_requested=True))

    def test_secret_redaction(self):
        self.assertNotIn("abcdef", certify.compact_error("Bearer sk-abcdef123456"))

    def test_report_contains_client_versions(self):
        args = certify.parse_args(["--model", "glm-5.2", "--profile", "api"])
        report = certify.build_report(args, [])
        self.assertIn("client_versions", report["target"])

    def test_clients_only_cannot_be_certified(self):
        results = [
            certify.CheckResult("codex", "codex_client", certify.PASS, True, 1),
            certify.CheckResult("claude", "claude_client", certify.PASS, True, 1),
        ]
        self.assertEqual("experimental", certify.classify(results, clients_requested=True))

    def test_codex_child_env_scrubs_ambient_openai_credentials(self):
        env = certify.codex_child_env(Path("/tmp/codex-cert"), {
            "PATH": "/bin",
            "OPENAI_API_KEY": "wrong",
            "OPENAI_BASE_URL": "https://wrong.example",
            "CODEX_API_KEY": "wrong-too",
        })
        self.assertEqual("/bin", env["PATH"])
        self.assertEqual("/tmp/codex-cert", env["CODEX_HOME"])
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("OPENAI_BASE_URL", env)
        self.assertNotIn("CODEX_API_KEY", env)

    def test_pin_channel_key_does_not_double_pin(self):
        self.assertEqual("sk-token-233", certify.pin_channel_key("sk-token", "233"))
        self.assertEqual("sk-token-233", certify.pin_channel_key("sk-token-233", "233"))
        with self.assertRaisesRegex(ValueError, "already pinned to channel 160"):
            certify.pin_channel_key("sk-token-160", "233")


if __name__ == "__main__":
    unittest.main()
