from __future__ import annotations

import unittest
from pathlib import Path

from beefapi_conformance.cursor_agent_protocol import (
    grade_caller_tool_wire,
    load_contract,
)

ROOT = Path(__file__).resolve().parents[1]


class CursorAgentProtocolContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_contract(ROOT)

    def test_old_allowlist_is_rejected(self) -> None:
        problems = grade_caller_tool_wire(
            self.contract,
            {
                "allowlist": ["mcp_tool_call"],
                "has_caller_tools": True,
                "request_context_fields": [4, 7, 16],
                "mcp_meta_enabled": False,
                "ignored_tool_call_fields": [54, 57, 59, 60],
                "caller_tool_server": "beefapi",
            },
        )
        self.assertTrue(any("GET_MCP_TOOLS" in problem for problem in problems))
        self.assertTrue(any("mcp_meta_tool_options" in problem for problem in problems))

    def test_current_caller_tool_wire_passes(self) -> None:
        problems = grade_caller_tool_wire(
            self.contract,
            {
                "allowlist": [
                    "mcp_tool_call",
                    "get_mcp_tools_tool_call",
                    "web_search_tool_call",
                    "web_fetch_tool_call",
                ],
                "allow_hosted_search": True,
                "allow_hosted_fetch": True,
                "has_caller_tools": True,
                "request_context_fields": [4, 7, 16, 34],
                "mcp_meta_enabled": True,
                "ignored_tool_call_fields": self.contract["ignored_tool_call_fields"],
                "advisory_interaction_fields": self.contract["advisory_interaction_fields"],
                "caller_tool_server": "beefapi",
            },
        )
        self.assertEqual(problems, [])

    def test_field_42_stays_fail_closed(self) -> None:
        contract = dict(self.contract)
        contract["advisory_interaction_fields"] = list(contract["advisory_interaction_fields"]) + [42]
        problems = grade_caller_tool_wire(
            contract,
            {
                "allowlist": contract["caller_tool_allowlist"],
                "has_caller_tools": False,
                "ignored_tool_call_fields": contract["ignored_tool_call_fields"],
                "advisory_interaction_fields": contract["advisory_interaction_fields"],
            },
        )
        self.assertTrue(any("field 42" in problem for problem in problems))

    def test_unmodelled_inventory_does_not_include_the_required_discovery_tool(self) -> None:
        unmodelled = set(self.contract["not_required_for_a_caller_tool_run"]["tool_call_variants_still_fail_closed"])
        self.assertNotIn(44, unmodelled)
        self.assertIn(41, unmodelled)
