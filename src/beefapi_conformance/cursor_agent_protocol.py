"""Cursor Agent v1 MCP meta-tool contract.

The current agent renders the MCP invocation tool by looking up GET_MCP_TOOLS.
An allowlist that keeps mcp_tool_call and drops get_mcp_tools_tool_call makes
that lookup raise "Required tool GET_MCP_TOOLS not found in allTools".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def contract_path(root: Path) -> Path:
    return root / "contracts" / "cursor-agent-mcp-meta.json"


def load_contract(root: Path) -> dict[str, Any]:
    data = json.loads(contract_path(root).read_text())
    if not isinstance(data, dict):
        raise ValueError("cursor agent protocol contract must be an object")
    return data


def grade_caller_tool_wire(contract: dict[str, Any], observed: dict[str, Any]) -> list[str]:
    """Return problems for one Agent v1 caller-tool request.

    observed keys:
      allowlist: list of x-cursor-agent-allowed-tools names
      has_caller_tools: bool
      request_context_fields: list of RequestContext field numbers
      mcp_meta_enabled: bool, required when has_caller_tools
      ignored_tool_call_fields: list of ToolCall fields the decoder ignores
    """
    problems: list[str] = []
    allowlist = list(observed.get("allowlist") or [])
    required = list(contract["caller_tool_allowlist"])
    missing = [name for name in required if name not in allowlist]
    if missing:
        problems.append(
            "allowed tools omit " + ", ".join(missing) + "; GET_MCP_TOOLS must stay with mcp_tool_call"
        )
    if observed.get("allow_hosted_search") and contract["hosted_search_tool"] not in allowlist:
        problems.append("hosted search is enabled but web_search_tool_call is not allowed")
    if observed.get("allow_hosted_fetch") and contract["hosted_fetch_tool"] not in allowlist:
        problems.append("hosted fetch is enabled but web_fetch_tool_call is not allowed")
    if observed.get("has_caller_tools"):
        fields = set(observed.get("request_context_fields") or [])
        tools_field = contract["request_context_mcp_tools_field"]
        meta_field = contract["request_context_mcp_meta_tool_options_field"]
        if tools_field not in fields:
            problems.append(f"caller tools are missing RequestContext field {tools_field}")
        if meta_field not in fields or not observed.get("mcp_meta_enabled"):
            problems.append(
                f"caller tools require RequestContext.mcp_meta_tool_options field {meta_field} enabled"
            )
        if observed.get("caller_tool_server") not in (None, contract["caller_tool_server"]):
            problems.append(
                f"caller tool server must be {contract['caller_tool_server']}"
            )
    ignored = set(observed.get("ignored_tool_call_fields") or [])
    if 44 not in ignored:
        problems.append("ToolCall field 44 get_mcp_tools_tool_call must be ignored, not failed closed")
    fail_closed = contract["fail_closed"]
    if fail_closed["unknown_tool_call_field"] in ignored:
        problems.append("an unmodelled tool variant must still fail closed")
    if fail_closed["unknown_interaction_field"] in set(observed.get("advisory_interaction_fields") or contract["advisory_interaction_fields"]):
        problems.append("interaction field 42 must stay fail-closed")
    return problems
