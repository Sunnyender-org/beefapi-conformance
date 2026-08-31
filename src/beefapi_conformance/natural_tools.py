"""Natural Claude Code discovery: no forced tools or answer markers in the prompt."""

from __future__ import annotations

import json
from pathlib import Path

SCENARIO = "natural-skill-discovery"
FILES = {
    "available-skills/repo-audit/SKILL.md": (
        "# repo-audit\nRead-only repository structure and dependency review. "
        "Never write source files. Report label: READONLY-CEDAR-42.\n"
    ),
    "available-skills/document-index/SKILL.md": (
        "# document-index\nBuild a searchable local Markdown/text document index. "
        "This writes a generated index file; it is not purely read-only. "
        "Report label: INDEX-MAPLE-73.\n"
    ),
}


def prepare(workspace: Path) -> None:
    for name, text in FILES.items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def missing_evidence(output: str) -> list[str]:
    events = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    results = [e for e in events if e.get("type") == "result"]
    final = results[-1] if results else {}
    answer = final.get("result", "")
    if not isinstance(answer, str):
        answer = ""
    missing = []
    if final.get("is_error") is not False or not answer.strip():
        missing.append("successful nonempty terminal answer")
    for name in ("repo-audit", "document-index"):
        if name not in answer:
            missing.append("final answer: " + name)
    tools = [
        block
        for event in events
        if event.get("type") == "assistant"
        for block in event.get("message", {}).get("content", [])
        if isinstance(block, dict) and block.get("type") == "tool_use"
    ]
    if not tools:
        missing.append("actual local tool call")
    for label in ("READONLY-CEDAR-42", "INDEX-MAPLE-73"):
        if label not in output:
            missing.append("file-only evidence: " + label)
    return missing
