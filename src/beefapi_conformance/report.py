from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree

from .model import CellResult


def build_report(results: list[CellResult]) -> dict[str, object]:
    counts = {
        status: sum(1 for item in results if item.status == status)
        for status in ("pass", "fail", "skip")
    }
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "classification": classify(results),
        "summary": {"total": len(results), **counts},
        "results": [asdict(item) for item in results],
    }


def classify(results: list[CellResult]) -> str:
    if not results or all(item.status == "skip" for item in results):
        return "not_run"
    if any(item.status == "fail" for item in results):
        return "failed"
    if any(item.status == "skip" for item in results):
        return "partial"
    return "passed"


def write_report(report: dict[str, object], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "conformance.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    suite = ElementTree.Element("testsuite", name="beefapi-conformance")
    results = report.get("results", [])
    suite.set("tests", str(len(results)))
    for result in results:
        case = ElementTree.SubElement(
            suite,
            "testcase",
            name=str(result["cell_id"]),
            time=str(result["duration_ms"] / 1000),
        )
        if result["status"] == "fail":
            failure = ElementTree.SubElement(
                case,
                "failure",
                message=str(result.get("detail") or "conformance failure"),
            )
            failure.text = json.dumps(result.get("turns", []), ensure_ascii=False)
        elif result["status"] == "skip":
            ElementTree.SubElement(
                case, "skipped", message=str(result.get("detail", ""))
            )
    ElementTree.ElementTree(suite).write(
        output_dir / "junit.xml", encoding="utf-8", xml_declaration=True
    )
