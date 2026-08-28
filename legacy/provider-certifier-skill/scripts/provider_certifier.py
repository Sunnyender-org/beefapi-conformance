#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parents[1]
ALLOWED_ROOTS = {"references", "templates", "evals"}


def repo_path() -> Path | None:
    value = os.environ.get("BEEFAPI_REPO", "").strip()
    return Path(value).expanduser().resolve() if value else None


def harness_path() -> Path:
    repo = repo_path()
    if repo is not None:
        candidate = repo / "scripts/provider-certifier/certify.py"
        if candidate.is_file():
            return candidate
    return SKILL_DIR / "scripts/certify.py"


def readable_files() -> list[str]:
    files = ["SKILL.md"]
    for root in sorted(ALLOWED_ROOTS):
        directory = SKILL_DIR / root
        if directory.exists():
            files.extend(str(path.relative_to(SKILL_DIR)) for path in sorted(directory.rglob("*")) if path.is_file())
    return files


def safe_resource(value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise SystemExit("resource path is not allowed")
    if value != "SKILL.md" and (not relative.parts or relative.parts[0] not in ALLOWED_ROOTS):
        raise SystemExit("only SKILL.md, references, templates, and evals are readable")
    path = (SKILL_DIR / relative).resolve()
    if SKILL_DIR not in path.parents or not path.is_file():
        raise SystemExit("resource not found")
    return path


def validate() -> int:
    required = [
        SKILL_DIR / "SKILL.md",
        SKILL_DIR / "references/certification-matrix.md",
        SKILL_DIR / "templates/certification-report.example.json",
        SKILL_DIR / "evals/trigger_cases.json",
        SKILL_DIR / "scripts/certify.py",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        print(json.dumps({"ok": False, "missing": missing}, indent=2))
        return 1
    json.loads((SKILL_DIR / "templates/certification-report.example.json").read_text())
    json.loads((SKILL_DIR / "evals/trigger_cases.json").read_text())
    print(json.dumps({"ok": True, "skill": str(SKILL_DIR), "harness": str(harness_path())}, indent=2))
    return 0


def validate_report(path: Path) -> int:
    report = json.loads(path.read_text(encoding="utf-8"))
    required = {"schema_version", "generated_at", "target", "classification", "summary", "checks"}
    missing = sorted(required - set(report))
    allowed = {"certified", "limited", "experimental", "blocked"}
    errors = []
    if missing:
        errors.append(f"missing fields: {', '.join(missing)}")
    if report.get("classification") not in allowed:
        errors.append("invalid classification")
    if not isinstance(report.get("checks"), list):
        errors.append("checks must be a list")
    print(json.dumps({"ok": not errors, "errors": errors, "classification": report.get("classification")}, indent=2))
    return 0 if not errors else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    read = sub.add_parser("read")
    read.add_argument("resource")
    sub.add_parser("validate")
    sub.add_parser("doctor")
    run = sub.add_parser("run")
    run.add_argument("args", nargs=argparse.REMAINDER)
    report = sub.add_parser("validate-report")
    report.add_argument("path", type=Path)
    args = parser.parse_args()

    if args.command == "list":
        print("\n".join(readable_files()))
        return 0
    if args.command == "read":
        print(safe_resource(args.resource).read_text(encoding="utf-8"), end="")
        return 0
    if args.command == "validate":
        return validate()
    if args.command == "doctor":
        harness = harness_path()
        result = {
            "repo": str(repo_path()) if repo_path() else None,
            "harness_path": str(harness),
            "harness": harness.is_file(),
            "codex": bool(__import__("shutil").which("codex")),
            "claude": bool(__import__("shutil").which("claude")),
            "credential_env_set": bool(os.environ.get("BEEFAPI_PROVIDER_TEST_KEY")),
        }
        print(json.dumps(result, indent=2))
        return 0 if result["harness"] and result["codex"] and result["claude"] else 1
    if args.command == "validate-report":
        return validate_report(args.path)
    harness = harness_path()
    forwarded = list(args.args)
    if forwarded[:1] == ["--"]:
        forwarded = forwarded[1:]
    return subprocess.call([sys.executable, str(harness), *forwarded], cwd=repo_path() or SKILL_DIR)


if __name__ == "__main__":
    raise SystemExit(main())
