from __future__ import annotations

import shutil
from pathlib import Path


def validate_harbor_tasks(root: Path) -> list[str]:
    errors: list[str] = []
    tasks = list((root / "harbor/tasks").glob("*/task.toml"))
    if not tasks:
        return ["no Harbor tasks found"]
    for task_file in tasks:
        task = task_file.parent
        for relative in ("instruction.md", "environment/Dockerfile", "tests/test.sh"):
            if not (task / relative).is_file():
                errors.append(f"{task.name}: missing {relative}")
        if 'schema_version = "1.1"' not in task_file.read_text(encoding="utf-8"):
            errors.append(f"{task.name}: expected Harbor schema 1.1")
    return errors


def harbor_binary() -> str | None:
    return shutil.which("harbor")
