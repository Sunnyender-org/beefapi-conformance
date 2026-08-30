"""Platform helpers for running test fixtures without changing assertions."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MOCK_AGENT = ROOT / "fixtures" / "mock_agent.py"
_WIN_GIT_BASH = (
    r"C:\Program Files\Git\bin\bash.exe",
    r"C:\Program Files (x86)\Git\bin\bash.exe",
)


def mock_agent_candidates() -> tuple[str, ...]:
    """Python interpreter plus the mock fixture. Avoid shebang CreateProcess."""
    return (sys.executable, str(MOCK_AGENT))


def posix_bash() -> str:
    """Return a POSIX bash. On Windows prefer Git Bash, never the WSL stub."""
    if os.name != "nt":
        return "bash"
    return git_bash_windows()


def git_bash_windows() -> str:
    """Resolve Git Bash without using PATH (avoids System32 WSL stub)."""
    candidates: list[str] = []
    for root in (
        os.environ.get("ProgramW6432"),
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
    ):
        if root:
            candidates.append(os.path.join(root, "Git", "bin", "bash.exe"))
    candidates.extend(_WIN_GIT_BASH)
    for path in candidates:
        if "system32" in path.lower().replace("/", "\\"):
            continue
        if os.path.isfile(path):
            return path
    raise FileNotFoundError(
        "Git Bash was not found at C:/Program Files/Git/bin/bash.exe"
    )
