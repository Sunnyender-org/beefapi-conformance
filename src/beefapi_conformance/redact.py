from __future__ import annotations

import re

PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{6,}"),
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s\"']+"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,\"']+"),
)


def redact(text: str, secrets: tuple[str, ...] = ()) -> str:
    result = text
    for secret in secrets:
        if secret:
            result = result.replace(secret, "***")
    result = PATTERNS[0].sub("sk-***", result)
    result = PATTERNS[1].sub(r"\1***", result)
    result = PATTERNS[2].sub(r"\1***", result)
    return result
