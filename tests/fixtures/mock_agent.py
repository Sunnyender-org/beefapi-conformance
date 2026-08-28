#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

prompt = sys.argv[-1] if len(sys.argv) > 1 else ""
marker = (
    Path("marker.txt").read_text(encoding="utf-8").strip()
    if Path("marker.txt").exists()
    else ""
)
print('{"type":"thread.started","thread_id":"mock-thread"}')
print(marker)
print(prompt)
