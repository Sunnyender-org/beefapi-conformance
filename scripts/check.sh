#!/bin/bash
set -euo pipefail

if [[ -x .venv/bin/python ]]; then
  python_bin=.venv/bin/python
elif command -v python3.12 >/dev/null 2>&1; then
  python_bin=python3.12
else
  python_bin=python3
fi

PYTHONPATH=src "$python_bin" -m ruff check src tests scripts
PYTHONPATH=src "$python_bin" -m ruff format --check src tests scripts
PYTHONPATH=src "$python_bin" -m unittest discover -s tests -v
PYTHONPATH=src "$python_bin" -m beefapi_conformance validate
PYTHONPATH=src "$python_bin" -m beefapi_conformance plan --tier release --json > /tmp/beefapi-conformance-plan.json
