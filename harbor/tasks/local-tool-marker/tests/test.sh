#!/bin/bash
set -euo pipefail

mkdir -p /logs/verifier
if [[ -f /workspace/observed.txt ]] && [[ "$(cat /workspace/observed.txt)" == "BEEFAPI_HARBOR_TOOL_OK" ]]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
