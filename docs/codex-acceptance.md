# Codex acceptance and regression comparison

The Cursor adapter's unit tests are not a black-box certificate. This matrix
uses released clients and protocol calls against a pinned route, and binds
nightly/release results to server receipts. Local scripted upstream runs prove
client/runtime contracts only. They must not be reported as live acceptance.

## Coverage added for Cursor

| Scenario | Executable assertion |
| --- | --- |
| codex-namespace | Function identity and namespace survive generation; the exact returned call_id is used for result continuation |
| codex-custom | Custom input is returned as custom_tool_call, not wrapped function arguments; result is consumed |
| codex-apply_patch | A custom patch declaration reaches the model, patch text is preserved, and its result is consumed (raw probe never executes patches) |
| codex-compact-json | /responses/compact returns one opaque state, shrinks history, remembers a random secret after continuation, then repeats |
| codex-compact-stream | compaction_trigger returns one opaque state and clean terminal, then the same two-cycle continuation assertions |
| codex-foreign-compaction | Unknown encrypted state receives a typed error instead of a successful answer with missing context |
| codex-auto-compact-tools | Released Codex uses native tools, auto-compacts at a bounded test threshold, resumes and reads the fixture; wire capture must observe compaction and subsequent state replay |

These contracts run per compatible route/model even in representative coverage.
They require basic Responses/stream support rather than an optional compaction
capability flag: turning off a flag cannot hide a broken advertised Codex route.
The native auto-compaction scenario is Codex-only. Its 20000-token threshold is
an isolated test override, not a published production model-window claim.

Existing scenarios continue to own stream lifecycle, function history,
parallel function history, reasoning roundtrip, stateful continuation, search,
concurrent-user isolation, tool loops, and ordinary session resume.

## Reproduce and compare

```sh
PYTHONPATH=src python3 -m beefapi_conformance validate
PYTHONPATH=src python3 -m beefapi_conformance plan --tier release --client raw-http --json
# A live run requires an authorized restricted token and pinned local manifests.
PYTHONPATH=src python3 -m beefapi_conformance run --tier merge \
  --client raw-http --scenario codex-compact-stream \
  --routes manifests/routes.local.json --models manifests/models.local.json \
  --output reports/candidate
PYTHONPATH=src python3 -m beefapi_conformance compare \
  reports/baseline/conformance.json reports/candidate/conformance.json
```

Compare reports with the same requested route/model/scenario coverage. The
command fails when a previously passing cell fails, is skipped, or disappears;
it reports changed client versions separately. No intersecting cells also
fails, because that run cannot establish regression parity.

## Release gates not replaced by local mocks

Every enabled public model needs a real pinned-route run. Include CLI and
Desktop, supported OS/client versions, model switching, images for vision
models, repeated long-context compaction, runtime restart and account rollover.
Fault injection must verify pre-output and mid-output failures, invalid/expired
state and no duplicate external tool execution. Server receipts must cover
all observed requests, successful internal folds, cache usage and failed-fold
accounting. These operational/restart and Desktop gates need a controlled live
fixture; the JSON scenarios above do not pretend to automate them.

The full release report must retain unmet gates as missing evidence rather
than certifying the route from the six raw probes alone. This repository does
not mutate account configuration, restart production, enable disabled models,
or manufacture usage receipts.
