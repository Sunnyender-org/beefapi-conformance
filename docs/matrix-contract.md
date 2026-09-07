# Matrix Contract

## Axes

Every result identifies an exact:

- client and version;
- operating system;
- route and authentication mode;
- public model id plus client-specific alias;
- scenario and tier;
- start time, duration, terminal status, and bounded sanitized output;
- wire capture (per-request stream termination, timing, and tool declarations)
  for native clients running through the recording proxy;
- server evidence payload where the route provides one.

The committed manifests are examples and structural contracts, not a production
model catalog. Nightly automation generates local route/model manifests from
the authoritative BeefAPI catalog via `sync-inventory`.

## Tiers

| Tier | Gate | Intended coverage |
|---|---|---|
| `pr` | every change | schema, dry matrix, streaming protocol scenarios |
| `merge` | integration branch | real clients: long streams, tool loops, web search |
| `nightly` | scheduled | every active model/channel plus session resume |
| `release` | production promotion | OS and client-version matrix plus receipt evidence |

The compiler runs scenarios from the selected tier and every lower tier.

`--coverage full` keeps the complete Cartesian matrix. Scheduled production
runs use `--coverage representative`: every route/model pair gets a raw
streaming Responses check, every model gets a native-client text turn, and the
deep cases (`tool-loop`, `session-resume`, `web-search`, `long-stream`) rotate
deterministically across native clients per route. `--max-cells` fails closed
on accidental expansion.

## Grading

A cell passes only when all of the following hold:

1. every turn exited cleanly with the expected marker and events;
2. every completion request captured on the wire terminated with its
   protocol's terminal event (no early EOF, no error event, no 4xx/5xx);
3. scenario wire expectations hold (`multi_request` for tool loops,
   `web_search_requested` for web search);
3a. for `concurrency > 1`, every simulated user passed, no response carried
   another user's nonce, and p95 latency stayed within `max_slowdown` of the
   serial baseline;
4. on nightly/release, the route's server evidence resolves to a final usage
   receipt bound to the pinned channel and observed request ids.

## Classification

- `passed`: every scheduled cell ran and passed.
- `partial`: at least one cell passed and another was skipped.
- `failed`: at least one cell failed.
- `not_run`: no cells ran or every cell skipped.

Missing binaries, credentials, or the explicit local-tool opt-in are skips, not
passes. Capability-incompatible cells are excluded from the plan. An advertised
capability must have at least one scenario that exercises it; a capability no
scenario consumes must be removed from the manifests rather than kept as
decoration.

HTTP success, a local unit test, push, deployment, or one clean text turn
cannot substitute for this set.

## Codex required contracts

`scenarios/codex-contract.json` and `codex-auto-compact-tools` are the Codex
compatibility gates described in [Codex acceptance](codex-acceptance.md).
Raw `responses_contract` cases validate structured output and actual follow-up
requests; marker substrings alone cannot pass them. Required Codex contracts
survive representative sampling for every compatible route/model pair.
`compare` treats lost coverage and pass-to-skip transitions as regressions.

Expected rejection scenarios use a correlated error log (type 5, zero quota)
instead of a final consumption receipt. A consumption record for the same
rejected request is a failure. Missing rejection evidence stays a failure.

A verified type64 tool roundtrip can include a handoff response explicitly marked
`cursor_agent_v1_usage_pending=true`. That HTTP phase is not a finalized bill:
the following, call-id-bound tool-result continuation funds/finalizes the Run.
The structured tool contracts retain those handoff request IDs as wire evidence
and require the final continuation's server receipt; ordinary responses and
unverified/failed loops cannot use this exception.

## Cursor release handoff evidence

A type64 release also requires deployment-lifecycle evidence. Ordinary
`namespace` / `tool-loop` / `session-resume` passes do not certify a cutover.
These are external release gates, not additional runnable scenario IDs or
coverage automatically emitted by this CLI:

| Gate | Required observation |
|---|---|
| Parked owner handoff | Return a tool call on runtime A; keep process A alive; drain A; submit the same call ID to runtime B sharing its state directory; preserve checkpoint and billing Run. |
| Duplicate continuation | Replay the completed tool result; return the saved answer without another model execution or positive charge. |
| Active inference | Drain during generation; allow the reply to reach its normal terminal or persisted tool boundary. |
| Failed handoff | Keep the engine alive past the drain deadline; retain its lock and snapshot, refuse traffic cutover, restore normal parking on the still-serving instance. |
| Concurrent continuation | Race drain with a tool result on the original runtime; complete exactly once without returning an internal ownership race to the user. |
| Failed cutover / rollback | Restore the serving runtime's normal admission using authenticated undrain; preserve ongoing and recoverable sessions. |

The executable white-box references live in BeefAPI, rather than being copied
into this repository: `cpa_runtime_sidecar/internal/cursoragentv1/drain*_test.go`,
`cpa_runtime_sidecar/internal/cparuntime/drain_test.go`, and
`scripts/deploy/blue_green_deploy_test.sh` (introduced by
[BeefAPI PR180](https://github.com/Sunnyender-org/beefapi/pull/180)). Run the Go
cases with `-race`. Attach their results alongside the exact deployed commit,
route-bound live tool continuation and final receipt read-back.

The black-box CLI must never call privileged drain/undrain endpoints itself.
A release operator owns that action and its evidence. Missing lifecycle
evidence means the release handoff is unverified, even when all ordinary
protocol cells passed. A legacy runtime without the drain capability must be
reported as the one-time restart-recovery migration, never as an active-handoff
pass.
