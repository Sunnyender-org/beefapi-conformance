# Cursor Agent v1 completion

This is the transparent contract for BeefAPI channel type 64 before a route can
be called complete. It evaluates public client output and sanitized server
evidence. It does not inspect BeefAPI internals.

The executable inventory is `manifests/cursor-agent-v1-completion.json`.
Scenarios live in `scenarios/cursor-agent-v1.json` plus the existing trailing
system, local-tool, web-search, and session-resume cases.

## Why this lock exists

Type64 manifests already advertise `tool.shell`, `tool.custom`, `tool.web`, and
`session.resume`. Representative release runs could still target only dynamic
system and native web search. Server evidence could pass on commit plus a final
receipt while prompt and cache were reported as measured zero. That is not
completion.

## Comparison rules

| Surface | Pass | Fail |
|---|---|---|
| Usage | `observed_usage` and `billing_estimate` are both present and distinct. Type64 input/cache quality is `unknown` or `estimated`. | Flat `prompt_tokens: 0` / `cache_tokens: 0` treated as measured. Observed quality `measured` for unobservable fields. |
| Tool catalog | Caller canaries (`Bash`, `Read`, `beefapi_conformance_canary`) remain visible. | Cursor native shell/fs names appear in the visible catalog (`Shell`, `ReadFile`, `DeleteFile`, `edit_file`, `list_dir`). |
| Tool results | Identical completed `tool_result` retries at +23s and +3m stay 2xx with the same payload hash. Covering-set results and `tool_result` plus ordinary text stay 2xx. | Any of those requests 4xx, or a retry payload drifts. |
| Hosted web | Server-tool count, progress, and citations are present. Claude Code does not execute `WebSearch`/`WebFetch` itself. | Count-only receipts, missing citations/progress, or a local web-search tool_use. |
| MCP | Observed spans match the declared serial or parallel contract. | Serial spans overlap, or parallel spans do not overlap. |
| Thinking | First-byte is measured and the stream emits keepalive or progress during thinking-only time. | Silent wait until the final message. |
| Classifier | Claude Code auto-mode runs without `bypassPermissions` and classifier evidence is observed. | Classifier scenario uses bypass mode or produces no classifier evidence. |
| Lifecycle | Disconnect aborts an in-flight request then completes uniquely. Restart issues a new receipt hash. Receipt hashes do not collide across cells. | Reused receipt correlation, or a required abort never happens. |

Reports persist `request_id_hash` / `id_hash` (`sha256:` plus 16 hex chars). Raw
request ids, receipt ids, and `resp_bf_agentv1_*` public ids are not stored.

## Critical gates

Critical advertised type64 capabilities must be planned and executed on nightly
and release. Skip from a missing binary, missing credential, or missing
`--allow-local-tools` remains skip on ordinary cells and on PR/merge. The same
skip on a critical type64 release/nightly cell becomes fail. Classification
cannot be `passed` if any critical advertised capability is skipped or absent
from the planned matrix.

Major protocol text turns may still skip as `partial`. They do not unlock a
type64 completion claim by themselves.

`tool.web` is required only when the route advertises it.

## Weights

Critical: usage quality, trailing system, caller local tools, catalog canary,
custom-tool canary, tool_result retries, covering-set, mixed tool_result+text,
hosted web search, MCP serial/parallel, thinking progress, Claude Code
classifier, disconnect, restart, session resume, receipt uniqueness.

Major: responses/messages/chat text and a native text turn.
