# Cursor Agent v1 completion

This is the transparent contract for BeefAPI channel type 64 before a route can
be called complete. It evaluates public client output and sanitized server
evidence. It does not inspect BeefAPI internals.

The executable inventory is `manifests/cursor-agent-v1-completion.json`.
Scenarios live in `scenarios/cursor-agent-v1.json` plus the existing trailing
system, local-tool, web-search, and session-resume cases.

## Multi-stage tool driver

Retry, covering-set, mixed, custom-tool, and MCP HTTP scenarios do not ship
static assistant history. `tool_replay.py` drives public Messages traffic:

1. Stage A sends `tools` plus a forcing `tool_choice` (`{"type":"tool","name":...}`
   or `{"type":"any"}` for a batch). It parses `content[]` blocks with
   `type=tool_use` from JSON or SSE `data:` frames and keeps the exact assistant
   `content` array.
2. Stage B rebuilds `messages` as original user, that assistant message, then a
   user turn of `tool_result` blocks whose `tool_use_id` values are only the ids
   returned by that parked Run. Mixed adds a text block on the same user turn
   that consumes the tool result and requires the marker; it does not repeat the
   original must-call prompt. Stage B sends `tool_choice: none`. Any Stage B
   `tool_use` fails. Stage B must `end_turn` with the marker in assistant text;
   a marker only in tool input or `tool_result` is not a pass. Historical extras
   from a prior completed tool call are out of scope unless a genuine
   preliminary stage is added later.
3. Stage C POSTs the exact Stage B payload at absolute elapsed offsets +23s and
   +180s (sleeps 23s, then 157s). Stage B's HTTP request id must resolve to
   exactly one consume log and one final `receipt.id_hash`. Every Stage C exact
   duplicate request id must resolve to zero consume logs. C is recorded as
   `replay_without_consume` / `no_new_charge`; do not copy Stage B's receipt onto
   C. Terminal semantics and body hashes must equal Stage B. Across the replay
   window there is one logical final receipt and no added charge. Transport
   `http_request_id_hash` values may differ and are not receipt identity. If a
   receipt id header is actually present on the raw HTTP response, only its hash
   is kept and it must equal Stage B. BeefAPI's external response is not assumed
   to expose that header; Stage B's consume receipt plus C's zero logs plus an
   identical terminal snapshot is the supported proof.

If covering-set or MCP Stage A returns fewer than two live `tool_use` ids, the
cell is `blocked` rather than a pass on synthetic history.

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
| Tool results | Stage A returns a live `tool_use` id. Stage B sends that exact assistant history plus a real `tool_result` for those ids only, with `tool_choice: none`. Mixed adds an ordinary consume-the-result follow-up that requires the marker. Stage B must `end_turn` with the marker in assistant text and zero `tool_use` blocks. Stage C at absolute +23s/+180s replays Stage B. Stage B has exactly one consume log/receipt. Stage C adds zero consume logs and no new receipt (`replay_without_consume` / `no_new_charge`). | Static `toolu_conformance_*` history. Invented `toolu_historical_routed_*` ids. Marker-only custom-tool answers. Marker only in tool input/`tool_result`. Stage B `tool_use` under `tool_choice: none`. Copied receipts on C. Stage C consume log or new receipt. Stage B missing or ambiguous. Duplicate/conflicting consume logs. Covering-set without a real two-call parked batch (blocked). |
| Hosted web | Server-tool count, progress, and citations are present. Claude Code does not execute `WebSearch`/`WebFetch` itself. | Count-only receipts, missing citations/progress, or a local web-search tool_use. |
| MCP | Spans correlate to real returned `tool_use` ids and match the declared serial or parallel contract. | Arbitrary `mcp` JSON, spans without matching tool ids, or serial/parallel mismatch. |
| Thinking | First-byte is measured and the stream emits keepalive or progress during thinking-only time. | Silent wait until the final message. |
| Classifier | Claude Code reports active `auto` mode, executes the Bash canary, and direct classifier invocation evidence is observed. | Wrong/fallback mode, missing/failed canary, or no direct classifier evidence. |
| Lifecycle | Disconnect aborts an in-flight request then completes uniquely. Restart issues a new receipt hash. Receipt hashes do not collide across cells. | Reused receipt correlation, or a required abort never happens. |

### Classifier instrument boundary

The classifier cell requires `--allow-local-tools`. It requests only Bash in
the runner's temporary fixture and writes/reads `classifier-canary.txt` with
`printf` and `cat`. The driver passes `--permission-mode auto` and the
session-only `--settings '{"autoMode":{"classifyAllShell":true}}'`; it does
not add tool allow rules, bypass permissions, or change account/user settings.
Claude Code 2.1.233 on macOS advertises `auto` in `--help`.
[Official configuration documentation](https://code.claude.com/docs/en/auto-mode-config#route-all-shell-commands-through-the-classifier)
requires 2.1.193+ for `classifyAllShell`. Availability still depends on the
actual model/provider/settings, so requested mode is not observed mode.

The evaluator checks a native `system/init` reporting `permissionMode=auto`
and an exact Bash `tool_use` paired by id with its successful canary
`tool_result`. These prove mode and tool execution, not direct classifier
invocation. No positive classifier-invocation receipt from released CLI output
has been verified for this instrument. This cell therefore **fails closed**
even when those checks succeed, with an explicit direct-evidence gap. A future
positive path needs a sourced, correlated client evidence adapter. Assistant
prose, classifier error messages, invented `type=classifier` events, and a
gateway `cursor_agent_v1_classifier_invoked` boolean cannot satisfy it.

Reports persist `http_request_id_hash` (transport) and `receipt.id_hash`
(billing) as `sha256:` plus 16 hex chars. Those identities are not interchangeable.
Raw request ids, receipt ids, `tool_use` ids, and `resp_bf_agentv1_*` public ids
are not stored.

Claude Code, Codex CLI, Grok Build, and WorkBuddy each need their applicable
text / local-or-custom-tool / session cells. Missing required binaries fail
release. Anthropic hosted web-search blocks are not required from Codex, Grok,
or WorkBuddy.

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
