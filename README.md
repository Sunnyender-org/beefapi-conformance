# BeefAPI Conformance

`beefapi-conformance` is the black-box acceptance suite for BeefAPI routes. It
answers one question: **does this route work the way a real user actually uses
it** — through released Claude Code, Codex CLI, Grok Build, and WorkBuddy
binaries, with streaming, native tool loops, and web search — not merely
"does HTTP return 200".

Three kinds of evidence are required before a cell passes:

1. **Semantic**: the client produced the expected answer and tool effects.
2. **Wire**: every completion request observed between the client and the
   route streamed to a clean protocol terminal event (`message_stop`,
   `response.completed`, `[DONE]`). Native clients run through a local
   recording proxy, so silent stream drops, upstream error events, and
   missing tool declarations (for example a web search tool the client never
   received) fail the cell even when the printed text looks right.
3. **Server**: for production routes, a final usage receipt read back from the
   BeefAPI token log, bound to the exact channel, group, and request ids.

## Scenarios

Scenarios are organized around the ways routes fail in real use:

| Scenario | Tier | What it catches |
|---|---|---|
| `text-turn` | pr | client cannot complete a basic turn |
| `messages/responses/chat-stream` | pr | SSE transform broken per protocol |
| `long-stream` | merge | mid-stream disconnects and truncation on long answers |
| `tool-loop` | merge | multi-step tool loops: history replay, tool_result serialization |
| `web-search` | merge | web search tool not offered to or not usable by the client |
| `messages-tool-call` | merge | streamed tool_use blocks and argument deltas |
| `messages-web-search-tool` | merge | gateway rejects or swallows the server web_search tool |
| `messages/responses-concurrent` | merge | 8 simultaneous users: crosstalk between streams, 429/5xx under load, p95 collapse |
| `concurrent-users` | merge | 3 real client sessions at once through the recording proxy |
| `concurrent-tool-loop` | nightly | 2 real client sessions running multi-step tool loops simultaneously |
| `session-resume` | nightly | session continuation across turns |

### History shapes (where routes actually break)

Real clients replay long histories, and every content-block type is a separate
branch in a gateway's history transform. `scenarios/messages-history.json` and
`scenarios/responses-history.json` exercise each branch on its own so a failure
names the exact shape: `tool_result` with image blocks, `is_error` results,
parallel tool calls, system block arrays with `cache_control`, user-pasted
images, 40-turn tool loops, function_call/output replay, and stateful
`previous_response_id`.

Two-phase `history_source` scenarios first obtain a **real** response (with
thinking/reasoning blocks and signatures) from a route or model, then feed it
back as history — optionally to a *different* route or model. This is what a
client does when the user switches routing group or model mid-session; set
`history_route` / `history_model` on a route manifest to enable the
cross-route and cross-model variants.

### Promoting real traffic into fixtures

```bash
python -m beefapi_conformance run --tier merge --client claude-code \
  --scenario tool-loop --allow-local-tools --capture-wire reports/captures ...
python -m beefapi_conformance promote-capture \
  reports/captures/<cell>.jsonl --id captured-claude-code-tool-loop \
  > scenarios/captured-claude-code.json
```

`--capture-wire` stores the full redacted request/response bodies seen by the
recording proxy (base64 media collapsed to size placeholders).
`promote-capture` turns one of them into a pr-tier replay scenario, so the
suite carries the exact system prompt, tool schemas, cache_control and history
that a released client version emits — new block types show up here before
they show up as user-facing 422s.

Concurrent scenarios give every simulated user a unique nonce and fail if any
response contains another user's nonce (stream interleaving), if any request
does not stream to a clean terminal, or if p95 latency under load exceeds
`max_slowdown` times a serial baseline taken just before the burst.

Native clients keep their default tool surface — the suite must observe the
request shape a real user session produces, not a stripped-down variant.

## Quick start

Python 3.11+ is the only dependency.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m beefapi_conformance doctor
.venv/bin/python -m beefapi_conformance plan --tier pr
.venv/bin/python -m unittest discover -s tests -v
```

For a real run, copy the examples to ignored local manifests and provide a
dedicated restricted credential through the environment:

```bash
cp manifests/routes.example.json manifests/routes.local.json
cp manifests/models.example.json manifests/models.local.json

BEEFAPI_CONFORMANCE_TOKEN=sk-*** \
.venv/bin/python -m beefapi_conformance run \
  --routes manifests/routes.local.json \
  --models manifests/models.local.json \
  --tier merge \
  --client claude-code \
  --scenario tool-loop \
  --allow-local-tools
```

Secrets are referenced by environment-variable name, never stored in
manifests, and are redacted from reports. Every real client runs in an
isolated temporary workspace and configuration directory.

## Evidence tiers

- `pr`: deterministic schemas, dry matrix, streaming protocol scenarios.
- `merge`: real clients with long streams, tool loops, and web search.
- `nightly`: every active model/channel pair plus session resume, with
  mandatory server receipt read-back.
- `release`: nightly plus the client-version and OS matrix.

See [matrix contract](docs/matrix-contract.md) for classification rules and
[production conformance](docs/production.md) for the scheduled pipeline.

## WorkBuddy CLI

The runner auto-discovers the CLI bundled with WorkBuddy on macOS
(`/Applications/WorkBuddy.app/.../cli/bin/codebuddy`) as well as `codebuddy`
and `cbc` on `PATH`. WorkBuddy uses its own managed authenticated profile; the
harness never copies or exports that login, and wire capture is skipped for
managed-session routes.

```bash
.venv/bin/python -m beefapi_conformance run --tier pr \
  --client workbuddy-cli --route workbuddy-managed \
  --model workbuddy-test-model --scenario text-turn
```

## License

MIT
