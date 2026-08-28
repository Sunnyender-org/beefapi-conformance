# Certification Matrix

## Configuration

- Channel id/type/status and exact base URL are recorded.
- Exact-channel evidence uses BeefAPI's admin key suffix pin; a report-only
  `channel_id` without a verified pin cannot be certified.
- Normal API Key, Coding Plan, and Agent Plan routes are classified separately.
- Advertised model, upstream model mapping, pricing, group, and test Key model
  restriction are verified independently from protocol compatibility.
- The deployed commit/header is recorded for live acceptance.

## OpenAI Responses

Required:

- non-stream text;
- SSE text with `response.completed`;
- function tool selection and `function_call_output` replay;
- namespace tool flatten/restore and replay;
- the tool surface actually advertised by current Codex, including unsupported
  tool types such as `image_generation`;
- reasoning and historical items remain valid across resumed turns;
- terminal upstream errors become a client-visible failed terminal state.

Optional capability, but result must be explicit:

- provider-native `web_search`;
- image generation;
- WebSocket Responses.

Codex certification uses `/v1/responses`. Chat Completions is compatibility-only.

## Anthropic Messages

Required:

- non-stream and stream text with a valid terminal event;
- tool use plus `tool_result` replay;
- `/v1/messages/count_tokens`;
- current Claude Code system prompt and headers;
- a persisted multi-turn Claude Code session with real built-in tool use.

Claude Code certification uses `/v1/messages`. A successful curl alone is not
Claude Code acceptance.

## Real Clients

- Record exact Codex and Claude Code versions.
- Use isolated temporary homes and a disposable read-only workspace.
- Run 10 turns for final certification; every later turn must carry/recover
  prior context and complete successfully.
- At least one turn must use a real local tool in each client.
- Preserve the first failing turn and error class without credentials.

## Performance And Stability

- Record first event, first text, and total duration separately.
- Report p50 and p95 from repeated equivalent requests.
- Network handshake and provider generation latency must not be conflated.
- Web search latency is reported separately from ordinary generation.
- A route may be protocol-certified but still receive a poor performance grade.

## Evidence Rules

- Adapter unit tests prove conversion behavior only.
- Mock HTTP tests prove harness/parser behavior only.
- Production HTTP proves the deployed endpoint, not the real client.
- One real client turn proves only that turn.
- Push, deployment, or reviewer confidence is never certification evidence.
