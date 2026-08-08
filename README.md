# BeefAPI Provider Certifier

An evidence-backed Agent Skill for certifying an upstream model/channel across
the interfaces that coding agents actually use:

- OpenAI Responses, including SSE, tools, replay, namespaces, and optional web search;
- Anthropic Messages, including streaming, tool replay, and `count_tokens`;
- isolated, resumable Codex CLI sessions with real local tool use;
- isolated, resumable Claude Code sessions with real local tool use.

The result is classified as `certified`, `limited`, `experimental`, or
`blocked`. API-only and client-only runs cannot be mislabeled as complete
certification.

## Install as an Agent Skill

Clone the repository, then copy or symlink the packaged Skill into your agent's
skills directory.

```bash
git clone https://github.com/Sunnyender-org/beefapi-provider-certifier.git
cp -R beefapi-provider-certifier/skills/beefapi-provider-certifier \
  ~/.agents/skills/
```

## Run

Use a dedicated, model-limited test credential. The harness reads it from the
environment and never writes it to reports.

```bash
cd beefapi-provider-certifier/skills/beefapi-provider-certifier

python3 scripts/provider_certifier.py doctor

BEEFAPI_PROVIDER_TEST_KEY=sk-*** \
python3 scripts/provider_certifier.py run -- \
  --base-url https://your-gateway.example \
  --channel-id 123 \
  --pin-channel \
  --model provider-model \
  --profile all \
  --client-turns 10 \
  --web-search
```

`--pin-channel` uses BeefAPI's admin-key channel suffix contract. Do not use it
with ordinary end-user keys. Run without `--pin-channel` when your gateway does
not implement exact-channel routing; that run cannot prove a specific channel.

## Requirements

- Python 3.10+
- Codex CLI and Claude Code on `PATH` for full client certification
- a BeefAPI-compatible gateway exposing `/v1/responses` and `/v1/messages`

See [SKILL.md](skills/beefapi-provider-certifier/SKILL.md) for the agent contract and
[certification-matrix.md](skills/beefapi-provider-certifier/references/certification-matrix.md) for the
evidence matrix.

## Security

- Use disposable, low-risk credentials restricted to the target model.
- Never place credentials in command history, reports, issues, or CI secrets
  unless the CI environment is explicitly designed for live acceptance.
- The harness creates isolated temporary Codex and Claude homes and removes
  them after each run.

## License

MIT
