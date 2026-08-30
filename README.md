# BeefAPI Conformance

`beefapi-conformance` is the black-box compatibility and acceptance suite for
BeefAPI routes. It tests the interfaces users actually run, not only raw HTTP:

- Claude Code
- Codex CLI
- Grok Build
- WorkBuddy / CodeBuddy CLI (`codebuddy` or `cbc`)
- OpenAI Responses, Chat Completions, and Anthropic Messages

The suite compiles an explicit client × route × model × scenario matrix,
executes only capability-compatible cells, and records client output, timing,
route metadata, and optional server-side evidence in a stable report format.
An HTTP 200 by itself is never a conformance pass.

## Why this repository exists

BeefAPI's in-repository unit, race, adapter, and database tests remain in the
BeefAPI repository. This repository owns released-client behavior, native tool
loops, lifecycle failures, and cross-route evidence. Keeping that boundary
prevents a green gateway build from being mistaken for a working user client.

The previous provider certifier is preserved under
[`legacy/provider-certifier-skill`](legacy/provider-certifier-skill). It is
reference material while its protocol fixtures are migrated; it is not the
new matrix source of truth.

## Quick start

Python 3.11+ is the only local dependency. On this macOS workspace, use the
installed `python3.12` rather than Apple's older `/usr/bin/python3`.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m beefapi_conformance doctor
.venv/bin/python -m beefapi_conformance plan --tier pr
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/smoke_grok_local.py
```

For a real run, copy the examples to ignored local manifests and provide a
dedicated restricted credential through the environment:

```bash
cp manifests/routes.example.json manifests/routes.local.json
cp manifests/models.example.json manifests/models.local.json

BEEFAPI_CONFORMANCE_TOKEN=sk-*** \
python3 -m beefapi_conformance run \
  --routes manifests/routes.local.json \
  --models manifests/models.local.json \
  --tier merge \
  --client claude-code \
  --scenario local-tool-read \
  --allow-local-tools
```

Secrets are referenced by environment-variable name. They are not accepted as
manifest values and are redacted from reports. Every real client receives an
isolated temporary workspace and configuration directory. Managed-session
clients such as WorkBuddy can use their existing authenticated profile without
copying its cookies or tokens into this repository.

## WorkBuddy CLI

The runner auto-discovers the CLI bundled with WorkBuddy on macOS:

```text
/Applications/WorkBuddy.app/Contents/Resources/app.asar.unpacked/cli/bin/codebuddy
```

It also checks `codebuddy` and `cbc` on `PATH`. WorkBuddy is a first-class
client in the matrix, including print/streaming output, local tools, session
resume, model selection, and later ACP coverage. WorkBuddy has two authentication modes. A `managed_session` model uses the
user's already provisioned custom-model route; a direct BeefAPI credential is
never silently substituted for that managed route. An ordinary
`gateway_token` route uses the same dedicated request token as other clients:
the harness isolates CodeBuddy/WorkBuddy env and config dirs, passes
`--setting-sources none`, and selects the public model id. It does not write
credentials to disk or argv, and it does not reuse a WorkBuddy `auto` or other
custom alias.

Repeatable local WorkBuddy smokes (using the existing managed login) are:

```bash
.venv/bin/python -m beefapi_conformance run --tier pr \
  --client workbuddy-cli --route workbuddy-managed \
  --model workbuddy-test-model --scenario text-turn

.venv/bin/python -m beefapi_conformance run --tier merge \
  --client workbuddy-cli --route workbuddy-managed \
  --model workbuddy-test-model --scenario local-tool-read --allow-local-tools
```

## Harbor integration

The `harbor/` directory contains valid Harbor 1.1 tasks for agent-native,
container-isolated evaluation. The built-in runner remains useful for exact
released binaries and server evidence; Harbor owns reusable task environments
and normalized trajectories. See [architecture](docs/architecture.md).

## Evidence levels

- `pr`: deterministic schemas, fixtures, protocol transforms, and dry matrix.
- `merge`: representative real clients, route families, and tool behavior.
- `nightly`: all active model/channel pairs plus compact, resume, retry, and
  disconnect scenarios.
- `release`: current and previous client versions across supported operating
  systems, with server receipt and usage read-back.

See [matrix contract](docs/matrix-contract.md) and
[adding a client](docs/adding-a-client.md). Production inventory, exact-channel
pinning, scheduled CI, and receipt evidence are documented in
[production conformance](docs/production.md). Cursor Agent v1 type64 completion
gates are in [cursor-agent-v1-completion.md](docs/cursor-agent-v1-completion.md).

## License

MIT
