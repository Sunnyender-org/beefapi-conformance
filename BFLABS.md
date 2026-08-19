# BeefAPI Provider Certifier Repository Rules

## Purpose and evidence boundary

This repository certifies one upstream model/channel across OpenAI Responses, Anthropic Messages, Codex CLI, and Claude Code. A result is `certified`, `limited`, `experimental`, or `blocked`; API-only or client-only evidence must never be presented as complete certification.

## Start here

- `README.md`: installation, execution, requirements, and security overview.
- `skills/beefapi-provider-certifier/SKILL.md`: agent-facing operating contract.
- `skills/beefapi-provider-certifier/references/certification-matrix.md`: required evidence matrix.
- `.github/workflows/validate.yml`: package validation used by CI.

## Safety and execution rules

- Use a disposable, model-limited credential supplied through `BEEFAPI_PROVIDER_TEST_KEY`.
- Never write credentials to reports, issues, fixtures, logs, shell history, or committed files.
- `--pin-channel` requires BeefAPI's admin-key channel suffix contract; do not use it with an ordinary end-user key.
- Full certification requires isolated, resumable Codex and Claude Code sessions with real local tool use.
- Preserve temporary-home isolation and cleanup for both clients.
- A live gateway run, real credential use, channel mutation, or paid model call requires explicit authorization.

## Verification

Run from `skills/beefapi-provider-certifier`:

```bash
python3 scripts/provider_certifier.py validate
python3 -m unittest scripts/test_certify.py -v
```

Report which certification surfaces actually ran. Passing local validation does not certify a live provider.

