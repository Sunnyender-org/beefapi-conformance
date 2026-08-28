---
name: beefapi-provider-certifier
description: Certify a BeefAPI upstream channel/model for OpenAI Responses, Anthropic Messages, Codex CLI, Claude Code, tool loops, latency, and stability. Use when adding or rechecking a domestic/cloud model provider, deciding whether a channel is certified/limited/experimental/blocked, or reproducing client protocol gaps. Not for ordinary endpoint debugging, model-quality comparison without BeefAPI, production rollout, or creating credentials without explicit authorization.
metadata:
  short-description: Certify BeefAPI provider channels
  sunny_skill_type: library
---

# BeefAPI Provider Certifier

Use the bundled harness to produce one evidence-backed certification for a
channel/model route. When `BEEFAPI_REPO` is set, the wrapper prefers that
checkout's harness so a gateway can test its current source-of-truth fixtures.

## Boundary

Owns:

- OpenAI Responses and Anthropic Messages protocol certification;
- real Codex CLI and Claude Code acceptance with isolated temporary homes;
- tool/replay/web-search/error/latency evidence;
- final `certified`, `limited`, `experimental`, or `blocked` classification.

Does not own:

- creating, rotating, or deleting production credentials without explicit authority;
- fixing a provider adapter before the failing fixture is preserved;
- enabling a channel, deploying, pushing, or changing traffic weights;
- subjective model intelligence rankings.

## Required Route

1. Read the channel row without exposing its Key: id, type, base URL, model
   mapping, test model, status, and relevant settings.
2. Use a dedicated model-limited test Key supplied through
   `BEEFAPI_PROVIDER_TEST_KEY`. Never print, persist, or include it in reports.
3. Read [references/certification-matrix.md](references/certification-matrix.md).
4. Run `doctor`, then an API profile. Preserve every failed request class.
5. Run real clients only after API basics finish. Use isolated client homes;
   never rewrite the user's normal Codex or Claude configuration.
6. A failed client tool surface is evidence, not permission to patch. Capture
   the smallest failing fixture, inspect official provider/client contracts,
   then fix at the provider boundary if authorized.
7. Re-run the same complete profile after a fix. A local test, deployment, or
   single clean turn never upgrades the classification by itself.

## Commands

```bash
python3 scripts/provider_certifier.py doctor

BEEFAPI_PROVIDER_TEST_KEY=sk-*** \
  python3 scripts/provider_certifier.py run -- \
  --base-url https://your-gateway.example \
  --channel-id 123 --pin-channel --model provider-model --profile all \
  --client-turns 10 --web-search

python3 scripts/provider_certifier.py validate-report \
  /absolute/path/to/certification.json
```

The wrapper is self-contained. Set `BEEFAPI_REPO` only when you intentionally
want to run the harness from a BeefAPI checkout instead of the bundled copy.

## Acceptance

- `certified`: every required Responses, Messages, Codex, and Claude check passes.
- `limited`: a required advertised client capability is unsupported or a real
  client path fails while protocol basics remain usable.
- `experimental`: only API checks ran or required client evidence was skipped.
- `blocked`: a required Responses or Messages protocol check fails.

Report the exact client versions, target model/channel, pass/fail checks,
TTFT/total timing, known unsupported tools, and paths to the JSON/Markdown
evidence. Report any review/production/deploy gap separately.

## Output Contract

Every run produces `certification.json` and `certification.md`. The JSON must
contain `schema_version`, `generated_at`, `target`, `classification`, `summary`,
and `checks`. Every check records its layer, required flag, status, duration,
HTTP status when applicable, sanitized detail, and bounded evidence. Validate it
with `validate-report` before using it as an acceptance artifact.

## Agent-readable SOP

```bash
python3 scripts/provider_certifier.py list
python3 scripts/provider_certifier.py read references/certification-matrix.md
python3 scripts/provider_certifier.py validate
```

Only `SKILL.md`, `references/`, `templates/`, and `evals/` are readable through
this interface. Scripts, credentials, reports, and arbitrary paths are refused.
