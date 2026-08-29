# Production Conformance

## Scheduled route

`Production conformance` runs every day at 01:17 Asia/Shanghai. The scheduled
job uses `nightly + representative`; manual dispatch may select `release` or
`full`. It installs pinned Claude Code, Codex CLI, and Grok Build versions on a
clean hosted runner, generates model inventory from `/v1/models`, pins every
request to the exact sanitized channel snapshot, and uploads JSON/JUnit reports.

The workflow has no production SSH credential. It receives only:

- `BEEFAPI_CONFORMANCE_TOKEN`: the dedicated restricted acceptance Key;
- `BEEFAPI_CONFORMANCE_CHANNELS_JSON`: channel id/type/status/models/test_model,
  with no channel name, provider credential, URL override, or settings.

Refresh both values from the trusted local host without printing the Key:

```bash
./scripts/refresh_production_config.sh
```

Model inventory refreshes on every run. Channel inventory is a sanitized GitHub
variable because exposing the production exec/SSH capability to hosted CI would
be a much larger security risk.

The Key is injected only into input validation, inventory generation, and the
matrix process. Package managers and client installers never inherit it.

## Evidence

The runner takes one token-log fence before the serialized matrix and one
bounded final snapshot after it. It accepts only newly created consume logs
matching the exact model, group, and pinned channel. This avoids the production
critical-read limit while still keeping old rows outside the run. Release
evidence requires:

- current `X-New-Api-Commit`;
- expected channel id and group;
- completed terminal request correlation (`request_id_hash`);
- final usage receipt correlation (`id_hash`);
- usage quality: type64 `observed_usage` versus `billing_estimate`.

This prevents a recent earlier request from satisfying a new cell.
Raw HTTP cells additionally bind the response `X-Oneapi-Request-Id` exactly.
Native tool loops may legitimately create several requests per turn, so their
isolation boundary is the dedicated Key plus serialized workflow concurrency;
all rows in the fenced window are assigned to that cell, and it must contain at
least one final receipt per client turn. Intermediate provisional rows are
counted as evidence but never substitute for a final receipt.

## WorkBuddy boundary

WorkBuddy CodeBuddy uses a managed account/private-model route rather than a
portable gateway-token config. Its native CLI text/tool/resume checks therefore
run on a pre-authenticated local host. Hosted production CI does not copy a
WorkBuddy login or pretend that a built-in `auto` model is a BeefAPI route.
