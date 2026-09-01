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

Each cell takes a token-log fence before it runs and polls a bounded snapshot
after it. It accepts only newly created consume logs matching the exact model,
group, and pinned channel. Release evidence requires:

- current `X-New-Api-Commit`;
- expected channel id and group;
- completed terminal request id;
- final usage receipt;
- prompt/completion/quota/use-time values.

This prevents a recent earlier request from satisfying a new cell. Raw HTTP
cells bind the response `X-Oneapi-Request-Id` exactly; native cells bind the
request ids observed in client output when the route exposes them. Native tool
loops may legitimately create several requests per turn and must contain at
least one final receipt per client turn. Provisional rows never substitute for
a final receipt. The `web-search` scenario additionally requires a positive
server-side search call count.

Wire capture is the second evidence channel: every native cell runs through a
local recording proxy, and its report carries per-request stream termination,
timing gaps, and declared tool names alongside the receipt data.

## WorkBuddy boundary

WorkBuddy CodeBuddy uses a managed account/private-model route rather than a
portable gateway-token config. Its native CLI text/tool/resume checks therefore
run on a pre-authenticated local host. Hosted production CI does not copy a
WorkBuddy login or pretend that a built-in `auto` model is a BeefAPI route.
