# Adding a Client

1. Add one entry to `manifests/clients.json` with real binary discovery paths,
   supported operating systems, and only capabilities verified by the client.
2. Add a command adapter in `clients.py`. It must support non-interactive output,
   an isolated workspace, bounded timeout, version read-back, and sanitized logs.
3. Add the client to an example or local route and model.
4. Add unit tests for initial invocation, continuation, environment isolation,
   and credential redaction.
5. Run a text turn and local-tool scenario before enabling web or lifecycle
   scenarios.
6. Record current and previous stable versions in the live CI inventory.

Do not add a client by pointing the generic shell runner at a user profile. If a
client uses managed authentication, model that explicitly as `managed_session`.

## WorkBuddy notes

WorkBuddy Desktop bundles `codebuddy`/`cbc`. The adapter uses print mode and
stream JSON, supports `--model`, `--session-id`/`--resume`, and can accept a
controlled settings JSON through `WORKBUDDY_CONFORMANCE_SETTINGS_JSON` on
`managed_session` routes.

`gateway_token` cells isolate CodeBuddy/WorkBuddy auth, base URL, and config
directories, pass the already derived request token as `CODEBUDDY_AUTH_TOKEN`,
and require the argv pair `--setting-sources none`. Use the public model id.
Do not point gateway cells at `auto` or another custom alias: that would load
`modelConfig` url/key ahead of the isolated env. Do not write the token to
disk or argv. If the installed CLI still prompts for login despite that env,
report the client gap; do not fall back to a managed alias.

Provisioning a WorkBuddy private model for `managed_session` remains outside
this repository. Ordinary gateway acceptance does not require a
WorkBuddy-specific BeefAPI backend.
