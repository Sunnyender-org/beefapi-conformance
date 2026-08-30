# Architecture

## Boundary

```text
committed capability examples     live/local inventory
          |                              |
          +---------- matrix compiler ---+
                         |
              compatible matrix cells
                         |
        +----------------+----------------+
        |                                 |
 released-client runner              Harbor tasks
        |                                 |
 stdout / trajectory / timing       container trajectory
        |                                 |
        +---------- verifiers ------------+
                         |
       route + terminal + claim + receipt + usage evidence
                         |
                    JSON + JUnit
```

The matrix compiler is deliberately small. It intersects capabilities declared
by the client, route, and model, then schedules only scenarios whose requirements
fit that intersection. Unsupported combinations are absent from the plan rather
than failing randomly at runtime.

## Ownership

- BeefAPI owns request conversion, routing, billing, persistence, and internal
  tests.
- This repository owns client invocations, reusable black-box scenarios,
  released-version coverage, and report schemas.
- Harbor owns portable task environments and normalized agent trajectories.
- A server evidence command owns deployment-specific read-back. It accepts no
  shell string: the environment value is a JSON argv array, and its stdout must
  be one JSON object.

Production channel inventory is not committed. A generated `routes.local.json`
can name a group or pinned channel, but the production database remains the
authority.

## Authentication modes

`gateway_token` routes point to an environment-variable name. The runner passes
the secret to the child only and redacts it from captured output. WorkBuddy is
not limited to a private backend: on an ordinary gateway route it receives
`CODEBUDDY_AUTH_TOKEN`, `CODEBUDDY_BASE_URL` (`{base}/v1`), isolated
`CODEBUDDY_CONFIG_DIR` / `WORKBUDDY_CONFIG_DIR`, and `--setting-sources none`.
Custom aliases including `auto` are rejected before the process starts because
WorkBuddy prefers `modelConfig` url/key over those env values.

`managed_session` routes, currently used by WorkBuddy's provisioned profile,
keep the client's existing login. The harness does not copy cookies or auth
files, and it does not apply the gateway isolation flags. Single-turn runs
disable session persistence; resume scenarios necessarily create a
client-owned session in that managed profile. CI for those routes therefore
requires a dedicated pre-authenticated host runner rather than a developer's
everyday profile.

## Why the legacy certifier remains

The provider certifier contains useful protocol payloads and parsers. Keeping it
under `legacy/` makes migration reviewable while preventing two active matrix
contracts. New scenarios must be registered under `scenarios/`; protocol cases
move individually after their evidence semantics are represented here.

Cursor Agent v1 completion rules, critical/major weights, and comparison
semantics live in [cursor-agent-v1-completion.md](cursor-agent-v1-completion.md)
and `manifests/cursor-agent-v1-completion.json`.
