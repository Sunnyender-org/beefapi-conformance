# BeefAPI Conformance Repository Rules

## Purpose and boundary

This repository owns black-box conformance across clients, protocols, routes,
models, tools, lifecycle behavior, and server-side acceptance evidence. It does
not replace BeefAPI white-box tests, mutate production configuration, create
credentials, deploy code, or certify a route from HTTP success alone.

## Sources of truth

- `manifests/clients.json`: released client invocation and discovery contract.
- `manifests/routes*.json`: route capabilities and authentication mode.
- `manifests/models*.json`: model availability and capability declarations.
- `scenarios/*.json`: reusable behavioral cases and expected evidence.
- `docs/matrix-contract.md`: classification and tier policy.
- current client binaries and live server evidence outrank committed examples.

Do not duplicate production channel inventory or credentials here. Local/live
route and model manifests are ignored. The BeefAPI database and model catalog
remain authoritative.

## Safety

- Credentials are supplied only by referenced environment variable.
- Never print or persist credential values, cookies, auth profiles, or raw
  production database rows.
- Use dedicated, model-limited test credentials and pinned test routes.
- Client tool execution requires `--allow-local-tools` and an isolated temporary
  workspace. Do not point it at a user's repository.
- Production calls, route/channel mutation, and paid acceptance require explicit
  authorization.
- Managed-session clients may use an existing login, but the harness must not
  copy or export that login state.

## Verification

```bash
python3 -m unittest discover -s tests -v
python3 -m beefapi_conformance validate
python3 -m beefapi_conformance plan --tier release --json >/tmp/conformance-plan.json
```

Report separately: local validation, real client execution, live gateway
execution, and server evidence read-back. Push or CI success is not production
acceptance.
