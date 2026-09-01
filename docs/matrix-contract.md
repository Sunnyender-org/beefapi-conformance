# Matrix Contract

## Axes

Every result identifies an exact:

- client and version;
- operating system;
- route and authentication mode;
- public model id plus client-specific alias;
- scenario and tier;
- start time, duration, terminal status, and bounded sanitized output;
- wire capture (per-request stream termination, timing, and tool declarations)
  for native clients running through the recording proxy;
- server evidence payload where the route provides one.

The committed manifests are examples and structural contracts, not a production
model catalog. Nightly automation generates local route/model manifests from
the authoritative BeefAPI catalog via `sync-inventory`.

## Tiers

| Tier | Gate | Intended coverage |
|---|---|---|
| `pr` | every change | schema, dry matrix, streaming protocol scenarios |
| `merge` | integration branch | real clients: long streams, tool loops, web search |
| `nightly` | scheduled | every active model/channel plus session resume |
| `release` | production promotion | OS and client-version matrix plus receipt evidence |

The compiler runs scenarios from the selected tier and every lower tier.

`--coverage full` keeps the complete Cartesian matrix. Scheduled production
runs use `--coverage representative`: every route/model pair gets a raw
streaming Responses check, every model gets a native-client text turn, and the
deep cases (`tool-loop`, `session-resume`, `web-search`, `long-stream`) rotate
deterministically across native clients per route. `--max-cells` fails closed
on accidental expansion.

## Grading

A cell passes only when all of the following hold:

1. every turn exited cleanly with the expected marker and events;
2. every completion request captured on the wire terminated with its
   protocol's terminal event (no early EOF, no error event, no 4xx/5xx);
3. scenario wire expectations hold (`multi_request` for tool loops,
   `web_search_requested` for web search);
4. on nightly/release, the route's server evidence resolves to a final usage
   receipt bound to the pinned channel and observed request ids.

## Classification

- `passed`: every scheduled cell ran and passed.
- `partial`: at least one cell passed and another was skipped.
- `failed`: at least one cell failed.
- `not_run`: no cells ran or every cell skipped.

Missing binaries, credentials, or the explicit local-tool opt-in are skips, not
passes. Capability-incompatible cells are excluded from the plan. An advertised
capability must have at least one scenario that exercises it; a capability no
scenario consumes must be removed from the manifests rather than kept as
decoration.

HTTP success, a local unit test, push, deployment, or one clean text turn
cannot substitute for this set.
