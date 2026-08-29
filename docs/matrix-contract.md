# Matrix Contract

## Axes

Every result identifies an exact:

- client and version;
- operating system;
- route and authentication mode;
- public model id plus client-specific alias;
- scenario and tier;
- start time, duration, terminal status, and bounded sanitized output;
- optional server evidence payload.

The committed manifests are examples and structural contracts, not a production
model catalog. Nightly automation must generate local route/model manifests from
the authoritative BeefAPI catalog or a controlled acceptance inventory.

## Tiers

| Tier | Gate | Intended coverage |
|---|---|---|
| `pr` | every change | schema, dry matrix, deterministic fixtures |
| `merge` | integration branch | representative clients/routes, real local tool |
| `nightly` | scheduled | every active model/channel, web, resume, compact, retry, disconnect |
| `release` | production promotion | OS and client-version matrix plus ledger evidence |

The compiler runs scenarios from the selected tier and every lower tier.

`--coverage full` keeps the complete Cartesian matrix. Scheduled production
runs use `--coverage representative`: every route/model gets raw Responses,
every route gets all three protocols and all three native clients on its test
model, every model gets a native-client text turn, and deep tool/resume/web
cases rotate across clients. `--max-cells` fails closed on accidental expansion.
The scheduled representative bound is 150 cells; an explicitly requested full
run uses 500. Growing beyond either bound stops before sending model requests.

## Classification

- `passed`: every scheduled cell ran and passed.
- `partial`: at least one cell passed and another was skipped.
- `failed`: at least one cell failed or was blocked.
- `not_run`: no cells ran or every cell skipped.

Missing binaries, credentials, or the explicit local-tool opt-in are skips, not
passes. Capability-incompatible cells are excluded from the plan. An advertised
capability that should exist must therefore be corrected in the manifests rather
than hidden as unsupported.

Cursor Agent v1 (channel type 64) adds a completion inventory with critical and
major weights. Ordinary missing binaries remain skip. A required release or
nightly cell for a critical advertised type64 capability cannot stay skip: that
cell fails, and classification cannot be `passed` if any such capability was
skipped or never executed. See [Cursor Agent v1 completion](cursor-agent-v1-completion.md).

## Required release evidence

For a route to be declared user-ready, the release report must include:

1. native client terminal output and exit status;
2. expected tool/continuation evidence;
3. selected BeefAPI route/channel;
4. provider Run terminal state where applicable;
5. one claim and final receipt/usage read-back;
6. deployed commit identity;
7. no credential in report artifacts.

The evidence collector must emit one JSON object with `status=pass` plus
`commit`, `route`, `terminal`, `receipt`, and `usage`. Release execution fails
closed when a route marked `release_evidence_required` has no valid collector.

HTTP success, a local unit test, push, deployment, or one clean text turn cannot
substitute for this set.

Type64 usage evidence must distinguish `observed_usage` from `billing_estimate`.
Input and cache tokens are unobservable on that route: they are `unknown` or
`estimated`, never a measured zero. Report artifacts persist only hashed
request/receipt correlation ids, not raw identifiers.
