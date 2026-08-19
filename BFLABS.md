---
bflabs_governance_version: v1
scope: BF Labs repositories
canonical_source: Sunnyender-org/bflabs/BFLABS.md
---

# BF Labs Repository Collaboration Rules

These rules are the shared collaboration contract for humans and coding agents in BF Labs repositories. Keep this file byte-for-byte aligned across repositories.

## 1. Decision and source priority

Use this order when instructions differ:

1. The current explicit human instruction and approved task scope.
2. Repository-specific `PROJECT_RULES.md`.
3. This shared `BFLABS.md`.
4. The repository's README, development guide, documentation index, specifications, runbooks, code, and tests.

Current repository and runtime evidence outrank stale plans or chat summaries. Never weaken a security, privacy, attribution, production, or external-action boundary through inference.

## 2. Start with a bounded task contract

For non-trivial work, establish five fields before editing:

- **Outcome**: the user-visible result.
- **Entry**: the owning module, document, or command.
- **Forbidden scope**: files, systems, behavior, or data that must not change.
- **Verification**: the smallest checks that can prove the result.
- **Evidence**: the diff, test output, screenshot, runtime readback, or PR receipt required for handoff.

Ask only about a material decision that cannot be discovered safely. Otherwise inspect current truth, state any reversible assumption, and proceed.

## 3. Isolate concurrent work

- Different tasks use different branches and, when running concurrently, different worktrees or isolated checkouts.
- One task has one writable owner. Other agents may research or review, but they do not edit the same task branch concurrently.
- Preserve unrelated local changes and unknown worktrees. Do not clean, reset, overwrite, or repurpose them.
- Keep changes scoped. Do not mix opportunistic refactors with the requested outcome.
- Use the pull request as the durable handoff record for review, verification, unresolved risks, and follow-up.

## 4. Keep documentation navigable

Each document has one job:

- `README.md`: product purpose, quick start, and top-level orientation.
- `BFLABS.md`: shared BF Labs collaboration rules.
- `PROJECT_RULES.md`: repository-specific invariants and agent constraints.
- `DEVELOPMENT.md` or equivalent: local development workflow.
- `docs/INDEX.md`: task-oriented map to modules, specifications, tests, and runbooks.
- Issue, specification, or plan: change-specific intent and acceptance.
- Runbook: operational procedure and rollback.

Update the owning document when behavior changes. Update `docs/INDEX.md` when a non-obvious entry point moves or a new canonical document is added. Do not duplicate shared rules into tool-specific manuals; adapters should point back to these repository files.

## 5. Implement and verify proportionately

- Read the smallest source set that owns the behavior before changing it.
- Prefer the smallest complete change that preserves public contracts, compatibility, attribution, and data boundaries.
- Encode hard constraints in code, tests, scripts, branch protection, or CI when practical; prose alone is not enforcement.
- Run checks proportional to risk and report exact commands and results.
- A clean diff, HTTP 200, local build, or passing unit test is not proof of deployment, payment, production correctness, or customer acceptance.
- If a required check cannot run, name the gap and the next-best evidence.

## 6. Separate local work from external actions

Local inspection, editing, testing, and committing may proceed when they are within the approved task. The following require separate, explicit authorization naming the exact action and target:

- pushing a branch;
- opening, updating, merging, or closing a pull request;
- deploying, releasing, publishing, or changing DNS;
- reading or mutating production data or permissions;
- using real credentials, customer data, payment flows, or paid services;
- sending messages or making other public or customer-visible changes.

Authorization for one action does not imply authorization for the others.

## 7. Protect secrets, data, and attribution

- Never commit credentials, tokens, private customer data, production dumps, or sensitive local artifacts.
- Use redacted examples and synthetic fixtures by default.
- Preserve third-party licenses, notices, upstream identity, and required attribution.
- Treat generated content and agent suggestions as candidates until verified against canonical sources.

## 8. Human and agent responsibilities

Agents execute scoped work, keep evidence, and surface uncertainty. Humans own product intent, material tradeoffs, external authorization, acceptance, and merge decisions.

A handoff is complete only when another teammate can identify the outcome, changed files, verification performed, remaining risks, and next authorized action without reconstructing the chat history.

## 9. Maintain this contract without bloat

- The canonical source is `Sunnyender-org/bflabs/BFLABS.md`; repository copies are synchronized distribution artifacts.
- Add a rule here only when it applies across BF Labs repositories. Put repository-specific rules in `PROJECT_RULES.md` and tool-specific mechanics in their owning adapters or runbooks.
- Keep one concept in one clause. Prefer rewriting or deleting superseded text over appending another exception.
- Keep this file at or below 200 lines and 16 KiB. If it cannot stay within those limits, move details to the correct project document instead of creating a larger shared playbook.
- Bump `bflabs_governance_version` for material semantic changes. Editorial clarification may retain the version.
- Roll out canonical changes to every active BF Labs repository in one coordinated batch, then verify byte-for-byte equality and record the resulting SHA-256 in the PR evidence.
- Audit the contract when a repository joins or leaves the active set and at least once per quarter. Remove obsolete rules, duplicated guidance, stale tool assumptions, and examples that no longer change a decision.

