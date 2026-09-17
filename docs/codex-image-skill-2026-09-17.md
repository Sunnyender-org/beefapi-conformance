# Image-skill continuation regression

The September 17 incident exposed two failures through the real Codex client:

- Grok followed `number` schemas and returned floating-point literals for
  integer-only shell parameters, including `session_id`; polling failed.
- DeepSeek returned an empty completed response after tool execution. Codex
  ended the turn with no final reply, even when the image had already been saved.

`codex-image-skill-continuation` is a merge-tier native Codex cell. The harness
installs an isolated offline skill; its generator sleeps 12 seconds and writes
a known valid PNG. Passing requires observed native polling, exactly one
generator call, exact PNG bytes, and a final reply after the last command.
No image-provider credential or paid image request is used by this fixture.

The wire grader also rejects empty completed Responses and tool-argument parse
failures. These are failures even when the client eventually recovers; they are
not interchangeable with a clean production acceptance run.

## Observed validation

- Lint, formatting, 61 unit tests, manifest validation and release-plan generation passed.
- CLI: Codex Desktop bundled `0.154.0-alpha.6.2`, isolated homes/workspaces.
- Local patched BeefAPI handlers forwarding to live Grok 4.6: native fixture passed.
- Same path to live DeepSeek v4.1 flash: fixture completed semantically but wire
  grading failed on two error events. Final rerun after removal of the rejected
  cache-routing hint also failed. The provider remains unaccepted.
- Separate real Image2 runs in the BeefAPI repo produced images for both models;
  Grok delivered a final reply, while DeepSeek exhausted retries during final
  reply generation. Those paid runs are distinct from this offline fixture.

The companion BeefAPI branch is `codex/fix-image2-codex-continuation`; its report
`docs/reports/codex-image-skill-continuation-2026-09-17.md` owns gateway changes,
request IDs and remaining upstream limitations. Neither branch was deployed
as part of this local validation. Do not promote either model from a generic
HTTP 200 or an image file alone.


## Chat diagnostic follow-up

A separate local experiment explicitly disabled Codex native web search and
used the existing BeefAPI Responses-to-Chat converter. It is narrower than the
default-client matrix and must not be promoted as a default capability pass.
The model emitted undeclared read/shell/exec calls and invented skill paths;
the offline diagnostic was interrupted after 53 seconds and recorded failure.
The independent actual Image2 trial reached generation but launched a duplicate
generate command instead of polling the original process. These are separate
failures from empty Responses completion. Wire grading now rejects observed
client `unsupported call:` tool outputs even if later inference recovers.
Validation: 62 unit tests and targeted ruff checks pass. No production changes.

The later actual Image2 run finished naturally in 213 seconds with a valid PNG
and a final reply, but launched two generate commands (one success, one timeout).
Therefore Chat is end-to-end reachable but still fails exactly-once acceptance.
The default native-search matrix was not rerun or relabeled as passing.
