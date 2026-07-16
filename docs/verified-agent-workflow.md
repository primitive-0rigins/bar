# Verified Incremental Development Workflow

Use this workflow when improving an existing repository. It is intentionally
tool- and repository-agnostic: discover the project's own conventions and
commands instead of assuming a language, framework, test runner, or branch
model.

## Operating principle

Make one small, evidence-backed improvement at a time. Every change should be
easy to explain, test, review, revert, and commit independently.

Do not manufacture work to keep moving. Stop and ask for direction when the
next step requires a meaningful product, security, architecture, cost, or
external-publishing decision.

## Start every pass this way

1. Read all applicable repository instructions, contribution guidance, README,
   status/roadmap documents, and the relevant code and tests.
2. Record the current branch, latest commit, remotes, and working-tree status.
   Treat existing uncommitted changes as someone else's work unless proven
   otherwise.
3. Identify one concrete gap or invariant from repository evidence. Prefer a
   failing test, documented limitation, trust boundary, regression risk, or
   incomplete primary user path over a stylistic preference.
4. State the assumption and success criteria in one or two sentences. A good
   criterion is observable: “a malformed input is rejected and a focused test
   proves it.”

## Implement one slice

1. Reproduce the issue or add a focused regression test first when practical.
2. Make the smallest change that fixes the demonstrated problem.
3. Match existing conventions and reuse local helpers.
4. Do not refactor adjacent code, add unrelated features, introduce
   dependencies, weaken checks, or edit unrelated files.
5. Preserve fail-closed behavior at trust boundaries. If input, provenance,
   ownership, or freshness is uncertain, represent that uncertainty rather than
   inventing a positive result.
6. Update documentation only when the documented behavior, commands, status,
   or limitations actually changed.

## Verify in layers

Run the narrowest meaningful check first, then expand only after it passes:

1. Focused test or reproduction.
2. Affected module/package test suite.
3. Project formatter, linter, type checker, and build.
4. Full project test suite.
5. Existing dependency/security/license checks, if the repository supports
   them.
6. Diff validation and a final working-tree status check.

Never claim a change works merely because it compiles. If a check cannot run,
state the exact command, why it could not run, and what remains uncertain.

## Commit and publish

Only commit files traceable to the current slice. Use one concise, conventional
commit message that says what changed, for example:

```text
fix(component): reject malformed provenance input
test(component): preserve ambiguous mapping behavior
docs: add runnable verification example
```

Before pushing, confirm the commit contains no unrelated changes, secrets, or
private data. Push only when authorized by the repository owner or task.

## Repeat or stop

After a successful slice, inspect the next layer deeper:

- challenge boundary values and malformed inputs;
- verify downstream consumers enforce upstream invariants;
- look for stale documentation or an uncovered primary path;
- prefer the next documented roadmap gap when it is well specified.

Stop when the next improvement is speculative, broad, blocked on a decision,
or would require authority you do not have. Report the concrete options and the
evidence behind them.

## Handoff format

Report concisely:

- What changed and why.
- The behavior or risk now covered.
- Exact verification performed and its result.
- Commit hash and publication status, if applicable.
- Any remaining limitation or decision needed for the next slice.
