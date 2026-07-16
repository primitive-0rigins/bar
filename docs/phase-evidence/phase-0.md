# Phase 0 — Completion Evidence

Per spec Appendix AP, a phase cannot be marked complete without a
`PhaseCompletionEvidence` record, stored as an immutable artifact and linked
from `STATUS.md`. This is that record for **Phase 0 — Baseline, repository
skeleton, CI, STATUS** (spec §21).

| Field | Value |
|---|---|
| **phase** | 0 — Baseline, repository skeleton, CI, STATUS |
| **source_revision** | `13bbf07` (harness); phase spans `e5f8299 → 13bbf07` |
| **reviewed_by_human** | approved — Bryce Worthy, 2026-07-15 |
| **signed_by_agent** | build session, 2026-07-13 |

## Exit criteria (spec §21)

| Criterion | Status | Evidence |
|---|---|---|
| Daemon starts model-free | ✅ | `bar-daemon` boots on built-in defaults, logs a model-free readiness summary, exits 0; asserted by `resource_budget.rs`. |
| Old migrations replay | ✅ | `bar-store::tests::migrations_apply_and_replay` — reopened store applies no duplicate migrations. |
| Audit tamper test passes | ✅ | `bar-audit` tamper suite: value/timestamp/category/subject mutation, reorder, insertion, truncation, broken link all detected; clean chain verifies. |

## Required implementation (spec §21 Phase 0)

Workspace, core types, config, structured logging, audit chain, migrations,
resource benchmark harness — all delivered.

## requirement_ids_satisfied

- §3.1 — model-free start (hard invariant), enforced by regression test.
- §4 — resource contract: boot footprint measured and budget-asserted.
- §6.1 — stable identifier system (14 UUID newtypes + 2 content-hash ids).
- §6.3 — seven core persisted enums with stable string tokens.
- §18–19 — append-only hash-chained audit log; relational store + migrations.
- §20.1 — typed error policy with retry classification.
- §22 — resource benchmark implemented as a regression test, not documentation.
- Appendix C — complete configuration contract with `deny_unknown_fields` and
  range validation.

## requirement_ids_deferred

- §6.2 — revision-identity *bundle* (build manifest, toolchain, deployment id,
  topology) deferred to Phase 1, which supplies its inputs via the target
  connector. `RevisionId` itself exists.
- §4 *idle* CPU/RAM under load, incremental-scan RAM, high-volume ingestion,
  and target-pressure suspension (spec §23 performance rows) deferred to the
  phases that introduce a running service loop and ingestion.
- Audit JSONL mirror, DB index for signatures, and crash replay beyond reload —
  deferred to later storage work.

## tests_added / tests_run / test_results

- `cargo test` — **38 passed, 0 failed** across bar-core (14), bar-config (5),
  bar-audit (11), bar-store (3), bar-bench (4), and the bar-daemon
  `resource_budget` integration test (1).
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo fmt --check` — clean.

## fixture_results

None yet. Phase 0 ships no target fixtures; intentionally-flawed runtime
fixtures begin with the discovery and static-analysis phases (spec §5, §22).

## resource_measurements

| Measurement | Value | Budget (spec §4) |
|---|---|---|
| Daemon boot peak RSS, model-free | ~5.1 MB | idle target 100–300 MB; hard cap `max_memory_mb` 512 |
| Models resident at boot | none | 0 MB reserved by default |

Method: the daemon reads its own `/proc/self/status` `VmHWM` at readiness and
emits `peak_rss_bytes`; `resource_budget.rs` asserts it is under 300 MB. This
measures **boot peak**, not steady-state idle (no idle loop exists yet).

## security_checks

- `unsafe_code = "forbid"` workspace-wide.
- Config `deny_unknown_fields`: unknown key → startup error.
- Audit chain hashes over a canonical length-prefixed encoding, never serde, so
  storage-level row edits fail re-verification (`bar-store` tampered-row test).

## migrations

- `migrations/0001_baseline.sql` — `audit_log`. Replay verified idempotent.

## known_limitations

- The resource harness proves **boot** peak RSS only; it does not yet prove the
  §4 *idle* RAM/CPU contract, which requires the service loop (arrives with the
  API phase). Affected requirement: §4 idle rows.
- `peak_rss_bytes` is Linux-only (`/proc`); on other platforms the field is
  absent and the RSS assertion is skipped (model-free boot is still asserted).

## next_phase_dependencies

- Phase 1 (target registration/identity) supplies the inputs for the §6.2
  revision-identity bundle and the local Git/filesystem connector.
