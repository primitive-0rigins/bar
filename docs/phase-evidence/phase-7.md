# Phase 7 — Completion Evidence

This record covers **Phase 7 — Static finding engine**. The implementation is
complete and awaiting human review.

| Field | Value |
|---|---|
| **phase** | 7 — Static finding engine |
| **source_revision** | This evidence file is committed with the Phase 7 implementation as its immutable completion artifact. |
| **reviewed_by_human** | pending |
| **signed_by_agent** | build session, 2026-08-08 |

## Exit criteria

| Criterion | Status | Evidence |
|---|---|---|
| Required detector classes | ✅ | Missing implementation, contradiction, documentation conflict, dead mechanism, bypass path, state-machine violation, and architecture erosion are implemented. `architecture_detectors_cover_dead_bypass_state_and_erosion` and the `fixtures/bar-demo` end-to-end scan exercise the completed set. |
| Findings replay | ✅ | `promote_static_findings_aggregate_and_replay`, contradiction/documentation-conflict promotion tests, and `architecture_findings_replay_and_retain_false_positive_correction`. |
| Duplicates aggregate | ✅ | Stable finding identities exclude revision-scoped IDs; persisted promotions advance first/last-seen provenance without duplicating findings. |
| False-positive correction retained | ✅ | Every persisted detector family retains audited `rejected` dispositions across later promotion and replay. |

## Required implementation

`bar-findings` produces deterministic, source-bound, provisional findings from
contracts, traceability, and validated static facts. `bar-store` persists and
aggregates each implemented family through migrations `0016`–`0019`, validates
identity and target/revision provenance on reload, and records lifecycle changes
in the verified audit transaction. `bar-cli` connects the complete static
pipeline so the versioned `fixtures/bar-demo` target reaches a human-readable
report in one command.

The architecture-level detectors are deliberately conservative. “Dead” means no
certain caller in the analyzed scope, bypass requires a direct effect without a
same-symbol authority check, a state violation requires a transition after a
recognized terminal assignment in one symbol, and erosion requires an uncertain
call boundary. All remain provisional rather than authorizing repair.

## Migrations

- `0016_static_findings.sql` — missing-implementation aggregation.
- `0017_contradiction_findings.sql` — opposing-contract aggregation.
- `0018_documentation_conflict_findings.sql` — glossary-conflict aggregation.
- `0019_architecture_findings.sql` — dead, bypass, state, and erosion lifecycle.

## Verification

- `cargo test --workspace --all-targets` — full workspace gate.
- `cargo clippy --workspace --all-targets -- -D warnings` — warning-free.
- `cargo fmt --all -- --check` — formatted.
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` — documentation builds.
- `cargo audit --deny warnings` — no known locked-dependency advisories.
- `cargo +1.94.0 check --workspace --all-targets --locked` — declared MSRV.

## Deferred dependencies

- Finding dependency graphs are Phase 10.
- Full waiver expiry/reopen and signed approval are Phase 14.
- Runtime reachability, deployment identity, and live evidence begin in Phase 9.
- The Phase 8 dashboard currently reads an exported report; database-backed
  adjudication and evidence drill-down remain Phase 8 work.
