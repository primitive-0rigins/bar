# Phase 4 — Completion Evidence

Per spec Appendix AP, a phase cannot be marked complete without a
`PhaseCompletionEvidence` record. This is that record for **Phase 4 — Contract
scope, temporal resolver, adjudication** (spec §21).

| Field | Value |
|---|---|
| **phase** | 4 — Contract scope, temporal resolver, adjudication |
| **source_revision** | `5a9b3ef` → `f9e71af` → `414be5c` → `ed0f016` → `2054c8d` → `a93a672` → `5483b93` → `3e63c89` → `ee9b01d` → `1862d2e` → `1c21194` → `d3d4c2a` → `3ec5aa9` → `37b3642` → `3696360` → `d0d8480` |
| **reviewed_by_human** | approved — Bryce Worthy, 2026-07-15 |
| **signed_by_agent** | build sessions, 2026-07-15 |

## Exit criteria (spec §21)

| Criterion | Status | Evidence |
|---|---|---|
| Ambiguous conflict never becomes definitive without resolution | ✅ | `phase_four_resolution_corpus_is_fail_safe`, `precedence_resolves_override_but_overlap_requires_adjudication`, and the checked-in `fixtures/phase-4-resolution/expected.json` retain equal, malformed, and context-unknown conflicts as `adjudication_required`. `resolve_conflict` returns only `inactive`, a strictly more-specific `scoped_override`, or `adjudication_required`; it has no definitive-defect output. |

## Required implementation (spec §21 Phase 4)

Scope precedence, inclusive temporal validity, immutable same-target
supersession, and versioned operator rulings are delivered as durable,
source-bound library capabilities. Applicability is derived at evidence time,
not stored as stale workflow state.

## changed_files

- `README.md`
- `STATUS.md`
- `crates/bar-contract/src/lib.rs`
- `crates/bar-contract/src/ruling.rs`
- `crates/bar-contract/src/scope.rs`
- `crates/bar-store/src/attestation.rs`
- `crates/bar-store/src/context_resolution.rs`
- `crates/bar-store/src/lib.rs`
- `crates/bar-store/src/ruling.rs`
- `crates/bar-store/src/scope_context.rs`
- `docs/phase-evidence/phase-4.md`
- `fixtures/phase-4-resolution/expected.json`
- `migrations/0007_contract_resolution.sql`
- `migrations/0008_scope_context_evidence.sql`
- `migrations/0009_contract_rulings.sql`
- `migrations/0010_scope_context_attestations.sql`
- `migrations/0011_contract_ruling_dispositions.sql`

## requirement_ids_satisfied

- §7.2 / §7.2.1 — closed scope context, deterministic precedence tiers,
  inclusive validity, inactive historical/planned/example/superseded contracts,
  and strict semantic-version ranges that fail closed.
- §7.4 — immutable rulings with the closed `chosen`, `deferred`, `rejected`,
  and `request_more_evidence` dispositions; operator identity, rationale,
  scope, effectiveness, expiry, rejected alternatives, and supersession are
  preserved without rewriting source documents.
- §21 Phase 4 — scope precedence, validity, supersession, and operator rulings
  are durable; the ambiguity exit criterion is covered by adversarial fixtures.
- §22 — Phase 4 persisted state has migration replay, unknown-value,
  idempotency, rollback, source/target-boundary, reload, and audit-chain tests.
- §23 scope/time and Appendix AP — adversarial environment, deployment,
  configuration, component, mode, feature-flag, temporal, historical, and
  semantic-range cases are versioned in a fixture and exercised by the pure
  resolver.

## requirement_ids_deferred

- §7.3 authoritative hierarchy and scoped-exception parent linkage — Phase 3
  hierarchy is still a non-authoritative structural proposal. Impact: no
  lower-level contract can silently weaken a parent because BAR does not yet
  promote hierarchy candidates; code/static corroboration is deferred to Phase
  5.
- §7.4 dashboard presentation and ruling controls — deferred to Phase 8.
  Impact: the store APIs are complete, but an operator needs an API/client or
  direct library integration rather than a dashboard.
- Automatic runtime context adapters — deferred to Phase 9. Impact: automatic
  deployment/environment/configuration/component/mode/flag/tenant capture is
  not claimed; the source-bound operator-attested path remains available.
- Process-crash and PostgreSQL recovery exercises — deferred to Phase 23.
  SQLite transaction rollback, migration replay, idempotency, and database
  reopen are covered, but this phase does not kill a process mid-transaction.

## tests_added / tests_run / test_results

- `cargo test --workspace --all-targets` — **113 passed, 0 failed**.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo fmt --all -- --check` — clean.
- `git diff --check` — clean.
- `cargo audit --ignore RUSTSEC-2023-0071` — no advisories beyond the existing
  documented SQLx optional-MySQL RSA dependency.

Coverage of note: strict scope JSON and vocabulary; all documented precedence
tiers; incomplete context and malformed temporal data; historical/planned/
example/superseded inactivity; exact and range-bounded versions; immutable
resolution and supersession; source-bound evidence-time context; operator
attestation; all ruling dispositions; replay, corruption, target-boundary,
expiry, replacement, reopen, and audit-chain behavior.

## fixture_results

`fixtures/phase-4-resolution/expected.json` is a checked-in adversarial corpus.
It covers product-versus-deployment and product-versus-environment/component
overrides, repeat ambiguity, missing deployment/feature-flag context, future
and expired windows, malformed temporal declarations, semantic ranges, and
historical text. The `phase_four_resolution_corpus_is_fail_safe` test consumes
the fixture through the real resolver.

## resource_measurements

No model, adapter, network, or polling process is enabled by Phase 4. The
existing model-free daemon resource-budget regression remains applicable; scope
resolution and persistence are bounded in-process SQLite operations.

## security_checks

- Scope and context JSON reject unknown fields and blank values; invalid range,
  timestamp, or observed-version data resolves as ambiguous instead of selecting
  a contract.
- Context evidence binds one complete inventoried artifact, exact digest,
  revision, target, and observation time; caller-supplied source revision is
  overwritten with stored revision identity.
- Rulings and attestations validate context, contract, and target ownership on
  create, replay, and reload; corrupt rows fail closed.
- Supersession edges are same-target, immutable, and replay-revalidated.
- `unsafe_code = "forbid"` remains workspace-wide.

## migrations

- `migrations/0007_contract_resolution.sql` — scope/validity declarations and
  contract supersession edges.
- `migrations/0008_scope_context_evidence.sql` — source-bound context evidence.
- `migrations/0009_contract_rulings.sql` — immutable operator rulings,
  references, and supersession.
- `migrations/0010_scope_context_attestations.sql` — operator corroboration of
  context evidence.
- `migrations/0011_contract_ruling_dispositions.sql` — closed ruling outcomes.

All migrations are embedded and their replay is covered by
`migrations_apply_and_replay`.

## known_limitations

- Per Appendix AP, this evidence records the implementation closure but does
  not enable new authority; human review was approved 2026-07-15 (see header).
- Phase 4 deliberately exposes no dashboard, API, runtime adapter, active
  probe, production telemetry, or automated remediation. Their requirement IDs
  remain owned by Phases 8, 9, and later.

## next_phase_dependencies

- Phase 5 consumes durable contracts and their Phase 4 scope/temporal inputs
  for static architecture corroboration.
- Phase 8 consumes stored rulings and dispositions for operator-facing
  adjudication.
- Phase 9 supplies automatic, target-isolated runtime context and concurrent
  evidence adapters.
