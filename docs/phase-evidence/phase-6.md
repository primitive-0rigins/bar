# Phase 6 — Completion Evidence

Per spec Appendix AP, a phase cannot be marked complete without a
`PhaseCompletionEvidence` record. This record covers **Phase 6 — Traceability
and proof obligations**. The implementation is awaiting human review. This file
is committed with the implementation as the immutable completion artifact
required by Appendix AP.

| Field | Value |
|---|---|
| **phase** | 6 — Traceability and proof obligations |
| **source_revision** | Completion changes span `6b73d8a` (`feat: add static facts and traceability foundations`) through `32d13e8` (`feat(coverage): add proof-obligation freshness policies`). |
| **reviewed_by_human** | pending |
| **signed_by_agent** | build session, 2026-07-21 |

## Exit criteria

| Criterion | Status | Evidence |
|---|---|---|
| Unmapped and unproven are distinct | ✅ | `bar_coverage::MappingStatus` (mapping completeness) is a separate type from `bar_core::ProofStatus` (proof support); `unmapped_and_partially_mapped_are_distinct_from_proof_status` proves an unmapped/partially-mapped contract never implies a proof status, and a mapped contract is not thereby proven. |
| Evidence levels enforced | ✅ | `proof_requirements_enforce_evidence_levels_without_claiming_static_proof` shows a code-only trace against a code+test requirement stays `Unproven` with the missing level reported; a mapping never fabricates a stronger evidence origin. |

## Required implementation

`bar-coverage` deterministically maps a contract's closed Markdown code spans to
unique, source-bound static facts (symbols, tests, literal TOML/JSON/INI/YAML
configuration keys, authority guards, and state transitions), keeping duplicate
names and dynamic facts as explicit ambiguity rather than guessed proof. It
declares immutable proof obligations (required evidence levels plus a freshness
policy) and assesses them without inventing proof. `bar-store` persists those
obligations (`0013`) and their freshness policy (`0015`), rebuilds traceability
from persisted contracts and static facts for one exact revision, and evaluates
freshness against a later revision's facts. No live action is taken and no
derived proof status is persisted.

## changed_files

- `crates/bar-core/src/enums.rs`, `crates/bar-core/src/lib.rs` (the
  `FreshnessPolicy` vocabulary)
- `crates/bar-coverage/src/lib.rs`, `crates/bar-coverage/Cargo.toml`
- `crates/bar-coverage/examples/config_traceability.rs`,
  `crates/bar-coverage/examples/proof_assessment.rs`
- `crates/bar-static/src/lib.rs`, `crates/bar-static/Cargo.toml` (INI/YAML
  configuration-key extraction feeding traceability)
- `crates/bar-store/src/traceability.rs`,
  `crates/bar-store/src/proof_obligations.rs`, `crates/bar-store/src/lib.rs`
- `migrations/0013_proof_obligations.sql`,
  `migrations/0015_proof_obligation_freshness_policy.sql`
- `Cargo.toml`, `Cargo.lock` (the `yaml-rust2` parser for YAML keys)
- `STATUS.md`, `README.md`, `docs/phase-evidence/phase-6.md`

The revision-bound shadow finding-candidate seam
(`crates/bar-findings`, `crates/bar-store/src/static_findings.rs`, migration
`0014`) was landed alongside Phase 6 as the **Phase 7 foundation** and is not
claimed as a Phase 6 deliverable.

## requirement_ids_satisfied

- §10 / §21 Phase 6 — contracts map to code, tests, and configuration through
  unique source-bound facts; plain-language matches are never evidence.
  `maps_only_unique_explicit_code_spans`,
  `duplicate_symbols_and_missing_references_stay_unresolved`.
- §10 — literal configuration keys are traceable across TOML, JSON, INI, and
  YAML while dynamic/quoted/complex keys stay explicit uncertainty.
  `valid_toml_keys_are_source_bound_without_guessing_quoted_keys`,
  `valid_json_keys_are_source_bound_without_guessing_escaped_keys`,
  `valid_ini_keys_are_source_bound_without_guessing_quoted_keys`,
  `valid_yaml_keys_are_source_bound_without_guessing_complex_keys`,
  `traceability_maps_literal_configuration_keys_from_persisted_static_facts`.
- §9 / §10.3 — authority guards and state transitions are traceable targets;
  recurrence and symbol-name collisions resolve as ambiguous.
  `valid_authority_and_state_facts_are_traceable`.
- §10.2 — proof obligations declare required evidence levels and are immutable,
  revision-bound, replay-safe, and fail closed on forged persisted values.
  `traceability_maps_persisted_contracts_to_revision_bound_static_facts`.
- §10.2 / §10.4 / §92 / §400 — freshness is policy-driven. `Pinned` is stale off
  the declared revision; `ReferenceStable` stays fresh while the contract's
  mapped references still resolve (same reference name and target kind) and goes
  stale when one disappears.
  `reference_stable_policy_stays_fresh_while_references_resolve`,
  `reference_stable_proof_freshness_follows_referenced_symbol`,
  `freshness_policy_tokens`.
- §19 / §22 — proof obligations and their freshness policy are atomically
  audited, idempotent on exact replay, and fail closed on unknown persisted
  tokens or cross-target/revision binding. `migrations_apply_and_replay`.

## requirement_ids_deferred

- **Richer freshness dimensions (§10.4).** Only revision-pinned and
  reference-stability policies exist. Config/dependency/model/topology-change
  invalidation and time- or evidence-age windows are not modeled. Impact:
  freshness reacts to referenced-symbol existence, not to every §10.4 trigger.
- **Broader configuration and cross-contract semantics.** Configuration coverage
  is the literal TOML/JSON/INI/YAML key set; formats beyond these and semantic
  cross-contract reasoning (hierarchy corroboration, glossary merging) remain
  later work. Impact: unsupported forms stay unmapped rather than guessed.
- **Runtime/live proof (§11, §16, §17).** This phase produces mapping and
  declared evidence requirements only. No runtime evidence, live observation, or
  finding conclusion is derived from a mapping. Impact: `Mapped`/`TestSupported`
  never implies a live or contradicted proof.

## tests_added / tests_run / test_results

- `cargo test --workspace --all-targets` — **156 passed, 0 failed**.
- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo audit` — 197 dependencies scanned; no advisories reported.

New Phase 6 coverage includes: unique-span mapping; duplicate/missing ambiguity;
TOML/JSON/INI/YAML literal keys with conservative uncertainty; authority/state
traceability with recurrence and symbol-collision ambiguity; proof-obligation
persistence, replay, cross-boundary rejection, and forged-value fail-closed;
`Pinned` vs `ReferenceStable` freshness at the unit and store level, including a
symbol that survives (fresh) versus disappears (stale) across revisions and an
unknown persisted policy token failing closed on reload.

## fixture_results

Phase 6 reuses the `fixtures/phase-5-static` corpus for static facts and the
`fixtures/phase-3-contract-corpus` corpus for contracts; traceability and proof
tests build temporary target trees, persist contracts and static facts across
multiple revisions, and re-scan modified source to prove reference-stable
freshness tracks referenced-symbol existence.

## resource_measurements

No daemon loop, model, network request, or target mutation is introduced.
Traceability and proof assessment are read-only shadow operations over persisted
facts; the Phase-0 model-free daemon resource-budget regression remains green.

## security_checks

- Every mapping validates its traceability (status/reference/target integrity)
  before it can drive a proof assessment; a target must carry real
  path/name/line provenance.
- Proof obligations validate their contract's stored target, revision, and
  fingerprint before write; exact replay is revalidated and changed replay is
  rejected; an unknown persisted evidence or freshness token fails closed on
  reload.
- Freshness re-mapping is bounded to the same target's persisted static facts for
  the evaluated revision; a foreign target's revision is rejected.
- Optional-model output remains untrusted; the deterministic traceability path
  invokes no model.
- `unsafe_code = "forbid"` remains workspace-wide.

## migrations

- `migrations/0013_proof_obligations.sql` — immutable, revision-bound proof
  obligations.
- `migrations/0015_proof_obligation_freshness_policy.sql` — immutable
  per-obligation freshness policy, `pinned` by default so existing rows and
  replays are unchanged.

Both are covered by `migrations_apply_and_replay` and the proof-obligation
persistence tests.

## known_limitations

- Reference stability compares reference name and target kind, not target
  identity: a same-named symbol reintroduced in a different file counts as "still
  resolves." Affected requirement: §400 is read as "the referenced symbol/
  mechanism still exists," not "at the same location."
- Freshness reacts only to referenced-symbol existence, not to the full §10.4
  change set (config/dependency/model/topology). Affected requirement: §10.4
  invalidation breadth.
- Configuration traceability is limited to the literal TOML/JSON/INI/YAML key
  set. Affected requirement: §10 configuration coverage for other formats and
  dynamic keys, which stay explicit uncertainty.

## next_phase_dependencies

- The static finding engine (Phase 7) consumes revision-bound traceability and
  proof status without treating a mapping as a conclusion; its foundation
  (missing-implementation candidates, migration `0014`) is already seeded.
- Runtime and coverage phases consume proof obligations and freshness to decide
  when evidence must be re-observed rather than re-derived.
- A later daemon/API phase supplies the registered-target lifecycle and
  scheduling that invoke traceability and proof assessment automatically.
