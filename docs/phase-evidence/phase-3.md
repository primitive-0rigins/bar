# Phase 3 — Completion Evidence

Per spec Appendix AP, a phase cannot be marked complete without a
`PhaseCompletionEvidence` record. This is that record for **Phase 3 — Contract
extraction shadow** (spec §21).

| Field | Value |
|---|---|
| **phase** | 3 — Contract extraction shadow |
| **source_revision** | `3fb0fc6` → `74e1408` → `85fff4d` → `b483f02` → `3ca47dc` → `c5959d1` → `3238221` → `502037f` |
| **reviewed_by_human** | approved — Bryce Worthy, 2026-07-15 |
| **signed_by_agent** | build sessions, 2026-07-15 |

## Exit criteria (spec §21)

| Criterion | Status | Evidence |
|---|---|---|
| Every claim cites source | ✅ | `deterministic_claims_are_exactly_source_bound` verifies exact artifact identity, UTF-8 byte span, and SHA-256. `ArtifactText` rejects whole-artifact hash mismatch before analysis. The golden corpus carries these claims through discovery, durable contract/candidate persistence, and reload. |
| Malformed/model-injected output rejected | ✅ | `model_output_must_match_source_and_rejects_unknown_fields` rejects malformed JSON, unknown fields/vocabulary, fabricated text, invalid spans, and hash mismatch. `model_cannot_promote_prompt_injection_text_to_a_claim` proves deterministic and model-output paths reject injected text, including cross-sentence paragraph taint. |

## Required implementation (spec §21 Phase 3)

Normative classification, exact source spans, structural hierarchy candidates,
glossary candidates, and provisional conflict candidates are delivered and
durable in shadow mode. The optional small-model path is deliberately absent:
strict output validation exists, deterministic extraction remains complete
without it, and the daemon reports configured-but-unintegrated model support as
`unavailable` rather than claiming capability.

## changed_files

- `Cargo.lock`
- `Cargo.toml`
- `README.md`
- `STATUS.md`
- `crates/bar-audit/src/lib.rs`
- `crates/bar-contract/Cargo.toml`
- `crates/bar-contract/src/lib.rs`
- `crates/bar-core/src/lib.rs`
- `crates/bar-daemon/src/main.rs`
- `crates/bar-daemon/tests/resource_budget.rs`
- `crates/bar-store/Cargo.toml`
- `crates/bar-store/src/lib.rs`
- `docs/phase-evidence/phase-3.md`
- `fixtures/phase-3-contract-corpus/expected.json`
- `fixtures/phase-3-contract-corpus/operations.md`
- `fixtures/phase-3-contract-corpus/policy.md`
- `migrations/0005_contracts.sql`
- `migrations/0006_contract_candidates.sql`

## requirement_ids_satisfied

- §7.1 / Appendix H.1 — source-bound shadow contracts with deterministic
  normative kind, conservative level, normalized statement, source span, and
  fingerprint.
- §7.3 / Appendix H.1 — source-bound structural hierarchy proposals; candidates
  assign no authority and do not write `parent_contract_id`.
- §8.1 / Appendix H.1 — explicit glossary definitions and aliases are
  preserved; competing definitions become ambiguity candidates without merge.
- §7.4 / Appendix H.1 — direct required/prohibited opposites become provisional
  conflicts and are never auto-adjudicated.
- §21 Phase 3 — both exit criteria are covered by deterministic and adversarial
  tests.
- §22 — model-assisted behavior has deterministic fallback and explicit
  disabled/unavailable state; new persistence is replay-idempotent,
  transactional, audited, and rejects unknown state during reload.
- §23 / Appendix Y — malicious instructions, fenced examples, cross-document
  conflict, glossary ambiguity, exact outputs, and persistence round trips are
  represented in a versioned golden corpus.

## requirement_ids_deferred

- **Appendix H.1 step 8 — explicit-reference and semantic hierarchy.** Phase 3
  supplies structural containment candidates. The spec defines no explicit
  reference syntax, so inventing one is deferred; semantic/code corroboration
  belongs with static adapters. Impact: parent suggestions are incomplete but
  no false parent gains authority.
- **Appendix H.1 steps 6 and 9 — target-wide terminology normalization and
  scope/temporal resolution.** Competing definitions are preserved instead of
  selected. Resolution, validity, supersession, and operator rulings are Phase
  4 responsibilities.
- **§4.2 / Appendix O — optional model worker.** No model adapter is invoked.
  Impact: deterministic extraction is available; optional semantic enrichment
  is unavailable and reported honestly.
- **§8.1 source-authority weighting.** Discovery records artifact kind and
  source-of-truth metadata, but extraction does not yet weight claims by source
  authority. Impact: all candidates remain low-confidence shadow evidence.

## tests_added / tests_run / test_results

- `cargo test --all` — **95 passed, 0 failed**.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo fmt --all --check` — clean.
- `git diff --check` — clean.

Coverage of note: normative classes; whole-artifact and exact-span hashes;
multiline prose, blockquotes, tables, lists, comments, and fenced-code
exclusion; prompt injection before and after sentence segmentation; strict model
JSON; hierarchy/glossary/conflict derivation; cross-artifact ambiguity and
conflicts; transaction rollback; idempotent replay; audit-chain verification;
unknown persisted state; deterministic conflict ordering; and disabled versus
unavailable model readiness.

## fixture_results

`fixtures/phase-3-contract-corpus` is a checked-in, hand-authored adversarial
corpus. Its expected manifest is independent of runtime output. The store test
drives the real discovery → corpus analysis → contract persistence → candidate
reload path and proves fenced/injected text is excluded, two glossary
definitions remain separate, and the direct conflict stays provisional.

## resource_measurements

The real daemon still boots with models disabled below the 300 MB Phase-0
regression ceiling. Enabling model policy without an adapter starts in
deterministic mode and reports `unavailable`; no model process, GPU allocation,
network request, or polling loop is introduced.

## security_checks

- Whole-artifact hash verification prevents analysis against bytes different
  from discovery inventory.
- Every claim and derived source candidate retains exact byte provenance and a
  SHA-256 digest.
- Prompt-injection markers taint the whole paragraph before sentence splitting;
  fenced examples are excluded.
- Model output uses a bounded, closed schema and cannot fabricate statements,
  spans, hashes, kinds, levels, or extra fields.
- Candidate persistence validates every contract/artifact reference before any
  write; errors roll back the transaction.
- Model readiness logs expose only disabled/unavailable state, not provider or
  endpoint configuration.
- `unsafe_code = "forbid"` remains workspace-wide.

## migrations

- `migrations/0005_contracts.sql` — revision-scoped shadow contracts and exact
  source rows with fingerprint idempotency.
- `migrations/0006_contract_candidates.sql` — durable structural hierarchy,
  glossary, and provisional conflict candidates.
- Migration application and replay are covered by `migrations_apply_and_replay`.

## known_limitations

- **No active contract authority (§7).** All records remain discovered,
  low-confidence shadow candidates. This is intentional; interpretation and
  authority begin with Phase 4 adjudication.
- **Direct conflict rule only (Appendix H.1 step 10).** It compares normalized
  subjects for required/prohibited opposites without scope or time. Impact:
  false positives remain provisional and false negatives are possible until
  Phase 4.
- **Explicit definitions only (§8.1).** Code symbols, schemas, and operator
  corrections do not yet corroborate the alias graph. Impact: glossary coverage
  is incomplete and ambiguity is preserved.
- **No optional model adapter (§4.2, Appendix O).** Validated model output can be
  consumed, but this build invokes no model and performs no semantic enrichment.
- **Crash recovery and PostgreSQL are not exercised (§22).** Logical failures
  prove transaction rollback and replay idempotency on SQLite, but this phase
  does not kill a process mid-transaction or run the candidate migrations on a
  PostgreSQL service. Impact: process/database-specific recovery assurance is
  deferred to hardening; SQLite shadow operation is the proven path.

## next_phase_dependencies

- Phase 4 consumes durable contracts, hierarchy/glossary/conflict candidates,
  `parent_contract_id`, and exact source provenance to add scope precedence,
  validity, supersession, and versioned operator rulings.
- Ambiguous conflicts must remain provisional until a scope/temporal resolver or
  operator ruling selects an interpretation.
