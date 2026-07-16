# Phase 5 — Completion Evidence

Per spec Appendix AP, a phase cannot be marked complete without a
`PhaseCompletionEvidence` record. This record covers **Phase 5 — Static
architecture adapter v1**. The implementation is awaiting human review. This
file is committed with the implementation as the immutable completion artifact
required by Appendix AP.

| Field | Value |
|---|---|
| **phase** | 5 — Static architecture adapter v1 |
| **source_revision** | Completion changes based on `6fae9bd` (`feat(static): start phase 5 facts foundation`). |
| **reviewed_by_human** | pending |
| **signed_by_agent** | build session, 2026-07-16 |

## Exit criteria

| Criterion | Status | Evidence |
|---|---|---|
| Rust/Python source maps to provenance-bound shadow facts | ✅ | `analyze_inventory` reopens only inventoried code/test artifacts using discovery's containment, size, and digest checks; `static_facts_are_artifact_bound_replay_safe_and_reload_verified` proves the stored target/revision/artifact binding. |
| Unsupported and uncertain code cannot be treated as coverage | ✅ | `target_controlled_paths_fail_closed`, `parser_marks_syntax_and_dynamic_python_calls_uncertain`, and fixture tests retain unsupported language, syntax, macros, and dynamic calls as explicit uncertainty or per-artifact failure. |
| One artifact failure does not abort its target batch | ✅ | `inventory_batch_analyzes_code_and_keeps_source_drift_explicit` and `inventory_batch_marks_non_utf8_source_as_unanalyzed` preserve successful facts alongside explicit failures. |
| Persisted results are replay-safe and auditable | ✅ | Migration `0012`, atomic insertion plus audit, exact replay, altered replay rejection, tamper/reload checks, and `migrations_apply_and_replay`. |

## Required implementation

`bar-static` provides deterministic Tree-sitter adapters for Rust and Python.
The adapter emits one `StaticFacts` value per inventoried artifact and does not
modify the target. `bar-store` persists those facts only after validating their
artifact, target, revision, path, and canonical JSON binding. The batch seam
returns analysis failures explicitly while storage and provenance violations
remain hard errors.

## changed_files

- `Cargo.lock`
- `Cargo.toml`
- `README.md`
- `STATUS.md`
- `crates/bar-discovery/src/lib.rs`
- `crates/bar-static/Cargo.toml`
- `crates/bar-static/src/lib.rs`
- `crates/bar-store/Cargo.toml`
- `crates/bar-store/src/lib.rs`
- `crates/bar-store/src/static_facts.rs`
- `docs/phase-evidence/phase-5.md`
- `fixtures/phase-5-static/expected.json`
- `migrations/0012_static_facts.sql`

## requirement_ids_satisfied

- Appendix I — Rust/Python static facts: artifacts, symbols, references, call
  edges, conservative data edges, state definitions/transitions, authority
  checks, effects, tests, configuration reads, and uncertainty.
- Appendix I — dynamic dispatch, macros, syntax recovery, and dynamic Python
  lookup are explicit uncertainty rather than guessed architecture.
- Appendix I — direct effects propagate only through unique, certain local
  calls to a bounded fixed point; dynamic and ambiguous paths are not inferred.
- Appendix I — a single adapter failure does not abort the batch.
- §8 / Appendix AA — every analyzed source is reopened under discovery's
  containment, size, and digest checks before parsing.
- §19 and §22 — static facts are artifact/target/revision bound, atomically
  audited, idempotent on exact replay, and fail closed on altered or corrupt
  persisted values.

## requirement_ids_deferred

- **Target scheduling and watchers (§5.1, §8).** The bootstrap daemon has no
  registered-target lifecycle or long-running service loop. The Phase 2
  inventory evidence likewise defers prior-revision selection to that later
  orchestration. Impact: callers invoke the tested batch API directly.
- **Cross-artifact semantic data lineage (Appendix I).** Data edges intentionally
  cover only source-bound simple bindings and direct-call results. Impact:
  complex expressions, destructuring, dynamic values, and inter-artifact flow
  stay unmapped rather than becoming fabricated lineage.
- **Static findings and proof coverage (§9, §10, §16).** This phase produces
  evidence, not conclusions or repair authority. Impact: no finding is emitted
  from a static fact alone.

## tests_added / tests_run / test_results

- `cargo test --workspace --all-targets` — **129 passed, 0 failed**.
- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo audit` — 192 dependencies scanned; no advisories reported.
- `git diff --check` — clean.

Coverage includes comments/string decoys; unsupported paths; parser recovery;
dynamic calls; fixture extraction; explicit state/authority/configuration/data
facts; effect propagation; source drift; non-UTF-8 sources; persistence replay;
corrupt JSON; target/revision/path mismatch; audit-chain verification; and
migration replay.

## fixture_results

`fixtures/phase-5-static` provides Rust/Python source and a golden graph-shape
expectation consumed by `expected_fixture_graph_shape_is_stable`. Batch tests
build temporary target trees and modify or replace source after inventory to
prove that stale, unreadable, and non-UTF-8 artifacts become explicit failures
without contaminating neighboring results.

## resource_measurements

No daemon loop, model, network request, or target mutation is introduced.
Static parsing has a 5 MiB per-artifact source cap matching discovery's default;
the Phase-0 model-free daemon resource-budget regression remains green.

## security_checks

- Target-controlled paths are validated and reopened through the discovery
  boundary before static parsing; size and content digest are rechecked.
- Unsupported or uncertain source cannot become a positive architecture fact.
- Store writes validate artifact, target, revision, and path ownership before
  serializing; reload revalidates canonical JSON and the same binding.
- Exact replay is revalidated; changed replay and corrupt persisted facts fail
  closed. Insertion and its audit event share one transaction.
- `unsafe_code = "forbid"` remains workspace-wide.

## migrations

- `migrations/0012_static_facts.sql` — one artifact-bound JSON fact record per
  inventoried artifact, indexed by target/revision. Migration replay is covered
  by `migrations_apply_and_replay`.

## known_limitations

- A hostile writable target can still race path entries between the discovery
  checks and file open; the repository's existing descriptor-relative
  `openat`/no-follow limitation applies. Affected requirement: Appendix AA
  race-resistant monitoring is not claimed.
- No watcher or target scheduler invokes the batch automatically. Affected
  requirement: §5.1 service orchestration; library callers and tests invoke it
  directly.
- Parser coverage is intentionally Rust/Python-only and conservative. Affected
  requirement: Appendix I; unsupported languages and dynamic constructs remain
  explicit uncertainty rather than coverage.

## next_phase_dependencies

- Proof and coverage work consumes persisted facts with their immutable source
  provenance.
- Static findings consume the typed state, authority, effect, configuration,
  data, test, and uncertainty facts without treating them as conclusions.
- A later daemon/API phase supplies registered-target lifecycle, scheduling,
  prior-inventory selection, and target-isolated orchestration.
