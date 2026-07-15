# Phase 2 — Completion Evidence

Per spec Appendix AP, a phase cannot be marked complete without a
`PhaseCompletionEvidence` record. This is that record for **Phase 2 — Artifact
discovery** (spec §21).

| Field | Value |
|---|---|
| **phase** | 2 — Artifact discovery |
| **source_revision** | `3e8671a` (discovery engine) → `73d7ea8` (persistence) |
| **reviewed_by_human** | pending |
| **signed_by_agent** | build session, 2026-07-13 |

## changed_files

- `Cargo.lock`
- `Cargo.toml`
- `README.md`
- `STATUS.md`
- `crates/bar-core/src/lib.rs`
- `crates/bar-discovery/Cargo.toml`
- `crates/bar-discovery/src/classify.rs`
- `crates/bar-discovery/src/lib.rs`
- `crates/bar-discovery/src/walk.rs`
- `crates/bar-store/Cargo.toml`
- `crates/bar-store/src/lib.rs`
- `docs/phase-evidence/phase-2.md`
- `migrations/0003_artifacts.sql`

## Exit criteria (spec §21)

| Criterion | Status | Evidence |
|---|---|---|
| One-file change reparses only dependents | ⚠️ Partial | `one_file_change_rehashes_only_that_file` (unit) and `incremental_rescan_through_store_rehashes_only_the_changed_file` (end-to-end via the DB) prove that only one changed file is rehashed. No parser or dependency graph exists yet, so selective dependent reparsing is not implemented. |
| No full rescan | ✅ | Cross-revision carry-forward: files whose size and mtime are unchanged reuse the prior revision's stored hash and classification without being read. |

## Required implementation (spec §21 Phase 2)

Inventory of docs/code/tests/schemas/config/CI/diagrams/generated files; hash
cache and incremental scan — all delivered.

## requirement_ids_satisfied

- §8 — discovery pipeline: capture identity, walk artifacts, classify
  source-of-truth vs generated, store content hashes incrementally.
- §8 / Appendix AA — boundary and target model: `.git` never descended, nested
  repositories skipped as separate targets, symlink escape/loop protection.
- Appendix C `[scan]` — scan policy honored (`max_file_bytes`,
  `follow_symlinks`, `include_hidden`).
- Appendix E — `artifacts` table and idempotent persistence.
- Appendix F — `target.scan.started` / `target.scan.completed` audit events.
- §22 — new persisted state carries idempotency, unknown-value, and
  migration-replay tests.

## requirement_ids_deferred

- **`artifact_dependencies` (Appendix E), the dependency graph, and selective
  dependent reparsing (§21 Phase 2 exit criterion)** — not implemented. This is
  a Phase 2 closure gap: the current implementation can avoid rehashing unchanged
  files, but cannot identify or reparse dependents of a changed artifact.
- **Per-artifact delta audit events** (`artifact.discovered/changed/removed`) —
  deferred to the evidence-invalidation phase that consumes them; Phase 2 emits
  scan-level events to avoid thousands of records on an initial bulk scan.
- **Diagram/vocabulary parsing** (spec §8.1 — Mermaid/PlantUML/Graphviz content,
  glossary/alias graph) — diagrams are *classified* here; parsing their contents
  is later work.
- **Retention/compaction** of per-revision artifact snapshots (spec §19).

## tests_added / tests_run / test_results

- `cargo test` — **72 passed, 0 failed** (was 58): bar-discovery +12,
  bar-store +2.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo fmt --check` — clean.

Coverage of note: exit-criterion selectivity (unit and end-to-end via the DB),
`ScanMode::Full` re-hash, added/removed detection, oversized-not-read,
`.git`/hidden skipping with a significant-dotfile allowlist, symlink-loop
termination, nested-repo skipping, classification precedence (generated wins),
unknown-token rejection for `ArtifactKind`, idempotent persistence.

## fixture_results

Discovery tests construct real directory trees (including symlink loops and
nested `.git` repositories) in tempdirs at run time — the §22/§23 discovery
fixtures (symlink loops, huge binaries, generated files, linked repos,
changed-file invalidation).

## resource_measurements

The incremental scan reads only added/changed files: `ScanSummary::hashed`
measures the work and is asserted to be 1 after a one-file change over a 5-file
tree. The Phase-0 boot budget regression test still holds.

## security_checks

- **Boundary containment**: the walk never leaves the target root; followed
  symlinks are canonicalized and dropped if they escape, with a visited-dir
  guard against loops (spec §8, Appendix AA).
- **Bounded reads**: files over `max_file_bytes` are inventoried with a non-hex
  `unhashed:oversized` sentinel, never read — a huge or hostile binary cannot
  force an unbounded read.
- `unsafe_code = "forbid"` still holds workspace-wide.

## migrations

- `migrations/0003_artifacts.sql` — `artifacts`. Replay covered by the existing
  `migrations_apply_and_replay` test.

## known_limitations

- **Dependency-aware reparsing is absent (§21 Phase 2 exit criterion).** The
  scanner reports changed artifacts but has no parser outputs or dependency
  edges, so downstream dependents cannot yet be selected for reprocessing.

- **The mtime heuristic has a blind spot.** Incremental mode decides "unchanged"
  from `(size, mtime)`; a content edit that preserves both is a silent miss.
  `ScanMode::Full` re-hashes everything as the integrity fallback. Affected
  requirement: §8 change detection under adversarial mtime.
- **"Prior revision" selection is the caller's.** `load_inventory(revision_id)`
  loads a specific revision; choosing which revision is "prior" belongs to the
  daemon scan loop (a later phase). Phase 2 lands scan + persistence as library
  capabilities, orchestrated in tests (shadow-first).
- **Per-revision row growth**: each revision holds a full inventory snapshot;
  retention/compaction (spec §19) bounds this later.
- **Classification is heuristic Tier-0** (path + content markers); a small
  model (Tier 1) can refine ambiguous cases in a later phase.

## next_phase_dependencies

- Phase 3 (contract extraction) reads discovered artifacts, their kinds, and
  source spans; the `artifacts` inventory and `source_of_truth` flag are its
  inputs.
