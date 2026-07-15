# Phase 2 — Completion Evidence

Per spec Appendix AP, a phase cannot be marked complete without a
`PhaseCompletionEvidence` record. This is that record for **Phase 2 — Artifact
discovery** (spec §21).

| Field | Value |
|---|---|
| **phase** | 2 — Artifact discovery |
| **source_revision** | `3e8671a` (discovery) → `73d7ea8` (inventory persistence) → `50600c1` (dependency-aware reparse planning) |
| **reviewed_by_human** | pending |
| **signed_by_agent** | build sessions, 2026-07-13 through 2026-07-15 |

## changed_files

- `Cargo.lock`
- `Cargo.toml`
- `README.md`
- `STATUS.md`
- `crates/bar-core/src/lib.rs`
- `crates/bar-discovery/Cargo.toml`
- `crates/bar-discovery/src/classify.rs`
- `crates/bar-discovery/src/dependency.rs`
- `crates/bar-discovery/src/lib.rs`
- `crates/bar-discovery/src/walk.rs`
- `crates/bar-store/Cargo.toml`
- `crates/bar-store/src/lib.rs`
- `docs/phase-evidence/phase-2.md`
- `migrations/0003_artifacts.sql`
- `migrations/0004_artifact_dependencies.sql`

## Exit criteria (spec §21)

| Criterion | Status | Evidence |
|---|---|---|
| One-file change reparses only dependents | ✅ | `one_change_selects_only_transitive_dependents` proves deterministic reverse-closure selection. `persisted_dependencies_select_only_changed_artifact_and_dependents` proves the full Phase 2 seam: one changed file is rehashed, its invalidation path seeds the persisted graph, only it and its transitive dependents enter the reparse plan, and an unrelated file is excluded. Parser-specific execution lands with the parser phases. |
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
- Appendix E — `artifacts` and `artifact_dependencies` tables with idempotent,
  transactional persistence.
- Appendix F — `target.scan.started` / `target.scan.completed` audit events.
- §22 — new persisted state carries idempotency, unknown-value, and
  migration-replay tests.

## requirement_ids_deferred

- **Language-specific dependency extraction (§8, §9)** — deferred to contract
  extraction and static adapters. Phase 2 validates, persists, reloads, and
  consumes supplied edges; it does not infer Rust/Python imports or schema
  references itself.
- **Per-artifact delta audit events** (`artifact.discovered/changed/removed`) —
  deferred to the evidence-invalidation phase that consumes them; Phase 2 emits
  scan-level events to avoid thousands of records on an initial bulk scan.
- **Diagram/vocabulary parsing** (spec §8.1 — Mermaid/PlantUML/Graphviz content,
  glossary/alias graph) — diagrams are *classified* here; parsing their contents
  is later work.
- **Retention/compaction** of per-revision artifact snapshots (spec §19).

## tests_added / tests_run / test_results

- `cargo test --all` — **78 passed, 0 failed** (was 58): bar-discovery +16,
  bar-store +4.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo fmt --check` — clean.

Coverage of note: exit-criterion selectivity (unit and end-to-end via the DB),
`ScanMode::Full` re-hash, added/removed detection, oversized-not-read,
`.git`/hidden skipping with a significant-dotfile allowlist, symlink-loop
termination, nested-repo skipping, classification precedence (generated wins),
unknown-token rejection for `ArtifactKind`, dependency cycles and duplicate
edges, unsafe edge input rejection, dependency transaction rollback, idempotent
inventory and edge persistence.

## fixture_results

Discovery tests construct real directory trees (including symlink loops and
nested `.git` repositories) in tempdirs at run time — the §22/§23 discovery
fixtures (symlink loops, huge binaries, generated files, linked repos,
changed-file invalidation).

## resource_measurements

The incremental scan reads only added/changed files: `ScanSummary::hashed`
measures the work and is asserted to be 1 after a one-file change over a 5-file
tree. Reparse planning walks only the reachable reverse dependency closure. The
Phase-0 boot budget regression test still holds.

## security_checks

- **Boundary containment**: the walk never leaves the target root; followed
  symlinks are canonicalized and dropped if they escape, with a visited-dir
  guard against loops (spec §8, Appendix AA).
- **Bounded reads**: files over `max_file_bytes` are inventoried with a non-hex
  `unhashed:oversized` sentinel, never read — a huge or hostile binary cannot
  force an unbounded read.
- **Dependency input validation**: paths reject absolute/traversal forms;
  relation tokens are length- and character-bounded; missing endpoints roll the
  entire edge transaction back.
- `unsafe_code = "forbid"` still holds workspace-wide.

## migrations

- `migrations/0003_artifacts.sql` — `artifacts`. Replay covered by the existing
  `migrations_apply_and_replay` test.
- `migrations/0004_artifact_dependencies.sql` — revision-scoped dependency
  edges with foreign keys, bounded relation kind, and reverse-lookup index.

## known_limitations

- **Edge extraction is caller-supplied (§8, §9).** The graph mechanics are
  complete, but no language parser produces edges yet; until Phase 3/5, the
  capability is exercised through deterministic fixtures rather than a live
  adapter.

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
  source spans; the artifact inventory and invalidation plan are its inputs, and
  extracted references can populate the dependency graph.
