# Phase 1 — Completion Evidence

Per spec Appendix AP, a phase cannot be marked complete without a
`PhaseCompletionEvidence` record. This is that record for **Phase 1 — Target
registration and identity** (spec §21).

| Field | Value |
|---|---|
| **phase** | 1 — Target registration and identity |
| **source_revision** | `e26aca1` (identity layer) → `00d4274` (registry) |
| **reviewed_by_human** | pending |
| **signed_by_agent** | build session, 2026-07-13 |

## Exit criteria (spec §21)

| Criterion | Status | Evidence |
|---|---|---|
| Repeat registration is idempotent | ✅ | `registration_is_idempotent_on_root` — a second registration of the same canonical root returns the existing `TargetId` with outcome `Unchanged`, leaves exactly one row, and emits no duplicate audit event. `recording_a_revision_is_idempotent_and_content_sensitive` covers revisions. |
| Symlink/path traversal blocked | ✅ (primitive) | `resolve_within` rejects `..` traversal, symlink escape, and missing paths (`resolve_within_rejects_dotdot_traversal`, `resolve_within_rejects_symlink_escape`, `resolve_within_errors_on_missing_path_without_panicking`). See known limitations — the primitive is built and proven; the discovery-time file walk that consumes it lands Phase 2. |

## Required implementation (spec §21 Phase 1)

Local Git/filesystem connector, commit/dirty hash, target registry, read-only
policy — all delivered.

## requirement_ids_satisfied

- §6.1 — content-hash `RevisionId` derivation (deterministic, injective).
- §6.2 — revision identity slice: source commit + content-sensitive dirty hash;
  explicit **unbound** state when a commit cannot be proven.
- §8 / Appendix AA — target boundary: canonical root locator; `resolve_within`
  confines all later path resolution to the target root.
- Appendix F — `target.registered` and `revision.discovered` audit events
  emitted on first registration / first revision sighting.
- §21 Phase 1 — idempotent registration; read-only connector (no method writes
  to a target).

## requirement_ids_deferred

- §6.2 revision-identity **bundle** beyond commit/dirty: build manifest,
  dependency lock + toolchain, config/schema/flag/model identity, deployment id,
  environment, topology, start time. The `target_revisions` columns exist and
  are left NULL until the discovery, build-identity, and runtime phases supply
  them.
- **Operator entry point** (CLI/HTTP registration) — deferred to the API phase;
  Phase 1 lands registration as a tested library capability (shadow-first).
- **Full Appendix F audit envelope** — first-class `event_type`, idempotency
  key, causal mechanism, payload schema version. Current events use the existing
  chained `LifecycleTransition` primitive; the fuller envelope is an
  audit-hardening pass.

## tests_added / tests_run / test_results

- `cargo test` — **57 passed, 0 failed** (was 38): bar-target +15, bar-store +4,
  bar-core unchanged count with re-exports.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo fmt --check` — clean.

New tests of note: traversal/symlink escape rejection; unbound filesystem
target; content-sensitive dirty hash (the property `git status --porcelain`
fails); untracked-file dirtiness; idempotent registration and revision
recording; registration audit event chains and verifies; unknown-token
rejection for `ConnectorKind`/`TargetStatus` (spec §22).

## fixture_results

Git-backed tests construct a real repository in a tempdir at run time (the §22
"fixture that fails before, passes after") and skip cleanly when the `git`
binary is unavailable, so the suite still runs offline.

## resource_measurements

No new steady-state cost; registration is event-driven and bounded. The Phase-0
boot budget regression test still holds.

## security_checks

- **Path traversal / symlink escape**: `resolve_within` canonicalizes both root
  and candidate and enforces containment (spec §8 exit criterion).
- **Read-only policy**: git reads use only read-only subcommands; no
  `git add`/`write-tree`, no index or worktree mutation.
- **No fabricated identity**: unreadable git state (incl. "dubious ownership"
  when monitoring another user's checkout) becomes an explicit unbound revision.
- `unsafe_code = "forbid"` still holds workspace-wide.

## migrations

- `migrations/0002_targets.sql` — `targets` + `target_revisions`. Replay covered
  by the existing `migrations_apply_and_replay` test (embedded migrations apply
  and re-apply idempotently).

## known_limitations

- **Traversal enforcement is the primitive, not yet the walk.** `resolve_within`
  is built and proven; nothing walks target files until discovery (Phase 2).
  Affected requirement: §8 discovery-time enforcement.
- **`git` is invoked as a subprocess.** Simple and dependency-free for V1, but it
  requires `git` on PATH and treats any non-zero exit as unbound. A pure-Rust
  backend can swap in behind the same functions later.
- Dirty-hash reads untracked file contents; discovery-phase size/ignore limits
  (spec §23, scan config) are not yet applied here.
- The registration idempotency key is the `root_locator` string via
  `to_string_lossy`, so two distinct non-UTF-8 paths could in principle collide
  to one key (Linux-only edge). Canonical repository roots are UTF-8 in practice.

## next_phase_dependencies

- Phase 2 (artifact discovery) consumes `resolve_within` for its file walk and
  the `ResolvedTarget` root/connector for inventory.
