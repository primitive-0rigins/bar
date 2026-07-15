# STATUS

Living status of the Behavioral Assurance Runtime build. Newest first.

## Current phase: 3 — Contract extraction shadow (in progress)

Per [`docs/spec.md`](docs/spec.md) §21 and Appendix H.1, Phase 3 classifies
normative claims, preserves exact source spans, proposes hierarchy/glossary/
conflict candidates, and treats optional-model output as untrusted data.

### Delivered

- `bar-contract`: deterministic extraction from supported prose/list segments.
  It recognizes required, prohibited, expected, and planned language; assigns a
  conservative behavioral/architecture level; and fingerprints the normalized
  statement plus exact source identity and byte span.
- Segmentation now covers Markdown headings, multiline paragraphs with
  sentence boundaries, list items, table cells, multiline Markdown blockquote
  paragraphs, single- and multiline HTML/Rust-style block comments, and
  Rust-style line comments. Quote continuation markers are removed only from
  normalized candidate text while the exact cited bytes retain them. Unclosed
  comment blocks are discarded conservatively. Fenced Markdown code/examples
  are excluded so example `MUST` text cannot become an active-looking candidate.
- Claims inherit the nearest Markdown heading as a source-bound structural
  hierarchy candidate. This is a proposal only—it does not establish an
  authoritative parent contract.
- Explicit `means` / `is defined as` statements produce source-bound glossary
  candidates; `also called` / `aka` clauses produce aliases without rewriting
  source text or merging entities automatically.
- Direct required/prohibited opposites produce provisional conflict candidates
  only when their normalized subject is identical. Same-direction claims and
  different subjects do not conflict, and neither side is selected or promoted.
- Revision-level corpus analysis deterministically combines artifact results,
  deduplicates source-bound fingerprints, detects direct conflicts across
  artifacts, and preserves competing glossary definitions as explicit
  ambiguity candidates instead of silently selecting or merging one.
- Every extracted claim carries an `ArtifactId`, exact UTF-8 byte offsets, and a
  SHA-256 of the exact cited bytes. `ArtifactText` first verifies the complete
  text against the discovery inventory hash, so extraction cannot silently bind
  to different content.
- Strict optional-model JSON validation uses `deny_unknown_fields`, bounded
  output/claim counts, closed normative/level vocabularies, UTF-8-safe offsets,
  exact-text hashes, and statement-to-source equality. Malformed JSON,
  fabricated statements, unknown fields/tokens, invalid spans, and known prompt
  injection markers are rejected. Injection taint applies to the complete
  paragraph before sentence segmentation, so a marker cannot hide in a prior
  sentence while a following command becomes a claim. The deterministic path
  remains independent of a model.
- `bar-store`: migration `0005` adds revision-scoped `contracts` and mandatory
  `contract_sources`. Persistence is fingerprint-idempotent and records
  each newly extracted contract as an audited evidence mutation in the same
  transaction. A missing source rolls back the full contract batch; unknown
  persisted vocabulary/state is rejected during reload.
- `bar-store`: migration `0006` adds durable structural hierarchy, glossary,
  and provisional conflict candidates. Candidate persistence validates all
  contract and artifact references before writing, is replay-idempotent, and
  audits newly detected conflicts atomically. Reload rejects corrupt aliases,
  spans, hashes, heading levels, and unknown conflict states; glossary
  ambiguities are reconstructed from the preserved definitions.
- The versioned `fixtures/phase-3-contract-corpus` golden corpus drives real
  discovery, deterministic analysis, contract/candidate persistence, and
  reload against hand-authored expected output. It covers fenced examples,
  cross-sentence prompt injection, multiline blockquotes, glossary ambiguity,
  and cross-document conflict; conflict pairs are fingerprint-canonical across
  persistence round trips.

The implemented slice passes the two Phase 3 safety invariants: every emitted
claim cites verified source bytes, and malformed or source-inconsistent model
output is rejected. The full phase is not complete. All 94 repository tests
pass; clippy `-D warnings` and fmt are clean. Implementation revisions:
`3fb0fc6`, `74e1408`, `85fff4d`, `b483f02`, `3ca47dc`, `c5959d1`, and
`3238221`.

### Remaining before Phase 3 completion

- Explicit-reference hierarchy and semantic hierarchy proposals; current
  attachment is structural Markdown containment only.
- Glossary/alias graph corroboration and operator correction inputs;
  cross-artifact ambiguity is durable, but aliases still come only from
  explicit definitions and no terms are merged automatically.
- Scope- and temporal-aware conflict generation; direct cross-artifact
  required/prohibited opposites are now durable candidates.
- Optional worker integration and its explicit disabled/unavailable runtime
  state; current code validates bounded output but invokes no model.
- Phase 3 completion evidence after the remaining capabilities and human review.

## Phase 2 — Artifact discovery (implementation complete)

Per [`docs/spec.md`](docs/spec.md) §21, Phase 2 delivers an inventory of
docs/code/tests/schemas/config/CI/diagrams/generated files, a hash cache, and an
incremental scan.

### Done

- `bar-discovery`: the discovery engine (pure crate: walk + classify +
  incremental scan, no DB, read-only). **Cross-revision carry-forward** is the
  core — because a target's `RevisionId` changes on every content edit and
  artifacts are unique per `(revision, logical_path)`, a naive re-scan would
  re-hash every file. `scan` instead carries unchanged files (same size + mtime)
  forward from the prior revision's inventory without reading them, hashing only
  what changed. `ScanSummary::hashed` reports the real cost, and selective
  rehashing is proven by asserting `hashed == 1` after a one-file edit — unit and
  end-to-end through the database.
- `bar-discovery`: `ScanMode::Full` re-hashes everything as the integrity
  fallback for the mtime heuristic's blind spot (a content edit preserving size +
  mtime). Boundary-respecting walk: never descends `.git`, skips nested
  repositories, guards symlink escape and loops, honors hidden/oversized policy
  (oversized files inventoried with a non-hex sentinel, never read). Deterministic
  Tier-0 classification into `ArtifactKind` with a fixed precedence.
- `bar-store`: migration `0003` (`artifacts`); `persist_inventory` inserts a
  scan idempotently (content-derived `ArtifactId`) bracketed by
  `target.scan.started`/`completed` audit events; `load_inventory` reloads a
  revision's inventory to drive the next scan's carry-forward.
- `bar-discovery` + `bar-store`: validated dependency edges (`dependent` →
  `dependency`), migration `0004` (`artifact_dependencies`), idempotent and
  transactional persistence, and deterministic transitive reparse plans. Scan
  results expose sorted added/changed/removed invalidation paths. Cycles and
  duplicate edges terminate without duplicate work; unrelated artifacts stay
  out of the plan.
- Oversized artifacts now invalidate on metadata changes instead of appearing
  unchanged merely because both revisions carry the `unhashed:oversized`
  sentinel.

Both Phase 2 exit criteria are met at the discovery boundary: a one-file change
rehashes only that file and produces a reparse plan containing only the changed
artifact and its transitive dependents; unchanged, unrelated files are neither
read nor selected. All 78 tests pass; clippy `-D warnings` and fmt are clean.
Phase evidence per spec Appendix AP:
[`docs/phase-evidence/phase-2.md`](docs/phase-evidence/phase-2.md) — **pending
human review**.

Language-specific parsers populate dependency edges in the contract/static
adapter phases; Phase 2 accepts validated edges and owns their persistence and
invalidation planning. Per-artifact delta audit events remain deferred to
evidence invalidation. The daemon scan loop that picks the "prior" revision is
later work; Phase 2 lands scan + persistence as library capabilities
(shadow-first).

## Phase 1 — Target registration and identity

Per [`docs/spec.md`](docs/spec.md) §21, Phase 1 delivers a local Git/filesystem
connector, commit/dirty revision identity, an idempotent target registry, and a
read-only policy.

### Done

- `bar-target`: the connector + identity layer (read-only throughout).
  `resolve_target` produces a canonical root locator, a connector kind
  (`git` | `filesystem`), and the Phase-1 slice of revision identity. A git tree
  BAR cannot read yields an explicit **unbound** revision (spec §6.2), never
  fabricated identity.
- `bar-target`: `resolve_within` — the security primitive behind the
  "symlink/path traversal blocked" exit criterion. It canonicalizes both the
  root and any candidate path so `..`, relative paths, and symlinks collapse to
  their real location, then rejects anything escaping the root. The file *walk*
  that consumes it lands with discovery (Phase 2); Phase 1 builds and proves the
  primitive.
- `bar-target`: read-only git reads (HEAD + a **content-sensitive** dirty hash
  over `git diff HEAD` and untracked path+content — two different edits hash
  differently, which `git status --porcelain` cannot distinguish). Deterministic,
  injective `RevisionId` derivation so recording a revision is idempotent.
- `bar-store`: migration `0002`, and an **idempotent** target registry.
  `register_target` dedupes on the canonical root (exit criterion), mints a
  `TargetId`, and records the mandated `target.registered` audit event
  (Appendix F) in the same transaction; `record_revision` dedupes on the
  content-derived `RevisionId` and emits `revision.discovered`. No duplicate
  rows, no duplicate audit events; the chain still verifies.
- `bar-core`: `Error::Target`; `TargetId`/`RevisionId` re-exported at the root.

Both exit criteria are met and tested (57 tests, clippy `-D warnings` and fmt
clean). Completion evidence per spec Appendix AP:
[`docs/phase-evidence/phase-1.md`](docs/phase-evidence/phase-1.md) — **pending
human review**.

The operator entry point (CLI/HTTP registration) is deferred to the API phase;
Phase 1 lands registration as a tested library capability (shadow-first). The
full Appendix F audit envelope (first-class `event_type`, idempotency key,
causal mechanism, payload schema version) is a later audit-hardening pass.

## Phase 0 — Baseline, repository skeleton

Per [`docs/spec.md`](docs/spec.md) §21, Phase 0 delivers the workspace, core
types, config, structured logging, audit chain, migrations, and a resource
benchmark harness.

### Done

- Cargo workspace scaffolded with shared metadata; `unsafe_code` forbidden and
  clippy `all` warned workspace-wide.
- `bar-core`: the seven core persisted enums (spec §6.3) with stable string
  tokens, plus the typed `Error`/`Result` foundation with retry classification
  (spec §20.1). Fully tested.
- `bar-core`: the stable identifier system (spec §6.1) — 14 UUID newtypes and
  the two content-hash ids (`RevisionId`, `ArtifactId`) over a `Sha256Digest`,
  each with a fixed namespace prefix and canonical `prefix/body` string form.
  Distinct types (a `FindingId` cannot stand in for a `RepairId`). Fully tested;
  `cargo test`, `cargo clippy -D warnings`, `cargo fmt --check` all clean.
- `bar-config`: the complete configuration contract (spec Appendix C) — all nine
  sections with documented defaults, `deny_unknown_fields` (unknown key →
  startup error), and range validation before start. The appendix TOML is a
  round-trip test fixture.
- `bar-daemon`: the mandatory process shell (spec §5.1). Loads config from
  `$BAR_CONFIG` (or built-in defaults), initializes structured logging via
  `tracing` (text or `BAR_LOG_FORMAT=json`), and **starts model-free** — verified
  by running it: boots, logs a structured readiness summary, exits 0. Its
  long-running service loop lands with the API phase.
- `bar-audit`: the append-only, hash-chained audit log (spec §18–19). Each record
  commits (SHA-256 over a length-prefixed canonical encoding) to its
  predecessor's hash. **The tamper test — the Phase-0 exit criterion — passes:**
  value/timestamp/category/subject mutation, reorder, insertion, truncation, and
  broken links are all detected; a clean chain verifies. JSONL mirror, DB index,
  optional signatures, and crash replay are deferred to the storage layer.
- `bar-store`: the relational store and migrations (spec §19), on `sqlx` with
  SQLite locally and PostgreSQL as a production option. Root `migrations/` are
  embedded at compile time; **replay is idempotent** (a reopened store applies
  no duplicate migrations — the "old migrations replay" exit criterion). The
  audit chain persists to a DB-indexed `audit_log` and reloads with stored
  hashes intact, so a row edited outside BAR fails re-verification. Queries are
  runtime-checked, so a clean build needs no live database.
- `bar-bench`: the resource benchmark harness (spec §4, §22). `peak_rss_bytes()`
  reads the process high-water mark from Linux `/proc/self/status` (`VmHWM`) —
  race-free, no sampling loop, no `unsafe`; `None` off `/proc` rather than a
  fabricated number. The daemon reports its boot footprint, and
  `resource_budget.rs` spawns the real binary model-free and asserts it stays
  under the §4 budget — making the resource contract a **regression test, not a
  documentation target** (spec §22). Observed boot peak: ~5.1 MB. This proves
  *boot* peak RSS, not the §4 *idle* contract (no idle loop exists yet); at this
  footprint the 300 MB ceiling's real job is guarding the model-free invariant
  (§3.1). `bar-bench` is the measurement primitive later §23 performance rows
  build on — distinct from the future `bar-resource` governor (§5), which *acts*
  on these readings rather than taking them.
- Repository foundation: README, MIT license, `.gitignore`, CI (fmt + clippy +
  test), and the normative spec under `docs/`.

### Phase 0 status

All Phase-0 implementation items are delivered and green (38 tests, clippy
`-D warnings` and fmt clean). Completion evidence per spec Appendix AP:
[`docs/phase-evidence/phase-0.md`](docs/phase-evidence/phase-0.md) — **pending
human review** before the phase is formally closed and Phase 1 begins.

Idle CPU/RAM, incremental-scan RAM, high-volume ingestion, and target-pressure
suspension (spec §23 performance rows) join the harness with the service loop.

The revision-identity *bundle* (spec §6.2 — commit/dirty hash, build manifest,
toolchain, deployment id, topology) is deferred to **Phase 1**, where the target
connector supplies its inputs (§21 Phase 1). `RevisionId` itself already exists.

**Exit criteria:** daemon starts model-free; old migrations replay; audit tamper
test passes.
