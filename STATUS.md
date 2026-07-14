# STATUS

Living status of the Behavioral Assurance Runtime build. Newest first.

## Current phase: 0 — Baseline, repository skeleton

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
