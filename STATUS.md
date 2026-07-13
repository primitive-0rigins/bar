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
- Repository foundation: README, MIT license, `.gitignore`, CI (fmt + clippy +
  test), and the normative spec under `docs/`.

### Next (remaining Phase 0)

- Resource benchmark harness (the last Phase-0 item). "Daemon starts model-free"
  is already met by `bar-daemon`.

The revision-identity *bundle* (spec §6.2 — commit/dirty hash, build manifest,
toolchain, deployment id, topology) is deferred to **Phase 1**, where the target
connector supplies its inputs (§21 Phase 1). `RevisionId` itself already exists.

**Exit criteria:** daemon starts model-free; old migrations replay; audit tamper
test passes.
