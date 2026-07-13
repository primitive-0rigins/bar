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
  (spec §20.1). Fully tested; `cargo test`, `cargo clippy`, `cargo fmt --check`
  all clean.
- Repository foundation: README, MIT license, `.gitignore`, CI (fmt + clippy +
  test), and the normative spec under `docs/`.

### Next (remaining Phase 0)

- `bar-core`: stable identifiers and revision identity (spec §6.1–6.2).
- Config loading and structured logging.
- `bar-audit`: append-only audit chain + tamper test.
- `migrations/` + replay test.
- Resource benchmark harness; daemon starts model-free.

**Exit criteria:** daemon starts model-free; old migrations replay; audit tamper
test passes.
