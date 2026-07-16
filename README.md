# BAR — Behavioral Assurance Runtime

A lightweight, model-optional assurance daemon written in Rust. You point it at
one or more software runtimes; it learns each runtime's *intended* behavior from
the runtime itself, compares that intent against implementation and live
execution, prepares repair-ready findings, waits for **human approval**, hands
approved work to a connected coding agent, and then independently verifies the
result.

> **Status:** Phase 6 — traceability and proof obligations — has begun with a
> deterministic contract-to-code mapping foundation. Phase 5’s Rust/Python
> static architecture adapter is implemented and awaiting human review. It
> persists artifact/revision-bound shadow facts and records unsupported or
> uncertain code explicitly. A Phase 7 shadow-only missing-implementation
> candidate detector is also available; it neither persists findings nor grants
> repair authority. Daemon watchers and target scheduling remain later
> orchestration work. Build progresses through the phased manual in
> [`docs/spec.md`](docs/spec.md) §21; see [`STATUS.md`](STATUS.md) for current
> work and completion evidence.

## What it is

BAR is a continuously maintained model of what a runtime *claims, permits,
executes, and can prove*. Its pipeline runs:

```
target pointer → artifact discovery → contract extraction → hierarchy & adjudication
→ static/path model → build-deployment identity → runtime evidence
→ proof-obligation & coverage → finding & causal investigation → repair-ready contract
→ human approval → coding-agent implementation → pre-merge impact → post-change verification
→ assurance history
```

### Ownership boundary

| BAR owns | Human owns | Coding agent owns | External systems own |
|---|---|---|---|
| Discovery, evidence, contracts, findings, repair constraints, verification | Interpretation rulings, approvals, waivers, accepted risk | Repository inspection, plan, edits, tests, implementation report | Source control, CI, artifact build, deployment, production credentials |

### Design commitments

- **Target-first resources.** The monitored workload owns the machine. BAR runs
  without a GPU, keeps no model resident by default, stays near-idle when nothing
  changes, and suspends optional semantic work under target pressure.
- **Concurrent multi-runtime monitoring (planned).** One daemon will watch
  multiple registered targets concurrently with isolated state, per-target job
  serialization, and bounded target-fair shared workers. Fleet-level pattern
  suggestions remain a later, separate capability.
- **Model-optional.** BAR remains useful with all models disabled.
- **Human-gated repair.** No repair job is visible to the coding agent before
  approval; approval binds to exact job content, target, scope, base revision,
  and expiry. BAR never grants production deployment authority.
- **Honest evidence.** Documentation is evidence, but may be stale, contradictory,
  or wrong — it never becomes proof on its own. Every finding cites exact evidence
  and states its limitations.

### Explicit non-goals

Not a personal companion, agent orchestrator, scheduler, security scanner, CI/CD
system, issue tracker, or observability replacement — and it emits no single
"correctness score." See [`docs/spec.md`](docs/spec.md) §2.1.

## Repository layout

```
bar/
├── crates/
│   ├── bar-core/      # IDs, enums, schemas, typed errors
│   ├── bar-config/    # configuration contract (spec Appendix C)
│   ├── bar-audit/     # append-only hash-chained audit log
│   ├── bar-store/     # sqlx store + migrations (SQLite / PostgreSQL)
│   ├── bar-target/    # read-only target resolution and revision identity
│   ├── bar-discovery/ # incremental inventory and dependency-aware reparse plans
│   ├── bar-contract/  # source-bound claims, hierarchy, glossary, conflicts
│   ├── bar-static/    # shadow static architecture facts (Phase 5 foundation)
│   ├── bar-coverage/  # deterministic contract-to-static-fact traceability
│   ├── bar-findings/  # shadow static-finding candidates (Phase 7 foundation)
│   ├── bar-bench/     # resource benchmark harness (spec §4, §22)
│   └── bar-daemon/    # the mandatory model-free process (spec §5.1)
├── migrations/        # root SQL migrations, embedded at compile time
├── fixtures/          # versioned adversarial and end-to-end test corpora
├── docs/              # normative specification and phase evidence
├── STATUS.md          # living project status
└── Cargo.toml         # workspace root
```

The full target layout (19 crates, UI, adapters, fixtures) is defined in
[`docs/spec.md`](docs/spec.md) §5. Crates land as their phase is implemented, so
the tree always builds clean.

## Build

### Quick start

BAR currently provides its model-free bootstrap daemon while the remaining
phases are under construction. From a checkout with a stable Rust toolchain
(1.85+):

```sh
cargo run -p bar-daemon
```

The command initializes structured logging, reports its model-free readiness,
and exits cleanly. It does not yet watch a target or expose the planned API;
those capabilities land in later phases. Set `BAR_LOG_FORMAT=json` for
machine-readable logs. The daemon uses built-in defaults when no configuration
file is present; set `BAR_CONFIG=/path/to/bar.toml` to load an explicit,
validated configuration. Its complete contract is in
[`docs/spec.md`](docs/spec.md#appendix-c-complete-configuration-contract).

### Verify a checkout

```sh
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI runs the same format, lint, and test gates on every pull request. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution expectations and
[`SECURITY.md`](SECURITY.md) to report a vulnerability privately.

## Documentation

- [`docs/spec.md`](docs/spec.md) — the complete, normative implementation
  specification and build manual (the contract this repo is built against).
- [`STATUS.md`](STATUS.md) — current phase, delivered evidence, and known debt.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development and review expectations.
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — community participation standards.
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting policy.

## License

Licensed under the [MIT License](LICENSE).
