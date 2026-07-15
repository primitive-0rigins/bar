# BAR — Behavioral Assurance Runtime

A lightweight, model-optional assurance daemon written in Rust. You point it at a
software runtime; it learns the runtime's *intended* behavior from the runtime
itself, compares that intent against implementation and live execution, prepares
repair-ready findings, waits for **human approval**, hands approved work to a
connected coding agent, and then independently verifies the result.

> **Status:** Phase 4 — contract scope, temporal resolution, and adjudication,
> in progress. The pure applicability resolver implements closed fail-safe
> states, inclusive validity windows, documented scope precedence, and mandatory
> adjudication for ties or unknown context. Scope, validity, and supersession
> inputs now persist transactionally and reload into that resolver; contextual
> applicability remains derived. Phase 3 extraction is implementation complete
> and pending human review. Build progresses through
> the phased manual in [`docs/spec.md`](docs/spec.md) §21. See [`STATUS.md`](STATUS.md)
> for the current state and remaining Phase 4 work.

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

```sh
cargo test          # build + run the test suite
cargo clippy        # lint (warnings are treated as defects here)
cargo fmt --check   # formatting
```

Requires a stable Rust toolchain (1.85+).

## Documentation

- [`docs/spec.md`](docs/spec.md) — the complete, normative implementation
  specification and build manual (the contract this repo is built against).

## License

Licensed under the [MIT License](LICENSE).
