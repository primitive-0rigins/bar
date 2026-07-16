# Contributing

BAR is built against the normative specification in [`docs/spec.md`](docs/spec.md).
That document is the contract; when code and spec disagree, the spec wins (or the
spec is changed deliberately, in its own commit).

## Ground rules

- **Read the relevant spec section before writing code.** Every change should
  trace to a requirement (MUST / MUST NOT / SHOULD / MAY carry their RFC 2119
  meanings).
- **The tree stays green.** `cargo test`, `cargo clippy`, and `cargo fmt --check`
  must all pass with no warnings before a commit.
- **Crates land when their phase does.** New crates are added as the phased build
  manual (§21) reaches them, so `cargo build` is always clean — no empty stubs.
- **No `unsafe`.** It is forbidden workspace-wide.

## Before you commit

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Update [`STATUS.md`](STATUS.md) when a phase item is completed.

## Pull requests

- Keep each pull request focused on one behavior or documentation change.
- Explain the spec requirement, user-visible effect, and verification in the
  pull request description.
- Include tests for changed behavior. Do not weaken verification gates to make
  a change pass.
- Do not report vulnerabilities in public issues or pull requests; follow
  [`SECURITY.md`](SECURITY.md) instead.
- Participate according to the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
