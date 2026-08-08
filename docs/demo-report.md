# BAR scan: bar-demo

- Artifacts: 3
- Contracts: 4
- Finding classes: 7
- Evidence mode: deterministic static analysis

## Findings

- **missing_implementation** — required contract target `recover_journal` is absent.
- **contract_contradiction** — opposing requirements both govern whether the cache retains entries.
- **documentation_conflict** — `Dispatcher` has two incompatible definitions.
- **bypass_path** — `bypass` performs a filesystem effect without a same-symbol authority check.
- **dead_mechanism** — `bypass` and `reopen` have no certain in-scope callers.
- **state_machine_violation** — `reopen` assigns a new state after a terminal state.
- **architecture_erosion** — `callback.call` crosses an uncertain static call boundary.

All findings are provisional. Static evidence cannot establish runtime
reachability, deployment identity, or authority to repair the target.

Regenerate this report from the versioned fixture:

```sh
cargo run -p bar-cli -- scan fixtures/bar-demo
```
