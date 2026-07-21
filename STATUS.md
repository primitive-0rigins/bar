# STATUS

Living status of the Behavioral Assurance Runtime build. Newest first.

## Current phase: 7 — Static finding engine (started)

Phase 6 implementation is complete (contracts map to code/tests/config, authority
and state traceability, immutable evidence-level-enforced proof obligations, and
`Pinned`/`ReferenceStable` freshness); its completion record is
[`docs/phase-evidence/phase-6.md`](docs/phase-evidence/phase-6.md), and human
review of it and Phase 5's
[`docs/phase-evidence/phase-5.md`](docs/phase-evidence/phase-5.md) is pending.

### Phase 7 started

- `bar-findings` promotes detector **candidates** into durable, aggregated
  **findings**. A candidate's fingerprint embeds the revision-scoped
  `contract_id`, so the same real defect at two revisions produces two distinct
  candidates; a `StaticFinding` instead has a stable, revision-independent
  identity (spec Appendix H.5) built from the finding class, the contract's
  revision-stable cited-text hash, and the sorted missing-reference set — never a
  revision-scoped id or byte offset. So the same symptom aggregates into one
  finding, while a changed statement or reference set is a new finding.
- `Store::promote_static_findings` reads one revision's persisted candidates and
  upserts findings by fingerprint (migration `0016`, keyed by target + stable
  fingerprint): a new symptom inserts as `detected`; a symptom already seen at
  another revision advances only its `last_seen_*` (aggregation) with status
  preserved; re-promoting the same revision is an idempotent no-op (replay). Each
  insert and aggregation is atomically audited, and a forged identity or unknown
  status token fails closed on reload. The `status` column uses the canonical
  finding lifecycle vocabulary so the next increment can add false-positive
  retention without a schema change.
- `Store::reject_static_finding` records an operator's false-positive correction:
  a `detected` finding transitions to `rejected` (Appendix G), audited as a
  lifecycle transition, and that correction is **retained across every later
  scan** — `promote_static_findings` leaves a non-`detected` finding untouched
  (neither advancing its occurrence window nor reopening it, spec Appendix H.5:
  only an active finding updates occurrence), surfaced as a `retained` count.
  Re-rejecting is idempotent; an empty reason, an unknown finding, or a forged
  status token all fail closed. Authorization of *who* may correct a finding
  (approver role, signed job) is Phase 14; this increment provides only the
  durable, replay-safe retention of the correction itself. No new migration: the
  correction lives in the existing `status` column.
- Three deliberate scoping notes. The stable identity uses the contract's
  `exact_text_sha256` rather than H.5's `normalized_active_contract_ids`, so two
  distinct contracts with byte-identical cited text and the same missing
  references collapse into one finding (same symptom); occurrence tracking is
  monotonic in promotion time, so out-of-order re-scanning of an older revision
  with a newer clock is not yet ordered by revision; and the false-positive
  correction is represented as `status = rejected` (spec `AssuranceDisposition::
  false_positive` is not yet a distinct persisted field — the disposition is
  carried in the audit trail), and the aggregate-vs-retain gate treats only
  `detected` as aggregating because it is the only status this layer reaches, not
  because H.5's "active" set is that narrow. All three are acceptable for the
  shadow layer and refined with the finding lifecycle.
- A second detector class, **contradiction**, promotes the persisted conflict
  candidates (two directly opposing claims — one `required`, one `prohibited` —
  over the same normalized subject) into aggregated findings.
  `Store::promote_contradiction_findings` mirrors the missing-implementation
  finding layer (migration `0017`, its own table): insert as `detected`,
  aggregate `last_seen_*`, replay no-op, and retain an operator-rejected finding
  untouched; `Store::reject_contradiction_finding` records the same false-positive
  correction. Its stable identity (Appendix H.5) is the `contradiction` class,
  the two claims' revision-stable cited-text hashes (sorted, so the pair order is
  irrelevant), and the shared subject — resolved at promotion time by joining each
  claim's fingerprint to its single source row. A contradiction is **provisional
  by construction**: the static layer cannot see contract scope, so an apparent
  contradiction may be a scoped exception (spec §"scoped exception, not
  contradiction") the operator corrects — `detected` is not a definitive
  contradiction label. It is a separate table, not a column-generalized reuse of
  `static_findings`, because the two classes' identities do not overlap; a shared
  abstraction is deferred until several classes prove a real commonality.
- A third detector class, **documentation conflict**, promotes one glossary term
  carrying two or more conflicting definitions into aggregated findings.
  `Store::promote_documentation_conflict_findings` (migration `0018`, its own
  table) reuses `bar_contract::glossary_ambiguities` as the authoritative decision
  of *which* terms conflict, then builds each finding's identity from the term and
  the sorted set of its distinct **lowercased-definition** hashes — the same
  equivalence the detector used, so a whitespace- or case-only edit does not
  fragment aggregation. Insert as `detected`, aggregate `last_seen_*`, replay
  no-op, retain an operator-rejected finding untouched;
  `Store::reject_documentation_conflict_finding` records the same false-positive
  correction. A documentation conflict is **provisional** (spec §"Operator can
  resolve a documentation conflict through a versioned ruling"), so `detected` is
  not a definitive label. Glossary ambiguities have no upstream ruling touchpoint
  (rulings are contract-claim scoped), so this finding is their first disposition
  path; wiring findings to versioned rulings is deferred with the waiver lifecycle.
- All three aggregated finding loaders revalidate that their first- and
  last-seen revisions belong to the finding's target. A valid revision from a
  different target is treated as corrupt provenance rather than crossing the
  target-isolation boundary.
- Full waiver lifecycle (approval, expiry → reopen, §12.6), the remaining detector
  classes (dead path, bypass, state, architecture erosion), and the finding
  dependency graph (§12.4) remain Phase 7 work.

### Current verification

Verified on 2026-07-21:

- `cargo test --workspace --all-targets` — 163 passed, 0 failed.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo fmt --all -- --check` — clean.
- `cargo audit` — no advisories reported.

### Phase 6 delivered

- `bar-coverage` maps only explicit closed Markdown code spans in a source-bound
  contract statement to one unique, validated static symbol, test, literal
  environment key, literal TOML key, or literal JSON object key. TOML and JSON
  keys are analyzed only after the complete document parses; literal TOML table
  headers retain their section even with a trailing comment, while quoted and
  escaped keys remain unmapped. The result retains target artifact/path/line
  provenance; plain-language matches are not considered evidence.
- Missing and duplicate references remain distinct `missing` or `ambiguous`
  unresolved results. A separate closed mapping status distinguishes unmapped,
  ambiguous, partially mapped, and mapped contracts; it is not the existing
  proof status, so mapped never implies proven.
- `Store::map_contract_traceability` joins persisted contracts with validated
  static facts for one exact target revision. It is a read-only shadow seam:
  cross-target/revision data is excluded before mapping, stored facts are
  revalidated on load, and traceability emits no audit mutation.
- `bar-coverage::ProofObligation` declares required evidence levels against an
  exact contract ID, source-contract fingerprint, and revision. Its evaluator
  returns only `mapped`, `test_supported`, `unproven`, or `stale` at this stage:
  every explicit reference must map before a partial trace can claim mapping or
  test support, and a symbol or config mapping never becomes static or runtime
  proof by implication. The `proof_assessment` example demonstrates that
  incomplete mapping stays unproven and reports its unresolved references.
- `bar-store` migration `0013` persists immutable proof-obligation declarations
  bound to one contract fingerprint, target, revision, and exact freshness
  revision. Insert and audit are atomic; exact replay revalidates, changed
  replay and cross-target binding fail, and unknown persisted evidence tokens
  fail closed on reload.
- `Store::assess_persisted_proof_obligation` reloads that declaration, rebuilds
  traceability from the stored source revision, and returns a fresh assessment
  with canonical unresolved-reference names without persisting or auditing a
  derived proof status. Its explicit
  revision-assessment variant accepts only another known revision of that target
  and returns `stale` when it differs from the declaration's freshness revision.
- `bar-findings` begins the next shadow-only layer with a deterministic
  missing-implementation candidate detector. It emits only when an explicit
  required source-bound contract reference is absent; prose-only, planned,
  prohibited, or expected contracts, any contract with an ambiguous reference,
  and merely unmapped contracts do not become findings. Detector input revalidates that
  each source-bound claim's deterministic identity, trace's declared mapping
  status, references from the contract's closed code spans, target names,
  distinct ambiguity candidates, and nonempty source-span provenance match its
  resolved and unresolved data before it can become a candidate. Migration `0014` persists each
  validated candidate only against a required contract, source, target, and
  revision; writes and their audit event are atomic, and only an exact,
  revalidated replay is accepted. A candidate batch validates its full input
  before it writes, so a bad member cannot leave a partial scan result.
  Revision-scoped retrieval revalidates every returned record before later
  review work can use it. Finding lifecycle and false-positive correction
  remain Phase 7 work.
- `bar-static` now extracts direct, literal INI-family (`.ini`, `.cfg`, `.conf`)
  configuration keys, so a source-bound contract can name an INI setting the same
  way it already names a TOML or JSON key. There is no strict INI grammar or
  validator dependency, so extraction stays conservative: only `key = value` and
  `key : value` entries whose key is a literal alphanumeric/`_`/`-`/`.` token
  become `configuration` reads, emitted in both their bare and section-qualified
  spellings; a `:` inside a value never splits the key. Quoted or spaced keys and
  malformed `[section]` headers record `unsupported_ini_key` uncertainty instead
  of an invented key, and non-INI `.conf` lines (which carry no delimiter) invent
  nothing. `bar-coverage` maps these keys through the existing traceability seam
  with no change; the addition persists no new state and needs no migration.
- `bar-static` also extracts direct, literal YAML (`.yaml`, `.yml`) mapping keys,
  so a contract can name a YAML setting the way it already names TOML, JSON, and
  INI keys. Parsing uses `yaml-rust2`'s marked event stream (the one added
  dependency: maintained, pure-Rust, no `unsafe`) so every key stays source-bound
  to its line. Extraction mirrors the JSON analyzer and stays conservative: nested
  keys keep both their bare and dotted spellings, sequence elements never receive
  invented indexes, and only literal scalar keys (the shared
  alphanumeric/`_`/`-`/`.` charset) become `configuration` reads. Quoted-with-
  special-characters, aliased, merge (`<<`), and complex (mapping or sequence)
  keys record `unsupported_yaml_key` uncertainty and are skipped, never guessed;
  CI-directory YAML stays classified as CI and is not analyzed as configuration.
  Like INI, this persists no new state and needs no migration.
- `bar-coverage` traceability now also resolves a contract's closed-code-span
  reference to two source-bound static facts it previously ignored: **authority
  checks** (guard-call vocabulary such as `require_permission`) and **state
  transitions** (qualified variants such as `JobState::Running`). Both carry
  path/line provenance and a `code` evidence origin, so a contract like "each
  write MUST pass `require_permission`" or "the job MUST reach
  `JobState::Completed`" now maps. Recurrence is handled by the existing model,
  not new logic: a guard or state set at multiple sites, or a name shared with a
  symbol, resolves `ambiguous` rather than a guessed unique match. State
  *definitions* are deliberately excluded — they are already traceable as
  symbols. No migration; the store's live traceability seam picks up the new
  targets from already-persisted static facts.
- Proof obligations now carry a **freshness policy** (`bar_core::FreshnessPolicy`)
  instead of a single implicit rule. `Pinned` (the default, and every existing
  row via migration `0015`) keeps the historical behavior: fresh only at the
  exact declared revision. `ReferenceStable` encodes the spec's own freshness
  rule (§92 "stale without contradicted", §400 "referenced symbols and
  mechanisms must still exist", §10.4): a proof stays fresh at a later revision
  as long as the contract's mapped references still resolve there, and goes
  `stale` only when one disappears. The store evaluates this by re-mapping the
  declared claim against the evaluated revision's persisted static facts — no
  live action, no new derived state persisted. Migration `0015` adds the
  immutable per-obligation policy column with a `pinned` default, so old rows and
  replays are unchanged; an unknown persisted policy token fails closed on
  reload.
- Broader configuration formats and cross-contract semantics remain later work;
  Phase 6's exit criteria (unmapped vs. unproven distinct, evidence levels
  enforced) and its proof-obligation, traceability, and freshness scope are
  implemented.

### Phase 5 delivered

- `bar-static` defines the Appendix I `StaticFacts` shape for artifacts,
  symbols, references, call edges, state definitions, effects, tests,
  configuration reads, and uncertainty.
- The adapter accepts Rust and Python source artifacts through their Tree-sitter
  grammars, rejects unsafe target-controlled paths, marks unsupported languages
  as explicit `unsupported_language` uncertainty, and records syntax errors,
  dynamic dispatch, macros, dynamic Python lookup, and unresolved dynamic calls
  instead of guessing.
- Syntax-node extraction covers modules, imports/uses, functions, classes,
  traits, impls, Rust state enums, Python state constants, tests, call edges,
  decorators, and the effect catalog entries visible in the fixture corpus.
  Comments and string literals no longer create false symbols, calls, or effects.
- `fixtures/phase-5-static` adds Rust and Python fixture sources plus a golden
  graph-shape fixture. The crate tests prove fixture extraction, fail-safe path
  handling, unsupported-language uncertainty, syntax uncertainty, and rejection
  of comment/string decoys.
- `bar-store` migration `0012` persists exactly one serialized `StaticFacts`
  result for an already-inventoried artifact. Insert and audit are atomic;
  exact replay is a revalidated no-op; altered replay, cross-target/revision
  binding, unknown JSON fields, and corrupted source paths fail closed on write
  or reload.
- `bar-static::analyze_inventory` is the scan-ready, shadow-only batch seam.
  It reopens each code/test artifact through discovery's containment, size, and
  digest checks before parsing, excludes non-code inventory, and returns source
  drift, unreadable files, and non-UTF-8 code as explicit per-artifact failures
  without aborting the remaining batch.
- `Store::persist_static_batch` connects successful batch members to the
  artifact-bound store, reports inserted versus replayed facts, and returns the
  unchanged per-artifact failures to the caller. Storage or provenance faults
  remain hard errors instead of being misrepresented as analysis failures.
- Direct effects now propagate through unique, certain intra-artifact calls to
  a fixed point. The adapter caps propagation at 64 iterations and records an
  explicit uncertainty if the cap is reached; dynamic, macro, and ambiguous
  calls never receive invented summaries.
- Configuration reads are source-bound for a closed set of environment access
  forms: Rust `std::env::{var,var_os,vars,vars_os}` and Python `os.getenv`,
  `os.environ.get`, and `os.environ[...]`. Direct unescaped quoted keys are
  retained for traceability; dynamic keys and unknown framework-specific access
  are deliberately left unmapped. Persisted configuration access tokens must
  match their analyzed Rust, Python, TOML, or JSON artifact language.
- Authority checks are typed, source-bound facts for an exact guard-call
  vocabulary: `authorize`, `check_permission`, `has_permission`,
  `require_permission`, `require_role`, `is_authorized`, and
  `user.has_permission`. The adapter does not infer authority from generic
  naming or framework conventions outside that set.
- State transitions are typed, source-bound facts when a `.state` or `.status`
  field receives a qualified variant of a declared Rust enum or Python
  `*State`/`*Status` enum class in the same artifact. Ordinary assignments and
  unrecognized lifecycle conventions remain unmapped.
- Data edges are typed, source-bound facts for simple Rust/Python bindings and
  direct-call results. The adapter records the enclosing function, source,
  destination, and line, but deliberately skips literals, destructuring,
  compound expressions, and dynamic values rather than inventing lineage.

Current limitation: the bootstrap daemon has no target-monitoring scheduler or
registered-target service yet. That orchestration requires a target lifecycle
and is deferred beyond this shadow-only adapter phase; the completed library
seam is exercised end-to-end by the Phase 5 fixture tests.

### Phase 4 delivered

- `bar-contract::scope` defines strict `ContractScope`, `ScopeContext`, and
  `TemporalWindow` inputs plus closed `applicable`, `not_applicable`, and
  `ambiguous` states. JSON rejects unknown fields/states; blank declared scope
  identifiers and inverted time ranges resolve as ambiguous instead of matching.
- Applicability uses inclusive millisecond validity bounds. Future, expired,
  historical, planned, example, and explicitly superseded contracts are not
  applicable in the evaluated context; missing required context is ambiguous,
  while an explicit mismatch is not applicable.
- The resolver encodes the §7.2 precedence tiers: exact deployment/config,
  exact environment+component, feature flag/mode, revision-bounded component,
  then product-wide. Partially specified combinations outside those tiers have
  no invented rank.
- Opposing applicable contracts produce only `scoped_override` when one tier
  clearly outranks the other. Equal, unranked, malformed, or context-unknown
  overlap returns `adjudication_required`; the resolver exposes no automatic
  definitive-defect state.
- `bar-store` migration `0007` adds immutable scope/validity declarations and
  directed same-target supersession edges. The first assignment and every new
  edge are audited atomically; exact replay revalidates the declaration and
  edge target ownership before becoming a no-op, changed declarations are
  rejected, and an invalid edge rolls back the complete transaction.
- Resolution inputs reload after database reopen into the pure resolver.
  Incoming supersession edges derive `TemporalWindow::superseded`; both edge
  endpoints must belong to the contract target. Scope JSON, inverted/negative
  timestamps, unknown scope state, and out-of-range external millisecond values
  fail closed. Applicability remains deliberately derived from durable
  declarations plus evidence-bound context instead of being stored as stale
  context-free state.
- `bar-store` migration `0008` adds immutable scope-context evidence bound to a
  target, revision, observed timestamp, and complete inventoried artifact. The
  whole-artifact digest remains independently verifiable until excerpt evidence
  storage lands. Persistence revalidates stored evidence before accepting a
  replay and is atomically audited; cross-target references, invalid
  spans/digests, blank values, malformed JSON, and negative stored observation
  times fail closed. A caller-supplied source revision cannot override stored
  revision identity, and snapshots reload after database reopen.
- `bar-contract::ruling` and `bar-store` migration `0009` add immutable,
  source-context-bound operator rulings. The store validates contract and
  evidence target ownership plus complete source-context integrity before create
  or reload, records an ordered contract-reference index, and audits creation
  and supersession atomically. An unchanged ambiguity reuses its active ruling;
  an edit creates a replacement record; expiry permits a new ruling; replay is
  idempotent only after revalidation; corrupt persisted links, target
  boundaries, timestamps, or serialized values fail closed on replay or reload.
- `bar-store` migration `0011` adds closed durable ruling dispositions:
  `chosen`, `deferred`, `rejected`, and `request_more_evidence`. Chosen
  rulings preserve an interpretation and rejected alternatives; non-final
  outcomes carry a clear reason without claiming a selected interpretation.
- `bar-store::resolve_contract_in_context` resolves scope only at the persisted
  scope-context observation time and requires the contract and context evidence
  to belong to the same target. Callers can no longer reuse one evidence record
  with a substituted earlier or later evaluation time.
- `bar-store` migration `0010` adds immutable operator attestations for
  source-bound scope context. Each attestation is first-class evidence tied to
  the exact target/revision/context, is actor-audited and replay-idempotent, and
  revalidates existing records before returning a replay. It rejects malformed
  source context before write and on reload. The explicit attested resolver
  consumes this human-trusted path without treating raw source text as semantic
  proof.
- `fixtures/phase-4-resolution/expected.json` is a checked-in adversarial
  resolver corpus. Its strict, table-driven test covers both precedence
  directions, scoped exceptions, repeated ambiguity, missing context,
  feature-flag scope, expired/future windows, malformed temporal declarations,
  and inactive historical text.
- Scope now supports validated `source_revision_range` and `deployment_range`
  fields using the strict §7.2.1 release-version comparator grammar. Exact
  identifiers retain exact matching; invalid ranges and unparseable observed
  versions resolve as ambiguous rather than selecting a contract.

All 113 repository tests pass; clippy `-D warnings` and fmt are clean.
Implementation revisions: `5a9b3ef`, `f9e71af`, `414be5c`, `15adcfd`, `ed0f016`, `2054c8d`, `a93a672`, `5483b93`, `3e63c89`, `ee9b01d`, `1862d2e`, `1c21194`, `d3d4c2a`, `3ec5aa9`, `37b3642`, `3696360`, `d0d8480`, `87adee3`.

### Phase 4 completion evidence

[`docs/phase-evidence/phase-4.md`](docs/phase-evidence/phase-4.md) records the
implemented requirements, fixtures, migrations, security checks, and remaining
cross-phase dependencies. Human review approved 2026-07-15. Automatic runtime
context adapters remain Phase 9 work; dashboard adjudication remains Phase 8
work.

### Roadmap addition — concurrent multi-runtime monitoring

- One BAR daemon will watch multiple registered runtimes concurrently. Each
  target keeps isolated revisions, evidence, contracts, policy, audit subjects,
  and per-target serialized scan/compaction work.
- Shared workers and ingestion queues will be globally bounded and target-fair,
  so a noisy runtime cannot starve another or violate BAR's resource contract.
- Baseline concurrent watchers land with Phase 9 runtime adapters. Phase 22 is
  reserved for fleet analytics and cross-target suggestions; it must not weaken
  per-target authority or permit evidence leakage.
- Acceptance requires simultaneous-change, noisy-neighbor, restart/replay, and
  cross-target contamination tests before the capability is called delivered.

### Repository hardening pass

- Target resolution now rejects noncanonical declared roots. Discovery
  canonicalizes its root, rechecks containment and the configured size limit on
  the opened file, uses descriptor metadata, and skips non-UTF-8 paths rather
  than creating lossy logical-path collisions.
- Logical artifact paths use one portable validator and reject absolute paths,
  dot segments, NULs, empty segments, and backslashes. Inventory persistence
  verifies target/revision ownership before auditing or writing and revalidates
  conflict-skipped artifact rows inside the transaction. Altered replay rows
  now fail without adding partial scan audit events; scan audit subjects identify
  the target instead of a generic event token.
- Store integer boundaries use checked conversions. Oversized timestamps,
  sizes, and offsets plus negative persisted values fail closed; a corrupt
  audit sequence blocks and rolls back later mutations instead of overflowing.
- Scope-context evidence is restricted to a complete inventoried artifact and
  revalidates its digest during reload. An arbitrary but well-formed SHA-256 can
  no longer masquerade as source provenance.
- An explicitly configured missing `BAR_CONFIG` path now fails startup. Built-in
  defaults remain available only when no explicit path is supplied and the
  standard default file is absent.

### Known repository debt

- Canonicalization and open-time rechecks block stable traversal, symlink, and
  size-limit escapes, but a concurrently hostile writable target can still race
  directory entries between resolution and open. Descriptor-relative
  `openat`/no-follow traversal is required before BAR claims race-resistant
  monitoring of untrusted writable trees.
- `crates/bar-store/src/lib.rs` remains the primary god-file hotspot: about
  1,700 production lines plus its in-file test module. Ruling, attestation,
  and scope-context persistence are isolated in dedicated modules; split audit,
  target/inventory, and contract persistence in a later behavior-preserving
  refactor.
- Resolved 2026-07-15: the SQLx 0.9 upgrade dropped the optional-MySQL `rsa`
  lock entry (`RUSTSEC-2023-0071`). An unqualified `cargo audit` now reports no
  advisories.

## Phase 3 — Contract extraction shadow (implementation complete)

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
- `bar-daemon` exposes a closed optional-model readiness state. Default policy
  reports `disabled`; enabling models in this adapter-free build reports
  `unavailable`, emits a warning without provider/endpoint details, and still
  completes deterministic startup. It never reports configured intent as an
  available capability.
- `bar-store`: migration `0005` adds revision-scoped `contracts` and mandatory
  `contract_sources`. Persistence is fingerprint-idempotent and records
  each newly extracted contract as an audited evidence mutation in the same
  transaction. Every input, replay, and reload recomputes the normalized
  statement/source-span fingerprint before exposing a source-bound claim; a
  missing source rolls back the full contract batch; unknown persisted
  vocabulary/state is rejected during reload.
- `bar-store`: migration `0006` adds durable structural hierarchy, glossary,
  and provisional conflict candidates. Candidate persistence validates all
  contract and artifact references before writing, revalidates the full
  candidate set on every replay, and audits newly detected conflicts
  atomically. Reload rejects corrupt aliases, spans, hashes, heading levels,
  and unknown conflict states; glossary ambiguities are reconstructed from the
  preserved definitions.
- The versioned `fixtures/phase-3-contract-corpus` golden corpus drives real
  discovery, deterministic analysis, contract/candidate persistence, and
  reload against hand-authored expected output. It covers fenced examples,
  cross-sentence prompt injection, multiline blockquotes, glossary ambiguity,
  and cross-document conflict; conflict pairs are fingerprint-canonical across
  persistence round trips.

The implementation passes the two Phase 3 safety invariants: every emitted
claim cites verified source bytes, and malformed or source-inconsistent model
output is rejected. All 95 repository tests pass; clippy `-D warnings` and fmt
are clean. Implementation revisions:
`3fb0fc6`, `74e1408`, `85fff4d`, `b483f02`, `3ca47dc`, `c5959d1`,
`3238221`, and `502037f`.

Completion evidence per spec Appendix AP:
[`docs/phase-evidence/phase-3.md`](docs/phase-evidence/phase-3.md) — reviewed
and approved 2026-07-15.

### Known limitations and next-phase work

- Explicit-reference hierarchy has no defined syntax in the spec; current
  attachment is structural Markdown containment only. Semantic corroboration
  follows the static-adapter phases.
- Glossary/alias graph corroboration and operator correction inputs;
  cross-artifact ambiguity is durable, but aliases still come only from
  explicit definitions and no terms are merged automatically.
- Scope- and temporal-aware conflict resolution, validity, supersession, and
  operator rulings are Phase 4; direct cross-artifact required/prohibited
  opposites remain durable provisional candidates.
- Optional worker adapter invocation, isolation, and resource-pressure
  suspension; current code validates bounded output and reports unavailable
  honestly but invokes no model.
- Human review of the Phase 3 completion evidence was approved 2026-07-15.

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
[`docs/phase-evidence/phase-2.md`](docs/phase-evidence/phase-2.md) — reviewed
and approved 2026-07-15.

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
[`docs/phase-evidence/phase-1.md`](docs/phase-evidence/phase-1.md) — reviewed
and approved 2026-07-15.

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
[`docs/phase-evidence/phase-0.md`](docs/phase-evidence/phase-0.md) — reviewed
and approved 2026-07-15.

Idle CPU/RAM, incremental-scan RAM, high-volume ingestion, and target-pressure
suspension (spec §23 performance rows) join the harness with the service loop.

The revision-identity *bundle* (spec §6.2 — commit/dirty hash, build manifest,
toolchain, deployment id, topology) is deferred to **Phase 1**, where the target
connector supplies its inputs (§21 Phase 1). `RevisionId` itself already exists.

**Exit criteria:** daemon starts model-free; old migrations replay; audit tamper
test passes.
