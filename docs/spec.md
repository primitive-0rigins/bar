**Behavioral Assurance Runtime**

Complete Rust Implementation Specification and Build Manual

Version 2.0 • July 2026 • Coding-agent execution contract

> **Mission**
>
> Build a lightweight, self-discovering assurance daemon that points at one or more software runtimes, learns intended behavior from each target itself, compares that intent with implementation and execution, prepares repair-ready findings, waits for human approval, hands approved work to a connected coding agent, and independently verifies the result.

> **Non-negotiable resource rule**
>
> The monitored workload owns the machine. BAR must function without a GPU, keep no model resident by default, remain near-idle when nothing changes, and suspend optional semantic work under target resource pressure.

# 1. Normative Status and Instructions to the Implementing Agent

This document is the normative build contract. Requirements marked MUST, MUST NOT, SHOULD, and MAY use their RFC meanings.

1\. Read the complete document before editing code.

2\. Implement phases in order. Do not pull later authority, active probing, autonomous remediation, fleet, or deployment features into earlier phases.

3\. Preserve the central product boundary: BAR diagnoses and verifies; the human authorizes; the coding agent implements; CI/CD deploys.

4\. Use Rust for every mandatory always-on component. Optional semantic inference must be replaceable and isolated behind process or HTTP boundaries.

5\. Every persisted enum and workflow state is append-only after release. Add values; do not repurpose existing values.

6\. Every generated conclusion must retain source references, target revision, tool/model version, and uncertainty.

7\. Passing mocks is not live proof. Green tests do not automatically resolve a live-path finding.

8\. Unknown states, malformed model output, missing approval, and scope mismatch fail closed.

9\. Update STATUS.md after every phase with built, tested, shadow, active, deferred, and known-gap distinctions.

10\. Run the complete test suite and resource benchmarks after every phase.

> **Honesty requirement**
>
> No implementation can guarantee flawless behavior. The required standard is deterministic contracts, explicit uncertainty, replayable evidence, exhaustive tests for specified paths, and safe failure when assumptions are unmet.

# 2. Product Definition and Boundary

BAR is a continuously maintained assurance model of what a runtime claims, permits, executes, and can prove.

target pointer  
→ artifact discovery  
→ contract extraction  
→ contract hierarchy and adjudication  
→ static architecture/path model  
→ source-build-deployment identity  
→ runtime evidence ingestion  
→ proof-obligation and coverage evaluation  
→ finding and causal investigation  
→ repair-ready contract  
→ human approval  
→ coding-agent implementation  
→ pre-merge semantic impact analysis  
→ post-change verification  
→ assurance history update

| **BAR owns**                                                               | **Human owns**                                            | **Coding agent owns**                                            | **External systems own**                                               |
|----------------------------------------------------------------------------|-----------------------------------------------------------|------------------------------------------------------------------|------------------------------------------------------------------------|
| Discovery, evidence, contracts, findings, repair constraints, verification | Interpretation rulings, approvals, waivers, accepted risk | Repository inspection, plan, edits, tests, implementation report | Source control, CI, artifact build, deployment, production credentials |

## 2.1 Explicit non-goals

- Personal companion, cognitive identity system, research hypothesis engine, mathematical reference, general coding tutor.

- Multi-agent orchestration, worker assignment, scheduling, autonomous project management.

- Silent code modification, self-approval, autonomous production deployment, or unrestricted shell execution.

- Replacement for observability, CI/CD, issue trackers, source control, security scanners, or incident-management systems.

- A single correctness, safety, maturity, or confidence score.

# 3. Product Principles and Hard Invariants

| **Principle**             | **Operational requirement**                                                                                        |
|---------------------------|--------------------------------------------------------------------------------------------------------------------|
| Target-derived intent     | Initial expected behavior is discovered from repository/runtime artifacts rather than manually entered rule files. |
| Documentation is evidence | Documentation seeds intent but may be stale, contradictory, aspirational, or wrong.                                |
| Hierarchical contracts    | Separate goal, property, architecture constraint, current mechanism, implementation, and proof.                    |
| Typed evidence            | Documentation, code, tests, simulation, telemetry, operator reports, and BAR inference never collapse.             |
| Human-directed repair     | A coding task cannot start until exact job hash and base revision are approved.                                    |
| Incremental operation     | Only changed artifacts and dependent conclusions are recomputed.                                                   |
| Multi-runtime isolation   | One daemon may monitor multiple targets concurrently; state, evidence, policy, and jobs remain target-bound.       |
| Resource subordination    | Target workload always outranks BAR semantic work.                                                                 |
| Replayability             | Findings and decisions reconstruct from retained evidence and versioned analysis.                                  |
| Evidence freshness        | Proof can become stale without becoming contradicted.                                                              |
| Do-nothing allowed        | Monitor, waive, correct documentation, or accept risk may be valid outcomes.                                       |

## 3.1 Hard invariants

1\. No generated inference is recorded as observation.

2\. No claim becomes verified solely because documentation says it is true.

3\. No repair job is visible to the coding agent before approval.

4\. Approval binds to exact job content, target, repository scope, base revision, and expiry.

5\. Material scope, contract, or base-revision changes invalidate approval.

6\. BAR never grants production deployment authority.

7\. Every finding cites exact evidence and explains limitations.

8\. Every resolution evaluates the original proof obligation.

9\. Resolved findings reopen when invalidating or contradictory evidence arrives.

10\. BAR remains useful with all models disabled.

11\. BAR model work may not consume reserved target GPU or memory.

12\. Model, parser, prompt, policy, and schema versions are retained for reproducibility.

13\. Unknown contract scope or temporal applicability blocks definitive contradiction labels.

14\. Operator corrections and rulings are versioned, reversible, and never erase history.

15\. Concurrent target monitoring uses bounded target-fair workers; work is serialized where required per target, and evidence or authority never crosses target boundaries.

# 4. Resource and Performance Contract

| **Resource**         | **Default target**                               | **Hard behavior**                                 |
|----------------------|--------------------------------------------------|---------------------------------------------------|
| Idle CPU             | Approximately 0%; event-driven wakeups           | No polling loops faster than configured minimum.  |
| Idle RAM             | 100–300 MB single target                         | No mandatory model residency.                     |
| Incremental scan RAM | \<1 GB normal repository                         | Bounded queues; streaming parsers.                |
| GPU                  | 0 MB reserved by default                         | Optional worker only; unload/suspend on pressure. |
| Threads              | 1 async runtime + bounded workers                | No unbounded spawn.                               |
| Disk                 | Content-addressed metadata and selected evidence | Retention, compaction, deduplication.             |
| Telemetry overhead   | Configurable and sampled                         | Backpressure; never block target execution.       |
| Network              | Local/on-prem default                            | No external model call unless configured.         |

## 4.1 Resource governor

if target_latency_breached:  
suspend_semantic_jobs()  
reduce_ingest_concurrency()  
  
if gpu_use_not_explicitly_enabled:  
prohibit_gpu_worker()  
  
if target_gpu_utilization \>= configured_limit:  
unload_or_pause_bar_gpu_model()  
  
if free_vram \< target_reserved_vram:  
prohibit_new_gpu_job()  
  
if memory_pressure_high or io_pressure_high:  
pause_repository_deep_scan()  
keep critical evidence ingestion alive()  
  
priority:  
1 target workload  
2 evidence integrity and critical event ingestion  
3 deterministic verification  
4 user-opened analysis  
5 background semantic enrichment

## 4.2 Model ladder

| **Tier** | **Implementation**                         | **Use**                                                                     |
|----------|--------------------------------------------|-----------------------------------------------------------------------------|
| 0        | Rust rules, parsers, Tree-sitter, FTS/BM25 | Always preferred; monitoring, extraction candidates, mapping, verification. |
| 1        | Optional 0.5B–1.5B quantized CPU model     | Closed-schema claim extraction, classification, concise evidence summaries. |
| 2        | Optional 3B–7B local/remote burst model    | Difficult cross-document mapping, causal alternatives, repair drafting.     |
| 3        | Explicit external specialized service      | Only when operator policy allows and smaller tiers are insufficient.        |

Model outputs are proposals. Rust validates schema, references, permissions, lifecycle, and proof status.

# 5. Recommended Repository and Process Layout

bar/  
├── Cargo.toml  
├── crates/  
│ ├── bar-core/ \# IDs, enums, schemas, errors, clocks  
│ ├── bar-audit/ \# append-only audit chain  
│ ├── bar-store/ \# SQLite/PostgreSQL repository  
│ ├── bar-target/ \# connectors and target identity  
│ ├── bar-discovery/ \# artifact inventory  
│ ├── bar-contracts/ \# claims, hierarchy, scope, rulings  
│ ├── bar-static/ \# language adapters and path model  
│ ├── bar-evidence/ \# evidence normalization/invalidation  
│ ├── bar-runtime/ \# logs, traces, journals, topology  
│ ├── bar-coverage/ \# proof obligations and coverage matrix  
│ ├── bar-findings/ \# lifecycle, dependencies, assurance debt  
│ ├── bar-investigate/ \# causal hypotheses and experiments  
│ ├── bar-repair/ \# repair specs and impact analysis  
│ ├── bar-agent-bridge/ \# human-gated coding-agent protocol  
│ ├── bar-verify/ \# pre/post change verification  
│ ├── bar-resource/ \# target-first resource governor  
│ ├── bar-model-adapter/ \# optional isolated semantic adapters  
│ ├── bar-api/ \# local HTTP API  
│ └── bar-cli/  
├── ui/ \# static TypeScript/React dashboard  
├── adapters/ \# target, telemetry, model, CI plugins  
├── fixtures/ \# intentionally flawed runtimes  
├── migrations/  
├── docs/  
└── STATUS.md

## 5.1 Process isolation

bar-daemon (mandatory Rust)  
├── watchers, ingestion, graph, workflow, API, deterministic verification  
├── no GPU  
└── survives model-worker failure  
  
bar-model-worker (optional separate process/service)  
├── strict request schema  
├── CPU by default  
├── optional GPU with resource lease  
└── killable without monitoring interruption  
  
bar-ui  
└── static assets served by daemon or separate web server

# 6. Data and Identity Model

## 6.1 Stable identifiers

target/\<uuid\>  
revision/\<sha256\>  
artifact/\<sha256\>  
component/\<uuid\>  
contract/\<uuid\>  
ruling/\<uuid\>  
evidence/\<uuid\>  
path/\<uuid\>  
proof/\<uuid\>  
finding/\<uuid\>  
waiver/\<uuid\>  
repair/\<uuid\>  
approval/\<uuid\>  
verification/\<uuid\>  
incident/\<uuid\>  
decision/\<uuid\>

## 6.2 Revision identity

- Source commit plus dirty-tree hash.

- Build manifest and artifact/container digest.

- Dependency lock hash and toolchain version.

- Configuration hash, schema version, feature-flag snapshot, model identity.

- Deployment ID, environment, topology snapshot, start time.

- BAR must label runtime evidence unbound when deployment identity cannot be proven.

## 6.3 Core persisted enums

NormativeKind = required \| prohibited \| expected \| descriptive \| planned \| historical \| example  
ContractLevel = product_goal \| behavioral_property \| architecture_constraint \| mechanism \| implementation  
EvidenceKind = documentation \| code \| configuration \| unit_test \| integration_test \|  
live_trace \| journal_event \| log \| metric \| operator_observation \|  
synthetic_probe \| replay \| bar_inference  
ProofStatus = discovered \| mapped \| statically_supported \| test_supported \|  
live_observed \| failure_observed \| contradicted \| unproven \|  
stale \| superseded \| invalid  
FindingStatus = detected \| triaged \| investigating \| evidence_sufficient \|  
repair_ready \| awaiting_approval \| approved \| implementing \|  
submitted \| verifying \| resolved \| partially_resolved \|  
failed \| rolled_back \| reopened \| rejected \| deferred \| waived  
RepairKind = code \| test \| documentation \| configuration \| instrumentation \|  
migration \| policy \| contract_ruling \| no_change  
AssuranceDisposition = repair \| monitor \| request_evidence \| adjudicate \|  
waive \| accept_risk \| external_dependency \| false_positive

# 7. Contract System

## 7.1 Contract schema

Contract {  
contract_id  
target_id  
parent_contract_id?  
level  
normative_kind  
statement  
subject_refs\[\]  
conditions\[\]  
required_behavior?  
prohibited_behavior\[\]  
scope {  
components\[\]  
environments\[\]  
modes\[\]  
feature_flags\[\]  
tenant_scope?  
source_revision_range?  
deployment_range?  
}  
valid_from?  
valid_until?  
source_refs\[\]  
supersedes\[\]  
proof_obligation_id?  
confidence  
freshness  
conflict_refs\[\]  
created_by  
analysis_versions  
}

## 7.2 Scope precedence

1\. Exact deployment and configuration scope.

2\. Exact environment and component scope.

3\. Feature-flag or operating-mode scope.

4\. Version-bounded component contract.

5\. Product-wide contract.

6\. Historical, planned, example, and superseded text never override active normative contracts.

## 7.3 Contract hierarchy rules

- Changing a mechanism is not a violation when parent properties and constraints remain satisfied.

- A lower-level contract cannot weaken a higher-level required property without explicit ruling.

- A scoped exception must name parent contract, scope, reason, and expiry.

- Ambiguous overlap becomes an adjudication item rather than an automatic defect.

## 7.4 Contract adjudication

ContractRuling {  
ruling_id  
contract_refs\[\]  
chosen_interpretation  
rejected_interpretations\[\]  
rationale  
scope  
effective_from  
expires_at?  
operator_id  
created_at  
superseded_by?  
}

- Dashboard presents competing interpretations and evidence.

- Operator may choose, edit, reject, defer, or request more evidence.

- Rulings become first-class evidence but do not rewrite source documents.

- Repeated ambiguity must reuse the ruling until scope or evidence materially changes.

# 8. Discovery and Artifact Authority

1\. Capture target and revision identity.

2\. Discover README, STATUS, architecture docs, ADRs, design specifications, runbooks, incident reports, diagrams, comments, TODO/FIXME, manifests, schemas, tests, generated artifacts, configuration, CI, deployment descriptors, telemetry definitions, and linked repositories.

3\. Classify source-of-truth versus generated artifacts.

4\. Extract metadata, symbols, references, normative strength, scope, freshness, and conflicts.

5\. Store content hashes and parse outputs incrementally.

| **Authority dimension** | **Required treatment**                                                           |
|-------------------------|----------------------------------------------------------------------------------|
| Normative strength      | must/shall/invariant \> should \> descriptive \> planned/example.                |
| Freshness               | Referenced symbols and mechanisms must still exist.                              |
| Specificity             | Exact scoped rule may override broad default.                                    |
| Corroboration           | Independent code, test, runtime, or operator evidence.                           |
| Source type             | ADR and active spec differ from comment, TODO, incident note, or generated file. |
| Conflict                | Preserve all sides; never silently choose.                                       |

## 8.1 Diagram and vocabulary support

- Parse Mermaid, PlantUML, Graphviz, machine-readable state and sequence diagrams.

- Build target glossary and alias graph from definitions, code symbols, schemas, and operator corrections.

- Do not merge similarly named entities without structural corroboration.

# 9. Static Architecture and Behavioral Modeling

| **Model**            | **Required contents**                                                                 |
|----------------------|---------------------------------------------------------------------------------------|
| Component graph      | Responsibilities, allowed/forbidden dependencies, ownership, effects, data ownership. |
| Call/data-flow graph | Entrypoints, validators, dispatchers, stores, queues, external dependencies.          |
| State machines       | States, triggers, guards, effects, terminal states, illegal transitions.              |
| Authority graph      | Principal, delegate, scope, freshness, approval, effect path.                         |
| Side-effect ledger   | Intent record, authorization, idempotency, execution, settlement, compensation.       |
| Persistence graph    | Authoritative, immutable, append-only, recoverable, cached, ephemeral stores.         |
| Runtime mode graph   | Normal, degraded, read-only, maintenance, recovery, emergency modes.                  |
| Dependency contracts | Timeout, retry, rate limit, schema, idempotency, fallback assumptions.                |

## 9.1 Required static detectors

- Missing implementation, undocumented behavior, dead mechanisms, bypass paths, state-transition defects.

- Architecture erosion, cross-layer access, duplicated controls, direct store access, circular dependency growth.

- Transaction boundaries, partial-success windows, compensation gaps, retry/idempotency defects.

- Schema compatibility, generated-artifact staleness, parser differentials, unit and normalization mismatches.

- Feature-flag lifecycle, configuration behavior matrix, stale migration paths.

- Security trust-boundary, delegation, sandbox, policy-shadowing, supply-chain and build traceability.

# 10. Evidence, Proof Obligations, Coverage, and Freshness

## 10.1 Evidence schema

Evidence {  
evidence_id  
target_id  
target_revision  
deployment_identity?  
kind  
source_ref  
source_span?  
environment  
observed_at?  
ingested_at  
conditions\[\]  
integrity  
synthetic  
completeness  
supports_contracts\[\]  
contradicts_contracts\[\]  
analysis_versions  
retention_class  
}

## 10.2 Proof obligation schema

ProofObligation {  
proof_id  
contract_id  
required_evidence_levels\[\]  
required_conditions\[\]  
failure_conditions\[\]  
freshness_policy  
independence_requirement  
minimum_sample?  
statistical_protocol?  
resolution_rule  
}

## 10.3 Coverage dimensions

- Entrypoint, component, state, transition, authority level, actor, environment, mode.

- Configuration, feature flags, dependency state, data shape, traffic shape, concurrency.

- Success, failure, recovery, cancellation, timeout, retry, overload, rollback.

- Model version, prompt, decoding, evaluation dataset where probabilistic behavior exists.

## 10.4 Evidence invalidation

changed artifact/config/dependency/model/topology  
→ locate dependent mappings and proofs  
→ mark evidence stale or invalid  
→ recompute affected contracts  
→ reopen findings only when required proof is lost or contradicted  
→ retain prior evidence and reason for invalidation

# 11. Runtime Evidence and Operational Semantics

- OpenTelemetry traces, logs, metrics, journals, event buses, queue metadata, test reports, topology APIs.

- Runtime topology discovery and comparison with intended architecture.

- Source-build-release-deployment chain verification.

- User journey and business-process reconstruction across services.

- Accepted-work settlement and orphan detection.

- Queue, lease, lock, leader, clock, timeout, retry, cancellation, backpressure, and overload semantics.

- Replay classification: deterministic, captured-input deterministic, semantically equivalent, partial, non-replayable.

- Data lineage, cache invalidation, backup/restore, retention, deletion, privacy, tenant isolation.

- Runbook and operator-action validation.

## 11.1 Telemetry backpressure

- BAR ingestion may drop or sample noncritical high-volume data only under explicit policy.

- Integrity, approval, finding lifecycle, and critical contract evidence are never silently dropped.

- Every gap records time range, source, reason, and affected proof obligations.

- Telemetry failure creates BAR health and target observability findings separately.

# 12. Finding, Causality, and Assurance Debt

## 12.1 Finding classes

FindingClass = contract_contradiction \| missing_implementation \| undocumented_behavior \| bypass_path \| unproven_claim \| dead_mechanism \| state_machine_violation \| runtime_drift \| telemetry_blind_spot \| recovery_gap \| documentation_conflict \| verification_regression \| deployment_identity_gap \| schema_compatibility \| side_effect_settlement_gap \| architecture_erosion \| resilience_gap \| performance_contract \| privacy_flow \| operational_drift \| assurance_debt

## 12.2 Finding schema

Finding {  
finding_id  
class  
title  
summary  
severity  
confidence  
assurance_domain  
affected_contracts\[\]  
affected_components\[\]  
affected_paths\[\]  
evidence_refs\[\]  
uncertainty\[\]  
causal_hypotheses\[\]  
dependencies\[\]  
blocked_by\[\]  
risk_if_unresolved  
repair_readiness  
dispositions\[\]  
status  
revision_history\[\]  
}

## 12.3 Causal evidence levels

| **Level**               | **Meaning**                                                              |
|-------------------------|--------------------------------------------------------------------------|
| association             | Events co-occurred or followed each other.                               |
| structural              | Architecture permits the proposed causal path.                           |
| reproducible_trigger    | Controlled repetition produces the outcome.                              |
| alternative_elimination | Competing causes were tested and weakened.                               |
| counterfactual          | Removing/changing the cause changes outcome under controlled conditions. |
| direct                  | Instrumentation observes the mechanism.                                  |

## 12.4 Finding dependency graph

Relation = blocks \| caused_by \| duplicates \| subsumes \| shares_root_cause \| regresses \| requires_resolution_of

## 12.5 Assurance domains

- Authority integrity, state consistency, side-effect governance, durability, recovery readiness.

- Observability, deployment identity, configuration integrity, dependency resilience.

- Schema/data integrity, privacy/isolation, performance/capacity, operational readiness.

- Each view reports verified, contradicted, unproven, stale, waived, and blocked contracts—never one score.

## 12.6 Waivers

Waiver {  
waiver_id  
finding_id  
approved_by  
reason  
scope  
mitigation\[\]  
created_at  
review_at  
expires_at  
}  
expiry → reopen finding

# 13. Investigation and Diagnostic Experiment Design

1\. Generate multiple causal hypotheses with explicit supporting and contradicting evidence.

2\. Identify the smallest observation or experiment that separates leading hypotheses.

3\. Estimate target overhead, risk, compute, storage, and expected information qualitatively.

4\. Prefer passive evidence, then approved instrumentation, then nonproduction probes.

5\. Stop when evidence is sufficient, risk is disproportionate, or remaining uncertainty is irreducible.

InvestigationDisposition =  
continue_passive_observation \|  
request_operator_interpretation \|  
propose_instrumentation \|  
propose_test \|  
mark_unresolvable \|  
defer \|  
repair_ready

## 13.1 Active verification safety

- Disabled by default and never production by default.

- Allowlisted operation, environment identity, side-effect bound, stop condition, cleanup, and rollback required.

- Failure injection must record seed/input, target revision, expected observation, actual result, and collateral effects.

# 14. Repair Specification and Human Approval

## 14.1 Repair kinds

- Code correction, test addition, documentation correction, configuration correction.

- Instrumentation addition, schema/data migration, runtime policy change.

- Operator contract ruling, external dependency action, no-change/monitor decision.

## 14.2 Repair job

RepairJob {  
job_id  
finding_ids\[\]  
target_id  
base_revision  
approved_repository_scope\[\]  
behavioral_contract  
evidence_refs\[\]  
causal_basis  
required_invariants\[\]  
neighboring_contracts\[\]  
impact_graph\[\]  
acceptance_conditions\[\]  
prohibited_changes\[\]  
sequencing_constraints\[\]  
rollback_requirements  
allowed_tools\[\]  
expiry  
job_hash  
}

## 14.3 Approval and negotiation

- Approve, reject, defer, request evidence, accept risk, waive, or correct interpretation.

- Coding agent may accept, challenge assumption, propose alternative, request evidence, request scope expansion, declare blocked, or recommend no-code resolution.

- Any material contract, scope, sequencing, risk, or base-revision change returns to human approval.

- Use isolated branch/worktree; never edit the operator’s active branch directly.

# 15. Coding-Agent Bridge

The bridge is a job protocol, not an orchestrator.

GET /v1/agent/jobs/next  
GET /v1/agent/jobs/{id}  
GET /v1/agent/jobs/{id}/evidence/{ref}  
POST /v1/agent/jobs/{id}/plan  
POST /v1/agent/jobs/{id}/challenge  
POST /v1/agent/jobs/{id}/question  
POST /v1/agent/jobs/{id}/request-scope  
POST /v1/agent/jobs/{id}/start  
POST /v1/agent/jobs/{id}/progress  
POST /v1/agent/jobs/{id}/submit  
POST /v1/agent/jobs/{id}/fail  
POST /v1/agent/jobs/{id}/cancel-ack

- HTTP+JSON is normative. MCP adapter may mirror it.

- One job token is scoped to target, job, revision, paths, methods, and expiry.

- No endpoint for deployment, agent assignment, multi-worker sequencing, or self-approval.

- Submission includes commit/patch hash, changed files, tests, unresolved concerns, and rollback notes.

# 16. Semantic Diff, Pre-Merge, and Post-Repair Verification

## 16.1 Semantic behavior diff

- Contract added, removed, weakened, strengthened, moved, or scoped differently.

- Authority, state, side-effect, schema, recovery, fallback, mode, dependency, and topology changes.

- Changed proof obligations, invalidated evidence, new unproven assumptions, documentation/test obligations.

- Distinguish text/code change from actual behavioral change.

## 16.2 Verification pipeline

1\. Confirm patch ancestry and approved scope.

2\. Reconstruct static model for changed and dependent paths.

3\. Compare pre/post contract graph.

4\. Run required tests and property/metamorphic checks.

5\. Exercise live or failure path when proof obligation requires it and environment allows.

6\. Check neighboring invariants, rollback compatibility, and mixed-version behavior.

7\. Produce resolved, partially resolved, failed, regressed, unverifiable, or rolled-back outcome.

8\. Update evidence freshness and reopen dependent findings where appropriate.

## 16.3 Independent verification

- High-risk work must include at least one verifier independent of the generating model.

- Possible verifiers: deterministic rule, compiler/static analyzer, test runner, alternate model, security tool, operator.

- Verification strength records independence and evidence level.

# 17. Dashboard and Operator Interaction

| **View**        | **Required contents**                                                                     |
|-----------------|-------------------------------------------------------------------------------------------|
| Target overview | Revision identity, discovery state, BAR health, assurance domains, active/stale evidence. |
| Behavioral map  | Contract hierarchy, components, states, authority, effects, dependencies.                 |
| Findings inbox  | Severity, confidence, age, dependencies, repair readiness, disposition.                   |
| Finding detail  | Expected vs actual, source spans, evidence, uncertainty, causes, risk, repair.            |
| Adjudication    | Competing interpretations, evidence, ruling controls.                                     |
| Coverage matrix | Conditions proven, unproven, stale, contradicted.                                         |
| Assurance debt  | Critical unproven claims, waivers, blind spots, stale proof.                              |
| Repair review   | Scope, impact graph, acceptance, sequencing, rollback, approval.                          |
| Agent activity  | Plan, challenges, progress, changed files, tests, blockers.                               |
| Semantic diff   | Before/after contracts and affected proof.                                                |
| Verification    | Original obligation, pre/post evidence, disposition.                                      |
| Release report  | Changed contracts, unresolved critical items, rollback readiness.                         |
| BAR health      | Dropped telemetry, stale scans, model failures, queue/resource pressure.                  |
| Audit           | Approvals, waivers, rulings, access, lifecycle transitions.                               |

## 17.1 Explanation quality gate

- One-sentence impact, expected/observed distinction, direct evidence links.

- Facts separated from inference; alternative causes and limitations visible.

- Actionable scope without duplicated symptom findings.

- Final report must not assert more than cited evidence entails.

# 18. Security and Threat Model

| **Threat**                    | **Required mitigation**                                                 |
|-------------------------------|-------------------------------------------------------------------------|
| Prompt injection in docs/logs | All target content untrusted; fixed schemas; never authorizes tools.    |
| Agent scope expansion         | Signed job hash, path allowlist, approval invalidation.                 |
| Secret leakage                | Connector-side filtering, redaction, scanners, retention policy.        |
| Evidence tampering            | Hashing, source identity, append-only audit, optional signatures.       |
| Stale documentation           | Corroboration, freshness, adjudication.                                 |
| Malicious telemetry           | Typed parsing, size limits, escaping, no instruction following.         |
| Model hallucination           | Reference validation, schema enforcement, unsupported-claim rejection.  |
| BAR compromise                | Least privilege, separate credentials, local bind default, audit chain. |
| Unsafe probing                | Disabled default, allowlist, environment proof, stop/rollback.          |
| Supply chain                  | Pinned dependencies, SBOM, signed release, reproducible-build target.   |

## 18.1 BAR self-assurance

- Monitor connector failures, dropped telemetry, stale scans, audit integrity, evidence corruption.

- Monitor parser/model regression, queue backlog, resource governor, verification runner.

- BAR health failures never masquerade as target failures.

- Deterministic degraded mode continues critical ingestion and workflow without models.

# 19. Storage, Retention, and Compaction

| **Store**       | **Contents**                                                          | **V1**                                        |
|-----------------|-----------------------------------------------------------------------|-----------------------------------------------|
| Relational      | Targets, revisions, contracts, graph edges, findings, approvals, jobs | SQLite local; PostgreSQL production option.   |
| Object/evidence | Large snapshots, traces, reports, patches                             | Content-addressed filesystem.                 |
| Search          | Docs/code/evidence retrieval                                          | SQLite FTS5; optional embeddings.             |
| Audit           | Security/workflow history                                             | Hash-chained append-only JSONL plus DB index. |
| Graph           | Adjacency and dependency queries                                      | Relational projection; no graph DB required.  |

- Deduplicate artifacts by content hash.

- Incrementally invalidate dependent records.

- Archive superseded revisions while preserving audit and referenced evidence.

- Retention policies by sensitivity and proof obligation.

- Compaction may replace redundant projections, never source evidence required by unresolved or audited decisions.

# 20. Public Rust Interfaces

pub trait TargetConnector {  
fn identify(&self) -\> Result\<TargetIdentity\>;  
fn inventory(&self, since: Option\<RevisionId\>) -\> Result\<Vec\<ArtifactMeta\>\>;  
fn read(&self, artifact: &ArtifactId) -\> Result\<ArtifactStream\>;  
}  
  
pub trait LanguageAdapter {  
fn supports(&self, artifact: &ArtifactMeta) -\> bool;  
fn parse(&self, input: ArtifactStream) -\> Result\<StaticFacts\>;  
}  
  
pub trait EvidenceAdapter {  
fn poll(&mut self, cursor: Option\<Cursor\>) -\> Result\<EvidenceBatch\>;  
}  
  
pub trait ModelAdapter {  
fn capability(&self) -\> ModelCapability;  
fn infer(&self, req: StructuredInferenceRequest) -\> Result\<StructuredInferenceResponse\>;  
}  
  
pub trait AgentBridge {  
fn next_approved_job(&self, agent: &AgentIdentity) -\> Result\<Option\<RepairJob\>\>;  
fn submit_event(&self, job: &RepairJobId, event: AgentJobEvent) -\> Result\<()\>;  
}  
  
pub trait Verifier {  
fn evaluate(&self, ctx: VerificationContext) -\> Result\<VerificationResult\>;  
}

## 20.1 Error policy

- Use typed errors and retry classification.

- No panic on target-controlled input.

- Corrupt evidence quarantines the item and records BAR health event.

- Transactional workflow transitions with idempotency keys.

- Crash recovery replays audit/workflow state without duplicate jobs or approvals.

# 21. Phased Build Manual

| **Phase** | **Name**                                        | **Required implementation**                                                                                            | **Exit criteria**                                                          |
|-----------|-------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| 0         | Baseline, repository skeleton, CI, STATUS       | Workspace, core types, config, structured logging, audit chain, migrations, resource benchmark harness.                | Daemon starts model-free; old migrations replay; audit tamper test passes. |
| 1         | Target registration and identity                | Local Git/filesystem connector, commit/dirty hash, target registry, read-only policy.                                  | Repeat registration is idempotent; symlink/path traversal blocked.         |
| 2         | Artifact discovery                              | Inventory docs/code/tests/schemas/config/CI/diagrams/generated files; hash cache and incremental scan.                 | One-file change reparses only dependents; no full rescan.                  |
| 3         | Contract extraction shadow                      | Normative classification, source spans, hierarchy candidates, glossary, conflict candidates; optional small CPU model. | Every claim cites source; malformed/model-injected output rejected.        |
| 4         | Contract scope, temporal resolver, adjudication | Scope precedence, validity, supersession, operator rulings.                                                            | Ambiguous conflict never becomes definitive defect without resolution.     |
| 5         | Static architecture adapter v1                  | Start with Rust and Python or the primary target language; Tree-sitter; components, calls, states, effects, authority. | Fixture graphs match expected; unknown code remains explicit.              |
| 6         | Traceability and proof obligations              | Map contracts to code/tests/config; define proof requirements and freshness.                                           | Unmapped and unproven are distinct; evidence levels enforced.              |
| 7         | Static finding engine                           | Missing implementation, contradiction, dead path, bypass, state, architecture erosion, docs conflict.                  | Findings replay; duplicates aggregate; false-positive correction retained. |
| 8         | Dashboard v1                                    | Target, inventory, contracts, findings, evidence, adjudication, audit.                                                 | Operator can understand and correct findings without raw DB access.        |
| 9         | Runtime identity and evidence adapters          | Build/deploy identity, concurrent per-target watchers, OTel/log/journal/test adapters, topology snapshot, backpressure. | Multiple targets remain isolated; unbound telemetry and dropped ranges are explicit. |
| 10        | Coverage and conformance shadow                 | Coverage matrix, proof freshness, invariant evaluator, drift detection, finding dependencies.                          | No live action; compare recommendations with operator review.              |
| 11        | Operational semantics analyzers                 | Queues, retries, timeouts, cancellation, locks, leases, leader, clocks, modes, recovery, settlement.                   | Dedicated distributed-system fixtures pass.                                |
| 12        | Investigation engine                            | Causal hypotheses, evidence gaps, discriminating experiment proposals, assurance debt.                                 | No active probes; repair readiness deterministic.                          |
| 13        | Repair specification                            | Repair kinds, impact graph, acceptance, sequencing, rollback, no-change disposition.                                   | No vague repair-ready packet; each acceptance maps to proof.               |
| 14        | Human approval and waivers                      | Signed job hash, exact revision/scope, expiry, negotiation, waiver lifecycle.                                          | Unapproved and scope-mutated jobs inaccessible.                            |
| 15        | Coding-agent bridge                             | HTTP protocol, isolated worktree metadata, plan/challenge/question/progress/submit.                                    | No deployment endpoint; cancellation and reapproval work.                  |
| 16        | Semantic diff and pre-merge assurance           | Before/after contracts, invalidated proof, changed authority/state/schema/recovery.                                    | Patch can be rejected before merge for contract regression.                |
| 17        | Post-repair verification                        | Static/test/live evidence pipeline, independent verifier option, reopen logic.                                         | Passing tests alone cannot close live obligation.                          |
| 18        | Instrumentation proposals                       | Contract-to-observability mapping and minimal instrumentation repair jobs.                                             | No silent instrumentation; privacy/overhead shown.                         |
| 19        | Safe active verification                        | Nonproduction probes and failure injection with policy, cleanup, rollback.                                             | Disabled default; stop/side-effect bounds enforced.                        |
| 20        | Release and operational assurance               | Release reports, runbook validation, rollback proof, canary evidence stages.                                           | Release report reconstructable from evidence.                              |
| 21        | ML-runtime assurance                            | Statistical contracts, eval provenance, model/prompt/decoding/dataset drift.                                           | Deterministic and statistical proof remain separate.                       |
| 22        | Fleet analytics                                 | Cross-target pattern suggestions, fleet views, and shared adapter registry beyond baseline concurrent monitoring.       | No evidence/contract leakage; per-target policy remains authoritative.     |
| 23        | Hardening and production readiness              | Threat model closure, load tests, fuzzing, SBOM, signed builds, recovery exercises.                                    | Resource, security, migration, and disaster tests pass.                    |

# 22. Detailed Phase Rules

- Each phase ships disabled or shadow features before active authority.

- Every phase adds fixtures that fail before implementation and pass after.

- Every new persisted state includes replay, migration, unknown-value, idempotency, and crash tests.

- Every model-assisted feature has a deterministic fallback and explicit unavailable state.

- Resource benchmarks are regression tests, not documentation-only targets.

- Do not start coding-agent integration until static findings, adjudication, identity, and repair readiness are credible.

# 23. Mandatory Test Program

| **Test group**           | **Required coverage**                                                                   |
|--------------------------|-----------------------------------------------------------------------------------------|
| Compatibility and replay | Migration replay, audit integrity, duplicate requests, crash recovery, unknown enums.   |
| Discovery                | Symlink loops, huge binaries, generated files, linked repos, changed-file invalidation. |
| Contract extraction      | Normative classes, hierarchy, conflicts, stale docs, malicious instructions.            |
| Scope/time               | Environment/version/flag precedence, migrations, late telemetry, expiry.                |
| Static analysis          | Bypass, dead path, state violation, authority laundering, transaction gaps.             |
| Distributed semantics    | Retries, duplicate delivery, cancellation, timeout chains, leader fencing, skew.        |
| Data/schema              | Mixed versions, migrations, serialization, unit mismatch, deletion propagation.         |
| Evidence                 | Integrity, source binding, synthetic/live separation, freshness/invalidation.           |
| Findings                 | Dependencies, aggregation, reopen, waiver expiry, no-change disposition.                |
| Agent bridge             | Approval hash, scope expansion, cancellation, disagreement, token replay.               |
| Verification             | Partial, failed, regressed, unverifiable, independent verifier, rollback.               |
| Security                 | Prompt injection, path traversal, secret leakage, poisoned telemetry, sandbox escape.   |
| Performance              | Idle CPU/RAM, incremental scan, high-volume ingestion, target pressure suspension.      |
| Human factors            | Explanation entailment, review time, correct approval/ruling flow.                      |
| BAR self-health          | Model unavailable, DB recovery, adapter failure, audit corruption, degraded mode.       |

## 23.1 Required property/metamorphic tests

- Replaying the same evidence produces equivalent state.

- Independent event reorder does not alter result.

- Idempotent retry does not duplicate finding, job, or effect records.

- Reducing authority never increases reachable operations.

- Changing unrelated artifact does not invalidate unrelated proof.

- Restoring exact prior revision reconstructs prior contract graph.

- Model-disabled mode preserves deterministic monitoring and workflow.

- Target pressure causes semantic suspension without losing critical evidence.

## 23.2 Fuzz targets

- Document parsers, telemetry decoders, model JSON validator, API payloads.

- Path normalization, archive extraction, event ordering, migration input.

- Contract scope resolver, workflow state transitions, evidence graph invalidation.

# 24. Mandatory Acceptance Scenarios

1\. README says all effects pass dispatcher; alternate API bypass exists.

2\. Guarantee has no implementation: classify missing, not contradicted.

3\. Mock test passes; no live path: test-supported, not live-proven.

4\. Two active documents disagree: adjudication required.

5\. Mechanism changes but parent property remains: no false defect.

6\. Running binary does not match source commit: deployment identity finding.

7\. Config-specific behavior differs validly from default: scoped exception.

8\. Retry duplicates an external effect after timeout: side-effect settlement finding.

9\. Cancelled task continues writing: cancellation propagation finding.

10\. Rolling migration breaks old reader/new writer compatibility.

11\. Stale feature flag leaves deprecated path active.

12\. Runtime topology differs from architecture and disables redundancy.

13\. User journey is orphaned despite healthy components.

14\. Near miss exposes shared common-mode dependency.

15\. Malicious repository text cannot trigger tools.

16\. Operator approves exact job; agent requests scope expansion; approval invalidates.

17\. Agent proposes documentation repair instead of code; human can approve.

18\. Patch tests pass but original live invariant still fails; finding remains.

19\. Patch changes neighboring authority contract; pre-merge analysis flags it.

20\. Resolved finding becomes stale after dependency/model/config change.

21\. Target GPU busy; BAR model worker stays unloaded while monitoring continues.

22\. All models unavailable; deterministic service remains functional.

23\. BAR drops sampled noncritical telemetry and records affected coverage.

24\. Waiver expires and finding reopens.

25\. Correct action is monitor/no change and BAR does not manufacture work.

# 25. Dashboard Workflow Acceptance

1\. Register target with one pointer.

2\. Watch discovery progress without mandatory configuration form.

3\. Review provisional contracts and conflicts.

4\. Resolve only material ambiguities.

5\. See assurance domains and coverage without a misleading score.

6\. Open finding and understand expected, observed, evidence, uncertainty, and risk.

7\. Choose repair, monitor, adjudicate, waive, accept risk, external action, or incorrect.

8\. Approve exact repair job.

9\. Observe coding-agent plan, challenges, progress, and submission.

10\. Review semantic diff before merge.

11\. Review verification against original proof obligation.

12\. Export release or assurance report.

# 26. Feature Completeness Catalog

The following capability families consolidate the full discovery process. V1 need not activate every family, but the architecture and schemas must not block them.

| **Capability family**      | **Included scope**                                                                                                                                                                                      |
|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Intent and contracts       | Artifact discovery; claim extraction; hierarchy; scope; temporal validity; conflicts; adjudication; glossary; comments/TODO/generated-file policy; diagram interpretation; contract export/portability. |
| Architecture and behavior  | Components; responsibilities; allowed dependencies; state machines; authority; effects; transactions; modes; fallbacks; control loops; user journeys; business processes; operational procedures.       |
| Source to runtime identity | Source, dirty tree, build, dependencies, artifact digest, release, deployment, configuration, model, topology, environment parity, mixed versions.                                                      |
| Distributed semantics      | Queues, retries, timeouts, cancellation, deadlines, backpressure, overload, fairness, locks, leases, leaders, clocks, randomness, replay.                                                               |
| Data assurance             | Lineage, caches, persistence classification, backups, restore, retention, deletion, privacy, tenant isolation, schema evolution, serialization, identifiers, normalization, numeric boundaries.         |
| Security and policy        | Identity propagation, delegation, authorization freshness, credentials, break-glass, policy reconciliation/shadowing, sandbox, attack paths, abuse cases, supply chain.                                 |
| Evidence and observability | Typed evidence, contract-to-signal mapping, runtime topology, coverage, proof obligations, freshness, invalidation, synthetic/real separation, traffic representativeness.                              |
| Findings and causality     | Contradiction classification, dependency graph, incident clusters, near misses, defense in depth, common-mode failure, blast radius, assurance debt, root-cause confidence.                             |
| Diagnosis                  | Alternative hypotheses, smallest discriminating experiment, evidence cost, stopping, active-probe safety.                                                                                               |
| Repair                     | Repair kinds, impact prediction, batching suggestions, sequencing, risk, rollback, test synthesis, property tests, coding-agent negotiation.                                                            |
| Verification               | Semantic diff, pre-merge analysis, independent verifier, canary stages, rollback proof, effectiveness history, recurrence and architecture erosion.                                                     |
| Operations and reporting   | Dashboard, issue sync, alert linkage, release report, assurance case, runbook verification, operational drift, human decision provenance.                                                               |
| ML runtime assurance       | Deterministic vs statistical contracts, evaluation provenance, model/prompt/decoding drift, dataset representativeness, judge independence.                                                             |
| BAR platform               | Rust core, resource governor, isolated model worker, connectors, adapter SDK, storage, compaction, offline/degraded mode, self-monitoring, reproducibility, fleet isolation.                            |

# 27. Initial 16-Week Execution Plan

| **Week** | **Primary deliverable**                                                 |
|----------|-------------------------------------------------------------------------|
| 1        | Workspace, core schemas, audit chain, config, benchmarks.               |
| 2        | SQLite store, migrations, target registration, Git/filesystem identity. |
| 3        | Incremental artifact inventory and hashing.                             |
| 4        | Document classifier, glossary, deterministic claim candidates.          |
| 5        | Optional small CPU extraction worker and schema validation.             |
| 6        | Contract hierarchy, scope, temporal resolver, conflict view.            |
| 7        | Rust/Python Tree-sitter static adapter and component graph.             |
| 8        | State, authority, effect, test, and config mapping.                     |
| 9        | Proof obligations, coverage model, evidence freshness.                  |
| 10       | Static finding engine and dependency aggregation.                       |
| 11       | Dashboard target/contracts/findings/adjudication.                       |
| 12       | Repair packet and no-change/waiver dispositions.                        |
| 13       | Human approval hash and isolated-worktree contract.                     |
| 14       | Coding-agent HTTP bridge.                                               |
| 15       | Semantic patch diff and static post-change verification.                |
| 16       | End-to-end fixture demonstration and resource/security hardening.       |

# 28. V1 Demonstration Runtime

> **Required fixture**
>
> A small event-driven runtime containing: one correct governed effect path, one bypass, one stale document, one documentation conflict, one mocked-only test, one missing recovery mechanism, one duplicate retry effect, one invalid terminal transition, one feature-flag exception, and one deployment identity mismatch.

1\. Point BAR at the fixture with repository path only.

2\. BAR inventories and extracts provisional contracts.

3\. Operator resolves one real ambiguity.

4\. BAR distinguishes correct, missing, contradicted, unproven, and stale behavior.

5\. Operator approves one repair.

6\. Connected coding agent receives exact scoped job and submits a patch.

7\. BAR identifies semantic impact before merge.

8\. BAR verifies original contract and neighboring invariants.

9\. GPU use remains zero throughout; model work can be disabled without breaking the demo.

# 29. Definition of Done

- One-pointer onboarding produces useful results without manual contract authoring.

- Rust daemon performs all mandatory monitoring and workflow functions model-free.

- Optional models are isolated, bounded, replaceable, and target-subordinate.

- Contracts preserve hierarchy, scope, time, provenance, conflicts, rulings, and proof obligations.

- Runtime evidence binds to source/build/deployment identity or is explicitly unbound.

- Findings are evidence-backed, dependency-aware, understandable, and permit no-action outcomes.

- Human approval is exact, revocable, and mandatory before coding begins.

- Coding-agent bridge is simple and contains no orchestration or deployment authority.

- Semantic pre-merge and post-change verification evaluate original contracts.

- Evidence freshness, invalidation, waivers, regressions, and audit history work.

- Resource, security, crash, replay, fuzz, and fixture suites pass.

- STATUS accurately distinguishes implemented, tested, shadow, active, and deferred capabilities.

# 30. Final Architectural Rule

BAR discovers.  
BAR models.  
BAR observes.  
BAR proves or exposes uncertainty.  
BAR explains.  
BAR prepares.  
The human directs.  
The coding agent implements.  
BAR verifies.  
The monitored runtime keeps priority over BAR at all times.

> **Product position**
>
> A lightweight Rust behavioral assurance runtime with optional small semantic accelerators and a human-gated coding-agent bridge.

# Appendix A. Normative V1 Scope

> **V1 product wedge**
>
> V1 is a local, model-optional repository-derived behavioral contract engine with static analysis, human adjudication, repair approval, a narrow coding-agent bridge, semantic patch review, and static/post-test verification. It is not a production observability platform.

| **Must ship in V1**                                                                                                         | **Explicitly deferred after V1**                                                      |
|-----------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| Linux x86-64 local daemon; SQLite; local filesystem/Git targets                                                             | Production-scale live telemetry, fleet/tenant mode, distributed causal reconstruction |
| Incremental artifact discovery and hashing                                                                                  | Active production probes and automated fault injection                                |
| Documentation claim extraction with exact source spans                                                                      | Deployment control, autonomous remediation, agent orchestration                       |
| Contract hierarchy, scope, time, conflicts, operator rulings                                                                | Full attack-path, privacy deletion, backup/restore, and regulated assurance suites    |
| Rust and Python static adapters                                                                                             | Go, Java, C#, TypeScript beyond experimental adapter                                  |
| Static findings: missing implementation, contradiction, bypass, dead mechanism, state violation, stale docs, unproven claim | Full statistical ML-runtime assurance and dataset governance                          |
| Evidence, proof obligations, freshness, invalidation                                                                        | Issue tracker synchronization and broad third-party observability integrations        |
| Dashboard, approval, waiver, no-change disposition                                                                          | Production topology discovery and mixed-version runtime inference                     |
| HTTP coding-agent bridge with isolated worktree contract                                                                    | Any production deployment endpoint                                                    |
| Semantic patch diff and static/test verification                                                                            | Automatic canary rollout or rollback execution                                        |
| Zero-GPU operation; optional isolated small model worker                                                                    | Mandatory cloud model dependency                                                      |

# Appendix B. Supported Platforms and Installation

| **Platform** | **Status**       | **Required behavior**                                                      |
|--------------|------------------|----------------------------------------------------------------------------|
| Linux x86-64 | Primary          | All V1 features; systemd; inotify; cgroups v2 when present.                |
| Linux ARM64  | Secondary        | All non-GPU V1 features; same data formats.                                |
| macOS        | Development only | Repository scan and dashboard; no cgroup guarantees.                       |
| Windows      | Development only | Repository scan through native path handling; no production support in V1. |

Filesystem layout:  
/etc/bar/bar.toml  
/var/lib/bar/bar.db  
/var/lib/bar/evidence/  
/var/lib/bar/worktrees/  
/var/log/bar/  
/usr/bin/bar  
/usr/bin/bar-model-worker  
/usr/lib/systemd/system/bar.service

- Install as dedicated system user \`bar\` with no shell and no target write access by default.

- Database migration runs before service start; create automatic pre-migration backup.

- Failed migration aborts startup and preserves prior database.

- Upgrade rollback restores binary and database backup together.

- Uninstall must offer retain, archive, or purge modes for evidence and audit history.

# Appendix C. Complete Configuration Contract

\# /etc/bar/bar.toml  
\[server\]  
listen = "127.0.0.1:7878"  
public_base_url = "http://127.0.0.1:7878"  
max_request_bytes = 8388608  
  
\[storage\]  
database_url = "sqlite:///var/lib/bar/bar.db"  
evidence_dir = "/var/lib/bar/evidence"  
worktree_dir = "/var/lib/bar/worktrees"  
disk_quota_gb = 20  
read_only_on_quota_exhaustion = true  
  
\[resources\]  
max_cpu_percent = 10  
max_memory_mb = 512  
scan_worker_count = 2  
semantic_worker_count = 1  
max_pending_semantic_jobs = 128  
gpu_enabled = false  
gpu_utilization_ceiling_percent = 20  
target_reserved_vram_mb = 0  
pressure_sample_seconds = 5  
resume_hysteresis_seconds = 30  
  
\[models\]  
enabled = false  
provider = "none"  
endpoint = ""  
default_tier = 0  
timeout_seconds = 60  
max_context_tokens = 8192  
max_output_tokens = 2048  
repair_attempts = 1  
  
\[scan\]  
watch = true  
debounce_ms = 750  
max_file_bytes = 5242880  
follow_symlinks = false  
include_hidden = false  
  
\[retention\]  
raw_runtime_days = 7  
resolved_finding_days = 365  
audit_days = 0  
artifact_versions_per_path = 5  
  
\[security\]  
local_auth_required = true  
session_minutes = 60  
agent_token_minutes = 30  
allow_remote_bind = false  
tls_required_for_remote = true  
  
\[verification\]  
default_timeout_seconds = 900  
network_enabled = false  
max_output_bytes = 10485760  
  
\[baseline\]  
enabled = true  
minimum_hours = 0  
operator_review_required = true

| **Rule**                  | **Requirement**                                                              |
|---------------------------|------------------------------------------------------------------------------|
| Unknown key               | Startup error; never silently ignore.                                        |
| Secret value              | May reference environment or host secret store; never print.                 |
| Range validation          | Reject out-of-range values before service starts.                            |
| Reload                    | Only retention, notifications, and resource thresholds may hot reload in V1. |
| Security-sensitive change | Audit old/new hash and actor; require administrator.                         |

# Appendix D. Canonical Rust Types

\#\[derive(Debug, Clone, Serialize, Deserialize)\]  
\#\[serde(rename_all = "snake_case", deny_unknown_fields)\]  
pub struct Contract {  
pub contract_id: ContractId,  
pub target_id: TargetId,  
pub parent_contract_id: Option\<ContractId\>,  
pub level: ContractLevel,  
pub normative_kind: NormativeKind,  
pub statement: String,  
pub subject_refs: Vec\<EntityRef\>,  
pub conditions: Vec\<String\>,  
pub required_behavior: Option\<String\>,  
pub prohibited_behavior: Vec\<String\>,  
pub scope: ContractScope,  
pub valid_from: Option\<DateTime\<Utc\>\>,  
pub valid_until: Option\<DateTime\<Utc\>\>,  
pub source_refs: Vec\<SourceRef\>,  
pub supersedes: Vec\<ContractId\>,  
pub proof_obligation_id: Option\<ProofObligationId\>,  
pub confidence: ConfidenceLevel,  
pub freshness: FreshnessState,  
pub conflict_refs: Vec\<ContractId\>,  
pub created_by: ActorRef,  
pub analysis_versions: AnalysisVersions,  
}  
  
\#\[derive(Debug, Clone, Serialize, Deserialize)\]  
\#\[serde(rename_all = "snake_case", deny_unknown_fields)\]  
pub struct Finding {  
pub finding_id: FindingId,  
pub target_id: TargetId,  
pub target_revision: RevisionId,  
pub class: FindingClass,  
pub title: String,  
pub summary: String,  
pub severity: Severity,  
pub confidence: ConfidenceLevel,  
pub assurance_domain: AssuranceDomain,  
pub affected_contracts: Vec\<ContractId\>,  
pub affected_components: Vec\<ComponentId\>,  
pub affected_paths: Vec\<PathId\>,  
pub evidence_refs: Vec\<EvidenceId\>,  
pub uncertainty: Vec\<String\>,  
pub causal_hypotheses: Vec\<CausalHypothesis\>,  
pub dependencies: Vec\<FindingRelation\>,  
pub risk_if_unresolved: String,  
pub repair_readiness: RepairReadiness,  
pub dispositions: Vec\<AssuranceDisposition\>,  
pub status: FindingStatus,  
pub created_at: DateTime\<Utc\>,  
pub updated_at: DateTime\<Utc\>,  
pub version: u64,  
}

- All API and persisted structs use \`deny_unknown_fields\`.

- All timestamps are RFC3339 UTC with nanoseconds accepted and canonical millisecond output.

- IDs are lowercase typed newtypes; never accept raw arbitrary prefixes.

- Strings use explicit maximum lengths enforced before persistence.

- Database writes require optimistic version match for mutable workflow records.

- Unknown persisted enum values prevent activation and enter migration-required health state.

# Appendix E. Normative SQL Schema

CREATE TABLE targets (  
target_id TEXT PRIMARY KEY,  
name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 255),  
connector_kind TEXT NOT NULL,  
root_locator TEXT NOT NULL,  
status TEXT NOT NULL,  
created_at TEXT NOT NULL,  
updated_at TEXT NOT NULL,  
version INTEGER NOT NULL DEFAULT 1  
);  
  
CREATE TABLE target_revisions (  
revision_id TEXT PRIMARY KEY,  
target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,  
source_commit TEXT,  
dirty_hash TEXT,  
dependency_hash TEXT,  
config_hash TEXT,  
build_digest TEXT,  
deployment_id TEXT,  
environment TEXT,  
discovered_at TEXT NOT NULL,  
UNIQUE(target_id, source_commit, dirty_hash, config_hash, build_digest)  
);  
  
CREATE TABLE artifacts (  
artifact_id TEXT PRIMARY KEY,  
target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,  
revision_id TEXT NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,  
logical_path TEXT NOT NULL,  
content_sha256 TEXT NOT NULL,  
media_type TEXT NOT NULL,  
artifact_kind TEXT NOT NULL,  
source_of_truth INTEGER NOT NULL CHECK(source_of_truth IN (0,1)),  
size_bytes INTEGER NOT NULL,  
modified_at TEXT,  
discovered_at TEXT NOT NULL,  
UNIQUE(revision_id, logical_path)  
);  
  
CREATE TABLE artifact_dependencies (  
from_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,  
to_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,  
relation_kind TEXT NOT NULL,  
PRIMARY KEY(from_artifact_id, to_artifact_id, relation_kind)  
);  
  
CREATE TABLE contracts (  
contract_id TEXT PRIMARY KEY,  
target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,  
parent_contract_id TEXT REFERENCES contracts(contract_id),  
level TEXT NOT NULL,  
normative_kind TEXT NOT NULL,  
statement TEXT NOT NULL,  
scope_json TEXT NOT NULL,  
valid_from TEXT,  
valid_until TEXT,  
confidence TEXT NOT NULL,  
freshness TEXT NOT NULL,  
status TEXT NOT NULL,  
created_at TEXT NOT NULL,  
superseded_by TEXT REFERENCES contracts(contract_id),  
version INTEGER NOT NULL DEFAULT 1  
);  
  
CREATE TABLE contract_sources (  
contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,  
artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,  
start_offset INTEGER NOT NULL,  
end_offset INTEGER NOT NULL,  
exact_text_sha256 TEXT NOT NULL,  
PRIMARY KEY(contract_id, artifact_id, start_offset, end_offset)  
);  
  
CREATE TABLE contract_relations (  
from_contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,  
to_contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,  
relation_kind TEXT NOT NULL,  
PRIMARY KEY(from_contract_id, to_contract_id, relation_kind)  
);  
  
CREATE TABLE proof_obligations (  
proof_id TEXT PRIMARY KEY,  
contract_id TEXT NOT NULL UNIQUE REFERENCES contracts(contract_id) ON DELETE CASCADE,  
required_levels_json TEXT NOT NULL,  
required_conditions_json TEXT NOT NULL,  
freshness_policy_json TEXT NOT NULL,  
independence_requirement TEXT NOT NULL,  
resolution_rule TEXT NOT NULL  
);  
  
CREATE TABLE evidence (  
evidence_id TEXT PRIMARY KEY,  
target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,  
revision_id TEXT NOT NULL REFERENCES target_revisions(revision_id),  
kind TEXT NOT NULL,  
source_ref TEXT NOT NULL,  
source_span_json TEXT,  
environment TEXT,  
observed_at TEXT,  
ingested_at TEXT NOT NULL,  
conditions_json TEXT NOT NULL,  
integrity_json TEXT NOT NULL,  
synthetic INTEGER NOT NULL CHECK(synthetic IN (0,1)),  
completeness TEXT NOT NULL,  
retention_class TEXT NOT NULL,  
content_sha256 TEXT NOT NULL  
);  
  
CREATE TABLE evidence_contract_links (  
evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,  
contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,  
relation_kind TEXT NOT NULL CHECK(relation_kind IN ('supports','contradicts','invalidates')),  
PRIMARY KEY(evidence_id, contract_id, relation_kind)  
);  
  
CREATE TABLE findings (  
finding_id TEXT PRIMARY KEY,  
target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,  
revision_id TEXT NOT NULL REFERENCES target_revisions(revision_id),  
class TEXT NOT NULL,  
title TEXT NOT NULL,  
summary TEXT NOT NULL,  
severity TEXT NOT NULL,  
confidence TEXT NOT NULL,  
assurance_domain TEXT NOT NULL,  
repair_readiness TEXT NOT NULL,  
status TEXT NOT NULL,  
fingerprint TEXT NOT NULL,  
risk_if_unresolved TEXT NOT NULL,  
created_at TEXT NOT NULL,  
updated_at TEXT NOT NULL,  
version INTEGER NOT NULL DEFAULT 1,  
UNIQUE(target_id, fingerprint, status)  
);  
  
CREATE TABLE finding_contracts (  
finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,  
contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,  
PRIMARY KEY(finding_id, contract_id)  
);  
  
CREATE TABLE finding_evidence (  
finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,  
evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,  
role TEXT NOT NULL,  
PRIMARY KEY(finding_id, evidence_id, role)  
);  
  
CREATE TABLE finding_relations (  
from_finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,  
to_finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,  
relation_kind TEXT NOT NULL,  
PRIMARY KEY(from_finding_id, to_finding_id, relation_kind)  
);  
  
CREATE TABLE repair_jobs (  
job_id TEXT PRIMARY KEY,  
target_id TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,  
base_revision_id TEXT NOT NULL REFERENCES target_revisions(revision_id),  
job_hash TEXT NOT NULL UNIQUE,  
status TEXT NOT NULL,  
payload_json TEXT NOT NULL,  
created_at TEXT NOT NULL,  
updated_at TEXT NOT NULL,  
version INTEGER NOT NULL DEFAULT 1  
);  
  
CREATE TABLE approvals (  
approval_id TEXT PRIMARY KEY,  
job_id TEXT NOT NULL REFERENCES repair_jobs(job_id) ON DELETE CASCADE,  
approved_job_hash TEXT NOT NULL,  
approved_base_revision TEXT NOT NULL,  
approved_scope_json TEXT NOT NULL,  
approved_by TEXT NOT NULL,  
approved_at TEXT NOT NULL,  
expires_at TEXT,  
revoked_at TEXT  
);  
  
CREATE TABLE waivers (  
waiver_id TEXT PRIMARY KEY,  
finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,  
reason TEXT NOT NULL,  
scope_json TEXT NOT NULL,  
mitigation_json TEXT NOT NULL,  
approved_by TEXT NOT NULL,  
created_at TEXT NOT NULL,  
review_at TEXT,  
expires_at TEXT NOT NULL,  
revoked_at TEXT  
);  
  
CREATE TABLE verifications (  
verification_id TEXT PRIMARY KEY,  
job_id TEXT NOT NULL REFERENCES repair_jobs(job_id) ON DELETE CASCADE,  
submitted_revision_id TEXT NOT NULL REFERENCES target_revisions(revision_id),  
outcome TEXT NOT NULL,  
result_json TEXT NOT NULL,  
started_at TEXT NOT NULL,  
completed_at TEXT  
);  
  
CREATE TABLE audit_events (  
seq INTEGER PRIMARY KEY AUTOINCREMENT,  
event_id TEXT NOT NULL UNIQUE,  
event_type TEXT NOT NULL,  
actor TEXT NOT NULL,  
mechanism TEXT NOT NULL,  
causal_event_id TEXT,  
target_id TEXT,  
target_revision_id TEXT,  
idempotency_key TEXT NOT NULL UNIQUE,  
payload_json TEXT NOT NULL,  
occurred_at TEXT NOT NULL,  
previous_hash TEXT NOT NULL,  
event_hash TEXT NOT NULL UNIQUE  
);  
  
CREATE INDEX idx_artifacts_revision_path ON artifacts(revision_id, logical_path);  
CREATE INDEX idx_contracts_target_status ON contracts(target_id, status);  
CREATE INDEX idx_evidence_revision_kind ON evidence(revision_id, kind);  
CREATE INDEX idx_findings_target_status ON findings(target_id, status);  
CREATE INDEX idx_audit_target_seq ON audit_events(target_id, seq);

- All workflow transitions and audit append occur in one transaction.

- Evidence object write uses temp file, fsync, atomic rename, then database insert.

- Deleting a target uses archive or purge workflow; never direct cascade from UI.

- Schema migrations are monotonic, checksummed, and applied once.

# Appendix F. Closed Audit Event Registry

EVENT_TYPES = {  
"bar.started",  
"bar.stopped",  
"bar.health.degraded",  
"bar.health.recovered",  
"target.registered",  
"target.archived",  
"target.scan.started",  
"target.scan.completed",  
"target.scan.failed",  
"revision.discovered",  
"artifact.discovered",  
"artifact.changed",  
"artifact.removed",  
"artifact.parse.failed",  
"contract.extracted",  
"contract.updated",  
"contract.superseded",  
"contract.conflict.detected",  
"contract.ruling.created",  
"contract.ruling.superseded",  
"proof.created",  
"proof.status.changed",  
"evidence.ingested",  
"evidence.invalidated",  
"evidence.retention.applied",  
"finding.created",  
"finding.updated",  
"finding.transitioned",  
"finding.reopened",  
"finding.rejected",  
"waiver.created",  
"waiver.revoked",  
"waiver.expired",  
"repair.created",  
"repair.updated",  
"repair.approval.requested",  
"repair.approved",  
"repair.approval.revoked",  
"agent.registered",  
"agent.job.claimed",  
"agent.plan.submitted",  
"agent.challenge.submitted",  
"agent.scope.requested",  
"agent.job.started",  
"agent.progress.recorded",  
"agent.patch.submitted",  
"agent.job.failed",  
"agent.cancel.acknowledged",  
"verification.started",  
"verification.completed",  
"verification.failed",  
"model.requested",  
"model.completed",  
"model.failed",  
"model.suspended.resource_pressure",  
"security.auth.succeeded",  
"security.auth.failed",  
"security.token.revoked"  
}

- Every event requires actor, causal mechanism, idempotency key, timestamp, payload schema version, prior hash, and event hash.

- Unknown event type is rejected.

- Audit payload must contain references, not embedded secrets or large evidence.

- Replay reconstructs workflow state; derived indexes may be rebuilt.

# Appendix G. Workflow Transition Tables

| **Entity** | **From**            | **Allowed to**                                              | **Authority and prerequisites**                           |
|------------|---------------------|-------------------------------------------------------------|-----------------------------------------------------------|
| Finding    | detected            | triaged, rejected                                           | Operator or deterministic triage rule; evidence required. |
| Finding    | triaged             | investigating, deferred, waived, rejected                   | Operator; waiver requires expiry.                         |
| Finding    | investigating       | evidence_sufficient, deferred, rejected                     | BAR may propose; deterministic readiness check.           |
| Finding    | evidence_sufficient | repair_ready, monitor, adjudicate                           | Operator or rule based on disposition.                    |
| Finding    | repair_ready        | awaiting_approval, deferred, rejected                       | Repair packet passes readiness validator.                 |
| Finding    | awaiting_approval   | approved, deferred, rejected, waived                        | Approver role; exact job hash.                            |
| Finding    | approved            | implementing, reopened                                      | Agent claim or revision invalidation.                     |
| Finding    | implementing        | submitted, failed, reopened                                 | Agent event or scope/base mismatch.                       |
| Finding    | submitted           | verifying, reopened                                         | BAR verifier starts.                                      |
| Finding    | verifying           | resolved, partially_resolved, failed, rolled_back, reopened | Verification result.                                      |
| Finding    | resolved            | reopened                                                    | Only new contradictory/invalidating evidence.             |
| Repair job | created             | awaiting_approval, cancelled                                | System or operator.                                       |
| Repair job | awaiting_approval   | approved, cancelled                                         | Approver role.                                            |
| Repair job | approved            | claimed, cancelled, approval_invalidated                    | Agent token and unchanged hash.                           |
| Repair job | claimed             | implementing, cancelled                                     | Registered coding agent.                                  |
| Repair job | implementing        | submitted, failed, cancelled                                | Agent.                                                    |
| Repair job | submitted           | verifying                                                   | BAR.                                                      |
| Repair job | verifying           | completed, failed, reopened                                 | Verifier.                                                 |

- Terminal corrections create a new superseding record except \`resolved -\> reopened\`.

- Repeated identical transition request is idempotent and returns current record.

- Every transition validates optimistic version and required evidence.

- Cancellation requires agent acknowledgment before worktree cleanup.

# Appendix H. Deterministic Algorithms

## H.1 Contract extraction pipeline

1\. Filter supported textual artifacts and classify source authority.

2\. Segment by heading, list item, table row, paragraph, and comment block; preserve exact byte offsets.

3\. Apply deterministic candidate rules for normative verbs, prohibitions, guarantees, lifecycle language, and explicit plans.

4\. Run optional model only on candidate segments or unresolved semantic segments.

5\. Validate output schema, source span, exact quoted hash, subject references, and negation.

6\. Normalize whitespace and terminology through target glossary without rewriting source text.

7\. Create content fingerprint from normative kind, normalized statement, scope, and source span.

8\. Attach hierarchy by explicit references first, then structural containment, then semantic proposal.

9\. Run scope/temporal resolver.

10\. Generate conflict candidates; do not auto-adjudicate.

11\. Persist claim as discovered and emit audit event.

## H.2 Confidence derivation

| **Confidence** | **Deterministic minimum**                                                                                           |
|----------------|---------------------------------------------------------------------------------------------------------------------|
| confirmed      | Bound live evidence directly satisfies/contradicts proof obligation, or operator ruling establishes interpretation. |
| high           | Two independent strong sources, or static implementation plus relevant integration test.                            |
| moderate       | One strong source, or multiple consistent indirect sources.                                                         |
| low            | Single ambiguous document, generated inference, incomplete mapping, or unbound runtime evidence.                    |

- Model self-confidence is ignored.

- Confidence may only increase through new evidence and may decrease through invalidation.

- Contradictory evidence prevents \`confirmed\` until adjudicated or scoped.

## H.3 Severity derivation

| **Dimension** | **Ranks**                                           |
|---------------|-----------------------------------------------------|
| Consequence   | negligible, limited, material, severe, catastrophic |
| Reachability  | theoretical, constrained, plausible, observed       |
| Authority     | none, read, write, privileged, control-plane        |
| Reversibility | easy, moderate, difficult, irreversible             |
| Exposure      | development, test, internal, production             |
| Blast radius  | single operation, component, target, multi-target   |

severity precedence:  
critical = catastrophic OR (severe AND observed) OR privileged/control-plane production bypass  
high = severe OR material+observed OR irreversible production defect  
medium = material OR plausible authority/data defect  
low = limited and not observed  
informational = negligible, documentation-only, or accepted design note  
The model cannot set severity.

## H.4 Repair readiness

- \`ready\` requires scoped active contract, exact revision, inspectable/reproducible gap, evidence bundle, credible cause or bounded implementation objective, measurable acceptance conditions, prohibited changes, rollback expectation, and no blocking adjudication.

- \`partial\` has useful evidence but lacks one or more non-safety requirements.

- \`insufficient\` lacks contract, scope, evidence, or measurable resolution.

## H.5 Finding fingerprint and deduplication

fingerprint = sha256(  
class + normalized_active_contract_ids +  
normalized_component_ids + normalized_path_signature +  
normalized_environment_scope + root_cause_family  
)  
  
same fingerprint + active status → update occurrence/evidence  
resolved fingerprint + materially same new evidence → reopen  
same symptom but shared cause discovered → relate/subsume; do not delete history  
different scope or root cause → new finding

## H.6 Dependency invalidation

1\. Record typed graph edges from artifacts to facts, contracts, mappings, evidence, proofs, findings, and reports.

2\. On change, traverse outgoing dependency edges breadth-first with visited set.

3\. Mark derived records stale inside one transaction; never delete source history.

4\. Queue recomputation by topological strongly connected component order.

5\. Cycles recompute as one bounded component.

6\. On crash, pending invalidation batch resumes from persisted cursor.

7\. Only reopen a finding when required proof is lost or contradictory evidence appears.

# Appendix I. Static Adapter Contract

| **V1 language** | **Required coverage**                                                                                                                                                |
|-----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Rust            | Modules, uses, functions, impls, traits, async calls, macros as opaque unless supported, filesystem/network/process/database effects, tests, state enums.            |
| Python          | Modules, imports, functions/classes, decorators, async calls, dynamic calls as uncertain, filesystem/network/process/database effects, tests, state constants/enums. |

StaticFacts {  
artifacts\[\]  
symbols\[\]  
references\[\]  
call_edges\[\]  
data_edges\[\]  
state_definitions\[\]  
state_transitions\[\]  
authority_checks\[\]  
effects\[\]  
tests\[\]  
configuration_reads\[\]  
uncertainty\[\]  
}

- Dynamic dispatch, reflection, macros, monkey patching, and generated code must be marked uncertain rather than guessed.

- Effects use a closed catalog: filesystem_write, database_mutation, network_request, message_publish, process_execute, secret_read, config_mutation, permission_change, model_invoke, human_communication.

- Wrapper functions inherit effect summaries through fixed-point propagation with iteration cap.

- Adapter failure for one artifact must not abort the target scan.

# Appendix J. Canonical Runtime Evidence Envelope

{  
"schema_version": 1,  
"event_id": "evt/...",  
"target_id": "target/...",  
"revision_id": "revision/...",  
"deployment_id": "deploy/...",  
"trace_id": "...",  
"span_id": "...",  
"parent_span_id": "...",  
"event_type": "...",  
"component": "worker",  
"operation": "dispatch",  
"actor": {"kind":"service","id":"..."},  
"authority_ref": "...",  
"state_before": {},  
"state_after": {},  
"effect": null,  
"sequence": 123,  
"monotonic_ns": 123456,  
"occurred_at": "2026-07-13T15:00:00.000Z",  
"attributes": {}  
}

- Sequence is source-local unless source declares global semantics.

- Causal parent outranks wall-clock ordering.

- Duplicate event ID is idempotent; conflicting duplicate quarantines both.

- Late events update timelines and may reopen findings.

- Missing sequence ranges become explicit coverage gaps.

- Clock skew never fabricates causal ordering.

# Appendix K. Authentication and Authorization

| **Role**         | **Permissions**                                                 |
|------------------|-----------------------------------------------------------------|
| viewer           | Read targets, contracts, findings, reports.                     |
| operator         | Triage, adjudicate, defer, correct evidence, request repair.    |
| approver         | Approve/revoke repair jobs and waivers.                         |
| administrator    | Manage connectors, users, policies, retention, remote access.   |
| coding_agent     | Read exact approved jobs; submit plan/challenge/progress/patch. |
| telemetry_writer | Write canonical evidence only.                                  |

- Local UI uses secure session cookie, CSRF token, SameSite strict, and short session expiry.

- API tokens are random 256-bit values stored only as Argon2id hashes.

- Agent tokens are job-scoped, method-scoped, revision-scoped, expiring, and revocable.

- Remote bind requires TLS; local Unix socket is preferred where available.

- All authorization decisions are audited without storing token material.

# Appendix L. HTTP API Contract

Error envelope:  
{  
"error": {  
"code": "approval_revision_mismatch",  
"message": "Approved base revision no longer matches target.",  
"retryable": false,  
"details": {},  
"request_id": "req/..."  
}  
}  
  
Pagination:  
?limit=50&cursor=\<opaque\>  
Response: {"items":\[...\],"next_cursor":"..."}  
  
Mutations:  
Idempotency-Key header required.  
If-Match: "\<version\>" required for mutable records.  
409 on optimistic conflict.

| **Endpoint group** | **V1 endpoints**                                                                                                 |
|--------------------|------------------------------------------------------------------------------------------------------------------|
| Targets            | POST /v1/targets; GET /v1/targets; GET /v1/targets/{id}; POST /v1/targets/{id}/scan                              |
| Contracts          | GET /v1/targets/{id}/contracts; GET /v1/contracts/{id}; POST /v1/contracts/{id}/rulings                          |
| Findings           | GET /v1/findings; GET /v1/findings/{id}; POST /v1/findings/{id}/transition; POST /v1/findings/{id}/correct       |
| Repairs            | POST /v1/findings/{id}/repair; GET /v1/repairs/{id}; POST /v1/repairs/{id}/approve; POST /v1/repairs/{id}/revoke |
| Agents             | The bridge endpoints defined in Section 15.                                                                      |
| Verification       | POST /v1/repairs/{id}/verify; GET /v1/verifications/{id}                                                         |
| Health             | GET /health/live; GET /health/ready; GET /v1/health/details                                                      |

# Appendix M. Git and Worktree Contract

- Repair branch: \`bar/{finding-short}/{job-short}\`.

- Worktree: \`/var/lib/bar/worktrees/{job_id}\`.

- Base revision must be clean and exact; dirty target trees are snapshot-only and cannot receive automated work in V1.

- Agent may submit commit hash or unified patch; commit is preferred.

- Submodules are pinned and read-only unless explicitly in approved scope.

- Rebase onto changed base requires semantic diff and renewed approval.

- Cancellation freezes worktree, records patch hash, waits for acknowledgment, then archives or deletes per policy.

- No direct push to protected branch.

# Appendix N. Verification and Sandbox Contract

\# Optional repository file: .bar/verification.toml  
\[commands\]  
format = \["cargo fmt --check"\]  
lint = \["cargo clippy --all-targets -- -D warnings"\]  
unit = \["cargo test --lib"\]  
integration = \["cargo test --tests"\]  
  
\[limits\]  
timeout_seconds = 900  
memory_mb = 2048  
cpu_percent = 100  
pids = 256  
network = false  
output_bytes = 10485760

- Run in isolated process/container with read-only repository base and writable worktree.

- Mount only approved paths; filter environment variables; no host secret inheritance.

- Network disabled unless repair job explicitly allows destinations.

- Kill process tree on timeout; preserve bounded logs and exit metadata.

- Verification commands are evidence, not authority to resolve beyond their proof obligations.

# Appendix O. Optional Model Task Contracts

| **Task**                   | **Allowed use**                                      | **Output requirement**               |
|----------------------------|------------------------------------------------------|--------------------------------------|
| classify_section           | Classify requirement/mechanism/plan/history/example. | Closed enum plus source span.        |
| extract_contracts          | Extract candidate contracts from bounded text.       | Strict JSON; exact source offsets.   |
| map_claim_to_symbols       | Propose symbol candidates.                           | Existing symbol IDs only.            |
| summarize_evidence         | Concise dashboard summary.                           | Must cite supplied evidence IDs.     |
| generate_causal_hypotheses | Propose alternatives.                                | No observation claims; bounded list. |
| draft_repair_spec          | Draft constrained repair packet.                     | Cannot approve or select tools.      |
| check_report_entailment    | Detect unsupported wording.                          | Sentence-to-evidence mapping.        |

- Cache key includes task, normalized input hash, model ID, quantization, prompt version, schema version.

- One formatting repair attempt, then fail without blocking deterministic monitoring.

- Default task context \<= 8,192 tokens and output \<= 2,048 tokens.

- No model receives secrets or restricted evidence unless policy explicitly permits.

- Model worker has no repository write capability.

# Appendix P. Small-Model Evaluation and Promotion

| **Metric**                              | **Minimum V1 acceptance**                                 |
|-----------------------------------------|-----------------------------------------------------------|
| Contract extraction precision           | At least 0.90 on reviewed fixture corpus.                 |
| Contract extraction recall              | At least 0.75, with deterministic candidate fallback.     |
| Source-span accuracy                    | At least 0.95 exact/overlap threshold.                    |
| Normative classification accuracy       | At least 0.90.                                            |
| Hallucinated file/symbol reference rate | Below 0.5%.                                               |
| Schema-valid response rate              | At least 0.99 after one repair.                           |
| CPU memory                              | Within configured worker limit.                           |
| Regression                              | No critical target-specific decline versus current model. |

- New model runs shadow against fixed corpus and recent operator-reviewed examples.

- Promotion requires administrator approval and recorded lineage.

- Rollback is immediate and invalidates only model-derived caches, not source evidence.

- Smallest model meeting thresholds is preferred.

# Appendix Q. Baseline Mode

BaselineState =  
discovering \|  
provisional \|  
observing \|  
review_required \|  
active

- Static V1 may set observation duration to zero but still requires operator review before active assurance.

- During provisional mode, high-confidence static contradictions are visible but labeled provisional.

- Baseline records known feature flags, environments, temporary exceptions, and active documentation conflicts.

- Major architecture, repository bundle, or contract hierarchy change returns target to review_required.

- Baseline graduation requires target identity, artifact inventory, contract review summary, and acknowledged critical conflicts.

# Appendix R. Storage Growth, Quotas, Backup, and Recovery

- Content-address artifacts and compress large text evidence.

- On quota warning at 80%, suspend optional enrichment and run retention preview.

- At 95%, stop ingesting noncritical raw evidence and mark coverage gaps.

- At 100%, enter read-only safety mode; preserve audit and approvals.

- Daily SQLite online backup or PostgreSQL native backup; weekly restore test in production deployments.

- Audit chain and evidence object hashes are verified after restore.

- Maximum V1 target: 1 million LOC and 100 evidence events/second sustained on reference hardware; larger targets require explicit benchmark.

# Appendix S. Plugin and Adapter SDK

- Use process-level JSON-RPC or HTTP adapters; do not load untrusted native plugins into daemon.

- Adapter handshake declares protocol version, capabilities, target types, evidence types, and limits.

- Unknown capability is ignored; incompatible major version rejected.

- Adapter process receives least privilege, resource limits, health heartbeat, and restart budget.

- Signed plugin packages are recommended for distribution; hash always recorded.

# Appendix T. Report and Export Formats

| **Format**         | **Purpose**                                                                           |
|--------------------|---------------------------------------------------------------------------------------|
| JSON               | Complete machine-readable contracts, findings, evidence references, and verification. |
| Markdown           | Coding-agent and human implementation packet.                                         |
| SARIF              | CI and pull-request annotations for static findings.                                  |
| HTML               | Portable assurance and release report.                                                |
| Assurance manifest | Versioned claim-proof-limitation structure for audits.                                |

- Every export includes target/revision identity, BAR version, parser/model versions, generation time, evidence limitations, and content hash.

- Exports never embed secret/restricted evidence by default.

- SARIF severity maps from deterministic BAR severity and includes finding URL/fingerprint.

# Appendix U. Final V1 Definition of Done

1\. Fresh Linux installation registers a local Git repository with one pointer.

2\. Incremental scan discovers and hashes supported artifacts.

3\. Contract extraction produces exact source-linked claims with model disabled and optionally improves with a small model.

4\. Operator can resolve a documentation conflict through a versioned ruling.

5\. Rust/Python static adapters identify components, state transitions, authority checks, tests, and effects.

6\. BAR creates static findings with deterministic confidence, severity, fingerprint, and readiness.

7\. Evidence changes invalidate only dependent conclusions.

8\. Dashboard supports triage, correction, no-change, waiver, repair request, and approval.

9\. Approved repair job is available through scoped agent token in isolated worktree.

10\. Agent can challenge or request scope; material change invalidates approval.

11\. Submitted patch receives semantic contract diff and configured verification.

12\. Finding resolves only when original proof obligation is met.

13\. All models can be disabled without loss of mandatory functionality.

14\. Idle/resource-pressure benchmarks pass.

15\. Install, upgrade, database rollback, backup restore, crash recovery, audit replay, security, fuzz, and acceptance suites pass.

# Appendix V. Stable Requirement IDs and Specification Precedence

> **Purpose**
>
> Every normative requirement must be traceable to implementation, tests, and acceptance evidence. This appendix prevents coding agents from declaring broad completion without proving each obligation.

Requirement ID prefixes:  
BAR-CORE-###  
BAR-STORE-###  
BAR-DISC-###  
BAR-CONTRACT-###  
BAR-STATIC-###  
BAR-EVIDENCE-###  
BAR-FINDING-###  
BAR-REPAIR-###  
BAR-AGENT-###  
BAR-VERIFY-###  
BAR-UI-###  
BAR-SEC-###  
BAR-OPS-###  
BAR-MODEL-###  
BAR-TEST-###

| **Precedence** | **Source**                                               | **Rule**                                                  |
|----------------|----------------------------------------------------------|-----------------------------------------------------------|
| 1              | Hard invariants and explicit MUST/MUST NOT requirements  | Always controlling.                                       |
| 2              | Normative appendices and exact schemas/transition tables | Override descriptive architecture text.                   |
| 3              | Phase exit criteria                                      | Control phase completion.                                 |
| 4              | Architecture and subsystem sections                      | Guide implementation where no stricter rule exists.       |
| 5              | Examples and scenarios                                   | Illustrative only; never override normative requirements. |

- Every new requirement added after v4 receives an immutable ID.

- Requirement text may be clarified but not silently repurposed; semantic change creates a superseding ID.

- STATUS.md records implemented, tested, shadow, active, blocked, and deferred by requirement ID.

# Appendix W. Requirement Traceability Matrix Contract

TraceabilityRecord {  
requirement_id  
normative_text_hash  
phase  
crates\[\]  
database_entities\[\]  
api_endpoints\[\]  
ui_routes\[\]  
tests\[\]  
acceptance_scenarios\[\]  
implementation_status  
evidence_refs\[\]  
known_limitations\[\]  
superseded_by?  
}

| **Status**             | **Meaning**                                         |
|------------------------|-----------------------------------------------------|
| unimplemented          | No implementation evidence.                         |
| partial                | Some required behavior exists; gaps named.          |
| implemented_unverified | Code exists but required tests/evidence are absent. |
| verified               | All mapped proof obligations satisfied.             |
| shadow                 | Implemented and observed, but not authoritative.    |
| active                 | Enabled under intended authority.                   |
| blocked                | Cannot proceed until named dependency is resolved.  |
| deferred               | Explicitly outside current release scope.           |

- CI fails if a V1 MUST requirement lacks a traceability record.

- Phase completion requires all phase requirement IDs to be verified or explicitly deferred by the specification.

- Generated traceability reports must include source commit, test run, and BAR build version.

# Appendix X. Canonical Reference Fixture Repository

bar-fixture-runtime/  
├── README.md  
├── STATUS.md  
├── docs/  
│ ├── architecture.md  
│ ├── recovery.md  
│ └── stale-design.md  
├── src/  
│ ├── main.rs  
│ ├── dispatcher.rs  
│ ├── bypass.rs  
│ ├── journal.rs  
│ ├── state.rs  
│ └── retry.rs  
├── tests/  
│ ├── mocked_dispatch.rs  
│ ├── state_transitions.rs  
│ └── recovery_missing.rs  
├── config/  
│ ├── default.toml  
│ └── production.toml  
├── .bar/  
│ └── verification.toml  
└── expected/  
├── contracts.json  
├── findings.json  
├── traceability.json  
├── repair_job.json  
├── semantic_diff.json  
└── verification.json

| **Planted condition**                      | **Expected BAR interpretation**                  |
|--------------------------------------------|--------------------------------------------------|
| README says all effects pass dispatcher    | Required behavioral contract.                    |
| bypass.rs writes directly                  | High-severity bypass_path finding.               |
| mocked test passes                         | test_supported only; not live or all-path proof. |
| recovery.md promises crash recovery        | missing_implementation or unproven claim.        |
| stale-design.md references removed module  | stale documentation finding.                     |
| terminal state reopens                     | state_machine_violation.                         |
| retry path duplicates effect               | side_effect_settlement_gap.                      |
| production config validly changes behavior | Scoped exception, not contradiction.             |
| running digest mismatches source revision  | deployment_identity_gap.                         |
| malicious instruction in docs              | Treated as untrusted text; no tool effect.       |

- Golden outputs are exact for deterministic fields and tolerance-based only for approved semantic summaries.

- Every release runs the fixture from clean install through approved repair and verification.

- Mutation variants remove gates, reorder journal/effect steps, alter timeouts, and stale generated artifacts.

# Appendix Y. Golden Corpus and Adversarial Evaluation

- Maintain reviewed corpora for contract extraction, hierarchy, scope, conflicts, mappings, findings, repair packets, semantic diffs, and verification reports.

- Include deceptive documentation, copied stale architecture, dynamic dispatch, generated wrappers, feature-flag conflicts, malicious prompt injection, and misleading passing tests.

- Measure false negatives using seeded defects, not precision alone.

- Compare relevant findings against Clippy, Ruff, Semgrep, CodeQL, and language compilers where available.

- External-tool results remain typed evidence and never automatically resolve BAR findings.

| **Evaluation** | **Required output**                                                |
|----------------|--------------------------------------------------------------------|
| Extraction     | Precision, recall, source-span accuracy, normative-class accuracy. |
| Static finding | True-positive, false-positive, false-negative by finding class.    |
| Semantic diff  | Correct behavior-change classification.                            |
| Repair packet  | Human usefulness and contract completeness.                        |
| Verification   | False-resolution and missed-regression rate.                       |
| Adversarial    | Prompt-injection resistance and unsupported-reference rate.        |

# Appendix Z. Unsupported, Partial, and Opaque Coverage Semantics

| **Condition**                    | **Required BAR behavior**                                                                               |
|----------------------------------|---------------------------------------------------------------------------------------------------------|
| Unsupported language             | Inventory artifacts; mark static coverage unavailable; create blind-spot record for affected contracts. |
| Partial parse                    | Emit findings only within covered regions; cap confidence; show exact uncovered paths.                  |
| Dynamic dispatch/reflection      | Mark path uncertain; do not certify absence of bypass.                                                  |
| Opaque binary/generated artifact | Link provenance if known; do not infer source behavior.                                                 |
| Missing target identity          | Allow static analysis; block runtime proof and repair readiness requiring live identity.                |
| Missing telemetry                | Retain static/test status; state exact missing proof.                                                   |
| Unsupported feature              | Hide or disable dependent UI action and expose capability reason.                                       |

- Unsupported must never equal safe.

- Repair approval may be blocked when unsupported regions intersect protected contracts.

- Coverage percentage alone is insufficient; show affected contracts and paths.

# Appendix AA. Repository and Target Boundary Model

| **Repository role** | **Examples**                                       |
|---------------------|----------------------------------------------------|
| application         | Primary runtime source.                            |
| shared_library      | Reusable internal package.                         |
| infrastructure      | Terraform, Kubernetes, Helm, systemd.              |
| schema              | Event, API, database, or protocol definitions.     |
| deployment          | Release manifests and environment overlays.        |
| documentation       | Architecture and operational specifications.       |
| model               | Prompts, model manifests, evaluations.             |
| vendor              | Third-party or vendored code; excluded by default. |

- A target may contain multiple repositories joined by a revision bundle.

- Cross-repository approval names every writable repository and exact base revision.

- Monorepo discovery identifies workspaces, applications, libraries, infrastructure, generated code, tests, and vendored trees.

- Generated files inherit ownership from generator/source when provenance is known; repair packets target source rather than generated output.

- Build scripts, Dockerfiles, CI scripts, Makefiles, and shell scripts are inventoried in V1; Bash effect analysis is conservative and uncertainty-marked.

# Appendix AB. Configuration Resolution and Capability Graph

effective configuration precedence:  
compiled default  
\< default config file  
\< environment-specific config  
\< environment variables  
\< command-line flags  
\< authenticated runtime override

- Every effective value retains source and precedence.

- Secret-dependent paths are classified as statically reachable but runtime-disabled, enabled, or unknown.

- Environment-variable schema records required, default, sensitive, allowed values, and behavioral effect.

- Capabilities are dependency graphs; UI actions remain disabled until prerequisites exist.

Example:  
runtime_verification  
requires:  
deployment_identity  
evidence_adapter  
proof_obligation  
sufficient_coverage  
verifier_available

# Appendix AC. Assumptions, Defeaters, and Trust Transitivity

Assumption {  
assumption_id  
statement  
source_refs\[\]  
scope  
verification_status  
dependent_contracts\[\]  
expires_at?  
}  
  
Defeater {  
defeater_id  
contract_id  
statement  
evidence_refs\[\]  
status  
resolution_refs\[\]  
}

- Every high-strength assurance argument lists material assumptions and active defeaters.

- An unverified external guarantee cannot support a stronger internal proof than its own status.

- Dependency guarantees are classified as documented, contractual, observed, assumed, violated, or unknown.

- Resolving a defeater requires evidence or adjudication; hiding it from the dashboard is prohibited.

# Appendix AD. Agent Capability, Lease, Crash, and Cancellation Semantics

AgentCapability {  
languages\[\]  
tools\[\]  
git_modes\[\]  
sandbox_supported  
test_execution_supported  
patch_formats\[\]  
interactive_questions  
max_patch_bytes  
}  
  
JobLease {  
job_id  
agent_id  
fencing_token  
acquired_at  
expires_at  
heartbeat_seconds  
}

- BAR assigns no agent automatically. A human connects or selects the agent.

- Lease heartbeat default: 30 seconds; expiry default: 120 seconds.

- Expired lease suspends the job, revokes token, preserves worktree, and requires human reassignment.

- Fencing token is required on every mutation; stale agents cannot submit progress or patches.

- Cancellation during a tool action requests cooperative stop, then force-terminates sandbox after policy timeout.

- Cancellation after patch submission preserves the patch as reviewable evidence but prevents verification or merge until reauthorized.

- Automatic worker selection, job splitting, competitive patches, and autonomous retry with another agent are prohibited.

# Appendix AE. Human Approval Safety and High-Risk Policy

- Approval screen must display target, base revision, agent identity, scope, intended contract change, prohibited changes, tests, sequencing, rollback burden, expiry, and repair-risk class.

- No context-free one-click approval.

- Policy supports optional dual approval for authorization, encryption, audit-chain, destructive data, schema migration, and production configuration changes.

- Approval delegation is scope- and time-bounded, revocable, and audited.

- Emergency disable revokes all agent tokens, stops new jobs/model work/scans, preserves evidence, and leaves read-only dashboard available.

RepairRiskClass =  
local \|  
cross_component \|  
schema_affecting \|  
authority_affecting \|  
data_destructive \|  
deployment_sensitive \|  
irreversible

# Appendix AF. Startup, Shutdown, Scheduler, and Time Semantics

| **Operation**          | **Required behavior**                                                                                                                            |
|------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Safe shutdown          | Stop new work; checkpoint scans; finish/rollback transactions; revoke leases; flush audit; mark interrupted jobs.                                |
| Startup reconciliation | Resolve orphan worktrees, expired leases, unfinished scans, pending invalidations, incomplete evidence writes, stale approvals, expired waivers. |
| Scheduling clock       | Monotonic for durations/leases; UTC wall clock for records.                                                                                      |
| Clock rollback         | Never extend expired approval; record health event; monotonic jobs remain authoritative.                                                         |
| Missed scheduled work  | Run once after startup if still relevant; never duplicate.                                                                                       |
| Overlap                | Per-target scan and compaction jobs use leases and cannot overlap.                                                                               |
| Cross-target work      | Independent targets may run concurrently through bounded target-fair queues; no target can monopolize shared workers.                              |

| **Scheduled task**        | **V1 default**                          |
|---------------------------|-----------------------------------------|
| Repository watch debounce | 750 ms.                                 |
| Full integrity scan       | Daily, configurable.                    |
| Proof freshness review    | Hourly.                                 |
| Waiver/approval expiry    | Every minute.                           |
| Retention and compaction  | Daily.                                  |
| Backup                    | Daily.                                  |
| BAR health                | Every 15 seconds.                       |
| Semantic enrichment       | Queued, target-fair, resource-governed. |

# Appendix AG. Audit Atomicity and Recovery

> **Authoritative order**
>
> The relational transaction is authoritative for workflow state. Audit event payload and hash are inserted in the same database transaction. A JSONL mirror is appended asynchronously from committed rows and is not authoritative in V1.

1\. Begin database transaction.

2\. Validate transition, optimistic version, idempotency key, and prior committed audit hash.

3\. Insert audit event and state mutation in one transaction.

4\. Commit.

5\. Mirror committed audit rows to JSONL using persisted mirror cursor.

6\. Fsync mirror in bounded batches.

7\. On startup, regenerate missing mirror tail from database.

8\. Hash mismatch in authoritative database audit chain blocks all mutations and requires restore or explicit forensic mode.

- JSONL ahead of database is impossible because it mirrors only committed rows.

- Disk-full mirror failure degrades export but not authoritative workflow; health alert is critical.

- Audit key/signature rotation, if added, uses versioned key IDs and explicit rotation events.

# Appendix AH. Database Concurrency and Multi-Process Consistency

- SQLite V1 uses WAL mode, one asynchronous write coordinator, bounded read pool, 5-second busy timeout, and short read transactions.

- All background jobs use database leases with fencing tokens.

- Model workers and adapters never write workflow tables directly; they submit validated results through daemon API.

- Backups use SQLite online backup API and pause migrations, not normal reads.

- PostgreSQL mode may be added later without changing repository trait semantics.

# Appendix AI. Notification and Alert-Fatigue Policy

| **Notification**               | **Default**                                                          |
|--------------------------------|----------------------------------------------------------------------|
| Critical finding               | Immediate dashboard notification; optional configured webhook/email. |
| Approval requested             | Immediate.                                                           |
| Agent blocked or lease expired | Immediate.                                                           |
| Verification failed/regressed  | Immediate.                                                           |
| Waiver expiring                | 7 days and 1 day before expiry.                                      |
| BAR health degraded            | Immediate for critical; digest for warning.                          |
| Informational findings         | Daily digest only.                                                   |

- Notifications have delivered, viewed, acknowledged, dismissed, and escalated states separate from finding status.

- Duplicate suppression uses finding fingerprint and cooldown.

- Incident grouping and quiet periods must not suppress critical authority or audit failures.

- V1 may ship dashboard notifications only, but the schema must support webhook/email adapters.

# Appendix AJ. Dashboard Interaction and Safety Contract

Routes:  
/targets  
/targets/{id}  
/targets/{id}/contracts  
/targets/{id}/coverage  
/findings  
/findings/{id}  
/adjudications/{id}  
/repairs/{id}  
/agents  
/verifications/{id}  
/audit  
/health

- Tables use server-side pagination, filtering, sorting, and stable cursors.

- Graph views default to relevant subgraph, never entire monorepo.

- Evidence viewer escapes HTML/ANSI, disables scripts, and treats links as inert unless explicitly opened.

- Mutations use optimistic versions; stale UI receives 409 and reload prompt.

- Approval and waiver flows require confirmation summary and typed reason.

- Accessibility target: WCAG 2.1 AA for keyboard, contrast, focus, labels, and screen-reader structure.

- Mobile is read/review capable; complex graph adjudication may require desktop.

# Appendix AK. Query, Search, and Graph Cost Limits

- SQLite FTS indexes artifact path, headings, contract statements, symbols, findings, and redacted evidence summaries.

- Tokenizer preserves code symbols, snake_case, camelCase, paths, and quoted identifiers.

- Default query limit 50; maximum 500; graph traversal depth default 3, maximum 8.

- Every expensive query has timeout and cancellation.

- Restricted evidence is filtered before ranking and never leaks through snippets.

- Graph rendering clusters by component and expands on demand.

# Appendix AL. Model Locality, Auditing, Fairness, and Cache Invalidation

ModelLocalityPolicy =  
models_disabled \|  
local_only \|  
approved_remote_provider \|  
restricted_evidence_local_only

- Per-target policy controls whether source/evidence may leave the host.

- Model audit stores task, provider, model, quantization, prompt/schema versions, input/output hashes, token counts, latency, locality, and redaction status.

- Restricted prompts may store hashes and metadata without full content.

- Semantic queue uses per-target fair scheduling and bounded pending jobs.

- Cache invalidates on source, glossary, model, prompt, schema, policy, or operator-correction changes.

- User corrections may update aliases, authority classification, and false-positive patterns; they may not silently alter approval, severity, security, or proof policy.

# Appendix AM. Testing Closure: Mutation, Flakiness, and Statistical Proof

- Mutation testing must remove authorization checks, reorder journal/effect operations, delete recovery paths, reopen terminal states, alter timeouts, and stale generated schemas.

- Test provenance records command, environment, revision, dependencies, fixture, seed, output hash, and result.

- A flaky pass does not satisfy proof; repeated inconsistent results create test_quality finding.

- Statistical contracts require declared sample count, interval method, tolerated failure rate, stopping rule, and drift threshold.

- Performance proof invalidates on hardware, workload, compiler profile, dependency, model, or configuration changes.

VerificationOutcome =  
resolved \|  
partially_resolved \|  
implemented_but_unproven \|  
failed \|  
regressed \|  
unverifiable \|  
rolled_back

# Appendix AN. Data Sensitivity, Redaction, Encryption, and Export Review

| **Class**    | **Default handling**                                           |
|--------------|----------------------------------------------------------------|
| public       | May be displayed/exported.                                     |
| internal     | Local processing and authenticated display.                    |
| confidential | Local model preferred; explicit export review.                 |
| secret       | Never sent to model; redact before persistence where possible. |
| restricted   | Role-gated evidence; local-only; export prohibited by default. |

- Redaction covers API keys, passwords, tokens, private keys, connection strings, and configured PII patterns.

- Export preview lists every evidence item and classification leaving BAR.

- TLS uses rustls for remote mode.

- V1 at-rest encryption relies on encrypted host filesystem; application-level evidence encryption is deferred but schema reserves key ID.

- Air-gapped mode supports signed offline packages, local models or none, and local coding-agent bridge.

# Appendix AO. Packaging, Self-Update, Compatibility, and Deprecation

| **Artifact**             | **V1 requirement**                     |
|--------------------------|----------------------------------------|
| bar-linux-x86_64.tar.zst | Required.                              |
| Debian package           | Required for primary distribution.     |
| Linux ARM64 archive      | Secondary.                             |
| Container image          | Optional.                              |
| SBOM                     | CycloneDX or SPDX.                     |
| Checksums/signatures     | Published and verified before install. |

- BAR never self-updates silently.

- Update requires explicit operator action, signature verification, migration preview, backup, rollback point, and post-update health check.

- Support current and previous database/API/plugin major version during one documented transition window.

- Deprecation requires warning, support window, migration path, and removal version.

- Generate API, configuration, event registry, and schema references from source definitions.

# Appendix AP. Phase Completion Evidence

PhaseCompletionEvidence {  
phase  
source_revision  
changed_files\[\]  
requirement_ids_satisfied\[\]  
requirement_ids_deferred\[\]  
tests_added\[\]  
tests_run\[\]  
test_results\[\]  
fixture_results\[\]  
resource_measurements\[\]  
security_checks\[\]  
migrations\[\]  
known_limitations\[\]  
next_phase_dependencies\[\]  
signed_by_agent  
reviewed_by_human?  
}

- A coding agent cannot mark a phase complete without this record.

- Completion evidence is stored as an immutable artifact and linked from STATUS.md.

- Known limitations must name affected requirement IDs and capability impact.

- Human review is mandatory before enabling new authority, agent access, active probes, remote models, or production telemetry.

# Appendix AQ. Final Implementation Closure Checklist

1\. All V1 normative requirements have stable IDs.

2\. Traceability matrix maps every V1 requirement to code, schema, API, UI, tests, and acceptance evidence.

3\. Canonical fixture and golden corpus are versioned in repository.

4\. Unsupported and partial coverage are explicit and cannot inflate assurance.

5\. Repository, target, generated-code, configuration, and capability boundaries are deterministic.

6\. Assumptions and defeaters remain visible in assurance arguments.

7\. Agent lease, crash, cancellation, and reassignment semantics are tested.

8\. Approval UX exposes exact risk and scope; emergency disable works.

9\. Startup/shutdown, scheduler, clock, audit, and database recovery are deterministic.

10\. Notifications, UI, search, and graph queries have safety and scale limits.

11\. Model locality, auditing, fairness, and cache invalidation are implemented.

12\. Mutation, flaky-test, statistical, and performance invalidation policies are tested.

13\. Data sensitivity, export review, packaging, compatibility, and update policy are enforced.

14\. Every phase produces machine-readable completion evidence.
