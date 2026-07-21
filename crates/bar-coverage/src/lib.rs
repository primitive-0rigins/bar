//! Deterministic contract-to-static-fact traceability (Phase 6).
//!
//! A mapping exists only when a contract names a symbol in a closed Markdown
//! code span and exactly one analyzed artifact exposes that symbol. Plain prose,
//! dynamic facts, and duplicate names remain unresolved instead of becoming
//! guessed proof.

use std::collections::{BTreeMap, BTreeSet};

use bar_contract::{validate_extracted_claim, ExtractedClaim};
use bar_core::{
    ArtifactId, ContractId, Error, EvidenceKind, FreshnessPolicy, ProofId, ProofStatus, Result,
    RevisionId, Sha256Digest,
};
use bar_static::{validate_static_facts, StaticArtifactFacts, StaticTest};

/// The static fact an explicit contract reference resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TraceTargetKind {
    Symbol,
    Test,
    Configuration,
    Authority,
    State,
}

/// One unique source-bound static target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TraceTarget {
    pub artifact_id: ArtifactId,
    pub path: String,
    pub name: String,
    pub line: u32,
    pub kind: TraceTargetKind,
}

/// A resolved explicit contract reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceMapping {
    pub reference: String,
    pub target: TraceTarget,
}

/// An explicit reference deliberately left without a unique target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnresolvedReference {
    Missing {
        reference: String,
    },
    Ambiguous {
        reference: String,
        candidates: Vec<TraceTarget>,
    },
}

/// Completeness of deterministic contract-to-static-fact mapping. This is
/// deliberately separate from `bar_core::ProofStatus`: a mapped contract is
/// not thereby proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingStatus {
    Unmapped,
    Ambiguous,
    PartiallyMapped,
    Mapped,
}

/// Traceability result for one source-bound contract candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractTraceability {
    pub contract_fingerprint: Sha256Digest,
    pub status: MappingStatus,
    pub mappings: Vec<TraceMapping>,
    pub unresolved: Vec<UnresolvedReference>,
}

/// A revision-bound, caller-declared minimum evidence requirement for one
/// contract. It records the required evidence levels without inferring that a
/// trace mapping satisfies a behavioral property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofObligation {
    pub proof_id: ProofId,
    pub contract_id: ContractId,
    pub contract_fingerprint: Sha256Digest,
    pub required_evidence_levels: Vec<EvidenceKind>,
    pub freshness_revision: RevisionId,
    pub freshness_policy: FreshnessPolicy,
}

/// Result of checking only the declared mapping-level requirements. A status of
/// `Mapped` or `TestSupported` is not a claim of runtime proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofAssessment {
    pub proof_id: ProofId,
    pub contract_fingerprint: Sha256Digest,
    pub status: ProofStatus,
    pub missing_evidence_levels: Vec<EvidenceKind>,
    pub unresolved_references: Vec<String>,
}

/// Maps closed Markdown code spans in contract statements to unique static
/// symbols or tests. Every fact is validated before it can participate in a
/// trace, and duplicate names are retained as explicit ambiguity.
pub fn map_explicit_references(
    claims: &[ExtractedClaim],
    artifacts: &[StaticArtifactFacts],
) -> Result<Vec<ContractTraceability>> {
    let targets = static_targets(artifacts)?;
    for claim in claims {
        validate_extracted_claim(claim)?;
    }
    Ok(claims
        .iter()
        .map(|claim| map_claim(claim, &targets))
        .collect())
}

/// Rejects a traceability result whose declared completeness status does not
/// match its resolved and unresolved references. Consumers use this before
/// deriving findings from a trace supplied across a crate boundary.
pub fn validate_contract_traceability(traceability: &ContractTraceability) -> Result<()> {
    if traceability.status != mapping_status(&traceability.mappings, &traceability.unresolved) {
        return Err(Error::Corrupt(
            "traceability status does not match its mappings and unresolved references".into(),
        ));
    }
    let mut references = BTreeSet::new();
    for mapping in &traceability.mappings {
        validate_trace_reference(&mapping.reference, &mut references)?;
        validate_trace_target(&mapping.reference, &mapping.target)?;
    }
    for unresolved in &traceability.unresolved {
        match unresolved {
            UnresolvedReference::Missing { reference } => {
                validate_trace_reference(reference, &mut references)?;
            }
            UnresolvedReference::Ambiguous {
                reference,
                candidates,
            } => {
                validate_trace_reference(reference, &mut references)?;
                let mut distinct_candidates = BTreeSet::new();
                for candidate in candidates {
                    validate_trace_target(reference, candidate)?;
                    distinct_candidates.insert(candidate);
                }
                if distinct_candidates.len() < 2 {
                    return Err(Error::Corrupt(
                        "ambiguous traceability reference needs distinct candidates".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_trace_reference(reference: &str, references: &mut BTreeSet<String>) -> Result<()> {
    if reference.is_empty() || !references.insert(reference.to_string()) {
        return Err(Error::Corrupt(
            "traceability references must be nonempty and unique".into(),
        ));
    }
    Ok(())
}

fn validate_trace_target(reference: &str, target: &TraceTarget) -> Result<()> {
    if target.name != reference {
        return Err(Error::Corrupt(
            "traceability target does not match its explicit reference".into(),
        ));
    }
    if target.path.is_empty() || target.name.is_empty() || target.line == 0 {
        return Err(Error::Corrupt(
            "traceability target lacks source provenance".into(),
        ));
    }
    Ok(())
}

/// Evaluates an explicit trace against a declared evidence requirement. Stale
/// inputs take precedence over mapping support; unsatisfied requirements remain
/// `Unproven` rather than becoming a weaker proof claim.
///
/// Freshness depends on the obligation's [`FreshnessPolicy`]. A `Pinned`
/// obligation is fresh only at its exact declared revision. A `ReferenceStable`
/// obligation additionally stays fresh at a later revision when
/// `references_still_resolve` is `true` — the caller supplies that after
/// checking the contract's mapped references against the evaluated revision's
/// static facts (spec §400). `references_still_resolve` is ignored for `Pinned`
/// and at the declared revision.
pub fn assess_proof_obligation(
    obligation: &ProofObligation,
    traceability: &ContractTraceability,
    evaluated_revision: &RevisionId,
    references_still_resolve: bool,
) -> Result<ProofAssessment> {
    validate_proof_obligation(obligation)?;
    validate_contract_traceability(traceability)?;
    if obligation.contract_fingerprint != traceability.contract_fingerprint {
        return Err(Error::Corrupt(
            "proof obligation does not match traceability contract".into(),
        ));
    }
    let available = traceability
        .mappings
        .iter()
        .map(|mapping| evidence_kind_for(mapping.target.kind))
        .collect::<Vec<_>>();
    let missing_evidence_levels = obligation
        .required_evidence_levels
        .iter()
        .copied()
        .filter(|required| !available.contains(required))
        .collect::<Vec<_>>();
    let unresolved_references = traceability
        .unresolved
        .iter()
        .map(|reference| match reference {
            UnresolvedReference::Missing { reference }
            | UnresolvedReference::Ambiguous { reference, .. } => reference.clone(),
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let fresh = *evaluated_revision == obligation.freshness_revision
        || match obligation.freshness_policy {
            FreshnessPolicy::Pinned => false,
            FreshnessPolicy::ReferenceStable => references_still_resolve,
        };
    let status = if !fresh {
        ProofStatus::Stale
    } else if traceability.status != MappingStatus::Mapped || !missing_evidence_levels.is_empty() {
        ProofStatus::Unproven
    } else if obligation
        .required_evidence_levels
        .contains(&EvidenceKind::UnitTest)
    {
        ProofStatus::TestSupported
    } else {
        ProofStatus::Mapped
    };
    Ok(ProofAssessment {
        proof_id: obligation.proof_id,
        contract_fingerprint: obligation.contract_fingerprint,
        status,
        missing_evidence_levels,
        unresolved_references,
    })
}

/// Rejects empty or duplicate evidence-level declarations before persistence or
/// assessment.
pub fn validate_proof_obligation(obligation: &ProofObligation) -> Result<()> {
    if obligation.required_evidence_levels.is_empty() {
        return Err(Error::Corrupt(
            "proof obligation requires at least one evidence level".into(),
        ));
    }
    let unique = obligation
        .required_evidence_levels
        .iter()
        .map(|kind| kind.as_str())
        .collect::<BTreeSet<_>>();
    if unique.len() != obligation.required_evidence_levels.len() {
        return Err(Error::Corrupt(
            "proof obligation repeats an evidence level".into(),
        ));
    }
    Ok(())
}

/// Parses one closed persisted evidence token.
pub fn evidence_kind_from_token(token: &str) -> Result<EvidenceKind> {
    EvidenceKind::VARIANTS
        .iter()
        .copied()
        .find(|kind| kind.as_str() == token)
        .ok_or_else(|| Error::Corrupt(format!("unknown proof evidence kind `{token}`")))
}

/// Parses one closed persisted freshness-policy token, failing closed on an
/// unknown value.
pub fn freshness_policy_from_token(token: &str) -> Result<FreshnessPolicy> {
    FreshnessPolicy::VARIANTS
        .iter()
        .copied()
        .find(|policy| policy.as_str() == token)
        .ok_or_else(|| Error::Corrupt(format!("unknown proof freshness policy `{token}`")))
}

/// Whether every reference that resolved in `declared` still resolves to a
/// same-kind target in `evaluated`. This is the `ReferenceStable` freshness
/// check: the referenced symbols and mechanisms must still exist (spec §400).
/// Both inputs are validated before comparison.
pub fn references_still_resolve(
    declared: &ContractTraceability,
    evaluated: &ContractTraceability,
) -> Result<bool> {
    validate_contract_traceability(declared)?;
    validate_contract_traceability(evaluated)?;
    Ok(declared.mappings.iter().all(|declared_mapping| {
        evaluated.mappings.iter().any(|evaluated_mapping| {
            evaluated_mapping.reference == declared_mapping.reference
                && evaluated_mapping.target.kind == declared_mapping.target.kind
        })
    }))
}

fn evidence_kind_for(target: TraceTargetKind) -> EvidenceKind {
    match target {
        TraceTargetKind::Symbol => EvidenceKind::Code,
        TraceTargetKind::Test => EvidenceKind::UnitTest,
        TraceTargetKind::Configuration => EvidenceKind::Configuration,
        // Authority guards and state transitions are source-derived code facts;
        // the finer fact type is carried by `TraceTargetKind` itself.
        TraceTargetKind::Authority | TraceTargetKind::State => EvidenceKind::Code,
    }
}

fn static_targets(artifacts: &[StaticArtifactFacts]) -> Result<BTreeMap<String, Vec<TraceTarget>>> {
    let mut targets = BTreeMap::<String, BTreeSet<TraceTarget>>::new();
    for artifact in artifacts {
        validate_static_facts(&artifact.facts)?;
        for symbol in &artifact.facts.symbols {
            insert_target(
                &mut targets,
                &symbol.name,
                TraceTarget {
                    artifact_id: artifact.artifact_id,
                    path: symbol.path.clone(),
                    name: symbol.name.clone(),
                    line: symbol.line,
                    kind: TraceTargetKind::Symbol,
                },
            );
        }
        for test in &artifact.facts.tests {
            insert_test_target(&mut targets, artifact.artifact_id, test);
        }
        for read in artifact
            .facts
            .configuration_reads
            .iter()
            .filter_map(|read| read.key.as_deref().map(|key| (read, key)))
        {
            let (read, key) = read;
            insert_target(
                &mut targets,
                key,
                TraceTarget {
                    artifact_id: artifact.artifact_id,
                    path: read.path.clone(),
                    name: key.to_string(),
                    line: read.line,
                    kind: TraceTargetKind::Configuration,
                },
            );
        }
        for authority in &artifact.facts.authority_checks {
            insert_target(
                &mut targets,
                &authority.check,
                TraceTarget {
                    artifact_id: artifact.artifact_id,
                    path: authority.path.clone(),
                    name: authority.check.clone(),
                    line: authority.line,
                    kind: TraceTargetKind::Authority,
                },
            );
        }
        for transition in &artifact.facts.state_transitions {
            insert_target(
                &mut targets,
                &transition.state,
                TraceTarget {
                    artifact_id: artifact.artifact_id,
                    path: transition.path.clone(),
                    name: transition.state.clone(),
                    line: transition.line,
                    kind: TraceTargetKind::State,
                },
            );
        }
    }
    Ok(targets
        .into_iter()
        .map(|(name, targets)| (name, targets.into_iter().collect()))
        .collect())
}

fn insert_target(
    targets: &mut BTreeMap<String, BTreeSet<TraceTarget>>,
    name: &str,
    target: TraceTarget,
) {
    targets.entry(name.to_string()).or_default().insert(target);
}

fn insert_test_target(
    targets: &mut BTreeMap<String, BTreeSet<TraceTarget>>,
    artifact_id: ArtifactId,
    test: &StaticTest,
) {
    let candidates = targets.entry(test.symbol.clone()).or_default();
    candidates.retain(|candidate| {
        candidate.artifact_id != artifact_id
            || candidate.path != test.path
            || candidate.line != test.line
    });
    candidates.insert(TraceTarget {
        artifact_id,
        path: test.path.clone(),
        name: test.symbol.clone(),
        line: test.line,
        kind: TraceTargetKind::Test,
    });
}

fn map_claim(
    claim: &ExtractedClaim,
    targets: &BTreeMap<String, Vec<TraceTarget>>,
) -> ContractTraceability {
    let mut mappings = Vec::new();
    let mut unresolved = Vec::new();
    for reference in explicit_references(&claim.statement) {
        match targets.get(&reference).map(Vec::as_slice) {
            Some([target]) => mappings.push(TraceMapping {
                reference,
                target: target.clone(),
            }),
            Some(candidates) => unresolved.push(UnresolvedReference::Ambiguous {
                reference,
                candidates: candidates.to_vec(),
            }),
            None => unresolved.push(UnresolvedReference::Missing { reference }),
        }
    }
    let status = mapping_status(&mappings, &unresolved);
    ContractTraceability {
        contract_fingerprint: claim.fingerprint,
        status,
        mappings,
        unresolved,
    }
}

fn mapping_status(mappings: &[TraceMapping], unresolved: &[UnresolvedReference]) -> MappingStatus {
    if mappings.is_empty() {
        if unresolved
            .iter()
            .any(|reference| matches!(reference, UnresolvedReference::Ambiguous { .. }))
        {
            MappingStatus::Ambiguous
        } else {
            MappingStatus::Unmapped
        }
    } else if unresolved.is_empty() {
        MappingStatus::Mapped
    } else {
        MappingStatus::PartiallyMapped
    }
}

/// Returns the unique, closed Markdown code spans that may participate in
/// deterministic traceability for one contract statement.
pub fn explicit_references(statement: &str) -> Vec<String> {
    let mut spans = statement.split('`');
    let _ = spans.next();
    let mut references = BTreeSet::new();
    while let Some(reference) = spans.next() {
        let _ = spans.next();
        let reference = reference.trim();
        if !reference.is_empty() && !reference.chars().any(char::is_whitespace) {
            references.insert(reference.to_string());
        }
    }
    references.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use bar_contract::{claim_fingerprint, ExtractedClaim, SourceRef};
    use bar_core::{
        ArtifactId, ContractId, ContractLevel, EvidenceKind, FreshnessPolicy, NormativeKind,
        ProofId, ProofStatus, RevisionId, Sha256Digest,
    };
    use bar_static::{
        StaticArtifact, StaticArtifactFacts, StaticAuthorityCheck, StaticConfigurationRead,
        StaticFacts, StaticLanguage, StaticStateTransition, StaticSymbol, StaticTest, SymbolKind,
    };

    use super::{
        assess_proof_obligation, evidence_kind_for, freshness_policy_from_token,
        map_explicit_references, references_still_resolve, ContractTraceability, MappingStatus,
        ProofObligation, TraceMapping, TraceTarget, TraceTargetKind, UnresolvedReference,
    };

    fn artifact_id(byte: u8) -> ArtifactId {
        ArtifactId::from_digest(Sha256Digest::from_bytes([byte; 32]))
    }

    fn claim(statement: &str, byte: u8) -> ExtractedClaim {
        let source = SourceRef {
            artifact_id: artifact_id(byte),
            start_offset: 0,
            end_offset: 1,
            exact_text_sha256: Sha256Digest::from_bytes([byte; 32]),
        };
        ExtractedClaim {
            normative_kind: NormativeKind::Required,
            level: ContractLevel::Implementation,
            statement: statement.into(),
            fingerprint: claim_fingerprint(
                NormativeKind::Required,
                ContractLevel::Implementation,
                statement,
                &source,
            ),
            source,
        }
    }

    fn facts(id: ArtifactId, path: &str, name: &str, line: u32) -> StaticArtifactFacts {
        StaticArtifactFacts {
            artifact_id: id,
            facts: StaticFacts {
                artifacts: vec![StaticArtifact {
                    path: path.into(),
                    language: StaticLanguage::Rust,
                }],
                symbols: vec![StaticSymbol {
                    path: path.into(),
                    name: name.into(),
                    kind: SymbolKind::Function,
                    line,
                }],
                ..StaticFacts::default()
            },
        }
    }

    fn revision(byte: u8) -> RevisionId {
        RevisionId::from_digest(Sha256Digest::from_bytes([byte; 32]))
    }

    fn mapped_trace(fingerprint: Sha256Digest, kind: TraceTargetKind) -> ContractTraceability {
        ContractTraceability {
            contract_fingerprint: fingerprint,
            status: MappingStatus::Mapped,
            mappings: vec![TraceMapping {
                reference: "target".into(),
                target: TraceTarget {
                    artifact_id: artifact_id(1),
                    path: "src/target.rs".into(),
                    name: "target".into(),
                    line: 1,
                    kind,
                },
            }],
            unresolved: Vec::new(),
        }
    }

    #[test]
    fn maps_only_unique_explicit_code_spans() {
        let artifact = facts(artifact_id(1), "src/auth.rs", "authorize", 7);
        let traces = map_explicit_references(
            &[claim(
                "Requests MUST call `authorize`; authorize is mandatory.",
                9,
            )],
            &[artifact],
        )
        .unwrap();

        assert_eq!(traces[0].mappings.len(), 1);
        assert_eq!(traces[0].mappings[0].reference, "authorize");
        assert_eq!(traces[0].mappings[0].target.path, "src/auth.rs");
        assert_eq!(traces[0].status, MappingStatus::Mapped);
        assert!(traces[0].unresolved.is_empty());
    }

    #[test]
    fn duplicate_symbols_and_missing_references_stay_unresolved() {
        let first = facts(artifact_id(1), "src/one.rs", "serve", 3);
        let second = facts(artifact_id(2), "src/two.rs", "serve", 8);
        let traces = map_explicit_references(
            &[claim("`serve` MUST use `authorize`.", 9)],
            &[first, second],
        )
        .unwrap();

        assert!(traces[0].mappings.is_empty());
        assert_eq!(traces[0].status, MappingStatus::Ambiguous);
        assert!(matches!(
            traces[0].unresolved.as_slice(),
            [
                UnresolvedReference::Missing { reference },
                UnresolvedReference::Ambiguous { reference: ambiguous, candidates }
            ] if reference == "authorize" && ambiguous == "serve" && candidates.len() == 2
        ));
    }

    #[test]
    fn test_symbol_replaces_its_duplicate_function_target() {
        let id = artifact_id(1);
        let mut artifact = facts(id, "src/auth.rs", "test_authorize", 11);
        artifact.facts.tests.push(StaticTest {
            path: "src/auth.rs".into(),
            symbol: "test_authorize".into(),
            line: 11,
        });
        let traces =
            map_explicit_references(&[claim("`test_authorize` MUST pass.", 9)], &[artifact])
                .unwrap();

        assert_eq!(traces[0].mappings[0].target.kind, TraceTargetKind::Test);
    }

    #[test]
    fn unmapped_and_partially_mapped_are_distinct_from_proof_status() {
        let artifact = facts(artifact_id(1), "src/auth.rs", "authorize", 7);
        let traces = map_explicit_references(
            &[
                claim("Authorization is required.", 9),
                claim("`authorize` MUST precede `audit`.", 10),
            ],
            &[artifact],
        )
        .unwrap();

        assert_eq!(traces[0].status, MappingStatus::Unmapped);
        assert_eq!(traces[1].status, MappingStatus::PartiallyMapped);
        assert!(matches!(
            traces[1].unresolved.as_slice(),
            [UnresolvedReference::Missing { reference }] if reference == "audit"
        ));
    }

    #[test]
    fn literal_configuration_keys_are_traceable_but_dynamic_keys_are_not() {
        let id = artifact_id(1);
        let mut artifact = facts(id, "src/config.rs", "mode", 3);
        artifact
            .facts
            .configuration_reads
            .push(StaticConfigurationRead {
                path: "src/config.rs".into(),
                symbol: Some("mode".into()),
                access: "std::env::var".into(),
                key: Some("MODE".into()),
                line: 4,
            });
        artifact
            .facts
            .configuration_reads
            .push(StaticConfigurationRead {
                path: "src/config.rs".into(),
                symbol: Some("mode".into()),
                access: "std::env::var".into(),
                key: None,
                line: 5,
            });
        let traces =
            map_explicit_references(&[claim("`MODE` MUST be read.", 9)], &[artifact]).unwrap();

        assert_eq!(traces[0].status, MappingStatus::Mapped);
        assert_eq!(
            traces[0].mappings[0].target.kind,
            TraceTargetKind::Configuration
        );
    }

    #[test]
    fn valid_authority_and_state_facts_are_traceable() {
        // A guard and a state transition each resolve uniquely, with source
        // provenance and a code evidence origin.
        let mut artifact = facts(artifact_id(1), "src/svc.rs", "serve", 3);
        artifact.facts.authority_checks.push(StaticAuthorityCheck {
            path: "src/svc.rs".into(),
            symbol: Some("serve".into()),
            check: "require_permission".into(),
            line: 5,
        });
        artifact
            .facts
            .state_transitions
            .push(StaticStateTransition {
                path: "src/svc.rs".into(),
                symbol: Some("serve".into()),
                field: "job.state".into(),
                state: "JobState::Running".into(),
                line: 9,
            });
        let traces = map_explicit_references(
            &[claim(
                "Each write MUST pass `require_permission` then reach `JobState::Running`.",
                9,
            )],
            &[artifact],
        )
        .unwrap();

        assert_eq!(traces[0].status, MappingStatus::Mapped);
        let authority = traces[0]
            .mappings
            .iter()
            .find(|mapping| mapping.reference == "require_permission")
            .unwrap();
        assert_eq!(authority.target.kind, TraceTargetKind::Authority);
        assert_eq!(authority.target.path, "src/svc.rs");
        assert_eq!(authority.target.line, 5);
        assert_eq!(evidence_kind_for(authority.target.kind), EvidenceKind::Code);
        let state = traces[0]
            .mappings
            .iter()
            .find(|mapping| mapping.reference == "JobState::Running")
            .unwrap();
        assert_eq!(state.target.kind, TraceTargetKind::State);
        assert_eq!(state.target.line, 9);
        assert_eq!(evidence_kind_for(state.target.kind), EvidenceKind::Code);

        // The same guard used at two sites is not a unique target: ambiguous.
        let mut repeated = facts(artifact_id(2), "src/two.rs", "handle", 3);
        for line in [5, 6] {
            repeated.facts.authority_checks.push(StaticAuthorityCheck {
                path: "src/two.rs".into(),
                symbol: Some("handle".into()),
                check: "require_permission".into(),
                line,
            });
        }
        let traces = map_explicit_references(
            &[claim("Writes MUST pass `require_permission`.", 9)],
            &[repeated],
        )
        .unwrap();
        assert_eq!(traces[0].status, MappingStatus::Ambiguous);

        // A name shared by a symbol and a guard is genuinely ambiguous, not a
        // silent symbol match.
        let mut shared = facts(artifact_id(3), "src/guard.rs", "require_permission", 2);
        shared.facts.authority_checks.push(StaticAuthorityCheck {
            path: "src/guard.rs".into(),
            symbol: Some("caller".into()),
            check: "require_permission".into(),
            line: 8,
        });
        let traces = map_explicit_references(
            &[claim("Writes MUST pass `require_permission`.", 9)],
            &[shared],
        )
        .unwrap();
        assert_eq!(traces[0].status, MappingStatus::Ambiguous);

        // The same recurrence rule holds for a state reached at two sites.
        let mut restate = facts(artifact_id(4), "src/state.rs", "advance", 3);
        for line in [7, 12] {
            restate.facts.state_transitions.push(StaticStateTransition {
                path: "src/state.rs".into(),
                symbol: Some("advance".into()),
                field: "job.state".into(),
                state: "JobState::Running".into(),
                line,
            });
        }
        let traces = map_explicit_references(
            &[claim("The job MUST reach `JobState::Running`.", 9)],
            &[restate],
        )
        .unwrap();
        assert_eq!(traces[0].status, MappingStatus::Ambiguous);
    }

    #[test]
    fn source_bound_toml_keys_are_traceable_as_configuration() {
        let id = artifact_id(1);
        let artifact = StaticArtifactFacts {
            artifact_id: id,
            facts: StaticFacts {
                artifacts: vec![StaticArtifact {
                    path: "config/runtime.toml".into(),
                    language: StaticLanguage::Toml,
                }],
                configuration_reads: vec![StaticConfigurationRead {
                    path: "config/runtime.toml".into(),
                    symbol: None,
                    access: "toml".into(),
                    key: Some("server.port".into()),
                    line: 2,
                }],
                ..StaticFacts::default()
            },
        };
        let traces =
            map_explicit_references(&[claim("Server MUST set `server.port`.", 9)], &[artifact])
                .unwrap();

        assert_eq!(traces[0].status, MappingStatus::Mapped);
        assert_eq!(traces[0].mappings[0].target.path, "config/runtime.toml");
        assert_eq!(
            traces[0].mappings[0].target.kind,
            TraceTargetKind::Configuration
        );
    }

    #[test]
    fn duplicate_json_key_spellings_remain_ambiguous() {
        let artifact = StaticArtifactFacts {
            artifact_id: artifact_id(1),
            facts: bar_static::analyze_artifact(
                "config/runtime.json",
                "{\n  \"server\": { \"port\": 8080 },\n  \"metrics\": { \"port\": 9090 }\n}\n",
            )
            .unwrap(),
        };
        let traces =
            map_explicit_references(&[claim("Runtime MUST set `port`.", 9)], &[artifact]).unwrap();

        assert_eq!(traces[0].status, MappingStatus::Ambiguous);
        assert!(matches!(
            traces[0].unresolved.as_slice(),
            [UnresolvedReference::Ambiguous { reference, candidates }]
                if reference == "port" && candidates.len() == 2
        ));
    }

    #[test]
    fn traceability_validation_rejects_forged_or_insufficient_targets() {
        let contract = Sha256Digest::from_bytes([9; 32]);
        let mut duplicate = mapped_trace(contract, TraceTargetKind::Symbol);
        duplicate.mappings.push(duplicate.mappings[0].clone());
        assert!(super::validate_contract_traceability(&duplicate).is_err());

        let mut mismatched = mapped_trace(contract, TraceTargetKind::Symbol);
        mismatched.mappings[0].target.name = "other".into();
        assert!(super::validate_contract_traceability(&mismatched).is_err());

        let one_candidate_ambiguity = ContractTraceability {
            contract_fingerprint: contract,
            status: MappingStatus::Ambiguous,
            mappings: Vec::new(),
            unresolved: vec![UnresolvedReference::Ambiguous {
                reference: "authorize".into(),
                candidates: vec![TraceTarget {
                    artifact_id: artifact_id(1),
                    path: "src/auth.rs".into(),
                    name: "authorize".into(),
                    line: 1,
                    kind: TraceTargetKind::Symbol,
                }],
            }],
        };
        assert!(super::validate_contract_traceability(&one_candidate_ambiguity).is_err());
    }

    #[test]
    fn proof_assessment_rejects_inconsistent_traceability() {
        let contract = Sha256Digest::from_bytes([9; 32]);
        let obligation = ProofObligation {
            proof_id: ProofId::generate(),
            contract_id: ContractId::generate(),
            contract_fingerprint: contract,
            required_evidence_levels: vec![EvidenceKind::Code],
            freshness_revision: revision(1),
            freshness_policy: FreshnessPolicy::Pinned,
        };
        let mut traceability = mapped_trace(contract, TraceTargetKind::Symbol);
        traceability.status = MappingStatus::Unmapped;
        assert!(assess_proof_obligation(&obligation, &traceability, &revision(1), false).is_err());
    }

    #[test]
    fn proof_requirements_enforce_evidence_levels_without_claiming_static_proof() {
        let contract = Sha256Digest::from_bytes([9; 32]);
        let obligation = ProofObligation {
            proof_id: ProofId::generate(),
            contract_id: ContractId::generate(),
            contract_fingerprint: contract,
            required_evidence_levels: vec![EvidenceKind::Code, EvidenceKind::UnitTest],
            freshness_revision: revision(1),
            freshness_policy: FreshnessPolicy::Pinned,
        };
        let code_only = assess_proof_obligation(
            &obligation,
            &mapped_trace(contract, TraceTargetKind::Symbol),
            &revision(1),
            false,
        )
        .unwrap();
        assert_eq!(code_only.status, ProofStatus::Unproven);
        assert_eq!(code_only.missing_evidence_levels, [EvidenceKind::UnitTest]);

        let test_only = ProofObligation {
            required_evidence_levels: vec![EvidenceKind::UnitTest],
            ..obligation
        };
        let test = assess_proof_obligation(
            &test_only,
            &mapped_trace(contract, TraceTargetKind::Test),
            &revision(1),
            false,
        )
        .unwrap();
        assert_eq!(test.status, ProofStatus::TestSupported);

        let partial = ContractTraceability {
            contract_fingerprint: contract,
            status: MappingStatus::PartiallyMapped,
            mappings: vec![TraceMapping {
                reference: "target".into(),
                target: TraceTarget {
                    artifact_id: artifact_id(1),
                    path: "src/target.rs".into(),
                    name: "target".into(),
                    line: 1,
                    kind: TraceTargetKind::Symbol,
                },
            }],
            unresolved: vec![UnresolvedReference::Missing {
                reference: "audit".into(),
            }],
        };
        let partial_assessment = assess_proof_obligation(
            &ProofObligation {
                required_evidence_levels: vec![EvidenceKind::Code],
                ..obligation
            },
            &partial,
            &revision(1),
            false,
        )
        .unwrap();
        assert_eq!(partial_assessment.status, ProofStatus::Unproven);
        assert!(partial_assessment.missing_evidence_levels.is_empty());
        assert_eq!(partial_assessment.unresolved_references, ["audit"]);
    }

    #[test]
    fn stale_revision_and_invalid_requirements_fail_safe() {
        let contract = Sha256Digest::from_bytes([9; 32]);
        let obligation = ProofObligation {
            proof_id: ProofId::generate(),
            contract_id: ContractId::generate(),
            contract_fingerprint: contract,
            required_evidence_levels: vec![EvidenceKind::Configuration],
            freshness_revision: revision(1),
            freshness_policy: FreshnessPolicy::Pinned,
        };
        let stale = assess_proof_obligation(
            &obligation,
            &mapped_trace(contract, TraceTargetKind::Configuration),
            &revision(2),
            false,
        )
        .unwrap();
        assert_eq!(stale.status, ProofStatus::Stale);

        let invalid = ProofObligation {
            required_evidence_levels: Vec::new(),
            ..obligation
        };
        assert!(assess_proof_obligation(
            &invalid,
            &mapped_trace(contract, TraceTargetKind::Configuration),
            &revision(1),
            false,
        )
        .is_err());
    }

    #[test]
    fn reference_stable_policy_stays_fresh_while_references_resolve() {
        let contract = Sha256Digest::from_bytes([9; 32]);
        let obligation = ProofObligation {
            proof_id: ProofId::generate(),
            contract_id: ContractId::generate(),
            contract_fingerprint: contract,
            required_evidence_levels: vec![EvidenceKind::Code],
            freshness_revision: revision(1),
            freshness_policy: FreshnessPolicy::ReferenceStable,
        };
        let declared = mapped_trace(contract, TraceTargetKind::Symbol);

        // The reference still resolves at a later revision: not stale.
        let evaluated_same = mapped_trace(contract, TraceTargetKind::Symbol);
        let stable = references_still_resolve(&declared, &evaluated_same).unwrap();
        assert!(stable);
        let fresh = assess_proof_obligation(&obligation, &declared, &revision(2), stable).unwrap();
        assert_eq!(fresh.status, ProofStatus::Mapped);

        // The reference no longer resolves: stale.
        let evaluated_missing = ContractTraceability {
            contract_fingerprint: contract,
            status: MappingStatus::Unmapped,
            mappings: Vec::new(),
            unresolved: vec![UnresolvedReference::Missing {
                reference: "target".into(),
            }],
        };
        let unstable = references_still_resolve(&declared, &evaluated_missing).unwrap();
        assert!(!unstable);
        let stale =
            assess_proof_obligation(&obligation, &declared, &revision(2), unstable).unwrap();
        assert_eq!(stale.status, ProofStatus::Stale);

        // Resolving to a different target kind is not stability.
        let evaluated_kind = mapped_trace(contract, TraceTargetKind::Test);
        assert!(!references_still_resolve(&declared, &evaluated_kind).unwrap());

        // A pinned obligation ignores reference stability and is stale off-revision.
        let pinned = ProofObligation {
            freshness_policy: FreshnessPolicy::Pinned,
            ..obligation
        };
        let pinned_stale = assess_proof_obligation(&pinned, &declared, &revision(2), true).unwrap();
        assert_eq!(pinned_stale.status, ProofStatus::Stale);

        // Persisted freshness tokens round-trip and fail closed on the unknown.
        assert_eq!(
            freshness_policy_from_token("reference_stable").unwrap(),
            FreshnessPolicy::ReferenceStable
        );
        assert!(freshness_policy_from_token("bogus").is_err());

        // Stability requires *every* reference to survive: if one of two
        // references disappears, the proof is no longer reference-stable.
        let symbol = |name: &str, line: u32| TraceMapping {
            reference: name.into(),
            target: TraceTarget {
                artifact_id: artifact_id(1),
                path: "src/a.rs".into(),
                name: name.into(),
                line,
                kind: TraceTargetKind::Symbol,
            },
        };
        let two_references = ContractTraceability {
            contract_fingerprint: contract,
            status: MappingStatus::Mapped,
            mappings: vec![symbol("authorize", 1), symbol("audit", 2)],
            unresolved: Vec::new(),
        };
        let one_survives = ContractTraceability {
            contract_fingerprint: contract,
            status: MappingStatus::PartiallyMapped,
            mappings: vec![symbol("authorize", 1)],
            unresolved: vec![UnresolvedReference::Missing {
                reference: "audit".into(),
            }],
        };
        assert!(!references_still_resolve(&two_references, &one_survives).unwrap());
        assert!(references_still_resolve(&two_references, &two_references).unwrap());
    }
}
