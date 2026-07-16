//! Deterministic contract-to-static-fact traceability (Phase 6).
//!
//! A mapping exists only when a contract names a symbol in a closed Markdown
//! code span and exactly one analyzed artifact exposes that symbol. Plain prose,
//! dynamic facts, and duplicate names remain unresolved instead of becoming
//! guessed proof.

use std::collections::{BTreeMap, BTreeSet};

use bar_contract::{validate_extracted_claim, ExtractedClaim};
use bar_core::{
    ArtifactId, ContractId, Error, EvidenceKind, ProofId, ProofStatus, Result, RevisionId,
    Sha256Digest,
};
use bar_static::{validate_static_facts, StaticArtifactFacts, StaticTest};

/// The static fact an explicit contract reference resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TraceTargetKind {
    Symbol,
    Test,
    Configuration,
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
}

/// Result of checking only the declared mapping-level requirements. A status of
/// `Mapped` or `TestSupported` is not a claim of runtime proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofAssessment {
    pub proof_id: ProofId,
    pub contract_fingerprint: Sha256Digest,
    pub status: ProofStatus,
    pub missing_evidence_levels: Vec<EvidenceKind>,
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

/// Evaluates an explicit trace against a declared, exact-revision evidence
/// requirement. Stale inputs take precedence over mapping support; unsatisfied
/// requirements remain `Unproven` rather than becoming a weaker proof claim.
pub fn assess_proof_obligation(
    obligation: &ProofObligation,
    traceability: &ContractTraceability,
    evaluated_revision: &RevisionId,
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
    let status = if obligation.freshness_revision != *evaluated_revision {
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

fn evidence_kind_for(target: TraceTargetKind) -> EvidenceKind {
    match target {
        TraceTargetKind::Symbol => EvidenceKind::Code,
        TraceTargetKind::Test => EvidenceKind::UnitTest,
        TraceTargetKind::Configuration => EvidenceKind::Configuration,
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
        ArtifactId, ContractId, ContractLevel, EvidenceKind, NormativeKind, ProofId, ProofStatus,
        RevisionId, Sha256Digest,
    };
    use bar_static::{
        StaticArtifact, StaticArtifactFacts, StaticConfigurationRead, StaticFacts, StaticLanguage,
        StaticSymbol, StaticTest, SymbolKind,
    };

    use super::{
        assess_proof_obligation, map_explicit_references, ContractTraceability, MappingStatus,
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
        };
        let mut traceability = mapped_trace(contract, TraceTargetKind::Symbol);
        traceability.status = MappingStatus::Unmapped;
        assert!(assess_proof_obligation(&obligation, &traceability, &revision(1)).is_err());
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
        };
        let code_only = assess_proof_obligation(
            &obligation,
            &mapped_trace(contract, TraceTargetKind::Symbol),
            &revision(1),
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
        )
        .unwrap();
        assert_eq!(partial_assessment.status, ProofStatus::Unproven);
        assert!(partial_assessment.missing_evidence_levels.is_empty());
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
        };
        let stale = assess_proof_obligation(
            &obligation,
            &mapped_trace(contract, TraceTargetKind::Configuration),
            &revision(2),
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
        )
        .is_err());
    }
}
