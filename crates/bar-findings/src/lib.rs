//! Deterministic shadow static-finding candidates (Phase 7 foundation).
//!
//! The first detector reports a missing implementation only when a contract
//! explicitly names a target and validated static traceability says that target
//! is absent. Ambiguity and prose-only contracts remain coverage gaps, not
//! findings.

use std::collections::{BTreeMap, BTreeSet};

use bar_contract::{ExtractedClaim, SourceRef};
use bar_core::{ContractId, Error, Result, Sha256Digest};
use bar_coverage::{validate_contract_traceability, ContractTraceability, UnresolvedReference};
use sha2::{Digest, Sha256};

/// A source-bound contract paired with its deterministic traceability result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceableContract {
    pub contract_id: ContractId,
    pub claim: ExtractedClaim,
    pub traceability: ContractTraceability,
}

/// The closed set of shadow static detector classes implemented so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticFindingKind {
    MissingImplementation,
}

impl StaticFindingKind {
    /// Stable token for durable storage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingImplementation => "missing_implementation",
        }
    }

    /// Parses only currently implemented static detector classes.
    pub fn from_token(token: &str) -> Result<Self> {
        match token {
            "missing_implementation" => Ok(Self::MissingImplementation),
            _ => Err(Error::Corrupt(format!(
                "unknown static finding kind `{token}`"
            ))),
        }
    }
}

/// A deterministic, source-bound candidate. It is not a persisted finding and
/// has no authority to trigger repair or lifecycle transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticFindingCandidate {
    pub fingerprint: Sha256Digest,
    pub kind: StaticFindingKind,
    pub contract_id: ContractId,
    pub contract_fingerprint: Sha256Digest,
    pub source: SourceRef,
    pub missing_references: Vec<String>,
}

/// Revalidates a candidate before it crosses into durable storage. Only the
/// implemented missing-implementation class is accepted, with a canonical
/// reference set and its deterministic fingerprint.
pub fn validate_static_finding_candidate(candidate: &StaticFindingCandidate) -> Result<()> {
    if candidate.kind != StaticFindingKind::MissingImplementation
        || candidate.missing_references.is_empty()
        || candidate
            .missing_references
            .iter()
            .any(|reference| reference.is_empty())
        || !candidate
            .missing_references
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(Error::Corrupt(
            "static finding candidate has an invalid kind or missing-reference set".into(),
        ));
    }
    let expected = missing_implementation_fingerprint(
        candidate.contract_id,
        candidate.contract_fingerprint,
        &candidate.source,
        &candidate.missing_references,
    );
    if candidate.fingerprint != expected {
        return Err(Error::Corrupt(
            "static finding candidate fingerprint does not match its contents".into(),
        ));
    }
    Ok(())
}

/// Reports one candidate per contract with one or more explicit targets absent
/// from validated static traceability. The output and its fingerprints are
/// stable across input ordering.
pub fn detect_missing_implementations(
    contracts: &[TraceableContract],
) -> Result<Vec<StaticFindingCandidate>> {
    let mut seen_contracts = BTreeSet::new();
    let mut candidates = BTreeMap::new();
    for contract in contracts {
        if !seen_contracts.insert(contract.contract_id) {
            return Err(Error::Corrupt(
                "static finding input repeats a contract".into(),
            ));
        }
        if contract.claim.fingerprint != contract.traceability.contract_fingerprint {
            return Err(Error::Corrupt(
                "static finding traceability does not match its contract".into(),
            ));
        }
        validate_contract_traceability(&contract.traceability)?;
        let missing_references = contract
            .traceability
            .unresolved
            .iter()
            .filter_map(|reference| match reference {
                UnresolvedReference::Missing { reference } => Some(reference.clone()),
                UnresolvedReference::Ambiguous { .. } => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if missing_references.is_empty() {
            continue;
        }
        let candidate = StaticFindingCandidate {
            fingerprint: missing_implementation_fingerprint(
                contract.contract_id,
                contract.claim.fingerprint,
                &contract.claim.source,
                &missing_references,
            ),
            kind: StaticFindingKind::MissingImplementation,
            contract_id: contract.contract_id,
            contract_fingerprint: contract.claim.fingerprint,
            source: contract.claim.source.clone(),
            missing_references,
        };
        validate_static_finding_candidate(&candidate)?;
        candidates.insert(contract.contract_id, candidate);
    }
    Ok(candidates.into_values().collect())
}

fn missing_implementation_fingerprint(
    contract_id: ContractId,
    contract_fingerprint: Sha256Digest,
    source: &SourceRef,
    missing_references: &[String],
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, b"missing_implementation");
    hash_part(&mut hasher, contract_id.to_string().as_bytes());
    hash_part(&mut hasher, contract_fingerprint.to_string().as_bytes());
    hash_part(&mut hasher, source.artifact_id.to_string().as_bytes());
    hash_part(&mut hasher, &source.start_offset.to_be_bytes());
    hash_part(&mut hasher, &source.end_offset.to_be_bytes());
    hash_part(&mut hasher, source.exact_text_sha256.to_string().as_bytes());
    for reference in missing_references {
        hash_part(&mut hasher, reference.as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use bar_contract::{ExtractedClaim, SourceRef};
    use bar_core::{ArtifactId, ContractLevel, NormativeKind, Sha256Digest};
    use bar_coverage::{MappingStatus, TraceTarget, TraceTargetKind, UnresolvedReference};

    use super::{
        detect_missing_implementations, validate_static_finding_candidate, ContractTraceability,
        TraceableContract,
    };

    fn contract(
        statement: &str,
        byte: u8,
        unresolved: Vec<UnresolvedReference>,
    ) -> TraceableContract {
        let fingerprint = Sha256Digest::from_bytes([byte; 32]);
        let status = if unresolved
            .iter()
            .any(|reference| matches!(reference, UnresolvedReference::Ambiguous { .. }))
        {
            MappingStatus::Ambiguous
        } else {
            MappingStatus::Unmapped
        };
        TraceableContract {
            contract_id: bar_core::ContractId::generate(),
            claim: ExtractedClaim {
                normative_kind: NormativeKind::Required,
                level: ContractLevel::Implementation,
                statement: statement.into(),
                source: SourceRef {
                    artifact_id: ArtifactId::from_digest(Sha256Digest::from_bytes([byte; 32])),
                    start_offset: 3,
                    end_offset: 9,
                    exact_text_sha256: fingerprint,
                },
                fingerprint,
            },
            traceability: ContractTraceability {
                contract_fingerprint: fingerprint,
                status,
                mappings: Vec::new(),
                unresolved,
            },
        }
    }

    #[test]
    fn explicit_missing_references_aggregate_into_one_source_bound_candidate() {
        let input = contract(
            "`authorize` and `audit` are required.",
            1,
            vec![
                UnresolvedReference::Missing {
                    reference: "authorize".into(),
                },
                UnresolvedReference::Missing {
                    reference: "audit".into(),
                },
            ],
        );
        let candidates = detect_missing_implementations(std::slice::from_ref(&input)).unwrap();

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].contract_id, input.contract_id);
        assert_eq!(candidates[0].source, input.claim.source);
        assert_eq!(candidates[0].missing_references, ["audit", "authorize"]);
        assert_eq!(
            candidates,
            detect_missing_implementations(&[input]).unwrap()
        );
        let mut tampered = candidates[0].clone();
        tampered.missing_references.reverse();
        assert!(validate_static_finding_candidate(&tampered).is_err());
        tampered = candidates[0].clone();
        tampered.fingerprint = Sha256Digest::from_bytes([9; 32]);
        assert!(validate_static_finding_candidate(&tampered).is_err());
        tampered = candidates[0].clone();
        tampered.source.exact_text_sha256 = Sha256Digest::from_bytes([9; 32]);
        assert!(validate_static_finding_candidate(&tampered).is_err());
    }

    #[test]
    fn prose_only_and_ambiguous_contracts_do_not_become_findings() {
        let prose = contract("Authorization is required.", 1, Vec::new());
        let ambiguous = contract(
            "`authorize` is required.",
            2,
            vec![UnresolvedReference::Ambiguous {
                reference: "authorize".into(),
                candidates: vec![
                    TraceTarget {
                        artifact_id: ArtifactId::from_digest(Sha256Digest::from_bytes([2; 32])),
                        path: "src/auth.rs".into(),
                        name: "authorize".into(),
                        line: 1,
                        kind: TraceTargetKind::Symbol,
                    },
                    TraceTarget {
                        artifact_id: ArtifactId::from_digest(Sha256Digest::from_bytes([3; 32])),
                        path: "src/legacy_auth.rs".into(),
                        name: "authorize".into(),
                        line: 1,
                        kind: TraceTargetKind::Symbol,
                    },
                ],
            }],
        );

        assert!(detect_missing_implementations(&[prose, ambiguous])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn mismatched_or_duplicate_contract_input_fails_closed() {
        let mut mismatched = contract(
            "`authorize` is required.",
            1,
            vec![UnresolvedReference::Missing {
                reference: "authorize".into(),
            }],
        );
        mismatched.traceability.contract_fingerprint = Sha256Digest::from_bytes([2; 32]);
        assert!(detect_missing_implementations(&[mismatched]).is_err());

        let repeated = contract(
            "`authorize` is required.",
            1,
            vec![UnresolvedReference::Missing {
                reference: "authorize".into(),
            }],
        );
        assert!(detect_missing_implementations(&[repeated.clone(), repeated]).is_err());

        let mut inconsistent = contract(
            "`authorize` is required.",
            3,
            vec![UnresolvedReference::Missing {
                reference: "authorize".into(),
            }],
        );
        inconsistent.traceability.status = MappingStatus::Mapped;
        assert!(detect_missing_implementations(&[inconsistent]).is_err());
    }

    #[test]
    fn finding_kind_token_is_closed() {
        assert_eq!(
            super::StaticFindingKind::from_token("missing_implementation").unwrap(),
            super::StaticFindingKind::MissingImplementation
        );
        assert!(super::StaticFindingKind::from_token("forged").is_err());
    }
}
