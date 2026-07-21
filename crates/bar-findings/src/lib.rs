//! Deterministic shadow static-finding candidates (Phase 7 foundation).
//!
//! The first detector reports a missing implementation only when a contract
//! explicitly names a target and validated static traceability says that target
//! is absent. Ambiguity and prose-only contracts remain coverage gaps, not
//! findings.

use std::collections::{BTreeMap, BTreeSet};

use bar_contract::{validate_extracted_claim, ExtractedClaim, SourceRef};
use bar_core::{ContractId, Error, NormativeKind, Result, Sha256Digest};
use bar_coverage::{
    explicit_references, validate_contract_traceability, ContractTraceability, UnresolvedReference,
};
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

/// A stable, revision-independent finding aggregated from one or more candidate
/// occurrences. Its identity (spec Appendix H.5) is derived from the finding
/// class, the contract's revision-stable cited-text hash, and the normalized
/// missing-reference set — never a revision-scoped contract or artifact id — so
/// the same symptom seen at different revisions is one finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticFinding {
    pub finding_fingerprint: Sha256Digest,
    pub kind: StaticFindingKind,
    pub contract_exact_text_sha256: Sha256Digest,
    pub missing_references: Vec<String>,
}

/// A stable, revision-independent contradiction finding: two directly opposing
/// contract claims (one `required`, one `prohibited`) over the same normalized
/// subject. Its identity (spec Appendix H.5) is the finding class, the two
/// claims' revision-stable cited-text hashes sorted so the pair order is
/// irrelevant, and the shared subject — never a revision-scoped contract id — so
/// the same conflict aggregates across revisions. It is provisional by
/// construction: the static layer cannot see contract scope, so an apparent
/// contradiction may be a scoped exception (spec §"scoped exception, not
/// contradiction") an operator corrects as a false positive; it is never a
/// definitive contradiction label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContradictionFinding {
    pub finding_fingerprint: Sha256Digest,
    /// The lexicographically smaller of the two claims' cited-text hashes.
    pub left_exact_text_sha256: Sha256Digest,
    /// The lexicographically larger of the two claims' cited-text hashes.
    pub right_exact_text_sha256: Sha256Digest,
    pub shared_subject: String,
}

/// Builds a contradiction finding from the two opposing claims' revision-stable
/// cited-text hashes and their shared subject. The pair is sorted so the finding
/// identity is independent of which claim is "left", then revalidated.
pub fn contradiction_finding(
    one_exact_text_sha256: Sha256Digest,
    other_exact_text_sha256: Sha256Digest,
    shared_subject: &str,
) -> Result<ContradictionFinding> {
    let (left, right) = if one_exact_text_sha256 <= other_exact_text_sha256 {
        (one_exact_text_sha256, other_exact_text_sha256)
    } else {
        (other_exact_text_sha256, one_exact_text_sha256)
    };
    let finding = ContradictionFinding {
        finding_fingerprint: contradiction_fingerprint(left, right, shared_subject),
        left_exact_text_sha256: left,
        right_exact_text_sha256: right,
        shared_subject: shared_subject.to_string(),
    };
    validate_contradiction_finding(&finding)?;
    Ok(finding)
}

/// Revalidates a contradiction finding before it crosses into durable storage or
/// review: a nonempty subject, a sorted cited-text pair, and a fingerprint that
/// matches its contents. Fails closed.
pub fn validate_contradiction_finding(finding: &ContradictionFinding) -> Result<()> {
    if finding.shared_subject.is_empty()
        || finding.left_exact_text_sha256 > finding.right_exact_text_sha256
    {
        return Err(Error::Corrupt(
            "contradiction finding has an empty subject or unordered claim pair".into(),
        ));
    }
    let expected = contradiction_fingerprint(
        finding.left_exact_text_sha256,
        finding.right_exact_text_sha256,
        &finding.shared_subject,
    );
    if finding.finding_fingerprint != expected {
        return Err(Error::Corrupt(
            "contradiction finding fingerprint does not match its contents".into(),
        ));
    }
    Ok(())
}

/// Promotes one validated candidate into its stable finding identity. The
/// candidate is revalidated first, so a forged candidate cannot mint a finding.
pub fn promote_candidate(candidate: &StaticFindingCandidate) -> Result<StaticFinding> {
    validate_static_finding_candidate(candidate)?;
    let finding = StaticFinding {
        finding_fingerprint: finding_fingerprint(
            candidate.kind,
            candidate.source.exact_text_sha256,
            &candidate.missing_references,
        ),
        kind: candidate.kind,
        contract_exact_text_sha256: candidate.source.exact_text_sha256,
        missing_references: candidate.missing_references.clone(),
    };
    validate_static_finding(&finding)?;
    Ok(finding)
}

/// Revalidates a finding before it crosses into durable storage or review: a
/// nonempty, sorted, unique reference set and a fingerprint that matches its
/// contents.
pub fn validate_static_finding(finding: &StaticFinding) -> Result<()> {
    if finding.missing_references.is_empty()
        || finding
            .missing_references
            .iter()
            .any(|reference| reference.is_empty())
        || !finding
            .missing_references
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(Error::Corrupt(
            "static finding has an invalid missing-reference set".into(),
        ));
    }
    let expected = finding_fingerprint(
        finding.kind,
        finding.contract_exact_text_sha256,
        &finding.missing_references,
    );
    if finding.finding_fingerprint != expected {
        return Err(Error::Corrupt(
            "static finding fingerprint does not match its contents".into(),
        ));
    }
    Ok(())
}

/// Revalidates a candidate before it crosses into durable storage. Only the
/// implemented missing-implementation class is accepted, with a canonical
/// reference set and its deterministic fingerprint.
pub fn validate_static_finding_candidate(candidate: &StaticFindingCandidate) -> Result<()> {
    if candidate.kind != StaticFindingKind::MissingImplementation
        || candidate.source.start_offset >= candidate.source.end_offset
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
        validate_extracted_claim(&contract.claim)?;
        if contract.claim.fingerprint != contract.traceability.contract_fingerprint {
            return Err(Error::Corrupt(
                "static finding traceability does not match its contract".into(),
            ));
        }
        validate_contract_traceability(&contract.traceability)?;
        let traced_references = contract
            .traceability
            .mappings
            .iter()
            .map(|mapping| mapping.reference.clone())
            .chain(
                contract
                    .traceability
                    .unresolved
                    .iter()
                    .map(|reference| match reference {
                        UnresolvedReference::Missing { reference }
                        | UnresolvedReference::Ambiguous { reference, .. } => reference.clone(),
                    }),
            )
            .collect::<BTreeSet<_>>();
        if traced_references
            != explicit_references(&contract.claim.statement)
                .into_iter()
                .collect()
        {
            return Err(Error::Corrupt(
                "static finding traceability references do not match its contract".into(),
            ));
        }
        if contract.claim.normative_kind != NormativeKind::Required {
            continue;
        }
        if contract
            .traceability
            .unresolved
            .iter()
            .any(|reference| matches!(reference, UnresolvedReference::Ambiguous { .. }))
        {
            continue;
        }
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

/// The stable finding identity (spec Appendix H.5): class, the contract's
/// revision-stable cited-text hash, and the sorted missing-reference set. It
/// excludes the revision-scoped contract/artifact ids and byte offsets, so the
/// same symptom aggregates across revisions while a changed statement or
/// reference set is a new finding.
fn finding_fingerprint(
    kind: StaticFindingKind,
    contract_exact_text_sha256: Sha256Digest,
    missing_references: &[String],
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, b"static_finding");
    hash_part(&mut hasher, kind.as_str().as_bytes());
    hash_part(
        &mut hasher,
        contract_exact_text_sha256.to_string().as_bytes(),
    );
    for reference in missing_references {
        hash_part(&mut hasher, reference.as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

/// The stable contradiction identity (spec Appendix H.5): the
/// `contract_contradiction` class (spec §"FindingClass"), the two claims'
/// revision-stable cited-text hashes (already sorted by the caller), and the
/// shared subject. The distinct class token domain-separates it from a
/// missing-implementation fingerprint, so the two can never collide.
fn contradiction_fingerprint(
    left_exact_text_sha256: Sha256Digest,
    right_exact_text_sha256: Sha256Digest,
    shared_subject: &str,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, b"static_finding");
    hash_part(&mut hasher, b"contract_contradiction");
    hash_part(&mut hasher, left_exact_text_sha256.to_string().as_bytes());
    hash_part(&mut hasher, right_exact_text_sha256.to_string().as_bytes());
    hash_part(&mut hasher, shared_subject.as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use bar_contract::{claim_fingerprint, ExtractedClaim, SourceRef};
    use bar_core::{ArtifactId, ContractLevel, NormativeKind, Sha256Digest};
    use bar_coverage::{MappingStatus, TraceTarget, TraceTargetKind, UnresolvedReference};

    use super::{
        detect_missing_implementations, promote_candidate, validate_static_finding,
        validate_static_finding_candidate, ContractTraceability, TraceableContract,
    };

    fn contract(
        statement: &str,
        byte: u8,
        unresolved: Vec<UnresolvedReference>,
    ) -> TraceableContract {
        let source = SourceRef {
            artifact_id: ArtifactId::from_digest(Sha256Digest::from_bytes([byte; 32])),
            start_offset: 3,
            end_offset: 9,
            exact_text_sha256: Sha256Digest::from_bytes([byte; 32]),
        };
        let fingerprint = claim_fingerprint(
            NormativeKind::Required,
            ContractLevel::Implementation,
            statement,
            &source,
        );
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
                source,
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
        tampered = candidates[0].clone();
        tampered.source.end_offset = tampered.source.start_offset;
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
        let mixed = contract(
            "`authorize` and `audit` are required.",
            4,
            vec![
                UnresolvedReference::Missing {
                    reference: "audit".into(),
                },
                UnresolvedReference::Ambiguous {
                    reference: "authorize".into(),
                    candidates: vec![
                        TraceTarget {
                            artifact_id: ArtifactId::from_digest(Sha256Digest::from_bytes([4; 32])),
                            path: "src/auth.rs".into(),
                            name: "authorize".into(),
                            line: 1,
                            kind: TraceTargetKind::Symbol,
                        },
                        TraceTarget {
                            artifact_id: ArtifactId::from_digest(Sha256Digest::from_bytes([5; 32])),
                            path: "src/legacy_auth.rs".into(),
                            name: "authorize".into(),
                            line: 1,
                            kind: TraceTargetKind::Symbol,
                        },
                    ],
                },
            ],
        );

        assert!(detect_missing_implementations(&[prose, ambiguous, mixed])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn non_required_contracts_do_not_become_missing_implementation_findings() {
        let mut planned = contract(
            "`authorize` will eventually be available.",
            6,
            vec![UnresolvedReference::Missing {
                reference: "authorize".into(),
            }],
        );
        planned.claim.normative_kind = NormativeKind::Planned;
        planned.claim.fingerprint = claim_fingerprint(
            planned.claim.normative_kind,
            planned.claim.level,
            &planned.claim.statement,
            &planned.claim.source,
        );
        planned.traceability.contract_fingerprint = planned.claim.fingerprint;

        assert!(detect_missing_implementations(&[planned])
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

        let forged_reference = contract(
            "`authorize` is required.",
            4,
            vec![UnresolvedReference::Missing {
                reference: "audit".into(),
            }],
        );
        assert!(detect_missing_implementations(&[forged_reference]).is_err());

        let mut forged_span = contract(
            "`authorize` is required.",
            5,
            vec![UnresolvedReference::Missing {
                reference: "authorize".into(),
            }],
        );
        forged_span.claim.source.end_offset = forged_span.claim.source.start_offset;
        assert!(detect_missing_implementations(&[forged_span]).is_err());
    }

    #[test]
    fn candidates_promote_to_a_stable_revision_independent_finding() {
        // Two contracts with the same cited text and missing reference but
        // distinct (revision-scoped) contract ids produce distinct *candidate*
        // fingerprints yet the same *finding* fingerprint.
        let missing = || {
            vec![UnresolvedReference::Missing {
                reference: "authorize".into(),
            }]
        };
        let first = contract("`authorize` is required.", 1, missing());
        let second = contract("`authorize` is required.", 1, missing());
        let candidate_one = detect_missing_implementations(std::slice::from_ref(&first))
            .unwrap()
            .pop()
            .unwrap();
        let candidate_two = detect_missing_implementations(std::slice::from_ref(&second))
            .unwrap()
            .pop()
            .unwrap();
        assert_ne!(candidate_one.fingerprint, candidate_two.fingerprint);

        let finding_one = promote_candidate(&candidate_one).unwrap();
        let finding_two = promote_candidate(&candidate_two).unwrap();
        assert_eq!(finding_one, finding_two);
        assert_eq!(
            finding_one.contract_exact_text_sha256,
            Sha256Digest::from_bytes([1; 32])
        );

        // A different missing-reference set is a different finding.
        let other = contract(
            "`audit` is required.",
            1,
            vec![UnresolvedReference::Missing {
                reference: "audit".into(),
            }],
        );
        let other_finding = promote_candidate(
            &detect_missing_implementations(std::slice::from_ref(&other))
                .unwrap()
                .pop()
                .unwrap(),
        )
        .unwrap();
        assert_ne!(
            finding_one.finding_fingerprint,
            other_finding.finding_fingerprint
        );

        // Tampering the reference set or fingerprint fails closed.
        let mut wrong_fingerprint = finding_one.clone();
        wrong_fingerprint.missing_references = vec!["audit".into()];
        assert!(validate_static_finding(&wrong_fingerprint).is_err());
        let mut unsorted = finding_one.clone();
        unsorted.missing_references = vec!["b".into(), "a".into()];
        assert!(validate_static_finding(&unsorted).is_err());
    }

    #[test]
    fn contradiction_finding_identity_is_pair_order_independent() {
        use super::{contradiction_finding, validate_contradiction_finding};
        let one = Sha256Digest::from_bytes([1; 32]);
        let other = Sha256Digest::from_bytes([2; 32]);

        // The pair order does not change the finding.
        let a = contradiction_finding(one, other, "requests reach the ledger").unwrap();
        let b = contradiction_finding(other, one, "requests reach the ledger").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.left_exact_text_sha256, one);
        assert_eq!(a.right_exact_text_sha256, other);

        // A different subject is a different finding; a missing-implementation
        // fingerprint over the same hash never collides with a contradiction.
        let c = contradiction_finding(one, other, "requests bypass the ledger").unwrap();
        assert_ne!(a.finding_fingerprint, c.finding_fingerprint);

        // Tampering the subject, the ordering, or the fingerprint fails closed.
        let mut wrong_subject = a.clone();
        wrong_subject.shared_subject = "bypass the ledger".into();
        assert!(validate_contradiction_finding(&wrong_subject).is_err());
        let mut unordered = a.clone();
        std::mem::swap(
            &mut unordered.left_exact_text_sha256,
            &mut unordered.right_exact_text_sha256,
        );
        assert!(validate_contradiction_finding(&unordered).is_err());
        let mut empty_subject = a.clone();
        empty_subject.shared_subject = String::new();
        assert!(validate_contradiction_finding(&empty_subject).is_err());
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
