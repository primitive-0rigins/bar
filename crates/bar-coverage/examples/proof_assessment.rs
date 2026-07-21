use bar_contract::{claim_fingerprint, ExtractedClaim, SourceRef};
use bar_core::{
    ArtifactId, ContractId, ContractLevel, EvidenceKind, FreshnessPolicy, NormativeKind, ProofId,
    RevisionId, Sha256Digest,
};
use bar_coverage::{assess_proof_obligation, map_explicit_references, ProofObligation};
use bar_static::{analyze_artifact, StaticArtifactFacts};

fn main() -> bar_core::Result<()> {
    let artifact_id = ArtifactId::from_digest(Sha256Digest::from_bytes([7; 32]));
    let source = SourceRef {
        artifact_id,
        start_offset: 0,
        end_offset: 44,
        exact_text_sha256: Sha256Digest::from_bytes([8; 32]),
    };
    let claim = ExtractedClaim {
        normative_kind: NormativeKind::Required,
        level: ContractLevel::Implementation,
        statement: "Requests MUST call `authorize` and `audit`.".into(),
        fingerprint: claim_fingerprint(
            NormativeKind::Required,
            ContractLevel::Implementation,
            "Requests MUST call `authorize` and `audit`.",
            &source,
        ),
        source,
    };
    let facts = analyze_artifact("src/auth.rs", "fn authorize() {}")?;
    let trace = map_explicit_references(
        std::slice::from_ref(&claim),
        &[StaticArtifactFacts { artifact_id, facts }],
    )?
    .pop()
    .expect("one contract produces one trace");
    let revision = RevisionId::from_digest(Sha256Digest::from_bytes([9; 32]));
    let assessment = assess_proof_obligation(
        &ProofObligation {
            proof_id: ProofId::generate(),
            contract_id: ContractId::generate(),
            contract_fingerprint: claim.fingerprint,
            required_evidence_levels: vec![EvidenceKind::Code],
            freshness_revision: revision,
            freshness_policy: FreshnessPolicy::Pinned,
        },
        &trace,
        &revision,
        false,
    )?;

    println!("mapping status: {:?}", trace.status);
    println!("proof status: {:?}", assessment.status);
    println!(
        "unresolved: {}",
        assessment.unresolved_references.join(", ")
    );
    Ok(())
}
