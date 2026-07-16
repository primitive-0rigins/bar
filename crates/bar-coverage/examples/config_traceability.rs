use bar_contract::{claim_fingerprint, ExtractedClaim, SourceRef};
use bar_core::{ArtifactId, ContractLevel, NormativeKind, Sha256Digest};
use bar_coverage::map_explicit_references;
use bar_static::{analyze_artifact, StaticArtifactFacts};

fn main() -> bar_core::Result<()> {
    let artifact_id = ArtifactId::from_digest(Sha256Digest::from_bytes([7; 32]));
    let source = SourceRef {
        artifact_id,
        start_offset: 0,
        end_offset: 32,
        exact_text_sha256: Sha256Digest::from_bytes([8; 32]),
    };
    let contract = ExtractedClaim {
        normative_kind: NormativeKind::Required,
        level: ContractLevel::Implementation,
        statement: "Runtime MUST set `server.port`.".into(),
        fingerprint: claim_fingerprint(
            NormativeKind::Required,
            ContractLevel::Implementation,
            "Runtime MUST set `server.port`.",
            &source,
        ),
        source,
    };
    let facts = analyze_artifact("config/runtime.json", "{\"server\": {\"port\": 8080}}")?;
    let trace =
        map_explicit_references(&[contract], &[StaticArtifactFacts { artifact_id, facts }])?
            .pop()
            .expect("one contract produces one trace");

    println!("mapping status: {:?}", trace.status);
    for mapping in trace.mappings {
        println!(
            "`{}` → {}:{} ({:?})",
            mapping.reference, mapping.target.path, mapping.target.line, mapping.target.kind
        );
    }
    Ok(())
}
