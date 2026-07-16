//! Durable, revision-bound proof-obligation declarations (Phase 6).

use bar_audit::{AuditCategory, AuditEvent};
use bar_core::{
    ContractId, Error, EvidenceKind, ProofId, Result, RevisionId, Sha256Digest, TargetId,
};
use bar_coverage::{
    assess_proof_obligation, evidence_kind_from_token, validate_proof_obligation,
    ContractTraceability, ProofAssessment, ProofObligation,
};
use sqlx::FromRow;

use crate::{append_audit, required_sqlite_u64, storage, Store, SYSTEM_ACTOR};

/// Result of idempotently persisting one immutable proof obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofObligationPersistence {
    pub inserted: bool,
}

/// Reloaded proof obligation with its contract and revision provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredProofObligation {
    pub contract_id: ContractId,
    pub target_id: TargetId,
    pub revision_id: RevisionId,
    pub obligation: ProofObligation,
    pub created_at_ms: u64,
}

/// A persisted proof declaration with its freshly reconstructed traceability
/// and derived assessment. The assessment itself is intentionally not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredProofAssessment {
    pub proof: StoredProofObligation,
    pub traceability: ContractTraceability,
    pub assessment: ProofAssessment,
}

#[derive(FromRow)]
struct ProofObligationRow {
    proof_id: String,
    contract_id: String,
    target_id: String,
    revision_id: String,
    contract_fingerprint: String,
    required_evidence_json: String,
    freshness_revision_id: String,
    created_at_ms: i64,
    contract_target_id: String,
    contract_revision_id: String,
    stored_contract_fingerprint: String,
}

impl Store {
    /// Persists an immutable evidence-level requirement for one contract. The
    /// declaration must bind to the supplied target revision and its stored
    /// source-contract fingerprint; changed replay is rejected.
    pub async fn persist_proof_obligation(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        contract_id: &ContractId,
        obligation: &ProofObligation,
        now_ms: u64,
    ) -> Result<ProofObligationPersistence> {
        validate_proof_obligation(obligation)?;
        if obligation.freshness_revision != *revision_id {
            return Err(Error::Corrupt(
                "proof obligation freshness revision does not match its stored revision".into(),
            ));
        }
        let required_evidence_json = evidence_json(&obligation.required_evidence_levels)?;
        let created_at = required_sqlite_u64(now_ms, "proof obligation timestamp")?;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let contract: Option<(String, String, String)> = sqlx::query_as(
            "SELECT target_id, revision_id, fingerprint FROM contracts WHERE contract_id = ?",
        )
        .bind(contract_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("load proof contract"))?;
        let (stored_target, stored_revision, stored_fingerprint) = contract.ok_or_else(|| {
            Error::Corrupt(format!(
                "proof obligation references unknown contract {contract_id}"
            ))
        })?;
        if stored_target != target_id.to_string()
            || stored_revision != revision_id.to_string()
            || stored_fingerprint != obligation.contract_fingerprint.to_string()
        {
            return Err(Error::Corrupt(
                "proof obligation does not match its contract target, revision, or fingerprint"
                    .into(),
            ));
        }

        let existing: Option<(String, String, String, String, String)> = sqlx::query_as(
            "SELECT contract_id, target_id, revision_id, contract_fingerprint, required_evidence_json \
             FROM proof_obligations WHERE proof_id = ?",
        )
        .bind(obligation.proof_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("load proof obligation"))?;
        if let Some(existing) = existing {
            let expected = (
                contract_id.to_string(),
                target_id.to_string(),
                revision_id.to_string(),
                obligation.contract_fingerprint.to_string(),
                required_evidence_json.clone(),
            );
            if existing != expected {
                return Err(Error::Corrupt(
                    "persisted proof obligation does not match the submitted declaration".into(),
                ));
            }
            tx.commit().await.map_err(storage("commit"))?;
            self.load_proof_obligation(&obligation.proof_id).await?;
            return Ok(ProofObligationPersistence { inserted: false });
        }

        sqlx::query(
            "INSERT INTO proof_obligations \
             (proof_id, contract_id, target_id, revision_id, contract_fingerprint, required_evidence_json, freshness_revision_id, created_at_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(obligation.proof_id.to_string())
        .bind(contract_id.to_string())
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .bind(obligation.contract_fingerprint.to_string())
        .bind(required_evidence_json)
        .bind(obligation.freshness_revision.to_string())
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(storage("insert proof obligation"))?;
        append_audit(
            &mut tx,
            AuditEvent {
                category: AuditCategory::EvidenceMutation,
                actor: SYSTEM_ACTOR.to_string(),
                summary: "persisted proof obligation".into(),
                subject: Some(obligation.proof_id.to_string()),
                occurred_at_ms: now_ms,
            },
        )
        .await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(ProofObligationPersistence { inserted: true })
    }

    /// Reloads and revalidates an immutable proof obligation before exposing it
    /// to coverage assessment.
    pub async fn load_proof_obligation(&self, proof_id: &ProofId) -> Result<StoredProofObligation> {
        let row: Option<ProofObligationRow> = sqlx::query_as(
            "SELECT p.proof_id, p.contract_id, p.target_id, p.revision_id, p.contract_fingerprint, \
                    p.required_evidence_json, p.freshness_revision_id, p.created_at_ms, \
                    c.target_id AS contract_target_id, c.revision_id AS contract_revision_id, \
                    c.fingerprint AS stored_contract_fingerprint \
             FROM proof_obligations p JOIN contracts c ON c.contract_id = p.contract_id \
             WHERE p.proof_id = ?",
        )
        .bind(proof_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load proof obligation"))?;
        let row =
            row.ok_or_else(|| Error::Corrupt(format!("unknown proof obligation {proof_id}")))?;
        row.into_stored(proof_id)
    }

    /// Rebuilds traceability for a persisted proof declaration's exact target
    /// revision, then assesses it without storing a derived proof status.
    pub async fn assess_persisted_proof_obligation(
        &self,
        proof_id: &ProofId,
    ) -> Result<StoredProofAssessment> {
        let proof = self.load_proof_obligation(proof_id).await?;
        let traceability = self
            .map_contract_traceability(&proof.target_id, &proof.revision_id)
            .await?
            .into_iter()
            .find(|trace| trace.contract.contract_id == proof.contract_id)
            .map(|trace| trace.traceability)
            .ok_or_else(|| {
                Error::Corrupt(format!(
                    "proof obligation {} has no traceability contract",
                    proof.obligation.proof_id
                ))
            })?;
        let assessment =
            assess_proof_obligation(&proof.obligation, &traceability, &proof.revision_id)?;
        Ok(StoredProofAssessment {
            proof,
            traceability,
            assessment,
        })
    }
}

impl ProofObligationRow {
    fn into_stored(self, requested_id: &ProofId) -> Result<StoredProofObligation> {
        let proof_id: ProofId = self.proof_id.parse()?;
        let contract_id: ContractId = self.contract_id.parse()?;
        let target_id: TargetId = self.target_id.parse()?;
        let revision_id: RevisionId = self.revision_id.parse()?;
        let contract_fingerprint: Sha256Digest = self.contract_fingerprint.parse()?;
        if proof_id != *requested_id
            || self.contract_target_id != target_id.to_string()
            || self.contract_revision_id != revision_id.to_string()
            || self.stored_contract_fingerprint != contract_fingerprint.to_string()
        {
            return Err(Error::Corrupt(
                "persisted proof obligation crosses a contract, target, or revision boundary"
                    .into(),
            ));
        }
        let obligation = ProofObligation {
            proof_id,
            contract_fingerprint,
            required_evidence_levels: parse_evidence_json(&self.required_evidence_json)?,
            freshness_revision: self.freshness_revision_id.parse()?,
        };
        if obligation.freshness_revision != revision_id {
            return Err(Error::Corrupt(
                "persisted proof obligation freshness revision does not match its revision".into(),
            ));
        }
        validate_proof_obligation(&obligation)?;
        Ok(StoredProofObligation {
            contract_id,
            target_id,
            revision_id,
            obligation,
            created_at_ms: u64::try_from(self.created_at_ms)
                .map_err(|_| Error::Corrupt("negative proof obligation creation time".into()))?,
        })
    }
}

fn evidence_json(levels: &[EvidenceKind]) -> Result<String> {
    serde_json::to_string(
        &levels
            .iter()
            .map(|level| level.as_str())
            .collect::<Vec<_>>(),
    )
    .map_err(|error| Error::Corrupt(format!("serialize proof evidence levels: {error}")))
}

fn parse_evidence_json(json: &str) -> Result<Vec<EvidenceKind>> {
    let tokens: Vec<String> = serde_json::from_str(json)
        .map_err(|error| Error::Corrupt(format!("invalid proof evidence levels: {error}")))?;
    tokens
        .iter()
        .map(|token| evidence_kind_from_token(token))
        .collect()
}
