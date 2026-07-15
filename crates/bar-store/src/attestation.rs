//! Immutable operator corroboration for source-bound scope context (Phase 4).

use bar_audit::{AuditCategory, AuditEvent};
use bar_contract::scope::Applicability;
use bar_core::{ContractId, Error, EvidenceId, Result, RevisionId, TargetId};

use crate::{append_audit, required_sqlite_u64, storage, Store};

const MAX_OPERATOR_ID_BYTES: usize = 255;
const MAX_RATIONALE_BYTES: usize = 8_192;

/// Result of idempotently persisting operator corroboration of scope context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeContextAttestationPersistence {
    pub evidence_id: EvidenceId,
    pub inserted: bool,
}

/// A reloaded, immutable operator attestation bound to one context observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredScopeContextAttestation {
    pub evidence_id: EvidenceId,
    pub context_evidence_id: EvidenceId,
    pub target_id: TargetId,
    pub revision_id: RevisionId,
    pub operator_id: String,
    pub rationale: String,
    pub created_at_ms: u64,
}

impl Store {
    /// Records an operator's immutable corroboration that an existing
    /// source-bound context evidence record has the stated semantic meaning.
    /// Exact replay is a no-op; a different operator or rationale is retained
    /// as separate evidence rather than rewriting history.
    pub async fn persist_scope_context_attestation(
        &self,
        context_evidence_id: &EvidenceId,
        operator_id: &str,
        rationale: &str,
        now_ms: u64,
    ) -> Result<ScopeContextAttestationPersistence> {
        validate_attestation_text(operator_id, MAX_OPERATOR_ID_BYTES, "operator id")?;
        validate_attestation_text(rationale, MAX_RATIONALE_BYTES, "rationale")?;
        let created_at = required_sqlite_u64(now_ms, "attestation timestamp")?;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let context: Option<(String, String)> = sqlx::query_as(
            "SELECT target_id, revision_id FROM scope_context_evidence WHERE evidence_id = ?",
        )
        .bind(context_evidence_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("load attested scope context"))?;
        let (target_id, revision_id) = context.ok_or_else(|| {
            Error::Corrupt(format!("unknown scope context {context_evidence_id}"))
        })?;
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT evidence_id FROM scope_context_attestations \
             WHERE context_evidence_id = ? AND operator_id = ? AND rationale = ?",
        )
        .bind(context_evidence_id.to_string())
        .bind(operator_id)
        .bind(rationale)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("find scope context attestation"))?;
        if let Some(evidence_id) = existing {
            tx.commit().await.map_err(storage("commit"))?;
            return Ok(ScopeContextAttestationPersistence {
                evidence_id: evidence_id.parse()?,
                inserted: false,
            });
        }

        let evidence_id = EvidenceId::generate();
        sqlx::query(
            "INSERT INTO scope_context_attestations \
             (evidence_id, context_evidence_id, target_id, revision_id, operator_id, rationale, created_at_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(evidence_id.to_string())
        .bind(context_evidence_id.to_string())
        .bind(&target_id)
        .bind(&revision_id)
        .bind(operator_id)
        .bind(rationale)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(storage("insert scope context attestation"))?;
        append_audit(
            &mut tx,
            AuditEvent {
                category: AuditCategory::EvidenceMutation,
                actor: operator_id.to_string(),
                summary: "recorded operator scope-context attestation".into(),
                subject: Some(evidence_id.to_string()),
                occurred_at_ms: now_ms,
            },
        )
        .await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(ScopeContextAttestationPersistence {
            evidence_id,
            inserted: true,
        })
    }

    /// Reloads an attestation and verifies its duplicated target/revision
    /// binding against the underlying source-context evidence.
    pub async fn load_scope_context_attestation(
        &self,
        evidence_id: &EvidenceId,
    ) -> Result<StoredScopeContextAttestation> {
        let row: Option<(String, String, String, String, String, String, i64)> = sqlx::query_as(
            "SELECT context_evidence_id, target_id, revision_id, operator_id, rationale, evidence_id, created_at_ms \
             FROM scope_context_attestations WHERE evidence_id = ?",
        )
        .bind(evidence_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load scope context attestation"))?;
        let (
            context_evidence_id,
            target_id,
            revision_id,
            operator_id,
            rationale,
            stored_id,
            created_at_ms,
        ) = row.ok_or_else(|| {
            Error::Corrupt(format!("unknown scope context attestation {evidence_id}"))
        })?;
        if stored_id != evidence_id.to_string() {
            return Err(Error::Corrupt(
                "persisted scope context attestation identity does not match request".into(),
            ));
        }
        validate_attestation_text(&operator_id, MAX_OPERATOR_ID_BYTES, "operator id")?;
        validate_attestation_text(&rationale, MAX_RATIONALE_BYTES, "rationale")?;
        let context_evidence_id: EvidenceId = context_evidence_id.parse()?;
        let target_id: TargetId = target_id.parse()?;
        let revision_id: RevisionId = revision_id.parse()?;
        let context = self
            .load_scope_context_evidence(&context_evidence_id)
            .await?;
        if context.target_id != target_id || context.revision_id != revision_id {
            return Err(Error::Corrupt(
                "scope context attestation crosses target or revision boundary".into(),
            ));
        }
        Ok(StoredScopeContextAttestation {
            evidence_id: *evidence_id,
            context_evidence_id,
            target_id,
            revision_id,
            operator_id,
            rationale,
            created_at_ms: u64::try_from(created_at_ms)
                .map_err(|_| Error::Corrupt("negative scope context attestation time".into()))?,
        })
    }

    /// Resolves a contract through operator-attested context evidence. This is
    /// the trusted human path; adapter-backed context can continue to use the
    /// lower-level evidence-time resolver directly.
    pub async fn resolve_contract_in_attested_context(
        &self,
        contract_id: &ContractId,
        attestation_evidence_id: &EvidenceId,
    ) -> Result<Applicability> {
        let attestation = self
            .load_scope_context_attestation(attestation_evidence_id)
            .await?;
        self.resolve_contract_in_context(contract_id, &attestation.context_evidence_id)
            .await
    }
}

fn validate_attestation_text(value: &str, max_bytes: usize, field: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(Error::Corrupt(format!(
            "scope context attestation {field} must contain 1..={max_bytes} bytes"
        )));
    }
    Ok(())
}
