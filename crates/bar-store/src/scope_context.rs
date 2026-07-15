//! Source-bound scope-context evidence persistence (Phase 4).

use bar_audit::{AuditCategory, AuditEvent};
use bar_contract::scope::{validate_context, ScopeContext};
use bar_contract::SourceRef;
use bar_core::{Error, EvidenceId, Result, RevisionId, TargetId};
use sqlx::FromRow;

use crate::{append_audit, storage, Store, SYSTEM_ACTOR};

/// Result of idempotently persisting a scope-context observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeContextPersistence {
    pub evidence_id: EvidenceId,
    pub inserted: bool,
}

/// Reloaded context with exact target, revision, time, and source provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredScopeContextEvidence {
    pub evidence_id: EvidenceId,
    pub target_id: TargetId,
    pub revision_id: RevisionId,
    pub context: ScopeContext,
    pub source: SourceRef,
    pub observed_at_ms: u64,
}

#[derive(FromRow)]
struct ScopeContextEvidenceRow {
    target_id: String,
    revision_id: String,
    context_json: String,
    artifact_id: String,
    start_offset: i64,
    end_offset: i64,
    exact_text_sha256: String,
    observed_at_ms: i64,
    source_commit: Option<String>,
    size_bytes: i64,
    content_sha256: String,
}

impl ScopeContextEvidenceRow {
    fn into_evidence(self, evidence_id: EvidenceId) -> Result<StoredScopeContextEvidence> {
        let context: ScopeContext = serde_json::from_str(&self.context_json)
            .map_err(|e| Error::Corrupt(format!("invalid persisted scope context: {e}")))?;
        validate_context(&context)?;
        if context.source_revision != self.source_commit {
            return Err(Error::Corrupt(
                "scope context source revision does not match its revision".into(),
            ));
        }
        let start_offset = usize::try_from(self.start_offset)
            .map_err(|_| Error::Corrupt("negative scope context source offset".into()))?;
        let end_offset = usize::try_from(self.end_offset)
            .map_err(|_| Error::Corrupt("negative scope context source offset".into()))?;
        let size_bytes = usize::try_from(self.size_bytes)
            .map_err(|_| Error::Corrupt("negative scope context artifact size".into()))?;
        if start_offset != 0
            || start_offset >= end_offset
            || end_offset != size_bytes
            || self.exact_text_sha256 != self.content_sha256
        {
            return Err(Error::Corrupt(
                "invalid persisted scope context source span".into(),
            ));
        }
        Ok(StoredScopeContextEvidence {
            evidence_id,
            target_id: self.target_id.parse()?,
            revision_id: self.revision_id.parse()?,
            context,
            source: SourceRef {
                artifact_id: self.artifact_id.parse()?,
                start_offset,
                end_offset,
                exact_text_sha256: self.exact_text_sha256.parse()?,
            },
            observed_at_ms: u64::try_from(self.observed_at_ms)
                .map_err(|_| Error::Corrupt("negative scope context observation time".into()))?,
        })
    }
}

impl Store {
    /// Persists an immutable scope-context observation bound to an exact
    /// inventoried artifact in a target revision. Whole-artifact binding keeps
    /// the cited digest independently verifiable until excerpt evidence storage
    /// lands. Source revision is derived from stored revision identity, never
    /// accepted from caller-supplied context.
    pub async fn persist_scope_context_evidence(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        context: &ScopeContext,
        source: &SourceRef,
        observed_at_ms: u64,
        now_ms: u64,
    ) -> Result<ScopeContextPersistence> {
        let observed_at = i64::try_from(observed_at_ms)
            .map_err(|_| Error::Corrupt("timestamp exceeds SQLite integer range".into()))?;
        let created_at = i64::try_from(now_ms)
            .map_err(|_| Error::Corrupt("timestamp exceeds SQLite integer range".into()))?;
        let start_offset = i64::try_from(source.start_offset)
            .map_err(|_| Error::Corrupt("scope context source span is too large".into()))?;
        let end_offset = i64::try_from(source.end_offset)
            .map_err(|_| Error::Corrupt("scope context source span is too large".into()))?;
        if start_offset >= end_offset {
            return Err(Error::Corrupt("invalid scope context source span".into()));
        }
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let revision: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT target_id, source_commit FROM target_revisions WHERE revision_id = ?",
        )
        .bind(revision_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("load scope context revision"))?;
        let (_, source_commit) = revision
            .filter(|(stored_target, _)| stored_target == &target_id.to_string())
            .ok_or_else(|| {
                Error::Corrupt(format!(
                    "scope context references revision {revision_id} outside target {target_id}"
                ))
            })?;

        let artifact: Option<(i64, String)> = sqlx::query_as(
            "SELECT size_bytes, content_sha256 FROM artifacts \
             WHERE artifact_id = ? AND target_id = ? AND revision_id = ?",
        )
        .bind(source.artifact_id.to_string())
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("load scope context artifact"))?;
        let (artifact_size, content_sha256) = artifact.ok_or_else(|| {
            Error::Corrupt(format!(
                "scope context source {} is outside revision {revision_id}",
                source.artifact_id
            ))
        })?;
        if start_offset != 0
            || end_offset != artifact_size
            || source.exact_text_sha256.to_string() != content_sha256
        {
            return Err(Error::Corrupt(format!(
                "scope context source {} does not match its complete inventoried artifact",
                source.artifact_id
            )));
        }

        let mut bound_context = context.clone();
        bound_context.source_revision = source_commit;
        validate_context(&bound_context)?;
        let context_json = serde_json::to_string(&bound_context)
            .map_err(|e| Error::Corrupt(format!("serialize scope context: {e}")))?;
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT evidence_id FROM scope_context_evidence \
             WHERE revision_id = ? AND context_json = ? AND artifact_id = ? \
             AND start_offset = ? AND end_offset = ? AND exact_text_sha256 = ? \
             AND observed_at_ms = ?",
        )
        .bind(revision_id.to_string())
        .bind(&context_json)
        .bind(source.artifact_id.to_string())
        .bind(start_offset)
        .bind(end_offset)
        .bind(source.exact_text_sha256.to_string())
        .bind(observed_at)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("lookup scope context evidence"))?;
        if let Some(evidence_id) = existing {
            tx.commit().await.map_err(storage("commit"))?;
            return Ok(ScopeContextPersistence {
                evidence_id: evidence_id.parse()?,
                inserted: false,
            });
        }

        let evidence_id = EvidenceId::generate();
        sqlx::query(
            "INSERT INTO scope_context_evidence \
             (evidence_id, target_id, revision_id, context_json, artifact_id, start_offset, \
              end_offset, exact_text_sha256, observed_at_ms, created_at_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(evidence_id.to_string())
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .bind(&context_json)
        .bind(source.artifact_id.to_string())
        .bind(start_offset)
        .bind(end_offset)
        .bind(source.exact_text_sha256.to_string())
        .bind(observed_at)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(storage("insert scope context evidence"))?;
        append_audit(
            &mut tx,
            AuditEvent {
                category: AuditCategory::EvidenceMutation,
                actor: SYSTEM_ACTOR.to_string(),
                summary: "recorded source-bound scope context".into(),
                subject: Some(evidence_id.to_string()),
                occurred_at_ms: now_ms,
            },
        )
        .await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(ScopeContextPersistence {
            evidence_id,
            inserted: true,
        })
    }

    /// Reloads a strict scope-context observation and its source binding.
    pub async fn load_scope_context_evidence(
        &self,
        evidence_id: &EvidenceId,
    ) -> Result<StoredScopeContextEvidence> {
        let row: Option<ScopeContextEvidenceRow> = sqlx::query_as(
            "SELECT e.target_id, e.revision_id, e.context_json, e.artifact_id, e.start_offset, \
                    e.end_offset, e.exact_text_sha256, e.observed_at_ms, r.source_commit, \
                    a.size_bytes, a.content_sha256 \
             FROM scope_context_evidence e \
             JOIN target_revisions r ON r.revision_id = e.revision_id AND r.target_id = e.target_id \
             JOIN artifacts a ON a.artifact_id = e.artifact_id \
                AND a.revision_id = e.revision_id AND a.target_id = e.target_id \
             WHERE e.evidence_id = ?",
        )
        .bind(evidence_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load scope context evidence"))?;
        row.ok_or_else(|| Error::Corrupt(format!("unknown scope context {evidence_id}")))?
            .into_evidence(*evidence_id)
    }
}
