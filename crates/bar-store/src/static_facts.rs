//! Durable, artifact-bound static architecture facts (Phase 5).

use bar_audit::{AuditCategory, AuditEvent};
use bar_core::{ArtifactId, Error, Result, RevisionId, TargetId};
use bar_static::{validate_static_facts, StaticAnalysisBatch, StaticAnalysisFailure, StaticFacts};
use sqlx::FromRow;

use crate::{append_audit, required_sqlite_u64, storage, Store, SYSTEM_ACTOR};

/// Result of idempotently persisting one artifact's static facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticFactsPersistence {
    pub inserted: bool,
}

/// Result of persisting every successful fact in a static-analysis batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticBatchPersistence {
    pub inserted: usize,
    pub existing: usize,
    pub failures: Vec<StaticAnalysisFailure>,
}

/// Reloaded static facts with their immutable source provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredStaticFacts {
    pub artifact_id: ArtifactId,
    pub target_id: TargetId,
    pub revision_id: RevisionId,
    pub facts: StaticFacts,
    pub created_at_ms: u64,
}

#[derive(FromRow)]
struct StaticFactsRow {
    artifact_id: String,
    target_id: String,
    revision_id: String,
    facts_json: String,
    created_at_ms: i64,
    artifact_target_id: String,
    artifact_revision_id: String,
    artifact_path: String,
}

impl Store {
    /// Persists each successful member of a static-analysis batch. The batch's
    /// per-artifact analysis failures are preserved for the caller; a storage
    /// or provenance violation remains an error rather than being downgraded.
    pub async fn persist_static_batch(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        batch: &StaticAnalysisBatch,
        now_ms: u64,
    ) -> Result<StaticBatchPersistence> {
        let mut inserted = 0;
        let mut existing = 0;
        for artifact in &batch.facts {
            if self
                .persist_static_facts(
                    target_id,
                    revision_id,
                    &artifact.artifact_id,
                    &artifact.facts,
                    now_ms,
                )
                .await?
                .inserted
            {
                inserted += 1;
            } else {
                existing += 1;
            }
        }
        Ok(StaticBatchPersistence {
            inserted,
            existing,
            failures: batch.failures.clone(),
        })
    }

    /// Persists static facts for one already-inventoried artifact. Exact replay
    /// is a no-op after revalidating the stored row; a changed result for the
    /// same immutable artifact is rejected rather than silently overwritten.
    pub async fn persist_static_facts(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        artifact_id: &ArtifactId,
        facts: &StaticFacts,
        now_ms: u64,
    ) -> Result<StaticFactsPersistence> {
        validate_static_facts(facts)?;
        let created_at = required_sqlite_u64(now_ms, "static facts timestamp")?;
        let artifact_path = &facts.artifacts[0].path;
        let facts_json = serde_json::to_string(facts)
            .map_err(|error| Error::Corrupt(format!("serialize static facts: {error}")))?;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;

        let artifact: Option<(String, String, String)> = sqlx::query_as(
            "SELECT target_id, revision_id, logical_path FROM artifacts WHERE artifact_id = ?",
        )
        .bind(artifact_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("load static-facts artifact"))?;
        let (stored_target, stored_revision, stored_path) = artifact.ok_or_else(|| {
            Error::Corrupt(format!(
                "static facts reference unknown artifact {artifact_id}"
            ))
        })?;
        if stored_target != target_id.to_string()
            || stored_revision != revision_id.to_string()
            || stored_path != *artifact_path
        {
            return Err(Error::Corrupt(
                "static facts artifact does not match its target, revision, or path".into(),
            ));
        }

        let existing: Option<String> =
            sqlx::query_scalar("SELECT facts_json FROM static_facts WHERE artifact_id = ?")
                .bind(artifact_id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage("load persisted static facts"))?;
        if let Some(existing) = existing {
            let persisted = parse_static_facts(&existing)?;
            if persisted != *facts {
                return Err(Error::Corrupt(
                    "persisted static facts do not match the submitted artifact facts".into(),
                ));
            }
            tx.commit().await.map_err(storage("commit"))?;
            self.load_static_facts(artifact_id).await?;
            return Ok(StaticFactsPersistence { inserted: false });
        }

        sqlx::query(
            "INSERT INTO static_facts (artifact_id, target_id, revision_id, facts_json, created_at_ms) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(artifact_id.to_string())
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .bind(facts_json)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(storage("insert static facts"))?;
        append_audit(
            &mut tx,
            AuditEvent {
                category: AuditCategory::EvidenceMutation,
                actor: SYSTEM_ACTOR.to_string(),
                summary: "persisted static architecture facts".into(),
                subject: Some(artifact_id.to_string()),
                occurred_at_ms: now_ms,
            },
        )
        .await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(StaticFactsPersistence { inserted: true })
    }

    /// Reloads static facts and revalidates both the serialized value and its
    /// artifact/target/revision binding before exposing it to later analysis.
    pub async fn load_static_facts(&self, artifact_id: &ArtifactId) -> Result<StoredStaticFacts> {
        let row: Option<StaticFactsRow> = sqlx::query_as(
            "SELECT sf.artifact_id, sf.target_id, sf.revision_id, sf.facts_json, sf.created_at_ms, \
                    a.target_id AS artifact_target_id, a.revision_id AS artifact_revision_id, \
                    a.logical_path AS artifact_path \
             FROM static_facts sf JOIN artifacts a ON a.artifact_id = sf.artifact_id \
             WHERE sf.artifact_id = ?",
        )
        .bind(artifact_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load static facts"))?;
        let row =
            row.ok_or_else(|| Error::Corrupt(format!("unknown static facts for {artifact_id}")))?;
        let stored_artifact_id: ArtifactId = row.artifact_id.parse()?;
        let target_id: TargetId = row.target_id.parse()?;
        let revision_id: RevisionId = row.revision_id.parse()?;
        if stored_artifact_id != *artifact_id
            || row.artifact_target_id != target_id.to_string()
            || row.artifact_revision_id != revision_id.to_string()
        {
            return Err(Error::Corrupt(
                "persisted static facts cross an artifact, target, or revision boundary".into(),
            ));
        }
        let facts = parse_static_facts(&row.facts_json)?;
        if facts.artifacts[0].path != row.artifact_path {
            return Err(Error::Corrupt(
                "persisted static facts path does not match its artifact".into(),
            ));
        }
        Ok(StoredStaticFacts {
            artifact_id: stored_artifact_id,
            target_id,
            revision_id,
            facts,
            created_at_ms: u64::try_from(row.created_at_ms)
                .map_err(|_| Error::Corrupt("negative static facts creation time".into()))?,
        })
    }

    /// Reloads every validated static fact for exactly one target revision.
    pub async fn load_static_facts_for_revision(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
    ) -> Result<Vec<StoredStaticFacts>> {
        let artifact_ids: Vec<String> = sqlx::query_scalar(
            "SELECT artifact_id FROM static_facts \
             WHERE target_id = ? AND revision_id = ? ORDER BY artifact_id",
        )
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load revision static facts"))?;
        let mut facts = Vec::with_capacity(artifact_ids.len());
        for raw_id in artifact_ids {
            let artifact_id: ArtifactId = raw_id.parse()?;
            let stored = self.load_static_facts(&artifact_id).await?;
            if stored.target_id != *target_id || stored.revision_id != *revision_id {
                return Err(Error::Corrupt(
                    "revision static facts cross a target or revision boundary".into(),
                ));
            }
            facts.push(stored);
        }
        Ok(facts)
    }
}

fn parse_static_facts(json: &str) -> Result<StaticFacts> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| Error::Corrupt(format!("invalid persisted static facts JSON: {error}")))?;
    let facts: StaticFacts = serde_json::from_value(value.clone())
        .map_err(|error| Error::Corrupt(format!("invalid persisted static facts: {error}")))?;
    if serde_json::to_value(&facts)
        .map_err(|error| Error::Corrupt(format!("serialize persisted static facts: {error}")))?
        != value
    {
        return Err(Error::Corrupt(
            "persisted static facts contain unknown or noncanonical fields".into(),
        ));
    }
    validate_static_facts(&facts)?;
    Ok(facts)
}
