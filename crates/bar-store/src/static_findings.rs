//! Durable, revision-bound shadow static-finding candidates (Phase 7).

use std::collections::BTreeSet;

use bar_audit::{AuditCategory, AuditEvent};
use bar_contract::SourceRef;
use bar_core::{ContractId, Error, NormativeKind, Result, RevisionId, Sha256Digest, TargetId};
use bar_findings::{validate_static_finding_candidate, StaticFindingCandidate, StaticFindingKind};
use sqlx::sqlite::Sqlite;
use sqlx::{FromRow, Transaction};

use crate::{
    append_audit, required_sqlite_u64, required_sqlite_usize, storage, Store, SYSTEM_ACTOR,
};

/// Result of idempotently persisting one immutable shadow candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticFindingCandidatePersistence {
    pub inserted: bool,
}

/// Result of atomically persisting a candidate set for one revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticFindingCandidateBatchPersistence {
    pub inserted: usize,
    pub existing: usize,
}

/// Reloaded shadow candidate with its target and revision provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredStaticFindingCandidate {
    pub target_id: TargetId,
    pub revision_id: RevisionId,
    pub candidate: StaticFindingCandidate,
    pub created_at_ms: u64,
}

#[derive(FromRow)]
struct StaticFindingCandidateRow {
    fingerprint: String,
    kind: String,
    contract_id: String,
    target_id: String,
    revision_id: String,
    contract_fingerprint: String,
    source_artifact_id: String,
    source_start_offset: i64,
    source_end_offset: i64,
    source_exact_text_sha256: String,
    missing_references_json: String,
    created_at_ms: i64,
    contract_target_id: String,
    contract_revision_id: String,
    stored_contract_fingerprint: String,
    source_bound: i64,
}

struct StaticFindingCandidateSubmission<'a> {
    candidate: &'a StaticFindingCandidate,
    source_start: i64,
    source_end: i64,
    missing_references_json: String,
}

impl<'a> StaticFindingCandidateSubmission<'a> {
    fn new(candidate: &'a StaticFindingCandidate) -> Result<Self> {
        validate_static_finding_candidate(candidate)?;
        Ok(Self {
            candidate,
            source_start: required_sqlite_usize(
                candidate.source.start_offset,
                "static finding candidate source start",
            )?,
            source_end: required_sqlite_usize(
                candidate.source.end_offset,
                "static finding candidate source end",
            )?,
            missing_references_json: serde_json::to_string(&candidate.missing_references).map_err(
                |error| Error::Corrupt(format!("serialize missing references: {error}")),
            )?,
        })
    }
}

impl Store {
    /// Persists one detector candidate only when it exactly matches a
    /// source-bound contract in the supplied target revision. Exact replay is
    /// a validated no-op; changed data under an existing fingerprint fails.
    pub async fn persist_static_finding_candidate(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        candidate: &StaticFindingCandidate,
        now_ms: u64,
    ) -> Result<StaticFindingCandidatePersistence> {
        let result = self
            .persist_static_finding_candidates(
                target_id,
                revision_id,
                std::slice::from_ref(candidate),
                now_ms,
            )
            .await?;
        Ok(StaticFindingCandidatePersistence {
            inserted: result.inserted == 1,
        })
    }

    /// Atomically persists a detector result for one target revision. Every
    /// candidate is validated and bound before any row or audit event is
    /// written, so a bad later candidate cannot leave a partial scan result.
    pub async fn persist_static_finding_candidates(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        candidates: &[StaticFindingCandidate],
        now_ms: u64,
    ) -> Result<StaticFindingCandidateBatchPersistence> {
        let created_at = required_sqlite_u64(now_ms, "static finding candidate timestamp")?;
        let mut fingerprints = BTreeSet::new();
        let mut submissions = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if !fingerprints.insert(candidate.fingerprint) {
                return Err(Error::Corrupt(
                    "static finding candidate batch repeats a fingerprint".into(),
                ));
            }
            submissions.push(StaticFindingCandidateSubmission::new(candidate)?);
        }

        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let mut existing = Vec::with_capacity(submissions.len());
        for submission in &submissions {
            Self::verify_static_finding_candidate_binding(
                &mut tx,
                target_id,
                revision_id,
                submission,
            )
            .await?;
            let row_exists: Option<i64> =
                sqlx::query_scalar("SELECT 1 FROM static_finding_candidates WHERE fingerprint = ?")
                    .bind(submission.candidate.fingerprint.to_string())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(storage("load static-finding candidate"))?;
            existing.push(row_exists.is_some());
        }
        tx.commit().await.map_err(storage("commit"))?;

        for (submission, row_exists) in submissions.iter().zip(&existing) {
            if *row_exists {
                let persisted = self
                    .load_static_finding_candidate(&submission.candidate.fingerprint)
                    .await?;
                if persisted.target_id != *target_id
                    || persisted.revision_id != *revision_id
                    || persisted.candidate != *submission.candidate
                {
                    return Err(Error::Corrupt(
                        "persisted static finding candidate does not match the submitted candidate"
                            .into(),
                    ));
                }
            }
        }

        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let mut inserted = 0;
        for (submission, row_exists) in submissions.iter().zip(existing) {
            if row_exists {
                continue;
            }
            Self::verify_static_finding_candidate_binding(
                &mut tx,
                target_id,
                revision_id,
                submission,
            )
            .await?;
            sqlx::query(
                "INSERT INTO static_finding_candidates \
                 (fingerprint, kind, contract_id, target_id, revision_id, contract_fingerprint, \
                  source_artifact_id, source_start_offset, source_end_offset, source_exact_text_sha256, \
                  missing_references_json, created_at_ms) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(submission.candidate.fingerprint.to_string())
            .bind(submission.candidate.kind.as_str())
            .bind(submission.candidate.contract_id.to_string())
            .bind(target_id.to_string())
            .bind(revision_id.to_string())
            .bind(submission.candidate.contract_fingerprint.to_string())
            .bind(submission.candidate.source.artifact_id.to_string())
            .bind(submission.source_start)
            .bind(submission.source_end)
            .bind(submission.candidate.source.exact_text_sha256.to_string())
            .bind(&submission.missing_references_json)
            .bind(created_at)
            .execute(&mut *tx)
            .await
            .map_err(storage("insert static-finding candidate"))?;
            append_audit(
                &mut tx,
                AuditEvent {
                    category: AuditCategory::EvidenceMutation,
                    actor: SYSTEM_ACTOR.to_string(),
                    summary: "persisted shadow static-finding candidate".into(),
                    subject: Some(submission.candidate.fingerprint.to_string()),
                    occurred_at_ms: now_ms,
                },
            )
            .await?;
            inserted += 1;
        }
        tx.commit().await.map_err(storage("commit"))?;
        Ok(StaticFindingCandidateBatchPersistence {
            inserted,
            existing: submissions.len() - inserted,
        })
    }

    async fn verify_static_finding_candidate_binding(
        tx: &mut Transaction<'_, Sqlite>,
        target_id: &TargetId,
        revision_id: &RevisionId,
        submission: &StaticFindingCandidateSubmission<'_>,
    ) -> Result<()> {
        let candidate = submission.candidate;
        let contract: Option<(String, String, String, String)> = sqlx::query_as(
            "SELECT target_id, revision_id, fingerprint, normative_kind FROM contracts WHERE contract_id = ?",
        )
        .bind(candidate.contract_id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage("load static-finding contract"))?;
        let (stored_target, stored_revision, stored_fingerprint, stored_kind) = contract
            .ok_or_else(|| {
                Error::Corrupt(format!(
                    "static finding candidate references unknown contract {}",
                    candidate.contract_id
                ))
            })?;
        if stored_target != target_id.to_string()
            || stored_revision != revision_id.to_string()
            || stored_fingerprint != candidate.contract_fingerprint.to_string()
            || stored_kind != NormativeKind::Required.as_str()
        {
            return Err(Error::Corrupt(
                "static finding candidate does not match a required contract target, revision, or fingerprint"
                    .into(),
            ));
        }
        let source_bound: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM contract_sources \
             WHERE contract_id = ? AND artifact_id = ? AND start_offset = ? \
               AND end_offset = ? AND exact_text_sha256 = ?",
        )
        .bind(candidate.contract_id.to_string())
        .bind(candidate.source.artifact_id.to_string())
        .bind(submission.source_start)
        .bind(submission.source_end)
        .bind(candidate.source.exact_text_sha256.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage("load static-finding source"))?;
        if source_bound.is_none() {
            return Err(Error::Corrupt(
                "static finding candidate source does not match its contract".into(),
            ));
        }
        Ok(())
    }

    /// Reloads and revalidates one immutable shadow candidate before exposing
    /// it to future review or lifecycle work.
    pub async fn load_static_finding_candidate(
        &self,
        fingerprint: &Sha256Digest,
    ) -> Result<StoredStaticFindingCandidate> {
        let row: Option<StaticFindingCandidateRow> = sqlx::query_as(
            "SELECT f.fingerprint, f.kind, f.contract_id, f.target_id, f.revision_id, \
                    f.contract_fingerprint, f.source_artifact_id, f.source_start_offset, \
                    f.source_end_offset, f.source_exact_text_sha256, f.missing_references_json, \
                    f.created_at_ms, c.target_id AS contract_target_id, \
                    c.revision_id AS contract_revision_id, \
                    c.fingerprint AS stored_contract_fingerprint, \
                    EXISTS(SELECT 1 FROM contract_sources s \
                           WHERE s.contract_id = f.contract_id \
                             AND s.artifact_id = f.source_artifact_id \
                             AND s.start_offset = f.source_start_offset \
                             AND s.end_offset = f.source_end_offset \
                             AND s.exact_text_sha256 = f.source_exact_text_sha256) AS source_bound \
             FROM static_finding_candidates f \
             JOIN contracts c ON c.contract_id = f.contract_id \
             WHERE f.fingerprint = ?",
        )
        .bind(fingerprint.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load static-finding candidate"))?;
        let row = row.ok_or_else(|| {
            Error::Corrupt(format!("unknown static finding candidate {fingerprint}"))
        })?;
        row.into_stored(fingerprint)
    }

    /// Reloads every validated shadow candidate for exactly one target
    /// revision. The contract relation is the query boundary so corrupted
    /// candidate target or revision columns fail during per-record reload.
    pub async fn load_static_finding_candidates_for_revision(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
    ) -> Result<Vec<StoredStaticFindingCandidate>> {
        let fingerprints: Vec<String> = sqlx::query_scalar(
            "SELECT f.fingerprint FROM static_finding_candidates f \
             JOIN contracts c ON c.contract_id = f.contract_id \
             WHERE c.target_id = ? AND c.revision_id = ? ORDER BY f.fingerprint",
        )
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load revision static-finding candidates"))?;
        let mut candidates = Vec::with_capacity(fingerprints.len());
        for fingerprint in fingerprints {
            let fingerprint: Sha256Digest = fingerprint.parse()?;
            let stored = self.load_static_finding_candidate(&fingerprint).await?;
            if stored.target_id != *target_id || stored.revision_id != *revision_id {
                return Err(Error::Corrupt(
                    "revision static finding candidates cross a target or revision boundary".into(),
                ));
            }
            candidates.push(stored);
        }
        Ok(candidates)
    }
}

impl StaticFindingCandidateRow {
    fn into_stored(
        self,
        requested_fingerprint: &Sha256Digest,
    ) -> Result<StoredStaticFindingCandidate> {
        let fingerprint: Sha256Digest = self.fingerprint.parse()?;
        let contract_id: ContractId = self.contract_id.parse()?;
        let target_id: TargetId = self.target_id.parse()?;
        let revision_id: RevisionId = self.revision_id.parse()?;
        let contract_fingerprint: Sha256Digest = self.contract_fingerprint.parse()?;
        if fingerprint != *requested_fingerprint
            || self.contract_target_id != target_id.to_string()
            || self.contract_revision_id != revision_id.to_string()
            || self.stored_contract_fingerprint != contract_fingerprint.to_string()
            || self.source_bound != 1
        {
            return Err(Error::Corrupt(
                "persisted static finding candidate crosses a contract, source, target, or revision boundary"
                    .into(),
            ));
        }
        let candidate = StaticFindingCandidate {
            fingerprint,
            kind: StaticFindingKind::from_token(&self.kind)?,
            contract_id,
            contract_fingerprint,
            source: SourceRef {
                artifact_id: self.source_artifact_id.parse()?,
                start_offset: usize::try_from(self.source_start_offset).map_err(|_| {
                    Error::Corrupt("negative static finding candidate source start".into())
                })?,
                end_offset: usize::try_from(self.source_end_offset).map_err(|_| {
                    Error::Corrupt("negative static finding candidate source end".into())
                })?,
                exact_text_sha256: self.source_exact_text_sha256.parse()?,
            },
            missing_references: parse_missing_references_json(&self.missing_references_json)?,
        };
        validate_static_finding_candidate(&candidate)?;
        Ok(StoredStaticFindingCandidate {
            target_id,
            revision_id,
            candidate,
            created_at_ms: u64::try_from(self.created_at_ms).map_err(|_| {
                Error::Corrupt("negative static finding candidate creation time".into())
            })?,
        })
    }
}

fn parse_missing_references_json(json: &str) -> Result<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|error| {
        Error::Corrupt(format!(
            "invalid persisted missing references JSON: {error}"
        ))
    })?;
    let references: Vec<String> = serde_json::from_value(value.clone()).map_err(|error| {
        Error::Corrupt(format!("invalid persisted missing references: {error}"))
    })?;
    if serde_json::to_value(&references)
        .map_err(|error| Error::Corrupt(format!("serialize missing references: {error}")))?
        != value
    {
        return Err(Error::Corrupt(
            "persisted missing references contain noncanonical fields".into(),
        ));
    }
    Ok(references)
}
