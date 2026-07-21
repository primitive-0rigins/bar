//! Durable, revision-bound shadow static-finding candidates (Phase 7).

use std::collections::{BTreeMap, BTreeSet};

use bar_audit::{AuditCategory, AuditEvent};
use bar_contract::SourceRef;
use bar_core::{
    ContractId, Error, FindingStatus, NormativeKind, Result, RevisionId, Sha256Digest, TargetId,
};
use bar_findings::{
    promote_candidate, validate_static_finding, validate_static_finding_candidate, StaticFinding,
    StaticFindingCandidate, StaticFindingKind,
};
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

/// Result of promoting one revision's candidates into aggregated findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticFindingPromotion {
    pub inserted: usize,
    pub aggregated: usize,
}

/// A reloaded, revalidated aggregated finding with its lifecycle provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredStaticFinding {
    pub target_id: TargetId,
    pub finding: StaticFinding,
    pub status: FindingStatus,
    pub first_seen_revision_id: RevisionId,
    pub last_seen_revision_id: RevisionId,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
}

#[derive(FromRow)]
struct StaticFindingRow {
    target_id: String,
    finding_fingerprint: String,
    kind: String,
    contract_exact_text_sha256: String,
    missing_references_json: String,
    status: String,
    first_seen_revision_id: String,
    last_seen_revision_id: String,
    first_seen_at_ms: i64,
    last_seen_at_ms: i64,
}

impl Store {
    /// Promotes one revision's persisted candidates into durable, aggregated
    /// findings keyed by their stable cross-revision fingerprint. A new finding
    /// inserts as `detected`; a finding already seen at another revision advances
    /// only its `last_seen_*` (aggregation) with status preserved; re-promoting
    /// the same revision is an idempotent no-op (replay). All writes and their
    /// audit events share one transaction.
    pub async fn promote_static_findings(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        now_ms: u64,
    ) -> Result<StaticFindingPromotion> {
        let seen_at = required_sqlite_u64(now_ms, "static finding timestamp")?;
        let revision_exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM target_revisions WHERE target_id = ? AND revision_id = ?",
        )
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load promotion revision"))?;
        if revision_exists.is_none() {
            return Err(Error::Corrupt(
                "static finding promotion revision does not belong to its target".into(),
            ));
        }

        let candidates = self
            .load_static_finding_candidates_for_revision(target_id, revision_id)
            .await?;
        let mut findings = BTreeMap::new();
        for stored in &candidates {
            let finding = promote_candidate(&stored.candidate)?;
            findings.insert(finding.finding_fingerprint, finding);
        }

        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let mut inserted = 0;
        let mut aggregated = 0;
        for finding in findings.values() {
            let missing_references_json = serde_json::to_string(&finding.missing_references)
                .map_err(|error| {
                    Error::Corrupt(format!("serialize missing references: {error}"))
                })?;
            let existing: Option<(String, String, String, String, i64)> = sqlx::query_as(
                "SELECT kind, contract_exact_text_sha256, missing_references_json, last_seen_revision_id, last_seen_at_ms \
                 FROM static_findings WHERE target_id = ? AND finding_fingerprint = ?",
            )
            .bind(target_id.to_string())
            .bind(finding.finding_fingerprint.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("load static finding"))?;
            match existing {
                None => {
                    sqlx::query(
                        "INSERT INTO static_findings \
                         (target_id, finding_fingerprint, kind, contract_exact_text_sha256, \
                          missing_references_json, status, first_seen_revision_id, \
                          last_seen_revision_id, first_seen_at_ms, last_seen_at_ms) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(target_id.to_string())
                    .bind(finding.finding_fingerprint.to_string())
                    .bind(finding.kind.as_str())
                    .bind(finding.contract_exact_text_sha256.to_string())
                    .bind(&missing_references_json)
                    .bind(FindingStatus::Detected.as_str())
                    .bind(revision_id.to_string())
                    .bind(revision_id.to_string())
                    .bind(seen_at)
                    .bind(seen_at)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("insert static finding"))?;
                    append_audit(
                        &mut tx,
                        AuditEvent {
                            category: AuditCategory::EvidenceMutation,
                            actor: SYSTEM_ACTOR.to_string(),
                            summary: "promoted shadow static finding".into(),
                            subject: Some(finding.finding_fingerprint.to_string()),
                            occurred_at_ms: now_ms,
                        },
                    )
                    .await?;
                    inserted += 1;
                }
                Some((kind, exact_text, references_json, last_seen, last_seen_at)) => {
                    if kind != finding.kind.as_str()
                        || exact_text != finding.contract_exact_text_sha256.to_string()
                        || references_json != missing_references_json
                    {
                        return Err(Error::Corrupt(
                            "persisted static finding identity does not match its fingerprint"
                                .into(),
                        ));
                    }
                    // Replay or stale re-promotion is a no-op: only a strictly
                    // newer promotion (monotonic in a forward scan) advances the
                    // occurrence window, so `last_seen_*` never drifts backward
                    // and no spurious audit event is emitted.
                    if last_seen == revision_id.to_string() || seen_at <= last_seen_at {
                        continue;
                    }
                    sqlx::query(
                        "UPDATE static_findings SET last_seen_revision_id = ?, last_seen_at_ms = ? \
                         WHERE target_id = ? AND finding_fingerprint = ?",
                    )
                    .bind(revision_id.to_string())
                    .bind(seen_at)
                    .bind(target_id.to_string())
                    .bind(finding.finding_fingerprint.to_string())
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("aggregate static finding"))?;
                    append_audit(
                        &mut tx,
                        AuditEvent {
                            category: AuditCategory::EvidenceMutation,
                            actor: SYSTEM_ACTOR.to_string(),
                            summary: "aggregated shadow static finding occurrence".into(),
                            subject: Some(finding.finding_fingerprint.to_string()),
                            occurred_at_ms: now_ms,
                        },
                    )
                    .await?;
                    aggregated += 1;
                }
            }
        }
        tx.commit().await.map_err(storage("commit"))?;
        Ok(StaticFindingPromotion {
            inserted,
            aggregated,
        })
    }

    /// Reloads and revalidates one aggregated finding, failing closed on a forged
    /// identity or an unknown persisted status token.
    pub async fn load_static_finding(
        &self,
        target_id: &TargetId,
        finding_fingerprint: &Sha256Digest,
    ) -> Result<StoredStaticFinding> {
        let row: Option<StaticFindingRow> = sqlx::query_as(
            "SELECT target_id, finding_fingerprint, kind, contract_exact_text_sha256, \
                    missing_references_json, status, first_seen_revision_id, \
                    last_seen_revision_id, first_seen_at_ms, last_seen_at_ms \
             FROM static_findings WHERE target_id = ? AND finding_fingerprint = ?",
        )
        .bind(target_id.to_string())
        .bind(finding_fingerprint.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load static finding"))?;
        let row = row.ok_or_else(|| {
            Error::Corrupt(format!("unknown static finding {finding_fingerprint}"))
        })?;
        row.into_stored(target_id, finding_fingerprint)
    }
}

impl StaticFindingRow {
    fn into_stored(
        self,
        requested_target: &TargetId,
        requested_fingerprint: &Sha256Digest,
    ) -> Result<StoredStaticFinding> {
        let target_id: TargetId = self.target_id.parse()?;
        let finding_fingerprint: Sha256Digest = self.finding_fingerprint.parse()?;
        if target_id != *requested_target || finding_fingerprint != *requested_fingerprint {
            return Err(Error::Corrupt(
                "persisted static finding crosses a target or fingerprint boundary".into(),
            ));
        }
        let finding = StaticFinding {
            finding_fingerprint,
            kind: StaticFindingKind::from_token(&self.kind)?,
            contract_exact_text_sha256: self.contract_exact_text_sha256.parse()?,
            missing_references: parse_missing_references_json(&self.missing_references_json)?,
        };
        validate_static_finding(&finding)?;
        Ok(StoredStaticFinding {
            target_id,
            finding,
            status: finding_status_from_token(&self.status)?,
            first_seen_revision_id: self.first_seen_revision_id.parse()?,
            last_seen_revision_id: self.last_seen_revision_id.parse()?,
            first_seen_at_ms: u64::try_from(self.first_seen_at_ms)
                .map_err(|_| Error::Corrupt("negative static finding first-seen time".into()))?,
            last_seen_at_ms: u64::try_from(self.last_seen_at_ms)
                .map_err(|_| Error::Corrupt("negative static finding last-seen time".into()))?,
        })
    }
}

fn finding_status_from_token(token: &str) -> Result<FindingStatus> {
    FindingStatus::VARIANTS
        .iter()
        .copied()
        .find(|status| status.as_str() == token)
        .ok_or_else(|| Error::Corrupt(format!("unknown static finding status `{token}`")))
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
