//! Durable, aggregated shadow contradiction findings (Phase 7).
//!
//! Promotes the persisted conflict candidates (migration 0006) into stable,
//! cross-revision findings keyed by their revision-independent fingerprint (spec
//! Appendix H.5), mirroring the missing-implementation finding layer in
//! `static_findings`. A contradiction is provisional by construction — the
//! static layer cannot see contract scope — so it is emitted at `detected` and
//! an operator may correct an apparent contradiction that is really a scoped
//! exception as a false positive, which every later scan retains.

use std::collections::BTreeMap;

use bar_audit::{AuditCategory, AuditEvent};
use bar_core::{Error, FindingStatus, Result, RevisionId, Sha256Digest, TargetId};
use bar_findings::{contradiction_finding, validate_contradiction_finding, ContradictionFinding};
use sqlx::FromRow;

use crate::static_findings::finding_status_from_token;
use crate::{append_audit, required_sqlite_u64, storage, Store, SYSTEM_ACTOR};

/// Result of promoting one revision's conflict candidates into aggregated
/// contradiction findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContradictionPromotion {
    pub inserted: usize,
    pub aggregated: usize,
    /// Findings whose conflict recurred at this revision but which carry an
    /// operator disposition (e.g. a false-positive rejection of a scoped
    /// exception), so promotion leaves them untouched.
    pub retained: usize,
}

/// A reloaded, revalidated aggregated contradiction finding with its lifecycle
/// provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredContradictionFinding {
    pub target_id: TargetId,
    pub finding: ContradictionFinding,
    pub status: FindingStatus,
    pub first_seen_revision_id: RevisionId,
    pub last_seen_revision_id: RevisionId,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
}

impl Store {
    /// Promotes one revision's persisted conflict candidates into durable,
    /// aggregated contradiction findings keyed by their stable cross-revision
    /// fingerprint. A new conflict inserts as `detected`; a conflict already seen
    /// at another revision advances only its `last_seen_*` (aggregation) with
    /// status preserved; re-promoting the same revision is an idempotent no-op
    /// (replay); a finding carrying an operator disposition is retained untouched.
    /// All writes and their audit events share one transaction.
    pub async fn promote_contradiction_findings(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        now_ms: u64,
    ) -> Result<ContradictionPromotion> {
        let seen_at = required_sqlite_u64(now_ms, "contradiction finding timestamp")?;
        let revision_exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM target_revisions WHERE target_id = ? AND revision_id = ?",
        )
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load contradiction promotion revision"))?;
        if revision_exists.is_none() {
            return Err(Error::Corrupt(
                "contradiction finding promotion revision does not belong to its target".into(),
            ));
        }

        // Load this revision's conflict candidates, target-scoped, and resolve
        // each opposing claim's revision-stable cited-text hash. The stored
        // conflict status must be the closed `candidate` token or the load fails.
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT left_contract.fingerprint, right_contract.fingerprint, \
                    candidate.shared_subject, candidate.status \
             FROM contract_conflict_candidates candidate \
             JOIN contracts left_contract ON left_contract.contract_id = candidate.left_contract_id \
             JOIN contracts right_contract ON right_contract.contract_id = candidate.right_contract_id \
             WHERE left_contract.target_id = ? AND left_contract.revision_id = ? \
               AND right_contract.target_id = ? AND right_contract.revision_id = ? \
             ORDER BY left_contract.fingerprint, right_contract.fingerprint",
        )
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load conflict candidates"))?;

        let mut findings = BTreeMap::new();
        for (left_fingerprint, right_fingerprint, shared_subject, status) in rows {
            if status != "candidate" {
                return Err(Error::Corrupt(format!(
                    "unknown contract conflict candidate status `{status}`"
                )));
            }
            let left_exact = self
                .resolve_claim_exact_text(target_id, revision_id, &left_fingerprint)
                .await?;
            let right_exact = self
                .resolve_claim_exact_text(target_id, revision_id, &right_fingerprint)
                .await?;
            let finding = contradiction_finding(left_exact, right_exact, &shared_subject)?;
            findings.insert(finding.finding_fingerprint, finding);
        }

        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let mut inserted = 0;
        let mut aggregated = 0;
        let mut retained = 0;
        for finding in findings.values() {
            let existing: Option<(String, String, String, String, i64, String)> = sqlx::query_as(
                "SELECT left_exact_text_sha256, right_exact_text_sha256, shared_subject, \
                        last_seen_revision_id, last_seen_at_ms, status \
                 FROM contradiction_findings WHERE target_id = ? AND finding_fingerprint = ?",
            )
            .bind(target_id.to_string())
            .bind(finding.finding_fingerprint.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("load contradiction finding"))?;
            match existing {
                None => {
                    sqlx::query(
                        "INSERT INTO contradiction_findings \
                         (target_id, finding_fingerprint, left_exact_text_sha256, \
                          right_exact_text_sha256, shared_subject, status, \
                          first_seen_revision_id, last_seen_revision_id, \
                          first_seen_at_ms, last_seen_at_ms) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(target_id.to_string())
                    .bind(finding.finding_fingerprint.to_string())
                    .bind(finding.left_exact_text_sha256.to_string())
                    .bind(finding.right_exact_text_sha256.to_string())
                    .bind(&finding.shared_subject)
                    .bind(FindingStatus::Detected.as_str())
                    .bind(revision_id.to_string())
                    .bind(revision_id.to_string())
                    .bind(seen_at)
                    .bind(seen_at)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("insert contradiction finding"))?;
                    append_audit(
                        &mut tx,
                        AuditEvent {
                            category: AuditCategory::EvidenceMutation,
                            actor: SYSTEM_ACTOR.to_string(),
                            summary: "promoted shadow contradiction finding".into(),
                            subject: Some(finding.finding_fingerprint.to_string()),
                            occurred_at_ms: now_ms,
                        },
                    )
                    .await?;
                    inserted += 1;
                }
                Some((left, right, subject, last_seen, last_seen_at, status)) => {
                    if left != finding.left_exact_text_sha256.to_string()
                        || right != finding.right_exact_text_sha256.to_string()
                        || subject != finding.shared_subject
                    {
                        return Err(Error::Corrupt(
                            "persisted contradiction finding identity does not match its fingerprint"
                                .into(),
                        ));
                    }
                    // A finding carrying an operator disposition (only a
                    // false-positive rejection today) is retained: re-detecting
                    // the same conflict neither advances its occurrence window nor
                    // reopens it, so the correction survives every replay.
                    // `detected` is the only status this layer aggregates *by
                    // current reachability* — the same reasoning as
                    // `promote_static_findings`. An unknown token fails closed.
                    if finding_status_from_token(&status)? != FindingStatus::Detected {
                        retained += 1;
                        continue;
                    }
                    // Replay or stale re-promotion is a no-op: only a strictly
                    // newer promotion advances the occurrence window, so
                    // `last_seen_*` never drifts backward and no spurious audit
                    // event is emitted.
                    if last_seen == revision_id.to_string() || seen_at <= last_seen_at {
                        continue;
                    }
                    sqlx::query(
                        "UPDATE contradiction_findings \
                         SET last_seen_revision_id = ?, last_seen_at_ms = ? \
                         WHERE target_id = ? AND finding_fingerprint = ?",
                    )
                    .bind(revision_id.to_string())
                    .bind(seen_at)
                    .bind(target_id.to_string())
                    .bind(finding.finding_fingerprint.to_string())
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("aggregate contradiction finding"))?;
                    append_audit(
                        &mut tx,
                        AuditEvent {
                            category: AuditCategory::EvidenceMutation,
                            actor: SYSTEM_ACTOR.to_string(),
                            summary: "aggregated shadow contradiction finding occurrence".into(),
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
        Ok(ContradictionPromotion {
            inserted,
            aggregated,
            retained,
        })
    }

    /// Records an operator's false-positive correction of a contradiction: the
    /// apparent conflict is a scoped exception, not a real defect. A `detected`
    /// finding transitions to `rejected` (Appendix G), audited as a lifecycle
    /// transition, and `promote_contradiction_findings` retains it across every
    /// later scan. Re-rejecting is an idempotent no-op; any other current status
    /// fails closed. Authorization of *who* may correct a finding is Phase 14.
    pub async fn reject_contradiction_finding(
        &self,
        target_id: &TargetId,
        finding_fingerprint: &Sha256Digest,
        reason: &str,
        now_ms: u64,
    ) -> Result<()> {
        if reason.trim().is_empty() {
            return Err(Error::Corrupt(
                "false-positive correction requires a reason".into(),
            ));
        }
        let stored = self
            .load_contradiction_finding(target_id, finding_fingerprint)
            .await?;
        match stored.status {
            FindingStatus::Rejected => return Ok(()),
            FindingStatus::Detected => {}
            _ => {
                return Err(Error::Corrupt(
                    "only a detected contradiction finding can be corrected as a false positive"
                        .into(),
                ))
            }
        }

        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let updated = sqlx::query(
            "UPDATE contradiction_findings SET status = ? \
             WHERE target_id = ? AND finding_fingerprint = ? AND status = ?",
        )
        .bind(FindingStatus::Rejected.as_str())
        .bind(target_id.to_string())
        .bind(finding_fingerprint.to_string())
        .bind(FindingStatus::Detected.as_str())
        .execute(&mut *tx)
        .await
        .map_err(storage("reject contradiction finding"))?;
        if updated.rows_affected() != 1 {
            return Err(Error::Corrupt(
                "false-positive correction did not apply to exactly one detected finding".into(),
            ));
        }
        append_audit(
            &mut tx,
            AuditEvent {
                category: AuditCategory::LifecycleTransition,
                actor: SYSTEM_ACTOR.to_string(),
                summary: format!(
                    "corrected shadow contradiction finding as a false positive: {reason}"
                ),
                subject: Some(finding_fingerprint.to_string()),
                occurred_at_ms: now_ms,
            },
        )
        .await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }

    /// Reloads and revalidates one aggregated contradiction finding, failing
    /// closed on a forged identity or an unknown persisted status token.
    pub async fn load_contradiction_finding(
        &self,
        target_id: &TargetId,
        finding_fingerprint: &Sha256Digest,
    ) -> Result<StoredContradictionFinding> {
        let row: Option<ContradictionFindingRow> = sqlx::query_as(
            "SELECT finding_fingerprint, left_exact_text_sha256, right_exact_text_sha256, \
                    shared_subject, status, first_seen_revision_id, last_seen_revision_id, \
                    first_seen_at_ms, last_seen_at_ms \
             FROM contradiction_findings WHERE target_id = ? AND finding_fingerprint = ?",
        )
        .bind(target_id.to_string())
        .bind(finding_fingerprint.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load contradiction finding"))?;
        let row = row.ok_or_else(|| {
            Error::Corrupt(format!(
                "unknown contradiction finding {finding_fingerprint}"
            ))
        })?;
        row.into_stored(target_id, finding_fingerprint)
    }

    /// Resolves one contract claim's revision-stable cited-text hash by its
    /// revision-scoped claim fingerprint. Exactly one contract, with exactly one
    /// source row, must match within the target revision, or the conflict is
    /// corrupt.
    async fn resolve_claim_exact_text(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        claim_fingerprint: &str,
    ) -> Result<Sha256Digest> {
        let hashes: Vec<String> = sqlx::query_scalar(
            "SELECT s.exact_text_sha256 \
             FROM contracts c JOIN contract_sources s ON s.contract_id = c.contract_id \
             WHERE c.target_id = ? AND c.revision_id = ? AND c.fingerprint = ?",
        )
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .bind(claim_fingerprint)
        .fetch_all(&self.pool)
        .await
        .map_err(storage("resolve conflict claim source"))?;
        match hashes.as_slice() {
            [only] => only.parse(),
            _ => Err(Error::Corrupt(
                "conflict candidate claim does not resolve to exactly one source-bound contract"
                    .into(),
            )),
        }
    }
}

#[derive(FromRow)]
struct ContradictionFindingRow {
    finding_fingerprint: String,
    left_exact_text_sha256: String,
    right_exact_text_sha256: String,
    shared_subject: String,
    status: String,
    first_seen_revision_id: String,
    last_seen_revision_id: String,
    first_seen_at_ms: i64,
    last_seen_at_ms: i64,
}

impl ContradictionFindingRow {
    fn into_stored(
        self,
        requested_target: &TargetId,
        requested_fingerprint: &Sha256Digest,
    ) -> Result<StoredContradictionFinding> {
        let finding = contradiction_finding(
            self.left_exact_text_sha256.parse()?,
            self.right_exact_text_sha256.parse()?,
            &self.shared_subject,
        )?;
        validate_contradiction_finding(&finding)?;
        if finding.finding_fingerprint != *requested_fingerprint
            || self.finding_fingerprint != requested_fingerprint.to_string()
        {
            return Err(Error::Corrupt(
                "persisted contradiction finding does not match its stored fingerprint".into(),
            ));
        }
        Ok(StoredContradictionFinding {
            target_id: *requested_target,
            finding,
            status: finding_status_from_token(&self.status)?,
            first_seen_revision_id: self.first_seen_revision_id.parse()?,
            last_seen_revision_id: self.last_seen_revision_id.parse()?,
            first_seen_at_ms: u64::try_from(self.first_seen_at_ms).map_err(|_| {
                Error::Corrupt("negative contradiction finding first-seen time".into())
            })?,
            last_seen_at_ms: u64::try_from(self.last_seen_at_ms).map_err(|_| {
                Error::Corrupt("negative contradiction finding last-seen time".into())
            })?,
        })
    }
}
