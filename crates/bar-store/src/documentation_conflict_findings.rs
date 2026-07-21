//! Durable, aggregated shadow documentation-conflict findings (Phase 7).
//!
//! Promotes the glossary ambiguities derived from the persisted glossary
//! candidates (migration 0006) into stable, cross-revision findings keyed by
//! their revision-independent fingerprint (spec Appendix H.5), mirroring the
//! contradiction finding layer. A documentation conflict is one glossary term
//! carrying two or more conflicting definitions; it is provisional (spec
//! §"Operator can resolve a documentation conflict through a versioned ruling"),
//! so it is emitted at `detected` and an operator may correct an apparent
//! conflict as a false positive, which every later scan retains.

use std::collections::BTreeMap;

use bar_audit::{AuditCategory, AuditEvent};
use bar_core::{Error, FindingStatus, Result, RevisionId, Sha256Digest, TargetId};
use bar_findings::{
    documentation_conflict_finding, documentation_conflict_finding_from_digests,
    DocumentationConflictFinding,
};
use sqlx::FromRow;

use crate::static_findings::finding_status_from_token;
use crate::{append_audit, required_sqlite_u64, storage, Store, SYSTEM_ACTOR};

/// Result of promoting one revision's glossary ambiguities into aggregated
/// documentation-conflict findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentationConflictPromotion {
    pub inserted: usize,
    pub aggregated: usize,
    /// Findings whose conflict recurred at this revision but which carry an
    /// operator disposition (e.g. a false-positive rejection), so promotion
    /// leaves them untouched.
    pub retained: usize,
}

/// A reloaded, revalidated aggregated documentation-conflict finding with its
/// lifecycle provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDocumentationConflictFinding {
    pub target_id: TargetId,
    pub finding: DocumentationConflictFinding,
    pub status: FindingStatus,
    pub first_seen_revision_id: RevisionId,
    pub last_seen_revision_id: RevisionId,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
}

impl Store {
    /// Promotes one revision's glossary ambiguities into durable, aggregated
    /// documentation-conflict findings keyed by their stable cross-revision
    /// fingerprint. A new conflict inserts as `detected`; a conflict already seen
    /// at another revision advances only its `last_seen_*` (aggregation) with
    /// status preserved; re-promoting the same revision is an idempotent no-op
    /// (replay); a finding carrying an operator disposition is retained untouched.
    /// All writes and their audit events share one transaction.
    pub async fn promote_documentation_conflict_findings(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        now_ms: u64,
    ) -> Result<DocumentationConflictPromotion> {
        let seen_at = required_sqlite_u64(now_ms, "documentation conflict finding timestamp")?;
        let revision_exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM target_revisions WHERE target_id = ? AND revision_id = ?",
        )
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load documentation conflict promotion revision"))?;
        if revision_exists.is_none() {
            return Err(Error::Corrupt(
                "documentation conflict promotion revision does not belong to its target".into(),
            ));
        }

        // Reload this revision's revalidated glossary candidates and their
        // derived ambiguities. The ambiguity set is the authoritative decision of
        // *which* terms conflict; the candidates supply each term's definitions,
        // grouped by the same key (`canonical.to_lowercase()`) the detector uses.
        let candidates = self.load_analysis_candidates(revision_id).await?;
        let mut definitions_by_term: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for candidate in &candidates.glossary {
            definitions_by_term
                .entry(candidate.canonical.to_lowercase())
                .or_default()
                .push(candidate.definition.clone());
        }

        let mut findings = BTreeMap::new();
        for ambiguity in &candidates.glossary_ambiguities {
            let definitions = definitions_by_term
                .get(&ambiguity.normalized_term)
                .ok_or_else(|| {
                    Error::Corrupt(
                        "glossary ambiguity references a term with no persisted definitions".into(),
                    )
                })?;
            let finding = documentation_conflict_finding(&ambiguity.normalized_term, definitions)?;
            findings.insert(finding.finding_fingerprint, finding);
        }

        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let mut inserted = 0;
        let mut aggregated = 0;
        let mut retained = 0;
        for finding in findings.values() {
            let definition_hashes_json = definition_hashes_json(finding);
            let existing: Option<(String, String, String, i64, String)> = sqlx::query_as(
                "SELECT normalized_term, definition_hashes_json, \
                        last_seen_revision_id, last_seen_at_ms, status \
                 FROM documentation_conflict_findings \
                 WHERE target_id = ? AND finding_fingerprint = ?",
            )
            .bind(target_id.to_string())
            .bind(finding.finding_fingerprint.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("load documentation conflict finding"))?;
            match existing {
                None => {
                    sqlx::query(
                        "INSERT INTO documentation_conflict_findings \
                         (target_id, finding_fingerprint, normalized_term, \
                          definition_hashes_json, status, \
                          first_seen_revision_id, last_seen_revision_id, \
                          first_seen_at_ms, last_seen_at_ms) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(target_id.to_string())
                    .bind(finding.finding_fingerprint.to_string())
                    .bind(&finding.normalized_term)
                    .bind(&definition_hashes_json)
                    .bind(FindingStatus::Detected.as_str())
                    .bind(revision_id.to_string())
                    .bind(revision_id.to_string())
                    .bind(seen_at)
                    .bind(seen_at)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("insert documentation conflict finding"))?;
                    append_audit(
                        &mut tx,
                        AuditEvent {
                            category: AuditCategory::EvidenceMutation,
                            actor: SYSTEM_ACTOR.to_string(),
                            summary: "promoted shadow documentation conflict finding".into(),
                            subject: Some(finding.finding_fingerprint.to_string()),
                            occurred_at_ms: now_ms,
                        },
                    )
                    .await?;
                    inserted += 1;
                }
                Some((term, hashes, last_seen, last_seen_at, status)) => {
                    if term != finding.normalized_term || hashes != definition_hashes_json {
                        return Err(Error::Corrupt(
                            "persisted documentation conflict finding identity does not match its fingerprint"
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
                        "UPDATE documentation_conflict_findings \
                         SET last_seen_revision_id = ?, last_seen_at_ms = ? \
                         WHERE target_id = ? AND finding_fingerprint = ?",
                    )
                    .bind(revision_id.to_string())
                    .bind(seen_at)
                    .bind(target_id.to_string())
                    .bind(finding.finding_fingerprint.to_string())
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("aggregate documentation conflict finding"))?;
                    append_audit(
                        &mut tx,
                        AuditEvent {
                            category: AuditCategory::EvidenceMutation,
                            actor: SYSTEM_ACTOR.to_string(),
                            summary: "aggregated shadow documentation conflict finding occurrence"
                                .into(),
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
        Ok(DocumentationConflictPromotion {
            inserted,
            aggregated,
            retained,
        })
    }

    /// Records an operator's false-positive correction of a documentation
    /// conflict: the apparent conflict is not a real defect. A `detected` finding
    /// transitions to `rejected` (Appendix G), audited as a lifecycle transition,
    /// and `promote_documentation_conflict_findings` retains it across every later
    /// scan. Re-rejecting is an idempotent no-op; any other current status fails
    /// closed. Authorization of *who* may correct a finding is Phase 14.
    pub async fn reject_documentation_conflict_finding(
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
            .load_documentation_conflict_finding(target_id, finding_fingerprint)
            .await?;
        match stored.status {
            FindingStatus::Rejected => return Ok(()),
            FindingStatus::Detected => {}
            _ => {
                return Err(Error::Corrupt(
                    "only a detected documentation conflict finding can be corrected as a false positive"
                        .into(),
                ))
            }
        }

        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let updated = sqlx::query(
            "UPDATE documentation_conflict_findings SET status = ? \
             WHERE target_id = ? AND finding_fingerprint = ? AND status = ?",
        )
        .bind(FindingStatus::Rejected.as_str())
        .bind(target_id.to_string())
        .bind(finding_fingerprint.to_string())
        .bind(FindingStatus::Detected.as_str())
        .execute(&mut *tx)
        .await
        .map_err(storage("reject documentation conflict finding"))?;
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
                    "corrected shadow documentation conflict finding as a false positive: {reason}"
                ),
                subject: Some(finding_fingerprint.to_string()),
                occurred_at_ms: now_ms,
            },
        )
        .await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }

    /// Reloads and revalidates one aggregated documentation-conflict finding,
    /// failing closed on a forged identity or an unknown persisted status token.
    pub async fn load_documentation_conflict_finding(
        &self,
        target_id: &TargetId,
        finding_fingerprint: &Sha256Digest,
    ) -> Result<StoredDocumentationConflictFinding> {
        let row: Option<DocumentationConflictFindingRow> = sqlx::query_as(
            "SELECT finding_fingerprint, normalized_term, definition_hashes_json, status, \
                    first_seen_revision_id, last_seen_revision_id, \
                    first_seen_at_ms, last_seen_at_ms \
             FROM documentation_conflict_findings \
             WHERE target_id = ? AND finding_fingerprint = ?",
        )
        .bind(target_id.to_string())
        .bind(finding_fingerprint.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load documentation conflict finding"))?;
        let row = row.ok_or_else(|| {
            Error::Corrupt(format!(
                "unknown documentation conflict finding {finding_fingerprint}"
            ))
        })?;
        row.into_stored(target_id, finding_fingerprint)
    }
}

/// Serializes a finding's definition hashes as a JSON array of hex digests, the
/// stable stored form of its identity's definition set.
fn definition_hashes_json(finding: &DocumentationConflictFinding) -> String {
    let hexes: Vec<String> = finding
        .definition_text_sha256s
        .iter()
        .map(ToString::to_string)
        .collect();
    serde_json::to_string(&hexes).expect("serialize a Vec<String> of hex digests never fails")
}

#[derive(FromRow)]
struct DocumentationConflictFindingRow {
    finding_fingerprint: String,
    normalized_term: String,
    definition_hashes_json: String,
    status: String,
    first_seen_revision_id: String,
    last_seen_revision_id: String,
    first_seen_at_ms: i64,
    last_seen_at_ms: i64,
}

impl DocumentationConflictFindingRow {
    fn into_stored(
        self,
        requested_target: &TargetId,
        requested_fingerprint: &Sha256Digest,
    ) -> Result<StoredDocumentationConflictFinding> {
        let hexes: Vec<String> = serde_json::from_str(&self.definition_hashes_json)
            .map_err(|error| Error::Corrupt(format!("invalid definition hashes JSON: {error}")))?;
        let digests = hexes
            .iter()
            .map(|hex| hex.parse())
            .collect::<Result<Vec<Sha256Digest>>>()?;
        let finding = documentation_conflict_finding_from_digests(&self.normalized_term, &digests)?;
        if finding.finding_fingerprint != *requested_fingerprint
            || self.finding_fingerprint != requested_fingerprint.to_string()
        {
            return Err(Error::Corrupt(
                "persisted documentation conflict finding does not match its stored fingerprint"
                    .into(),
            ));
        }
        Ok(StoredDocumentationConflictFinding {
            target_id: *requested_target,
            finding,
            status: finding_status_from_token(&self.status)?,
            first_seen_revision_id: self.first_seen_revision_id.parse()?,
            last_seen_revision_id: self.last_seen_revision_id.parse()?,
            first_seen_at_ms: u64::try_from(self.first_seen_at_ms).map_err(|_| {
                Error::Corrupt("negative documentation conflict finding first-seen time".into())
            })?,
            last_seen_at_ms: u64::try_from(self.last_seen_at_ms).map_err(|_| {
                Error::Corrupt("negative documentation conflict finding last-seen time".into())
            })?,
        })
    }
}
