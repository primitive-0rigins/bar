//! Durable lifecycle for conservative architecture findings (Phase 7).

use bar_audit::{AuditCategory, AuditEvent};
use bar_core::{Error, FindingStatus, Result, RevisionId, Sha256Digest, TargetId};
use bar_findings::{
    detect_architecture_findings, validate_architecture_finding_candidate,
    ArchitectureFindingCandidate, ArchitectureFindingKind,
};
use bar_static::StaticArtifactFacts;
use sqlx::FromRow;

use crate::static_findings::finding_status_from_token;
use crate::{append_audit, required_sqlite_u64, storage, Store, SYSTEM_ACTOR};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchitectureFindingPromotion {
    pub inserted: usize,
    pub aggregated: usize,
    pub retained: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArchitectureFinding {
    pub target_id: TargetId,
    pub finding: ArchitectureFindingCandidate,
    pub status: FindingStatus,
    pub first_seen_revision_id: RevisionId,
    pub last_seen_revision_id: RevisionId,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
}

#[derive(FromRow)]
struct ArchitectureFindingRow {
    target_id: String,
    finding_fingerprint: String,
    kind: String,
    artifact_id: String,
    path: String,
    symbol: Option<String>,
    line: i64,
    evidence: String,
    status: String,
    first_seen_revision_id: String,
    last_seen_revision_id: String,
    first_seen_at_ms: i64,
    last_seen_at_ms: i64,
}

#[derive(FromRow)]
struct ArchitectureIdentityRow {
    kind: String,
    artifact_id: String,
    path: String,
    symbol: Option<String>,
    line: i64,
    evidence: String,
    status: String,
    last_seen_revision_id: String,
    last_seen_at_ms: i64,
}

impl Store {
    /// Recomputes the architecture detectors from authoritative stored facts,
    /// then inserts or aggregates their provisional findings atomically.
    pub async fn promote_architecture_findings(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        now_ms: u64,
    ) -> Result<ArchitectureFindingPromotion> {
        let seen_at = required_sqlite_u64(now_ms, "architecture finding timestamp")?;
        let facts = self
            .load_static_facts_for_revision(target_id, revision_id)
            .await?
            .into_iter()
            .map(|stored| StaticArtifactFacts {
                artifact_id: stored.artifact_id,
                facts: stored.facts,
            })
            .collect::<Vec<_>>();
        let findings = detect_architecture_findings(&facts)?;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let mut inserted = 0;
        let mut aggregated = 0;
        let mut retained = 0;
        for finding in &findings {
            validate_architecture_finding_candidate(finding)?;
            let existing: Option<ArchitectureIdentityRow> = sqlx::query_as(
                "SELECT kind, artifact_id, path, symbol, line, evidence, status, \
                            last_seen_revision_id, last_seen_at_ms \
                     FROM architecture_findings WHERE target_id = ? AND finding_fingerprint = ?",
            )
            .bind(target_id.to_string())
            .bind(finding.fingerprint.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("load architecture finding"))?;
            match existing {
                None => {
                    sqlx::query(
                        "INSERT INTO architecture_findings \
                         (target_id, finding_fingerprint, kind, artifact_id, path, symbol, line, evidence, \
                          status, first_seen_revision_id, last_seen_revision_id, first_seen_at_ms, last_seen_at_ms) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(target_id.to_string())
                    .bind(finding.fingerprint.to_string())
                    .bind(finding.kind.as_str())
                    .bind(finding.artifact_id.to_string())
                    .bind(&finding.path)
                    .bind(finding.symbol.as_deref())
                    .bind(i64::from(finding.line))
                    .bind(&finding.evidence)
                    .bind(FindingStatus::Detected.as_str())
                    .bind(revision_id.to_string())
                    .bind(revision_id.to_string())
                    .bind(seen_at)
                    .bind(seen_at)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("insert architecture finding"))?;
                    append_audit(
                        &mut tx,
                        AuditEvent {
                            category: AuditCategory::EvidenceMutation,
                            actor: SYSTEM_ACTOR.into(),
                            summary: format!("detected provisional {}", finding.kind.as_str()),
                            subject: Some(finding.fingerprint.to_string()),
                            occurred_at_ms: now_ms,
                        },
                    )
                    .await?;
                    inserted += 1;
                }
                Some(existing) => {
                    if existing.kind != finding.kind.as_str()
                        || existing.artifact_id != finding.artifact_id.to_string()
                        || existing.path != finding.path
                        || existing.symbol != finding.symbol
                        || existing.line != i64::from(finding.line)
                        || existing.evidence != finding.evidence
                    {
                        return Err(Error::Corrupt(
                            "persisted architecture finding identity is inconsistent".into(),
                        ));
                    }
                    if finding_status_from_token(&existing.status)? != FindingStatus::Detected {
                        retained += 1;
                    } else if existing.last_seen_revision_id != revision_id.to_string()
                        && seen_at > existing.last_seen_at_ms
                    {
                        sqlx::query(
                            "UPDATE architecture_findings SET last_seen_revision_id = ?, last_seen_at_ms = ? \
                             WHERE target_id = ? AND finding_fingerprint = ?",
                        )
                        .bind(revision_id.to_string())
                        .bind(seen_at)
                        .bind(target_id.to_string())
                        .bind(finding.fingerprint.to_string())
                        .execute(&mut *tx)
                        .await
                        .map_err(storage("aggregate architecture finding"))?;
                        aggregated += 1;
                    }
                }
            }
        }
        tx.commit().await.map_err(storage("commit"))?;
        Ok(ArchitectureFindingPromotion {
            inserted,
            aggregated,
            retained,
        })
    }

    pub async fn load_architecture_findings(
        &self,
        target_id: &TargetId,
    ) -> Result<Vec<StoredArchitectureFinding>> {
        let rows: Vec<ArchitectureFindingRow> = sqlx::query_as(
            "SELECT target_id, finding_fingerprint, kind, artifact_id, path, symbol, line, evidence, \
                    status, first_seen_revision_id, last_seen_revision_id, first_seen_at_ms, last_seen_at_ms \
             FROM architecture_findings WHERE target_id = ? ORDER BY kind, path, line",
        )
        .bind(target_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load architecture findings"))?;
        rows.into_iter()
            .map(ArchitectureFindingRow::into_stored)
            .collect()
    }

    pub async fn reject_architecture_finding(
        &self,
        target_id: &TargetId,
        fingerprint: &Sha256Digest,
        reason: &str,
        now_ms: u64,
    ) -> Result<()> {
        if reason.trim().is_empty() {
            return Err(Error::Corrupt(
                "finding correction requires a reason".into(),
            ));
        }
        let current = self
            .load_architecture_findings(target_id)
            .await?
            .into_iter()
            .find(|stored| stored.finding.fingerprint == *fingerprint)
            .ok_or_else(|| Error::Corrupt(format!("unknown architecture finding {fingerprint}")))?;
        if current.status == FindingStatus::Rejected {
            return Ok(());
        }
        if current.status != FindingStatus::Detected {
            return Err(Error::Corrupt(
                "only a detected architecture finding can be rejected".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        sqlx::query(
            "UPDATE architecture_findings SET status = ? \
             WHERE target_id = ? AND finding_fingerprint = ? AND status = ?",
        )
        .bind(FindingStatus::Rejected.as_str())
        .bind(target_id.to_string())
        .bind(fingerprint.to_string())
        .bind(FindingStatus::Detected.as_str())
        .execute(&mut *tx)
        .await
        .map_err(storage("reject architecture finding"))?;
        append_audit(
            &mut tx,
            AuditEvent {
                category: AuditCategory::LifecycleTransition,
                actor: SYSTEM_ACTOR.into(),
                summary: format!("corrected architecture finding as false positive: {reason}"),
                subject: Some(fingerprint.to_string()),
                occurred_at_ms: now_ms,
            },
        )
        .await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }
}

impl ArchitectureFindingRow {
    fn into_stored(self) -> Result<StoredArchitectureFinding> {
        let finding = ArchitectureFindingCandidate {
            fingerprint: self.finding_fingerprint.parse()?,
            kind: ArchitectureFindingKind::from_token(&self.kind)?,
            artifact_id: self.artifact_id.parse()?,
            path: self.path,
            symbol: self.symbol,
            line: u32::try_from(self.line)
                .map_err(|_| Error::Corrupt("invalid architecture finding line".into()))?,
            evidence: self.evidence,
        };
        validate_architecture_finding_candidate(&finding)?;
        Ok(StoredArchitectureFinding {
            target_id: self.target_id.parse()?,
            finding,
            status: finding_status_from_token(&self.status)?,
            first_seen_revision_id: self.first_seen_revision_id.parse()?,
            last_seen_revision_id: self.last_seen_revision_id.parse()?,
            first_seen_at_ms: u64::try_from(self.first_seen_at_ms)
                .map_err(|_| Error::Corrupt("negative first-seen timestamp".into()))?,
            last_seen_at_ms: u64::try_from(self.last_seen_at_ms)
                .map_err(|_| Error::Corrupt("negative last-seen timestamp".into()))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bar_discovery::{scan, PriorInventory, ScanConfig};
    use bar_static::analyze_inventory;
    use bar_target::resolve_target;

    #[tokio::test]
    async fn architecture_findings_replay_and_retain_false_positive_correction() {
        let database = tempfile::tempdir().unwrap();
        let store = Store::connect(&format!(
            "sqlite://{}",
            database.path().join("bar.db").display()
        ))
        .await
        .unwrap();
        store.migrate().await.unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(target_dir.path().join("src")).unwrap();
        std::fs::write(
            target_dir.path().join("src/runtime.rs"),
            "fn bypass() { std::fs::write(\"ledger\", \"x\"); }\nfn main() {}\n",
        )
        .unwrap();
        let target = resolve_target("runtime", target_dir.path()).unwrap();
        let registration = store.register_target(&target, 1).await.unwrap();
        let revision = store
            .record_revision(&registration.target_id, &target.revision, 1)
            .await
            .unwrap();
        let inventory = scan(
            &target.root_locator,
            &ScanConfig::default(),
            &PriorInventory::new(),
        )
        .unwrap();
        store
            .persist_inventory(
                &registration.target_id,
                &revision.revision_id,
                &inventory,
                2,
            )
            .await
            .unwrap();
        let batch =
            analyze_inventory(&target.root_locator, &inventory, &revision.revision_id).unwrap();
        store
            .persist_static_batch(&registration.target_id, &revision.revision_id, &batch, 3)
            .await
            .unwrap();

        let first = store
            .promote_architecture_findings(&registration.target_id, &revision.revision_id, 4)
            .await
            .unwrap();
        assert!(first.inserted >= 2);
        let replay = store
            .promote_architecture_findings(&registration.target_id, &revision.revision_id, 5)
            .await
            .unwrap();
        assert_eq!(replay.aggregated, 0);
        let stored = store
            .load_architecture_findings(&registration.target_id)
            .await
            .unwrap();
        let bypass = stored
            .iter()
            .find(|finding| finding.finding.kind == ArchitectureFindingKind::BypassPath)
            .unwrap();
        store
            .reject_architecture_finding(
                &registration.target_id,
                &bypass.finding.fingerprint,
                "external policy gate",
                6,
            )
            .await
            .unwrap();
        let retained = store
            .promote_architecture_findings(&registration.target_id, &revision.revision_id, 7)
            .await
            .unwrap();
        assert!(retained.retained >= 1);
    }
}
