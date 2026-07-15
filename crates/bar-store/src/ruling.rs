//! Durable, evidence-bound operator contract rulings (spec §7.4).

use bar_audit::{AuditCategory, AuditEvent};
use bar_contract::ruling::{validate_ruling, ContractRuling, RulingDisposition};
use bar_core::{Error, EvidenceId, Result, RulingId, TargetId};
use sqlx::{FromRow, Sqlite, Transaction};

use crate::{
    append_audit, required_sqlite_u64, sqlite_timestamp, storage, stored_timestamp, Store,
};

/// Result of creating or deterministically reusing an operator ruling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulingPersistence {
    pub ruling_id: RulingId,
    pub inserted: bool,
}

/// Reloaded immutable ruling with its evidence binding and history edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredContractRuling {
    pub ruling_id: RulingId,
    pub target_id: TargetId,
    pub context_evidence_id: EvidenceId,
    pub ruling: ContractRuling,
    pub created_at_ms: u64,
    pub superseded_by: Option<RulingId>,
}

#[derive(FromRow)]
struct ContractRulingRow {
    target_id: String,
    context_evidence_id: String,
    contract_refs_json: String,
    disposition: String,
    outcome: String,
    rejected_interpretations_json: String,
    rationale: String,
    scope_json: String,
    effective_from_ms: i64,
    expires_at_ms: Option<i64>,
    operator_id: String,
    created_at_ms: i64,
}

impl ContractRulingRow {
    fn into_ruling(
        self,
        ruling_id: RulingId,
        superseded_by: Option<String>,
    ) -> Result<StoredContractRuling> {
        let contract_refs = serde_json::from_str::<Vec<String>>(&self.contract_refs_json)
            .map_err(|e| Error::Corrupt(format!("invalid persisted ruling contract refs: {e}")))?
            .into_iter()
            .map(|id| id.parse())
            .collect::<Result<Vec<_>>>()?;
        let rejected_interpretations = serde_json::from_str(&self.rejected_interpretations_json)
            .map_err(|e| {
                Error::Corrupt(format!("invalid persisted rejected interpretations: {e}"))
            })?;
        let scope = serde_json::from_str(&self.scope_json)
            .map_err(|e| Error::Corrupt(format!("invalid persisted ruling scope: {e}")))?;
        let ruling = ContractRuling {
            contract_refs,
            disposition: RulingDisposition::from_token(&self.disposition)?,
            outcome: self.outcome,
            rejected_interpretations,
            rationale: self.rationale,
            scope,
            effective_from_ms: u64::try_from(self.effective_from_ms)
                .map_err(|_| Error::Corrupt("negative ruling effective time".into()))?,
            expires_at_ms: stored_timestamp(self.expires_at_ms)?,
            operator_id: self.operator_id,
        };
        validate_ruling(&ruling)?;
        Ok(StoredContractRuling {
            ruling_id,
            target_id: self.target_id.parse()?,
            context_evidence_id: self.context_evidence_id.parse()?,
            ruling,
            created_at_ms: u64::try_from(self.created_at_ms)
                .map_err(|_| Error::Corrupt("negative ruling creation time".into()))?,
            superseded_by: superseded_by.map(|id| id.parse()).transpose()?,
        })
    }

    fn matches(&self, expected: &Self) -> bool {
        self.target_id == expected.target_id
            && self.context_evidence_id == expected.context_evidence_id
            && self.contract_refs_json == expected.contract_refs_json
            && self.disposition == expected.disposition
            && self.outcome == expected.outcome
            && self.rejected_interpretations_json == expected.rejected_interpretations_json
            && self.rationale == expected.rationale
            && self.scope_json == expected.scope_json
            && self.effective_from_ms == expected.effective_from_ms
            && self.expires_at_ms == expected.expires_at_ms
            && self.operator_id == expected.operator_id
    }
}

impl Store {
    /// Persists an immutable operator ruling for an exact ambiguity context.
    /// An active ruling with the same contracts, scope, and evidence is reused.
    /// Editing a ruling creates a new record and an explicit supersession edge.
    pub async fn persist_contract_ruling(
        &self,
        target_id: &TargetId,
        context_evidence_id: &EvidenceId,
        ruling: &ContractRuling,
        supersedes: Option<&RulingId>,
        now_ms: u64,
    ) -> Result<RulingPersistence> {
        validate_ruling(ruling)?;
        let effective_from = required_sqlite_u64(ruling.effective_from_ms, "ruling timestamp")?;
        let expires_at = sqlite_timestamp(ruling.expires_at_ms)?;
        let created_at = required_sqlite_u64(now_ms, "ruling timestamp")?;
        let scope_json = serde_json::to_string(&ruling.scope)
            .map_err(|e| Error::Corrupt(format!("serialize ruling scope: {e}")))?;
        let mut contract_refs = ruling
            .contract_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        contract_refs.sort_unstable();
        let contract_refs_json = serde_json::to_string(&contract_refs)
            .map_err(|e| Error::Corrupt(format!("serialize ruling contract refs: {e}")))?;
        let rejected_json = serde_json::to_string(&ruling.rejected_interpretations)
            .map_err(|e| Error::Corrupt(format!("serialize rejected interpretations: {e}")))?;
        let target_key = target_id.to_string();
        let expected_replacement = ContractRulingRow {
            target_id: target_key.clone(),
            context_evidence_id: context_evidence_id.to_string(),
            contract_refs_json: contract_refs_json.clone(),
            disposition: ruling.disposition.as_str().into(),
            outcome: ruling.outcome.clone(),
            rejected_interpretations_json: rejected_json.clone(),
            rationale: ruling.rationale.clone(),
            scope_json: scope_json.clone(),
            effective_from_ms: effective_from,
            expires_at_ms: expires_at,
            operator_id: ruling.operator_id.clone(),
            created_at_ms: created_at,
        };
        let context = self
            .load_scope_context_evidence(context_evidence_id)
            .await?;
        if context.target_id != *target_id {
            return Err(Error::Corrupt(format!(
                "ruling context {context_evidence_id} belongs to another target"
            )));
        }
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        for contract_id in &contract_refs {
            let contract_target: Option<String> =
                sqlx::query_scalar("SELECT target_id FROM contracts WHERE contract_id = ?")
                    .bind(contract_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(storage("load ruling contract"))?;
            if contract_target.as_deref() != Some(target_key.as_str()) {
                return Err(Error::Corrupt(format!(
                    "ruling contract {contract_id} is missing or belongs to another target"
                )));
            }
        }

        if let Some(superseded_id) = supersedes {
            let existing_replacement: Option<String> = sqlx::query_scalar(
                "SELECT superseding_ruling_id FROM contract_ruling_supersessions \
                 WHERE superseded_ruling_id = ?",
            )
            .bind(superseded_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("load ruling replacement"))?;
            if let Some(replacement_id) = existing_replacement {
                let replacement: ContractRulingRow =
                    load_contract_ruling_row(&mut tx, &replacement_id, "load replayed ruling")
                        .await?;
                if replacement.matches(&expected_replacement) {
                    tx.commit().await.map_err(storage("commit"))?;
                    return Ok(RulingPersistence {
                        ruling_id: replacement_id.parse()?,
                        inserted: false,
                    });
                }
                return Err(Error::Conflict(format!(
                    "ruling {superseded_id} already has a different replacement"
                )));
            }
            let superseded_target: Option<String> =
                sqlx::query_scalar("SELECT target_id FROM contract_rulings WHERE ruling_id = ?")
                    .bind(superseded_id.to_string())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(storage("load superseded ruling"))?;
            if superseded_target.as_deref() != Some(target_key.as_str()) {
                return Err(Error::Corrupt(format!(
                    "superseded ruling {superseded_id} is missing or belongs to another target"
                )));
            }
        } else {
            let reusable: Option<String> = sqlx::query_scalar(
                "SELECT r.ruling_id FROM contract_rulings r \
                 WHERE r.target_id = ? AND r.context_evidence_id = ? \
                   AND r.contract_refs_json = ? AND r.scope_json = ? \
                   AND (r.expires_at_ms IS NULL OR r.expires_at_ms >= ?) \
                   AND NOT EXISTS (SELECT 1 FROM contract_ruling_supersessions s \
                                   WHERE s.superseded_ruling_id = r.ruling_id) \
                 ORDER BY r.effective_from_ms DESC, r.ruling_id LIMIT 1",
            )
            .bind(&target_key)
            .bind(context_evidence_id.to_string())
            .bind(&contract_refs_json)
            .bind(&scope_json)
            .bind(created_at)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("find reusable ruling"))?;
            if let Some(ruling_id) = reusable {
                tx.commit().await.map_err(storage("commit"))?;
                return Ok(RulingPersistence {
                    ruling_id: ruling_id.parse()?,
                    inserted: false,
                });
            }
        }

        let ruling_id = RulingId::generate();
        sqlx::query(
            "INSERT INTO contract_rulings \
             (ruling_id, target_id, context_evidence_id, contract_refs_json, disposition, \
              chosen_interpretation, rejected_interpretations_json, rationale, scope_json, \
              effective_from_ms, expires_at_ms, operator_id, created_at_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(ruling_id.to_string())
        .bind(&target_key)
        .bind(context_evidence_id.to_string())
        .bind(&contract_refs_json)
        .bind(ruling.disposition.as_str())
        .bind(&ruling.outcome)
        .bind(&rejected_json)
        .bind(&ruling.rationale)
        .bind(&scope_json)
        .bind(effective_from)
        .bind(expires_at)
        .bind(&ruling.operator_id)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(storage("insert contract ruling"))?;
        for contract_id in &contract_refs {
            sqlx::query(
                "INSERT INTO contract_ruling_contracts (ruling_id, contract_id) VALUES (?, ?)",
            )
            .bind(ruling_id.to_string())
            .bind(contract_id)
            .execute(&mut *tx)
            .await
            .map_err(storage("insert ruling contract reference"))?;
        }
        append_audit(
            &mut tx,
            AuditEvent {
                category: AuditCategory::Ruling,
                actor: ruling.operator_id.clone(),
                summary: "created contract interpretation ruling".into(),
                subject: Some(ruling_id.to_string()),
                occurred_at_ms: now_ms,
            },
        )
        .await?;
        if let Some(superseded_id) = supersedes {
            sqlx::query(
                "INSERT INTO contract_ruling_supersessions \
                 (superseding_ruling_id, superseded_ruling_id, created_at_ms) VALUES (?, ?, ?)",
            )
            .bind(ruling_id.to_string())
            .bind(superseded_id.to_string())
            .bind(created_at)
            .execute(&mut *tx)
            .await
            .map_err(storage("insert ruling supersession"))?;
            append_audit(
                &mut tx,
                AuditEvent {
                    category: AuditCategory::Ruling,
                    actor: ruling.operator_id.clone(),
                    summary: format!("superseded contract ruling {superseded_id}"),
                    subject: Some(ruling_id.to_string()),
                    occurred_at_ms: now_ms,
                },
            )
            .await?;
        }
        tx.commit().await.map_err(storage("commit"))?;
        Ok(RulingPersistence {
            ruling_id,
            inserted: true,
        })
    }

    /// Reloads a ruling, validates its redundant contract-reference index, and
    /// derives supersession state without mutating historical records.
    pub async fn load_contract_ruling(&self, ruling_id: &RulingId) -> Result<StoredContractRuling> {
        let row: ContractRulingRow = sqlx::query_as(
            "SELECT target_id, context_evidence_id, contract_refs_json, disposition, \
                    chosen_interpretation AS outcome, \
                    rejected_interpretations_json, rationale, scope_json, effective_from_ms, \
                    expires_at_ms, operator_id, created_at_ms \
             FROM contract_rulings WHERE ruling_id = ?",
        )
        .bind(ruling_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load contract ruling"))?
        .ok_or_else(|| Error::Corrupt(format!("unknown contract ruling {ruling_id}")))?;
        let indexed_refs: Vec<String> = sqlx::query_scalar(
            "SELECT contract_id FROM contract_ruling_contracts \
             WHERE ruling_id = ? ORDER BY contract_id",
        )
        .bind(ruling_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load ruling contract references"))?;
        let stored_refs: Vec<String> = serde_json::from_str(&row.contract_refs_json)
            .map_err(|e| Error::Corrupt(format!("invalid persisted ruling contract refs: {e}")))?;
        if stored_refs != indexed_refs {
            return Err(Error::Corrupt(
                "persisted ruling contract references disagree".into(),
            ));
        }
        let context_evidence_id: EvidenceId = row.context_evidence_id.parse()?;
        let context = self
            .load_scope_context_evidence(&context_evidence_id)
            .await?;
        if context.target_id.to_string() != row.target_id {
            return Err(Error::Corrupt(
                "persisted ruling context belongs to another target".into(),
            ));
        }
        for contract_id in &indexed_refs {
            let contract_target: Option<String> =
                sqlx::query_scalar("SELECT target_id FROM contracts WHERE contract_id = ?")
                    .bind(contract_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(storage("validate ruling contract target"))?;
            if contract_target.as_deref() != Some(row.target_id.as_str()) {
                return Err(Error::Corrupt(
                    "persisted ruling contract belongs to another target".into(),
                ));
            }
        }
        let superseded_by: Option<String> = sqlx::query_scalar(
            "SELECT superseding_ruling_id FROM contract_ruling_supersessions \
             WHERE superseded_ruling_id = ?",
        )
        .bind(ruling_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load ruling supersession"))?;
        if let Some(superseding_id) = &superseded_by {
            let superseding_target: Option<String> =
                sqlx::query_scalar("SELECT target_id FROM contract_rulings WHERE ruling_id = ?")
                    .bind(superseding_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(storage("validate ruling supersession target"))?;
            if superseding_target.as_deref() != Some(row.target_id.as_str()) {
                return Err(Error::Corrupt(
                    "persisted ruling supersession crosses target boundary".into(),
                ));
            }
        }
        row.into_ruling(*ruling_id, superseded_by)
    }
}

async fn load_contract_ruling_row(
    tx: &mut Transaction<'_, Sqlite>,
    ruling_id: &str,
    operation: &'static str,
) -> Result<ContractRulingRow> {
    sqlx::query_as(
        "SELECT target_id, context_evidence_id, contract_refs_json, disposition, \
                chosen_interpretation AS outcome, \
                rejected_interpretations_json, rationale, scope_json, effective_from_ms, \
                expires_at_ms, operator_id, created_at_ms \
         FROM contract_rulings WHERE ruling_id = ?",
    )
    .bind(ruling_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage(operation))?
    .ok_or_else(|| Error::Corrupt(format!("unknown contract ruling {ruling_id}")))
}
