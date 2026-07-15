//! Evidence-time-bound contract applicability resolution (spec §7.2–§7.4).

use bar_contract::scope::{resolve_applicability, Applicability, ScopedContract};
use bar_core::{ContractId, Error, EvidenceId, NormativeKind, Result, TargetId};

use crate::{storage, Store};

impl Store {
    /// Resolves a contract only at the timestamp and target recorded by its
    /// source-bound context evidence. Callers cannot substitute a newer or
    /// older evaluation time for the same evidence.
    pub async fn resolve_contract_in_context(
        &self,
        contract_id: &ContractId,
        context_evidence_id: &EvidenceId,
    ) -> Result<Applicability> {
        let (contract_target, normative_kind): (String, String) =
            sqlx::query_as("SELECT target_id, normative_kind FROM contracts WHERE contract_id = ?")
                .bind(contract_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(storage("load contract context resolution"))?
                .ok_or_else(|| Error::Corrupt(format!("unknown contract {contract_id}")))?;
        let contract_target: TargetId = contract_target.parse()?;
        let normative_kind = NormativeKind::VARIANTS
            .iter()
            .copied()
            .find(|kind| kind.as_str() == normative_kind)
            .ok_or_else(|| Error::Corrupt("unknown persisted contract normative kind".into()))?;
        let resolution = self.load_contract_resolution(contract_id).await?;
        if resolution.contract_id != *contract_id {
            return Err(Error::Corrupt(
                "loaded contract resolution identity does not match request".into(),
            ));
        }
        let context = self
            .load_scope_context_evidence(context_evidence_id)
            .await?;
        if context.target_id != contract_target {
            return Err(Error::Corrupt(format!(
                "contract {contract_id} and context {context_evidence_id} belong to different targets"
            )));
        }
        Ok(resolve_applicability(
            ScopedContract {
                scope: &resolution.scope,
                temporal: &resolution.temporal,
                normative_kind,
            },
            &context.context,
            context.observed_at_ms,
        ))
    }
}
