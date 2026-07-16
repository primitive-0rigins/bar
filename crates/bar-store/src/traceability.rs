//! Revision-bound contract-to-static-fact traceability (Phase 6).

use bar_core::{Result, RevisionId, TargetId};
use bar_coverage::{map_explicit_references, ContractTraceability};
use bar_static::StaticArtifactFacts;

use crate::{Store, StoredContract};

/// A persisted contract paired with its deterministic, revision-bound mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredContractTraceability {
    pub contract: StoredContract,
    pub traceability: ContractTraceability,
}

impl Store {
    /// Maps one target revision's persisted contracts against its validated
    /// static facts. This is a read-only shadow operation: mapping status is
    /// not proof status, and the result is not yet persisted.
    pub async fn map_contract_traceability(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
    ) -> Result<Vec<StoredContractTraceability>> {
        let contracts = self
            .load_contracts_for_target(target_id, revision_id)
            .await?;
        let facts = self
            .load_static_facts_for_revision(target_id, revision_id)
            .await?
            .into_iter()
            .map(|stored| StaticArtifactFacts {
                artifact_id: stored.artifact_id,
                facts: stored.facts,
            })
            .collect::<Vec<_>>();
        let claims = contracts
            .iter()
            .map(|contract| contract.claim.clone())
            .collect::<Vec<_>>();
        let traces = map_explicit_references(&claims, &facts)?;
        Ok(contracts
            .into_iter()
            .zip(traces)
            .map(|(contract, traceability)| StoredContractTraceability {
                contract,
                traceability,
            })
            .collect())
    }
}
