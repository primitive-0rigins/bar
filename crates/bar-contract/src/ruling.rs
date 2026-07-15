//! Immutable operator rulings for contract ambiguity (spec §7.4, Phase 4).

use std::collections::HashSet;

use bar_core::{ContractId, Error, Result};

use crate::scope::{validate_declaration, ContractScope};

const MAX_INTERPRETATION_BYTES: usize = 4_096;
const MAX_RATIONALE_BYTES: usize = 8_192;
const MAX_OPERATOR_ID_BYTES: usize = 255;
const MAX_REJECTED_INTERPRETATIONS: usize = 32;

/// The immutable content of an operator decision about competing contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractRuling {
    pub contract_refs: Vec<ContractId>,
    pub chosen_interpretation: String,
    pub rejected_interpretations: Vec<String>,
    pub rationale: String,
    pub scope: ContractScope,
    pub effective_from_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub operator_id: String,
}

/// Validates a ruling before it crosses a persistence boundary.
pub fn validate_ruling(ruling: &ContractRuling) -> Result<()> {
    if ruling.contract_refs.len() < 2 {
        return Err(Error::Corrupt(
            "a contract ruling requires at least two contract references".into(),
        ));
    }
    let unique_contracts = ruling.contract_refs.iter().collect::<HashSet<_>>();
    if unique_contracts.len() != ruling.contract_refs.len() {
        return Err(Error::Corrupt(
            "a contract ruling contains duplicate contract references".into(),
        ));
    }
    validate_text(
        &ruling.chosen_interpretation,
        MAX_INTERPRETATION_BYTES,
        "chosen interpretation",
    )?;
    if ruling.rejected_interpretations.len() > MAX_REJECTED_INTERPRETATIONS {
        return Err(Error::Corrupt(
            "a contract ruling contains too many rejected interpretations".into(),
        ));
    }
    let mut unique_rejected = HashSet::new();
    for rejected in &ruling.rejected_interpretations {
        validate_text(
            rejected,
            MAX_INTERPRETATION_BYTES,
            "rejected interpretation",
        )?;
        if rejected == &ruling.chosen_interpretation || !unique_rejected.insert(rejected) {
            return Err(Error::Corrupt(
                "a contract ruling contains duplicate interpretations".into(),
            ));
        }
    }
    validate_text(&ruling.rationale, MAX_RATIONALE_BYTES, "rationale")?;
    validate_text(&ruling.operator_id, MAX_OPERATOR_ID_BYTES, "operator id")?;
    validate_declaration(&ruling.scope, None, None)?;
    if ruling
        .expires_at_ms
        .is_some_and(|expires| expires < ruling.effective_from_ms)
    {
        return Err(Error::Corrupt(
            "a contract ruling expires before it becomes effective".into(),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, max_bytes: usize, field: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(Error::Corrupt(format!(
            "contract ruling {field} must contain 1..={max_bytes} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ruling() -> ContractRuling {
        ContractRuling {
            contract_refs: vec![ContractId::generate(), ContractId::generate()],
            chosen_interpretation: "retain entries".into(),
            rejected_interpretations: vec!["discard entries".into()],
            rationale: "The scoped production requirement controls.".into(),
            scope: ContractScope::default(),
            effective_from_ms: 10,
            expires_at_ms: Some(20),
            operator_id: "operator/alice".into(),
        }
    }

    #[test]
    fn ruling_validation_rejects_ambiguous_or_unbounded_inputs() {
        validate_ruling(&ruling()).unwrap();

        let mut invalid = ruling();
        invalid.contract_refs.truncate(1);
        assert!(validate_ruling(&invalid).is_err());

        let mut invalid = ruling();
        invalid.rejected_interpretations = vec![invalid.chosen_interpretation.clone()];
        assert!(validate_ruling(&invalid).is_err());

        let mut invalid = ruling();
        invalid.expires_at_ms = Some(9);
        assert!(validate_ruling(&invalid).is_err());

        let mut invalid = ruling();
        invalid.rationale = " ".into();
        assert!(validate_ruling(&invalid).is_err());
    }
}
