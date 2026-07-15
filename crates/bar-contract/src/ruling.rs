//! Immutable operator rulings for contract ambiguity (spec §7.4, Phase 4).

use std::collections::HashSet;

use bar_core::{ContractId, Error, Result};

use crate::scope::{validate_declaration, ContractScope};

const MAX_INTERPRETATION_BYTES: usize = 4_096;
const MAX_RATIONALE_BYTES: usize = 8_192;
const MAX_OPERATOR_ID_BYTES: usize = 255;
const MAX_REJECTED_INTERPRETATIONS: usize = 32;

/// Operator outcome for an ambiguity. Tokens are durable database values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulingDisposition {
    Chosen,
    Deferred,
    Rejected,
    RequestMoreEvidence,
}

impl RulingDisposition {
    pub const VARIANTS: &'static [Self] = &[
        Self::Chosen,
        Self::Deferred,
        Self::Rejected,
        Self::RequestMoreEvidence,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chosen => "chosen",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
            Self::RequestMoreEvidence => "request_more_evidence",
        }
    }

    /// Parses a persisted disposition token and rejects unknown values.
    pub fn from_token(token: &str) -> Result<Self> {
        Self::VARIANTS
            .iter()
            .copied()
            .find(|disposition| disposition.as_str() == token)
            .ok_or_else(|| Error::Corrupt(format!("unknown ruling disposition `{token}`")))
    }
}

/// The immutable content of an operator decision about competing contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractRuling {
    pub contract_refs: Vec<ContractId>,
    pub disposition: RulingDisposition,
    /// Selected interpretation for `Chosen`; a clear outcome for other states.
    pub outcome: String,
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
    validate_text(&ruling.outcome, MAX_INTERPRETATION_BYTES, "outcome")?;
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
        if rejected == &ruling.outcome || !unique_rejected.insert(rejected) {
            return Err(Error::Corrupt(
                "a contract ruling contains duplicate interpretations".into(),
            ));
        }
    }
    if ruling.disposition != RulingDisposition::Chosen
        && !ruling.rejected_interpretations.is_empty()
    {
        return Err(Error::Corrupt(
            "a non-chosen ruling cannot reject interpretations".into(),
        ));
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
            disposition: RulingDisposition::Chosen,
            outcome: "retain entries".into(),
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
        assert_eq!(
            RulingDisposition::RequestMoreEvidence.as_str(),
            "request_more_evidence"
        );
        assert!(RulingDisposition::from_token("unknown").is_err());

        let mut invalid = ruling();
        invalid.contract_refs.truncate(1);
        assert!(validate_ruling(&invalid).is_err());

        let mut invalid = ruling();
        invalid.rejected_interpretations = vec![invalid.outcome.clone()];
        assert!(validate_ruling(&invalid).is_err());

        let mut invalid = ruling();
        invalid.expires_at_ms = Some(9);
        assert!(validate_ruling(&invalid).is_err());

        let mut invalid = ruling();
        invalid.rationale = " ".into();
        assert!(validate_ruling(&invalid).is_err());

        for disposition in [
            RulingDisposition::Deferred,
            RulingDisposition::Rejected,
            RulingDisposition::RequestMoreEvidence,
        ] {
            let mut non_final = ruling();
            non_final.disposition = disposition;
            non_final.rejected_interpretations.clear();
            validate_ruling(&non_final).unwrap();
            non_final
                .rejected_interpretations
                .push("discard entries".into());
            assert!(validate_ruling(&non_final).is_err());
        }
    }
}
