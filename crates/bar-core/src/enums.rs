//! Core persisted enums.
//!
//! These are the canonical vocabularies BAR stores and reasons over. Each
//! variant has a single stable string token (the `as_str` value); those tokens
//! are the on-disk / on-the-wire representation and MUST NOT change once
//! persisted. Definitions mirror `docs/spec.md` §6.3 exactly.

/// Defines an enum whose variants each carry a stable, canonical string token
/// used for persistence and display. Keeps the token as the single source of
/// truth so serialization stays consistent across the workspace.
macro_rules! persisted_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $token:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// Canonical persisted string token for this variant.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $token),+
                }
            }

            /// Every variant, in declaration order.
            pub const VARIANTS: &'static [Self] = &[$(Self::$variant),+];
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

persisted_enum! {
    /// Normative force of a discovered claim (spec §6.3).
    NormativeKind {
        Required => "required",
        Prohibited => "prohibited",
        Expected => "expected",
        Descriptive => "descriptive",
        Planned => "planned",
        Historical => "historical",
        Example => "example",
    }
}

persisted_enum! {
    /// Position of a contract within the goal-to-implementation hierarchy (spec §6.3).
    ContractLevel {
        ProductGoal => "product_goal",
        BehavioralProperty => "behavioral_property",
        ArchitectureConstraint => "architecture_constraint",
        Mechanism => "mechanism",
        Implementation => "implementation",
    }
}

persisted_enum! {
    /// Origin of a piece of evidence (spec §6.3).
    EvidenceKind {
        Documentation => "documentation",
        Code => "code",
        Configuration => "configuration",
        UnitTest => "unit_test",
        IntegrationTest => "integration_test",
        LiveTrace => "live_trace",
        JournalEvent => "journal_event",
        Log => "log",
        Metric => "metric",
        OperatorObservation => "operator_observation",
        SyntheticProbe => "synthetic_probe",
        Replay => "replay",
        BarInference => "bar_inference",
    }
}

persisted_enum! {
    /// How well a proof obligation is currently supported (spec §6.3).
    ProofStatus {
        Discovered => "discovered",
        Mapped => "mapped",
        StaticallySupported => "statically_supported",
        TestSupported => "test_supported",
        LiveObserved => "live_observed",
        FailureObserved => "failure_observed",
        Contradicted => "contradicted",
        Unproven => "unproven",
        Stale => "stale",
        Superseded => "superseded",
        Invalid => "invalid",
    }
}

persisted_enum! {
    /// How a proof obligation's freshness is evaluated across revisions
    /// (spec §10.2 `freshness_policy`, §10.4, §400 freshness detector).
    ///
    /// `Pinned` treats any revision other than the declared one as stale.
    /// `ReferenceStable` keeps a proof fresh across revisions as long as the
    /// contract's mapped references still resolve — the spec's "referenced
    /// symbols and mechanisms must still exist" rule — and goes stale only when
    /// one disappears.
    FreshnessPolicy {
        Pinned => "pinned",
        ReferenceStable => "reference_stable",
    }
}

persisted_enum! {
    /// Lifecycle state of a finding (spec §6.3).
    FindingStatus {
        Detected => "detected",
        Triaged => "triaged",
        Investigating => "investigating",
        EvidenceSufficient => "evidence_sufficient",
        RepairReady => "repair_ready",
        AwaitingApproval => "awaiting_approval",
        Approved => "approved",
        Implementing => "implementing",
        Submitted => "submitted",
        Verifying => "verifying",
        Resolved => "resolved",
        PartiallyResolved => "partially_resolved",
        Failed => "failed",
        RolledBack => "rolled_back",
        Reopened => "reopened",
        Rejected => "rejected",
        Deferred => "deferred",
        Waived => "waived",
    }
}

persisted_enum! {
    /// Category of a proposed repair (spec §6.3).
    RepairKind {
        Code => "code",
        Test => "test",
        Documentation => "documentation",
        Configuration => "configuration",
        Instrumentation => "instrumentation",
        Migration => "migration",
        Policy => "policy",
        ContractRuling => "contract_ruling",
        NoChange => "no_change",
    }
}

persisted_enum! {
    /// Chosen disposition for an assurance concern (spec §6.3).
    AssuranceDisposition {
        Repair => "repair",
        Monitor => "monitor",
        RequestEvidence => "request_evidence",
        Adjudicate => "adjudicate",
        Waive => "waive",
        AcceptRisk => "accept_risk",
        ExternalDependency => "external_dependency",
        FalsePositive => "false_positive",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A persisted enum's tokens must be unique and non-empty, otherwise stored
    /// values become ambiguous.
    fn assert_tokens_unique(tokens: impl Iterator<Item = &'static str>) {
        let mut seen = HashSet::new();
        for token in tokens {
            assert!(!token.is_empty(), "empty token");
            assert!(seen.insert(token), "duplicate token: {token}");
        }
    }

    macro_rules! token_test {
        ($test:ident, $ty:ident, $count:expr) => {
            #[test]
            fn $test() {
                assert_eq!($ty::VARIANTS.len(), $count);
                assert_tokens_unique($ty::VARIANTS.iter().map(|v| v.as_str()));
                for &v in $ty::VARIANTS {
                    assert_eq!(v.to_string(), v.as_str());
                }
            }
        };
    }

    token_test!(normative_kind_tokens, NormativeKind, 7);
    token_test!(contract_level_tokens, ContractLevel, 5);
    token_test!(evidence_kind_tokens, EvidenceKind, 13);
    token_test!(proof_status_tokens, ProofStatus, 11);
    token_test!(freshness_policy_tokens, FreshnessPolicy, 2);
    token_test!(finding_status_tokens, FindingStatus, 18);
    token_test!(repair_kind_tokens, RepairKind, 9);
    token_test!(assurance_disposition_tokens, AssuranceDisposition, 8);
}
