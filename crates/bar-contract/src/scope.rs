//! Deterministic contract scope and temporal applicability (spec §7.2,
//! Phase 4). Unknown or overlapping applicability remains an adjudication item.

use bar_core::{Error, NormativeKind, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Whether a contract can govern behavior in a supplied context.
pub enum ApplicabilityState {
    Applicable,
    NotApplicable,
    Ambiguous,
}

impl ApplicabilityState {
    /// Stable token used at persistence and API boundaries.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applicable => "applicable",
            Self::NotApplicable => "not_applicable",
            Self::Ambiguous => "ambiguous",
        }
    }

    /// Parses a stable token and rejects unknown state.
    pub fn from_token(token: &str) -> Result<Self> {
        match token {
            "applicable" => Ok(Self::Applicable),
            "not_applicable" => Ok(Self::NotApplicable),
            "ambiguous" => Ok(Self::Ambiguous),
            other => Err(Error::Corrupt(format!(
                "unknown contract applicability state `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The scope-precedence tiers from spec §7.2, most to least specific.
pub enum ScopeSpecificity {
    ExactDeploymentConfiguration,
    ExactEnvironmentComponent,
    FeatureFlagMode,
    VersionBoundedComponent,
    ProductWide,
}

impl ScopeSpecificity {
    fn rank(self) -> u8 {
        match self {
            Self::ExactDeploymentConfiguration => 5,
            Self::ExactEnvironmentComponent => 4,
            Self::FeatureFlagMode => 3,
            Self::VersionBoundedComponent => 2,
            Self::ProductWide => 1,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
/// Constraints declared by a contract. Lists are allowed exact values.
pub struct ContractScope {
    pub deployments: Vec<String>,
    pub configurations: Vec<String>,
    pub environments: Vec<String>,
    pub components: Vec<String>,
    pub feature_flags: Vec<String>,
    pub modes: Vec<String>,
    pub source_revisions: Vec<String>,
    /// A strict semantic-version intersection for `source_revision`.
    pub source_revision_range: Option<String>,
    /// A strict semantic-version intersection for `deployment`.
    pub deployment_range: Option<String>,
    pub tenant_scope: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
/// Observed target context used to resolve a contract's declared scope.
pub struct ScopeContext {
    pub deployment: Option<String>,
    pub configuration: Option<String>,
    pub environment: Option<String>,
    pub component: Option<String>,
    pub feature_flags: Option<Vec<String>>,
    pub mode: Option<String>,
    pub source_revision: Option<String>,
    pub tenant_scope: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
/// Inclusive millisecond validity bounds plus explicit supersession state.
pub struct TemporalWindow {
    pub valid_from_ms: Option<u64>,
    pub valid_until_ms: Option<u64>,
    pub superseded: bool,
}

#[derive(Debug, Clone, Copy)]
/// A contract's inputs to deterministic applicability resolution.
pub struct ScopedContract<'a> {
    pub scope: &'a ContractScope,
    pub temporal: &'a TemporalWindow,
    pub normative_kind: NormativeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Applicability plus a precedence tier when the scope is fully understood.
pub struct Applicability {
    pub state: ApplicabilityState,
    pub specificity: Option<ScopeSpecificity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Side selected by an unambiguous scope-precedence override.
pub enum ConflictSide {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Safe disposition for an already-detected opposing contract pair.
pub enum ConflictDisposition {
    Inactive,
    ScopedOverride { preferred: ConflictSide },
    AdjudicationRequired,
}

/// Validates a declared scope and inclusive validity bounds before they cross
/// a persistence boundary.
pub fn validate_declaration(
    scope: &ContractScope,
    valid_from_ms: Option<u64>,
    valid_until_ms: Option<u64>,
) -> Result<()> {
    if !scope_is_valid(scope) {
        return Err(Error::Corrupt(
            "contract scope contains an empty value".into(),
        ));
    }
    if matches!((valid_from_ms, valid_until_ms), (Some(from), Some(until)) if from > until) {
        return Err(Error::Corrupt(
            "contract validity starts after it ends".into(),
        ));
    }
    Ok(())
}

/// Validates observed context values before they are bound to evidence.
pub fn validate_context(context: &ScopeContext) -> Result<()> {
    let values_are_valid = [
        context.deployment.as_deref(),
        context.configuration.as_deref(),
        context.environment.as_deref(),
        context.component.as_deref(),
        context.mode.as_deref(),
        context.source_revision.as_deref(),
        context.tenant_scope.as_deref(),
    ]
    .into_iter()
    .flatten()
    .all(|value| !value.trim().is_empty())
        && context
            .feature_flags
            .as_deref()
            .is_none_or(|flags| flags.iter().all(|flag| !flag.trim().is_empty()));
    if !values_are_valid {
        return Err(Error::Corrupt(
            "scope context contains an empty value".into(),
        ));
    }
    Ok(())
}

/// Resolves one contract without guessing when scope or time is malformed or
/// incomplete.
pub fn resolve_applicability(
    contract: ScopedContract<'_>,
    context: &ScopeContext,
    at_ms: u64,
) -> Applicability {
    let ambiguous = Applicability {
        state: ApplicabilityState::Ambiguous,
        specificity: None,
    };
    if matches!(
        (contract.temporal.valid_from_ms, contract.temporal.valid_until_ms),
        (Some(from), Some(until)) if from > until
    ) {
        return ambiguous;
    }
    if !scope_is_valid(contract.scope) {
        return ambiguous;
    }
    if contract.temporal.superseded
        || matches!(
            contract.normative_kind,
            NormativeKind::Historical | NormativeKind::Planned | NormativeKind::Example
        )
        || contract
            .temporal
            .valid_from_ms
            .is_some_and(|from| at_ms < from)
        || contract
            .temporal
            .valid_until_ms
            .is_some_and(|until| at_ms > until)
    {
        return Applicability {
            state: ApplicabilityState::NotApplicable,
            specificity: None,
        };
    }

    match match_scope(contract.scope, context) {
        DimensionMatch::Mismatch => Applicability {
            state: ApplicabilityState::NotApplicable,
            specificity: None,
        },
        DimensionMatch::Unknown => ambiguous,
        DimensionMatch::Matches => Applicability {
            state: ApplicabilityState::Applicable,
            specificity: scope_specificity(contract.scope),
        },
    }
}

/// Applies scope precedence to an opposing pair. Ties and unknowns always
/// remain adjudication items.
pub fn resolve_conflict(
    left: ScopedContract<'_>,
    right: ScopedContract<'_>,
    context: &ScopeContext,
    at_ms: u64,
) -> ConflictDisposition {
    let left = resolve_applicability(left, context, at_ms);
    let right = resolve_applicability(right, context, at_ms);
    if left.state == ApplicabilityState::NotApplicable
        || right.state == ApplicabilityState::NotApplicable
    {
        return ConflictDisposition::Inactive;
    }
    if left.state == ApplicabilityState::Ambiguous || right.state == ApplicabilityState::Ambiguous {
        return ConflictDisposition::AdjudicationRequired;
    }

    match (left.specificity, right.specificity) {
        (Some(left), Some(right)) if left.rank() > right.rank() => {
            ConflictDisposition::ScopedOverride {
                preferred: ConflictSide::Left,
            }
        }
        (Some(left), Some(right)) if right.rank() > left.rank() => {
            ConflictDisposition::ScopedOverride {
                preferred: ConflictSide::Right,
            }
        }
        _ => ConflictDisposition::AdjudicationRequired,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DimensionMatch {
    Matches,
    Mismatch,
    Unknown,
}

fn match_scope(scope: &ContractScope, context: &ScopeContext) -> DimensionMatch {
    let mut result = DimensionMatch::Matches;
    for dimension in [
        match_versioned_values(
            &scope.deployments,
            scope.deployment_range.as_deref(),
            context.deployment.as_deref(),
        ),
        match_values(&scope.configurations, context.configuration.as_deref()),
        match_values(&scope.environments, context.environment.as_deref()),
        match_values(&scope.components, context.component.as_deref()),
        match_values(&scope.modes, context.mode.as_deref()),
        match_versioned_values(
            &scope.source_revisions,
            scope.source_revision_range.as_deref(),
            context.source_revision.as_deref(),
        ),
        match_value(
            scope.tenant_scope.as_deref(),
            context.tenant_scope.as_deref(),
        ),
        match_flags(&scope.feature_flags, context.feature_flags.as_deref()),
    ] {
        if dimension == DimensionMatch::Mismatch {
            return DimensionMatch::Mismatch;
        }
        if dimension == DimensionMatch::Unknown {
            result = DimensionMatch::Unknown;
        }
    }
    result
}

fn match_values(expected: &[String], actual: Option<&str>) -> DimensionMatch {
    if expected.is_empty() {
        DimensionMatch::Matches
    } else if let Some(actual) = actual {
        if expected.iter().any(|value| value == actual) {
            DimensionMatch::Matches
        } else {
            DimensionMatch::Mismatch
        }
    } else {
        DimensionMatch::Unknown
    }
}

/// Matches exact identities and an optional semantic-version range. A malformed
/// observed version is unknown, not a mismatch, so it cannot select a scoped
/// contract automatically.
fn match_versioned_values(
    exact: &[String],
    range: Option<&str>,
    actual: Option<&str>,
) -> DimensionMatch {
    if exact.is_empty() && range.is_none() {
        return DimensionMatch::Matches;
    }
    let Some(actual) = actual else {
        return DimensionMatch::Unknown;
    };
    if exact.iter().any(|value| value == actual) {
        return DimensionMatch::Matches;
    }
    let Some(range) = range else {
        return DimensionMatch::Mismatch;
    };
    let Ok(actual) = parse_release_version(actual) else {
        return DimensionMatch::Unknown;
    };
    match parse_version_range(range) {
        Ok(comparators)
            if comparators
                .iter()
                .all(|comparator| comparator.matches(actual)) =>
        {
            DimensionMatch::Matches
        }
        Ok(_) => DimensionMatch::Mismatch,
        Err(()) => DimensionMatch::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ReleaseVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

#[derive(Debug, Clone, Copy)]
enum VersionComparator {
    Equal(ReleaseVersion),
    GreaterThan(ReleaseVersion),
    GreaterOrEqual(ReleaseVersion),
    LessThan(ReleaseVersion),
    LessOrEqual(ReleaseVersion),
}

impl VersionComparator {
    fn matches(self, actual: ReleaseVersion) -> bool {
        match self {
            Self::Equal(expected) => actual == expected,
            Self::GreaterThan(expected) => actual > expected,
            Self::GreaterOrEqual(expected) => actual >= expected,
            Self::LessThan(expected) => actual < expected,
            Self::LessOrEqual(expected) => actual <= expected,
        }
    }
}

/// Parses BAR's deliberately narrow semantic-version grammar: a release
/// version is `MAJOR.MINOR.PATCH` and a range is one or more whitespace-
/// separated `=`, `>`, `>=`, `<`, or `<=` comparators that all must match.
fn parse_version_range(input: &str) -> core::result::Result<Vec<VersionComparator>, ()> {
    if input.is_empty() || input.len() > 512 {
        return Err(());
    }
    let comparators = input
        .split_ascii_whitespace()
        .map(parse_version_comparator)
        .collect::<core::result::Result<Vec<_>, _>>()?;
    if comparators.is_empty() {
        return Err(());
    }
    Ok(comparators)
}

fn valid_version_range(input: &str) -> bool {
    parse_version_range(input).is_ok()
}

fn parse_version_comparator(input: &str) -> core::result::Result<VersionComparator, ()> {
    let (operator, version) = if let Some(version) = input.strip_prefix(">=") {
        (">=", version)
    } else if let Some(version) = input.strip_prefix("<=") {
        ("<=", version)
    } else if let Some(version) = input.strip_prefix('>') {
        (">", version)
    } else if let Some(version) = input.strip_prefix('<') {
        ("<", version)
    } else if let Some(version) = input.strip_prefix('=') {
        ("=", version)
    } else {
        ("=", input)
    };
    let version = parse_release_version(version)?;
    Ok(match operator {
        "=" => VersionComparator::Equal(version),
        ">" => VersionComparator::GreaterThan(version),
        ">=" => VersionComparator::GreaterOrEqual(version),
        "<" => VersionComparator::LessThan(version),
        "<=" => VersionComparator::LessOrEqual(version),
        _ => return Err(()),
    })
}

fn parse_release_version(input: &str) -> core::result::Result<ReleaseVersion, ()> {
    let mut parts = input.split('.');
    let major = parse_version_number(parts.next().ok_or(())?)?;
    let minor = parse_version_number(parts.next().ok_or(())?)?;
    let patch = parse_version_number(parts.next().ok_or(())?)?;
    if parts.next().is_some() {
        return Err(());
    }
    Ok(ReleaseVersion {
        major,
        minor,
        patch,
    })
}

fn parse_version_number(input: &str) -> core::result::Result<u64, ()> {
    if input.is_empty() || (input.len() > 1 && input.starts_with('0')) {
        return Err(());
    }
    input.parse().map_err(|_| ())
}

fn match_value(expected: Option<&str>, actual: Option<&str>) -> DimensionMatch {
    match (expected, actual) {
        (None, _) => DimensionMatch::Matches,
        (Some(_), None) => DimensionMatch::Unknown,
        (Some(expected), Some(actual)) if expected == actual => DimensionMatch::Matches,
        (Some(_), Some(_)) => DimensionMatch::Mismatch,
    }
}

fn match_flags(expected: &[String], actual: Option<&[String]>) -> DimensionMatch {
    if expected.is_empty() {
        DimensionMatch::Matches
    } else if let Some(actual) = actual {
        if expected.iter().all(|flag| actual.contains(flag)) {
            DimensionMatch::Matches
        } else {
            DimensionMatch::Mismatch
        }
    } else {
        DimensionMatch::Unknown
    }
}

fn scope_specificity(scope: &ContractScope) -> Option<ScopeSpecificity> {
    if !scope.deployments.is_empty() || !scope.configurations.is_empty() {
        Some(ScopeSpecificity::ExactDeploymentConfiguration)
    } else if !scope.environments.is_empty() && !scope.components.is_empty() {
        Some(ScopeSpecificity::ExactEnvironmentComponent)
    } else if !scope.feature_flags.is_empty() || !scope.modes.is_empty() {
        Some(ScopeSpecificity::FeatureFlagMode)
    } else if (!scope.source_revisions.is_empty()
        || scope.source_revision_range.is_some()
        || scope.deployment_range.is_some())
        && !scope.components.is_empty()
    {
        Some(ScopeSpecificity::VersionBoundedComponent)
    } else if scope.environments.is_empty()
        && scope.components.is_empty()
        && scope.source_revisions.is_empty()
        && scope.source_revision_range.is_none()
        && scope.deployment_range.is_none()
        && scope.tenant_scope.is_none()
    {
        Some(ScopeSpecificity::ProductWide)
    } else {
        None
    }
}

fn scope_is_valid(scope: &ContractScope) -> bool {
    [
        &scope.deployments,
        &scope.configurations,
        &scope.environments,
        &scope.components,
        &scope.feature_flags,
        &scope.modes,
        &scope.source_revisions,
    ]
    .into_iter()
    .flatten()
    .all(|value| !value.trim().is_empty())
        && scope
            .tenant_scope
            .as_deref()
            .is_none_or(|value| !value.trim().is_empty())
        && scope
            .source_revision_range
            .as_deref()
            .is_none_or(valid_version_range)
        && scope
            .deployment_range
            .as_deref()
            .is_none_or(valid_version_range)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ResolutionFixture {
        resolver_cases: Vec<ResolutionFixtureCase>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ResolutionFixtureCase {
        name: String,
        left: FixtureContract,
        right: FixtureContract,
        context: ScopeContext,
        at_ms: u64,
        #[serde(default = "one")]
        repeat: usize,
        expected: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureContract {
        scope: ContractScope,
        temporal: TemporalWindow,
        normative_kind: String,
    }

    fn one() -> usize {
        1
    }

    fn fixture_contract(input: &FixtureContract) -> ScopedContract<'_> {
        let normative_kind = NormativeKind::VARIANTS
            .iter()
            .copied()
            .find(|kind| kind.as_str() == input.normative_kind)
            .unwrap_or_else(|| panic!("unknown fixture normative kind {}", input.normative_kind));
        ScopedContract {
            scope: &input.scope,
            temporal: &input.temporal,
            normative_kind,
        }
    }

    fn expected_disposition(expected: &str) -> ConflictDisposition {
        match expected {
            "inactive" => ConflictDisposition::Inactive,
            "scoped_override_left" => ConflictDisposition::ScopedOverride {
                preferred: ConflictSide::Left,
            },
            "scoped_override_right" => ConflictDisposition::ScopedOverride {
                preferred: ConflictSide::Right,
            },
            "adjudication_required" => ConflictDisposition::AdjudicationRequired,
            other => panic!("unknown fixture disposition {other}"),
        }
    }

    fn required<'a>(scope: &'a ContractScope, temporal: &'a TemporalWindow) -> ScopedContract<'a> {
        ScopedContract {
            scope,
            temporal,
            normative_kind: NormativeKind::Required,
        }
    }

    #[test]
    fn applicability_tokens_and_scope_json_fail_closed() {
        for (state, token) in [
            (ApplicabilityState::Applicable, "applicable"),
            (ApplicabilityState::NotApplicable, "not_applicable"),
            (ApplicabilityState::Ambiguous, "ambiguous"),
        ] {
            assert_eq!(state.as_str(), token);
            assert_eq!(ApplicabilityState::from_token(token).unwrap(), state);
        }
        assert!(ApplicabilityState::from_token("active").is_err());
        assert_eq!(
            serde_json::to_string(&ApplicabilityState::NotApplicable).unwrap(),
            r#""not_applicable""#
        );
        assert!(serde_json::from_str::<ApplicabilityState>(r#""active""#).is_err());
        assert!(serde_json::from_str::<ContractScope>(r#"{"unknown":[]}"#).is_err());
        assert!(serde_json::from_str::<TemporalWindow>(r#"{"expires":4}"#).is_err());
        assert!(validate_context(&ScopeContext {
            feature_flags: Some(vec![" ".into()]),
            ..ScopeContext::default()
        })
        .is_err());
    }

    #[test]
    fn phase_four_resolution_corpus_is_fail_safe() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/phase-4-resolution/expected.json");
        let fixture: ResolutionFixture =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(
            fixture.resolver_cases.len() >= 9,
            "the reviewed Phase 4 corpus must retain all adversarial cases"
        );

        for case in fixture.resolver_cases {
            assert!(case.repeat > 0, "fixture {} has zero repeats", case.name);
            let expected = expected_disposition(&case.expected);
            for _ in 0..case.repeat {
                assert_eq!(
                    resolve_conflict(
                        fixture_contract(&case.left),
                        fixture_contract(&case.right),
                        &case.context,
                        case.at_ms,
                    ),
                    expected,
                    "fixture {}",
                    case.name
                );
            }
        }
    }

    #[test]
    fn missing_scope_and_invalid_time_are_ambiguous() {
        let scope = ContractScope {
            configurations: vec!["prod-a".into()],
            ..ContractScope::default()
        };
        let valid = TemporalWindow {
            valid_from_ms: Some(10),
            valid_until_ms: Some(20),
            superseded: false,
        };
        let contract = required(&scope, &valid);

        assert_eq!(
            resolve_applicability(contract, &ScopeContext::default(), 15).state,
            ApplicabilityState::Ambiguous
        );
        let matching = ScopeContext {
            configuration: Some("prod-a".into()),
            ..ScopeContext::default()
        };
        let mismatched = ScopeContext {
            configuration: Some("prod-b".into()),
            ..ScopeContext::default()
        };
        assert_eq!(
            resolve_applicability(contract, &matching, 10),
            Applicability {
                state: ApplicabilityState::Applicable,
                specificity: Some(ScopeSpecificity::ExactDeploymentConfiguration),
            }
        );
        assert_eq!(
            resolve_applicability(contract, &matching, 20).state,
            ApplicabilityState::Applicable,
            "temporal bounds are inclusive"
        );
        assert_eq!(
            resolve_applicability(contract, &matching, 21).state,
            ApplicabilityState::NotApplicable
        );
        assert_eq!(
            resolve_applicability(contract, &mismatched, 15).state,
            ApplicabilityState::NotApplicable
        );

        let invalid = TemporalWindow {
            valid_from_ms: Some(20),
            valid_until_ms: Some(10),
            superseded: false,
        };
        assert!(validate_declaration(&scope, Some(20), Some(10)).is_err());
        assert_eq!(
            resolve_applicability(required(&scope, &invalid), &matching, 15).state,
            ApplicabilityState::Ambiguous
        );

        let malformed = ContractScope {
            components: vec![" ".into()],
            ..ContractScope::default()
        };
        assert!(validate_declaration(&malformed, None, None).is_err());
        assert_eq!(
            resolve_applicability(
                required(&malformed, &TemporalWindow::default()),
                &ScopeContext {
                    component: Some(" ".into()),
                    ..ScopeContext::default()
                },
                15,
            )
            .state,
            ApplicabilityState::Ambiguous
        );
    }

    #[test]
    fn precedence_resolves_override_but_overlap_requires_adjudication() {
        let product = ContractScope::default();
        let production = ContractScope {
            deployments: vec!["production".into()],
            ..ContractScope::default()
        };
        let active = TemporalWindow::default();
        let context = ScopeContext {
            deployment: Some("production".into()),
            ..ScopeContext::default()
        };

        assert_eq!(
            resolve_conflict(
                required(&product, &active),
                required(&production, &active),
                &context,
                1,
            ),
            ConflictDisposition::ScopedOverride {
                preferred: ConflictSide::Right,
            }
        );
        assert_eq!(
            resolve_conflict(
                required(&product, &active),
                required(&product, &active),
                &context,
                1,
            ),
            ConflictDisposition::AdjudicationRequired
        );
        assert_eq!(
            resolve_conflict(
                required(&product, &active),
                required(&production, &active),
                &ScopeContext::default(),
                1,
            ),
            ConflictDisposition::AdjudicationRequired,
            "missing deployment context cannot select an override"
        );

        let future = TemporalWindow {
            valid_from_ms: Some(2),
            ..TemporalWindow::default()
        };
        assert_eq!(
            resolve_conflict(
                required(&product, &active),
                required(&production, &future),
                &context,
                1,
            ),
            ConflictDisposition::Inactive
        );
    }

    #[test]
    fn historical_planned_example_and_superseded_contracts_are_inactive() {
        let scope = ContractScope::default();
        let active = TemporalWindow::default();
        for normative_kind in [
            NormativeKind::Historical,
            NormativeKind::Planned,
            NormativeKind::Example,
        ] {
            let contract = ScopedContract {
                scope: &scope,
                temporal: &active,
                normative_kind,
            };
            assert_eq!(
                resolve_applicability(contract, &ScopeContext::default(), 0).state,
                ApplicabilityState::NotApplicable
            );
        }
        let superseded = TemporalWindow {
            superseded: true,
            ..TemporalWindow::default()
        };
        assert_eq!(
            resolve_applicability(required(&scope, &superseded), &ScopeContext::default(), 0,)
                .state,
            ApplicabilityState::NotApplicable
        );
    }

    #[test]
    fn documented_scope_precedence_is_stable() {
        let scopes = [
            ContractScope {
                deployments: vec!["prod".into()],
                ..ContractScope::default()
            },
            ContractScope {
                environments: vec!["prod".into()],
                components: vec!["api".into()],
                ..ContractScope::default()
            },
            ContractScope {
                feature_flags: vec!["new_dispatcher".into()],
                ..ContractScope::default()
            },
            ContractScope {
                components: vec!["api".into()],
                source_revisions: vec!["rev-a".into()],
                ..ContractScope::default()
            },
            ContractScope::default(),
        ];
        let expected = [
            ScopeSpecificity::ExactDeploymentConfiguration,
            ScopeSpecificity::ExactEnvironmentComponent,
            ScopeSpecificity::FeatureFlagMode,
            ScopeSpecificity::VersionBoundedComponent,
            ScopeSpecificity::ProductWide,
        ];
        for (scope, expected) in scopes.iter().zip(expected) {
            assert_eq!(scope_specificity(scope), Some(expected));
        }
        assert!(expected
            .windows(2)
            .all(|pair| pair[0].rank() > pair[1].rank()));

        let incomplete = ContractScope {
            components: vec!["api".into()],
            ..ContractScope::default()
        };
        assert_eq!(scope_specificity(&incomplete), None);
    }

    #[test]
    fn semantic_version_ranges_are_strict_and_fail_safe() {
        let scope = ContractScope {
            components: vec!["api".into()],
            source_revision_range: Some(">=1.2.3 <2.0.0".into()),
            ..ContractScope::default()
        };
        let active = TemporalWindow::default();
        assert_eq!(
            resolve_applicability(
                required(&scope, &active),
                &ScopeContext {
                    component: Some("api".into()),
                    source_revision: Some("1.8.0".into()),
                    ..ScopeContext::default()
                },
                1,
            ),
            Applicability {
                state: ApplicabilityState::Applicable,
                specificity: Some(ScopeSpecificity::VersionBoundedComponent),
            }
        );
        assert_eq!(
            resolve_applicability(
                required(&scope, &active),
                &ScopeContext {
                    component: Some("api".into()),
                    source_revision: Some("2.0.0".into()),
                    ..ScopeContext::default()
                },
                1,
            )
            .state,
            ApplicabilityState::NotApplicable
        );
        assert_eq!(
            resolve_applicability(
                required(&scope, &active),
                &ScopeContext {
                    component: Some("api".into()),
                    source_revision: Some("commit-a".into()),
                    ..ScopeContext::default()
                },
                1,
            )
            .state,
            ApplicabilityState::Ambiguous
        );

        let deployment_range = ContractScope {
            components: vec!["api".into()],
            deployment_range: Some(">=2.0.0 <3.0.0".into()),
            ..ContractScope::default()
        };
        assert_eq!(
            resolve_applicability(
                required(&deployment_range, &active),
                &ScopeContext {
                    component: Some("api".into()),
                    deployment: Some("2.4.1".into()),
                    ..ScopeContext::default()
                },
                1,
            )
            .state,
            ApplicabilityState::Applicable
        );
        for invalid in ["^1.2.3", "1.2", "1.02.3", ">=1.0.0, <2.0.0", " "] {
            assert!(validate_declaration(
                &ContractScope {
                    source_revision_range: Some(invalid.into()),
                    ..ContractScope::default()
                },
                None,
                None,
            )
            .is_err());
        }
    }
}
