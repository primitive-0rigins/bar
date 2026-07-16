//! Static architecture facts (spec Appendix I, Phase 5).
//!
//! This crate is intentionally shadow-only: it extracts deterministic facts from
//! one source artifact. Unsupported or syntactically uncertain code remains
//! explicit rather than becoming guessed architecture.

use std::collections::{BTreeMap, BTreeSet};

use bar_core::{ArtifactId, Error, Result, RevisionId};
use bar_discovery::{ArtifactKind, Inventory};
use serde::{Deserialize, Serialize};
use tree_sitter::{Language, Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticLanguage {
    Rust,
    Python,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Module,
    Function,
    Class,
    Impl,
    Trait,
    State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    FilesystemWrite,
    DatabaseMutation,
    NetworkRequest,
    MessagePublish,
    ProcessExecute,
    SecretRead,
    ConfigMutation,
    PermissionChange,
    ModelInvoke,
    HumanCommunication,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticArtifact {
    pub path: String,
    pub language: StaticLanguage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticSymbol {
    pub path: String,
    pub name: String,
    pub kind: SymbolKind,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticReference {
    pub path: String,
    pub source: Option<String>,
    pub target: String,
    pub kind: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCallEdge {
    pub path: String,
    pub caller: String,
    pub callee: String,
    pub line: u32,
    pub uncertain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticEffect {
    pub path: String,
    pub symbol: Option<String>,
    pub effect: EffectKind,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticAuthorityCheck {
    pub path: String,
    pub symbol: Option<String>,
    pub check: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticStateTransition {
    pub path: String,
    pub symbol: Option<String>,
    pub field: String,
    pub state: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticDataEdge {
    pub path: String,
    pub symbol: Option<String>,
    pub from: String,
    pub to: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticConfigurationRead {
    pub path: String,
    pub symbol: Option<String>,
    pub access: String,
    pub key: Option<String>,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticTest {
    pub path: String,
    pub symbol: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticUncertainty {
    pub path: String,
    pub reason: String,
    pub line: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticFacts {
    pub artifacts: Vec<StaticArtifact>,
    pub symbols: Vec<StaticSymbol>,
    pub references: Vec<StaticReference>,
    pub call_edges: Vec<StaticCallEdge>,
    pub data_edges: Vec<StaticDataEdge>,
    pub state_definitions: Vec<StaticSymbol>,
    pub state_transitions: Vec<StaticStateTransition>,
    pub authority_checks: Vec<StaticAuthorityCheck>,
    pub effects: Vec<StaticEffect>,
    pub tests: Vec<StaticTest>,
    pub configuration_reads: Vec<StaticConfigurationRead>,
    pub uncertainty: Vec<StaticUncertainty>,
}

/// The maximum source size accepted by the static adapter batch. It matches the
/// default discovery scan limit and prevents a target-controlled inventory from
/// turning static analysis into an unbounded allocation.
pub const MAX_STATIC_SOURCE_BYTES: u64 = 5 * 1024 * 1024;

/// Facts derived from one inventoried artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticArtifactFacts {
    pub artifact_id: ArtifactId,
    pub facts: StaticFacts,
}

/// One artifact that the batch deliberately left unanalyzed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticAnalysisFailure {
    pub artifact_id: ArtifactId,
    pub path: String,
    pub reason: String,
}

/// A shadow-only batch over an already-discovered inventory. Failures are kept
/// alongside successful facts so one target artifact never aborts the scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticAnalysisBatch {
    pub facts: Vec<StaticArtifactFacts>,
    pub failures: Vec<StaticAnalysisFailure>,
}

impl StaticFacts {
    fn for_artifact(path: &str, language: StaticLanguage) -> Self {
        Self {
            artifacts: vec![StaticArtifact {
                path: path.to_string(),
                language,
            }],
            ..Self::default()
        }
    }
}

pub fn analyze_artifact(path: &str, text: &str) -> Result<StaticFacts> {
    validate_path(path)?;
    match language_for(path) {
        StaticLanguage::Rust => analyze_rust(path, text),
        StaticLanguage::Python => analyze_python(path, text),
        StaticLanguage::Unsupported => {
            let mut facts = StaticFacts::for_artifact(path, StaticLanguage::Unsupported);
            facts
                .uncertainty
                .push(uncertainty(path, "unsupported_language", 1));
            Ok(facts)
        }
    }
}

/// Analyzes the code and test artifacts in an inventory. Each source is reopened
/// through discovery's containment, size, and digest checks before parsing;
/// source drift and unreadable/non-UTF-8 input become explicit failures while
/// later artifacts continue to be analyzed.
pub fn analyze_inventory(
    root: &std::path::Path,
    inventory: &Inventory,
    revision_id: &RevisionId,
) -> Result<StaticAnalysisBatch> {
    let canonical_root = std::fs::canonicalize(root).map_err(|error| {
        Error::Target(format!(
            "cannot resolve target root {}: {error}",
            root.display()
        ))
    })?;
    if canonical_root != root || !canonical_root.is_dir() {
        return Err(Error::Target(format!(
            "target root {} is not a canonical directory",
            root.display()
        )));
    }

    let mut batch = StaticAnalysisBatch::default();
    for artifact in inventory.artifacts.iter().filter(|artifact| {
        matches!(
            artifact.artifact_kind,
            ArtifactKind::Code | ArtifactKind::Test
        )
    }) {
        let artifact_id = artifact.artifact_id(revision_id);
        let bytes = match bar_discovery::read_artifact(
            &canonical_root,
            artifact,
            MAX_STATIC_SOURCE_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(_) => {
                batch.failures.push(StaticAnalysisFailure {
                    artifact_id,
                    path: artifact.logical_path.clone(),
                    reason: "source_changed_or_unreadable".into(),
                });
                continue;
            }
        };
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => {
                batch.failures.push(StaticAnalysisFailure {
                    artifact_id,
                    path: artifact.logical_path.clone(),
                    reason: "non_utf8_source".into(),
                });
                continue;
            }
        };
        match analyze_artifact(&artifact.logical_path, text) {
            Ok(facts) => batch.facts.push(StaticArtifactFacts { artifact_id, facts }),
            Err(_) => batch.failures.push(StaticAnalysisFailure {
                artifact_id,
                path: artifact.logical_path.clone(),
                reason: "adapter_error".into(),
            }),
        }
    }
    Ok(batch)
}

/// Validates that persisted or caller-supplied facts still describe exactly one
/// safely-addressable artifact. Store adapters call this again on reload so a
/// corrupt row cannot become trusted architecture evidence.
pub fn validate_static_facts(facts: &StaticFacts) -> Result<()> {
    let [artifact] = facts.artifacts.as_slice() else {
        return Err(Error::Corrupt(
            "static facts must describe exactly one artifact".into(),
        ));
    };
    validate_path(&artifact.path)?;
    if artifact.language != language_for(&artifact.path) {
        return Err(Error::Corrupt(
            "static facts language does not match artifact path".into(),
        ));
    }
    for symbol in facts.symbols.iter().chain(&facts.state_definitions) {
        validate_fact_location(&artifact.path, &symbol.path, symbol.line, &symbol.name)?;
    }
    for reference in &facts.references {
        validate_fact_location(
            &artifact.path,
            &reference.path,
            reference.line,
            &reference.target,
        )?;
        if reference.kind.trim().is_empty() {
            return Err(Error::Corrupt("static reference has a blank kind".into()));
        }
    }
    for read in &facts.configuration_reads {
        validate_fact_location(&artifact.path, &read.path, read.line, &read.access)?;
        if read.key.as_deref().is_some_and(str::is_empty) {
            return Err(Error::Corrupt(
                "static configuration read has a blank key".into(),
            ));
        }
    }
    for edge in &facts.call_edges {
        validate_fact_location(&artifact.path, &edge.path, edge.line, &edge.caller)?;
        if edge.callee.trim().is_empty() {
            return Err(Error::Corrupt("static call edge has a blank callee".into()));
        }
    }
    for edge in &facts.data_edges {
        validate_fact_location(&artifact.path, &edge.path, edge.line, &edge.from)?;
        if edge.to.trim().is_empty() {
            return Err(Error::Corrupt(
                "static data edge has a blank destination".into(),
            ));
        }
    }
    for effect in &facts.effects {
        validate_fact_location(&artifact.path, &effect.path, effect.line, "effect")?;
    }
    for check in &facts.authority_checks {
        validate_fact_location(&artifact.path, &check.path, check.line, &check.check)?;
    }
    for transition in &facts.state_transitions {
        validate_fact_location(
            &artifact.path,
            &transition.path,
            transition.line,
            &transition.field,
        )?;
        if transition.state.trim().is_empty() {
            return Err(Error::Corrupt(
                "static state transition has a blank state".into(),
            ));
        }
    }
    for test in &facts.tests {
        validate_fact_location(&artifact.path, &test.path, test.line, &test.symbol)?;
    }
    for item in &facts.uncertainty {
        validate_fact_location(&artifact.path, &item.path, item.line, &item.reason)?;
    }
    Ok(())
}

fn analyze_rust(path: &str, text: &str) -> Result<StaticFacts> {
    let mut facts = StaticFacts::for_artifact(path, StaticLanguage::Rust);
    let module = path
        .strip_suffix(".rs")
        .unwrap_or(path)
        .strip_prefix("src/")
        .unwrap_or_else(|| path.strip_suffix(".rs").unwrap_or(path))
        .replace('/', "::");
    facts
        .symbols
        .push(symbol(path, &module, SymbolKind::Module, 1));

    let tree = parse(text, tree_sitter_rust::LANGUAGE.into())?;
    let mut seen_effects = BTreeSet::new();
    visit_rust(
        tree.root_node(),
        path,
        text,
        None,
        &mut facts,
        &mut seen_effects,
    );
    retain_known_state_transitions(&mut facts);
    summarize_effects(&mut facts);
    Ok(facts)
}

fn analyze_python(path: &str, text: &str) -> Result<StaticFacts> {
    let mut facts = StaticFacts::for_artifact(path, StaticLanguage::Python);
    let module = path.strip_suffix(".py").unwrap_or(path).replace('/', ".");
    facts
        .symbols
        .push(symbol(path, &module, SymbolKind::Module, 1));

    let tree = parse(text, tree_sitter_python::LANGUAGE.into())?;
    let mut seen_effects = BTreeSet::new();
    visit_python(
        tree.root_node(),
        path,
        text,
        None,
        &mut facts,
        &mut seen_effects,
    );
    retain_known_state_transitions(&mut facts);
    summarize_effects(&mut facts);
    Ok(facts)
}

fn parse(text: &str, language: Language) -> Result<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| Error::Unavailable(format!("static parser setup failed: {error}")))?;
    parser
        .parse(text, None)
        .ok_or_else(|| Error::Unavailable("static parser cancelled before completion".to_string()))
}

fn visit_rust(
    node: Node<'_>,
    path: &str,
    text: &str,
    current_function: Option<&str>,
    facts: &mut StaticFacts,
    seen_effects: &mut BTreeSet<(EffectKind, u32)>,
) {
    record_syntax_uncertainty(node, path, facts);
    match node.kind() {
        "macro_invocation" => {
            facts
                .uncertainty
                .push(uncertainty(path, "macro_invocation", line(node)));
            return;
        }
        "dynamic_type" => facts
            .uncertainty
            .push(uncertainty(path, "dynamic_dispatch", line(node))),
        "use_declaration" => facts.references.push(reference(
            path,
            current_function,
            source(node, text),
            "use",
            line(node),
        )),
        "mod_item" => push_named_symbol(node, path, text, SymbolKind::Module, facts),
        "trait_item" => push_named_symbol(node, path, text, SymbolKind::Trait, facts),
        "impl_item" => {
            let type_name = source_field(node, text, "type");
            if !type_name.is_empty() {
                facts.symbols.push(symbol(
                    path,
                    &format!("impl {type_name}"),
                    SymbolKind::Impl,
                    line(node),
                ));
            }
        }
        "enum_item" => push_state(node, path, text, facts),
        "let_declaration" => push_data_edge(
            node,
            path,
            text,
            current_function,
            "pattern",
            "value",
            false,
            facts,
        ),
        "assignment_expression" => {
            if !is_state_transition(node, text, "::") {
                push_data_edge(
                    node,
                    path,
                    text,
                    current_function,
                    "left",
                    "right",
                    false,
                    facts,
                );
            }
            push_state_transition(node, path, text, current_function, "::", facts)
        }
        "function_item" | "function_signature_item" => {
            let name = source_field(node, text, "name");
            if name.is_empty() {
                visit_rust_children(node, path, text, current_function, facts, seen_effects);
                return;
            }
            facts
                .symbols
                .push(symbol(path, &name, SymbolKind::Function, line(node)));
            if rust_test(node, text) {
                facts.tests.push(StaticTest {
                    path: path.to_string(),
                    symbol: name.clone(),
                    line: line(node),
                });
            }
            visit_rust_children(node, path, text, Some(&name), facts, seen_effects);
            return;
        }
        "call_expression" => push_call(
            node,
            path,
            text,
            current_function,
            facts,
            seen_effects,
            false,
        ),
        _ => {}
    }
    visit_rust_children(node, path, text, current_function, facts, seen_effects);
}

fn visit_rust_children(
    node: Node<'_>,
    path: &str,
    text: &str,
    current_function: Option<&str>,
    facts: &mut StaticFacts,
    seen_effects: &mut BTreeSet<(EffectKind, u32)>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        visit_rust(child, path, text, current_function, facts, seen_effects);
    }
}

fn visit_python(
    node: Node<'_>,
    path: &str,
    text: &str,
    current_function: Option<&str>,
    facts: &mut StaticFacts,
    seen_effects: &mut BTreeSet<(EffectKind, u32)>,
) {
    record_syntax_uncertainty(node, path, facts);
    match node.kind() {
        "import_statement" | "import_from_statement" | "future_import_statement" => {
            facts.references.push(reference(
                path,
                current_function,
                source(node, text),
                "import",
                line(node),
            ));
        }
        "decorator" => facts.references.push(reference(
            path,
            current_function,
            source(node, text),
            "decorator",
            line(node),
        )),
        "class_definition" => {
            push_named_symbol(node, path, text, SymbolKind::Class, facts);
            if python_enum_state(node, text) {
                push_state(node, path, text, facts);
            }
        }
        "function_definition" => {
            let name = source_field(node, text, "name");
            if name.is_empty() {
                visit_python_children(node, path, text, current_function, facts, seen_effects);
                return;
            }
            facts
                .symbols
                .push(symbol(path, &name, SymbolKind::Function, line(node)));
            if name.starts_with("test_") {
                facts.tests.push(StaticTest {
                    path: path.to_string(),
                    symbol: name.clone(),
                    line: line(node),
                });
            }
            visit_python_children(node, path, text, Some(&name), facts, seen_effects);
            return;
        }
        "assignment" if python_state_assignment(node, text) => {
            push_state_assignment(node, path, text, facts)
        }
        "assignment" => {
            if !is_state_transition(node, text, ".") {
                push_data_edge(
                    node,
                    path,
                    text,
                    current_function,
                    "left",
                    "right",
                    true,
                    facts,
                );
            }
            push_state_transition(node, path, text, current_function, ".", facts)
        }
        "subscript" if source_field(node, text, "value") == "os.environ" => {
            push_configuration_subscript(node, path, text, current_function, facts)
        }
        "call" => push_call(
            node,
            path,
            text,
            current_function,
            facts,
            seen_effects,
            true,
        ),
        _ => {}
    }
    visit_python_children(node, path, text, current_function, facts, seen_effects);
}

fn visit_python_children(
    node: Node<'_>,
    path: &str,
    text: &str,
    current_function: Option<&str>,
    facts: &mut StaticFacts,
    seen_effects: &mut BTreeSet<(EffectKind, u32)>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        visit_python(child, path, text, current_function, facts, seen_effects);
    }
}

fn push_named_symbol(
    node: Node<'_>,
    path: &str,
    text: &str,
    kind: SymbolKind,
    facts: &mut StaticFacts,
) {
    let name = source_field(node, text, "name");
    if !name.is_empty() {
        facts.symbols.push(symbol(path, &name, kind, line(node)));
    }
}

fn push_state(node: Node<'_>, path: &str, text: &str, facts: &mut StaticFacts) {
    let name = source_field(node, text, "name");
    if name.is_empty() {
        return;
    }
    let state = symbol(path, &name, SymbolKind::State, line(node));
    facts.state_definitions.push(state.clone());
    facts.symbols.push(state);
}

fn push_state_assignment(node: Node<'_>, path: &str, text: &str, facts: &mut StaticFacts) {
    let name = source_field(node, text, "left");
    if name.is_empty() {
        return;
    }
    let state = symbol(path, &name, SymbolKind::State, line(node));
    facts.state_definitions.push(state.clone());
    facts.symbols.push(state);
}

fn push_state_transition(
    node: Node<'_>,
    path: &str,
    text: &str,
    current_function: Option<&str>,
    separator: &str,
    facts: &mut StaticFacts,
) {
    let field = source_field(node, text, "left");
    let state = source_field(node, text, "right");
    if is_state_transition(node, text, separator) {
        facts.state_transitions.push(StaticStateTransition {
            path: path.to_string(),
            symbol: current_function.map(str::to_string),
            field,
            state,
            line: line(node),
        });
    }
}

fn is_state_transition(node: Node<'_>, text: &str, separator: &str) -> bool {
    let field = source_field(node, text, "left");
    let state = source_field(node, text, "right");
    is_state_field(&field) && qualified_state_type(&state, separator).is_some()
}

#[allow(clippy::too_many_arguments)]
fn push_data_edge(
    node: Node<'_>,
    path: &str,
    text: &str,
    current_function: Option<&str>,
    destination_field: &str,
    source_field_name: &str,
    python: bool,
    facts: &mut StaticFacts,
) {
    let Some(destination) = node.child_by_field_name(destination_field) else {
        return;
    };
    let Some(origin) = node.child_by_field_name(source_field_name) else {
        return;
    };
    let Some(from) = data_source(origin, text, python) else {
        return;
    };
    if !data_binding(destination, python) {
        return;
    }
    facts.data_edges.push(StaticDataEdge {
        path: path.to_string(),
        symbol: current_function.map(str::to_string),
        from,
        to: source(destination, text),
        line: line(node),
    });
}

fn data_binding(node: Node<'_>, python: bool) -> bool {
    matches!(node.kind(), "identifier" | "field_expression")
        || (python && matches!(node.kind(), "attribute"))
}

fn data_source(node: Node<'_>, text: &str, python: bool) -> Option<String> {
    if data_binding(node, python) || node.kind() == "scoped_identifier" {
        return Some(source(node, text));
    }
    let call_kind = if python { "call" } else { "call_expression" };
    (node.kind() == call_kind)
        .then(|| node.child_by_field_name("function"))
        .flatten()
        .filter(|callee| data_binding(*callee, python) || callee.kind() == "scoped_identifier")
        .map(|callee| source(callee, text))
}

fn retain_known_state_transitions(facts: &mut StaticFacts) {
    let state_names = facts
        .state_definitions
        .iter()
        .map(|state| state.name.as_str())
        .collect::<BTreeSet<_>>();
    facts.state_transitions.retain(|transition| {
        qualified_state_type(
            &transition.state,
            if transition.state.contains("::") {
                "::"
            } else {
                "."
            },
        )
        .is_some_and(|state_type| state_names.contains(state_type))
    });
}

fn is_state_field(field: &str) -> bool {
    matches!(field.rsplit('.').next(), Some("state" | "status"))
}

fn qualified_state_type<'a>(state: &'a str, separator: &str) -> Option<&'a str> {
    let (state_type, variant) = state.split_once(separator)?;
    (!state_type.is_empty() && !variant.is_empty() && !variant.contains(separator))
        .then_some(state_type)
}

fn python_enum_state(node: Node<'_>, text: &str) -> bool {
    let name = source_field(node, text, "name");
    let declaration = source(node, text);
    let header = declaration.split_once(':').map_or("", |(header, _)| header);
    (name.ends_with("State") || name.ends_with("Status"))
        && (header.contains("(Enum") || header.contains("(StrEnum"))
}

fn push_call(
    node: Node<'_>,
    path: &str,
    text: &str,
    current_function: Option<&str>,
    facts: &mut StaticFacts,
    seen_effects: &mut BTreeSet<(EffectKind, u32)>,
    python: bool,
) {
    let callee_node = node.child_by_field_name("function");
    let callee = callee_node.map_or_else(String::new, |node| source(node, text));
    let line = line(node);
    let dynamic = callee_node.is_none_or(|node| {
        !matches!(node.kind(), "identifier" | "scoped_identifier")
            || (python && matches!(node.kind(), "attribute"))
    });
    if python && matches!(callee.as_str(), "getattr" | "setattr" | "__import__") {
        facts
            .uncertainty
            .push(uncertainty(path, "dynamic_python_lookup", line));
    } else if dynamic {
        facts
            .uncertainty
            .push(uncertainty(path, "dynamic_call", line));
    }
    if let Some(caller) = current_function.filter(|_| !callee.is_empty()) {
        facts.call_edges.push(StaticCallEdge {
            path: path.to_string(),
            caller: caller.to_string(),
            callee: callee.clone(),
            line,
            uncertain: dynamic,
        });
    }
    if let Some(effect) = effect_for(&callee) {
        if seen_effects.insert((effect, line)) {
            facts.effects.push(StaticEffect {
                path: path.to_string(),
                symbol: current_function.map(str::to_string),
                effect,
                line,
            });
        }
    }
    push_configuration_read(node, path, text, current_function, &callee, facts);
    if authority_check_for(&callee) {
        facts.authority_checks.push(StaticAuthorityCheck {
            path: path.to_string(),
            symbol: current_function.map(str::to_string),
            check: callee,
            line,
        });
    }
}

fn python_state_assignment(node: Node<'_>, text: &str) -> bool {
    let name = source_field(node, text, "left");
    let value = node.child_by_field_name("right");
    name.len() > 1
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        && value.is_some_and(|node| matches!(node.kind(), "list" | "dictionary" | "tuple" | "set"))
}

fn rust_test(node: Node<'_>, text: &str) -> bool {
    let Some(previous) = node.prev_named_sibling() else {
        return false;
    };
    previous.kind() == "attribute_item" && source(previous, text).starts_with("#[test]")
}

fn record_syntax_uncertainty(node: Node<'_>, path: &str, facts: &mut StaticFacts) {
    if node.is_error() || node.is_missing() {
        facts
            .uncertainty
            .push(uncertainty(path, "syntax_error", line(node)));
    }
}

fn effect_for(callee: &str) -> Option<EffectKind> {
    let checks = [
        (
            EffectKind::FilesystemWrite,
            ["std::fs::write", "fs::write", "File::create", "open("].as_slice(),
        ),
        (
            EffectKind::DatabaseMutation,
            ["sqlx::query", "execute"].as_slice(),
        ),
        (
            EffectKind::NetworkRequest,
            ["reqwest", "requests", "urllib"].as_slice(),
        ),
        (
            EffectKind::ProcessExecute,
            ["Command::new", "subprocess", "os.system"].as_slice(),
        ),
        (
            EffectKind::SecretRead,
            ["std::env::var", "os.environ", "getenv"].as_slice(),
        ),
        (
            EffectKind::MessagePublish,
            ["publish", "send_message"].as_slice(),
        ),
        (
            EffectKind::ModelInvoke,
            ["openai", "llm", "model.invoke"].as_slice(),
        ),
    ];
    checks.into_iter().find_map(|(effect, needles)| {
        needles
            .iter()
            .any(|needle| callee.contains(needle))
            .then_some(effect)
    })
}

fn configuration_read_for(callee: &str) -> bool {
    matches!(
        callee,
        "std::env::var"
            | "std::env::var_os"
            | "std::env::vars"
            | "std::env::vars_os"
            | "os.getenv"
            | "os.environ.get"
    )
}

fn push_configuration_read(
    node: Node<'_>,
    path: &str,
    text: &str,
    current_function: Option<&str>,
    callee: &str,
    facts: &mut StaticFacts,
) {
    if !configuration_read_for(callee) {
        return;
    }
    let key = first_string_argument(node, text);
    if configuration_key_required(callee) && key.is_none() {
        facts
            .uncertainty
            .push(uncertainty(path, "dynamic_configuration_key", line(node)));
    }
    facts.configuration_reads.push(StaticConfigurationRead {
        path: path.to_string(),
        symbol: current_function.map(str::to_string),
        access: callee.to_string(),
        key,
        line: line(node),
    });
}

fn push_configuration_subscript(
    node: Node<'_>,
    path: &str,
    text: &str,
    current_function: Option<&str>,
    facts: &mut StaticFacts,
) {
    let key = node
        .child_by_field_name("subscript")
        .and_then(|node| string_literal(&source(node, text)));
    if key.is_none() {
        facts
            .uncertainty
            .push(uncertainty(path, "dynamic_configuration_key", line(node)));
    }
    facts.configuration_reads.push(StaticConfigurationRead {
        path: path.to_string(),
        symbol: current_function.map(str::to_string),
        access: "os.environ".into(),
        key,
        line: line(node),
    });
}

fn configuration_key_required(callee: &str) -> bool {
    !matches!(callee, "std::env::vars" | "std::env::vars_os")
}

fn first_string_argument(node: Node<'_>, text: &str) -> Option<String> {
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let key = arguments
        .named_children(&mut cursor)
        .next()
        .and_then(|argument| string_literal(&source(argument, text)));
    key
}

fn string_literal(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let quote = *bytes.first()?;
    if !matches!(quote, b'\'' | b'\"') || bytes.last().copied()? != quote || bytes.len() < 2 {
        return None;
    }
    let key = &value[1..value.len() - 1];
    (!key.is_empty() && !key.contains('\\')).then_some(key.to_string())
}

fn authority_check_for(callee: &str) -> bool {
    matches!(
        callee,
        "authorize"
            | "check_permission"
            | "has_permission"
            | "require_permission"
            | "require_role"
            | "is_authorized"
            | "user.has_permission"
    )
}

const MAX_EFFECT_SUMMARY_ITERATIONS: usize = 64;

fn summarize_effects(facts: &mut StaticFacts) {
    let mut function_lines = BTreeMap::<String, Vec<u32>>::new();
    for symbol in facts
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Function)
    {
        function_lines
            .entry(symbol.name.clone())
            .or_default()
            .push(symbol.line);
    }
    let function_lines = function_lines
        .into_iter()
        .filter_map(|(name, lines)| (lines.len() == 1).then_some((name, lines[0])))
        .collect::<BTreeMap<_, _>>();
    let mut summaries = function_lines
        .keys()
        .map(|name| (name.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for effect in &facts.effects {
        if let Some(symbol) = &effect.symbol {
            if let Some(summary) = summaries.get_mut(symbol) {
                summary.insert(effect.effect);
            }
        }
    }

    let mut converged = false;
    for _ in 0..MAX_EFFECT_SUMMARY_ITERATIONS {
        let prior = summaries.clone();
        let mut changed = false;
        for edge in facts.call_edges.iter().filter(|edge| !edge.uncertain) {
            let Some(callee) = local_callee(&edge.callee) else {
                continue;
            };
            let Some(callee_effects) = prior.get(callee) else {
                continue;
            };
            let Some(caller_effects) = summaries.get_mut(&edge.caller) else {
                continue;
            };
            for effect in callee_effects {
                changed |= caller_effects.insert(*effect);
            }
        }
        if !changed {
            converged = true;
            break;
        }
    }
    if !converged {
        let artifact = &facts.artifacts[0];
        facts.uncertainty.push(uncertainty(
            &artifact.path,
            "effect_summary_iteration_cap",
            1,
        ));
    }

    let mut existing = facts
        .effects
        .iter()
        .filter_map(|effect| {
            effect
                .symbol
                .as_ref()
                .map(|symbol| (symbol.clone(), effect.effect))
        })
        .collect::<BTreeSet<_>>();
    for (symbol, effects) in summaries {
        for effect in effects {
            if existing.insert((symbol.clone(), effect)) {
                facts.effects.push(StaticEffect {
                    path: facts.artifacts[0].path.clone(),
                    symbol: Some(symbol.clone()),
                    effect,
                    line: function_lines[&symbol],
                });
            }
        }
    }
}

fn local_callee(callee: &str) -> Option<&str> {
    callee
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        .then_some(callee)
        .filter(|callee| !callee.is_empty())
}

fn validate_path(path: &str) -> Result<()> {
    let invalid = path.is_empty()
        || path.contains('\0')
        || path.contains('\\')
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..");
    if invalid {
        return Err(Error::Corrupt(format!(
            "invalid static artifact path `{path}`"
        )));
    }
    Ok(())
}

fn validate_fact_location(
    artifact_path: &str,
    item_path: &str,
    line: u32,
    value: &str,
) -> Result<()> {
    if item_path != artifact_path || line == 0 || value.trim().is_empty() {
        return Err(Error::Corrupt(
            "static fact does not have a valid artifact location".into(),
        ));
    }
    Ok(())
}

fn language_for(path: &str) -> StaticLanguage {
    if path.ends_with(".rs") {
        StaticLanguage::Rust
    } else if path.ends_with(".py") {
        StaticLanguage::Python
    } else {
        StaticLanguage::Unsupported
    }
}

fn symbol(path: &str, name: &str, kind: SymbolKind, line: u32) -> StaticSymbol {
    StaticSymbol {
        path: path.to_string(),
        name: name.to_string(),
        kind,
        line,
    }
}

fn reference(
    path: &str,
    source_name: Option<&str>,
    target: String,
    kind: &str,
    line: u32,
) -> StaticReference {
    StaticReference {
        path: path.to_string(),
        source: source_name.map(str::to_string),
        target,
        kind: kind.to_string(),
        line,
    }
}

fn uncertainty(path: &str, reason: &str, line: u32) -> StaticUncertainty {
    StaticUncertainty {
        path: path.to_string(),
        reason: reason.to_string(),
        line,
    }
}

fn source(node: Node<'_>, text: &str) -> String {
    text.get(node.byte_range())
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn source_field(node: Node<'_>, text: &str, field: &str) -> String {
    node.child_by_field_name(field)
        .map_or_else(String::new, |node| source(node, text))
}

fn line(node: Node<'_>) -> u32 {
    (node.start_position().row + 1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(root: &std::path::Path, path: &str, content: &[u8]) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn revision() -> RevisionId {
        RevisionId::from_digest(bar_core::Sha256Digest::from_bytes([7; 32]))
    }

    #[test]
    fn rust_fixture_extracts_symbols_effects_tests_and_uncertainty() {
        let facts = analyze_artifact(
            "src/dispatcher.rs",
            include_str!("../../../fixtures/phase-5-static/dispatcher.rs"),
        )
        .unwrap();

        assert!(facts.symbols.contains(&symbol(
            "src/dispatcher.rs",
            "Dispatcher",
            SymbolKind::Trait,
            3
        )));
        assert!(facts.symbols.contains(&symbol(
            "src/dispatcher.rs",
            "run_job",
            SymbolKind::Function,
            9
        )));
        assert_eq!(facts.tests[0].symbol, "writes_job_output");
        assert!(facts
            .effects
            .iter()
            .any(|effect| effect.effect == EffectKind::FilesystemWrite));
        assert!(facts
            .uncertainty
            .iter()
            .any(|item| item.reason == "dynamic_dispatch"));
    }

    #[test]
    fn python_fixture_extracts_imports_calls_state_and_effects() {
        let facts = analyze_artifact(
            "workers/runner.py",
            include_str!("../../../fixtures/phase-5-static/runner.py"),
        )
        .unwrap();

        assert!(facts.symbols.contains(&symbol(
            "workers/runner.py",
            "Runner",
            SymbolKind::Class,
            5
        )));
        assert!(facts.state_definitions.contains(&symbol(
            "workers/runner.py",
            "STATES",
            SymbolKind::State,
            3
        )));
        assert!(facts
            .effects
            .iter()
            .any(|effect| effect.effect == EffectKind::ProcessExecute));
        assert!(facts
            .references
            .iter()
            .any(|reference| reference.target == "import subprocess"));
    }

    #[test]
    fn parser_ignores_comment_and_string_decoys_and_keeps_function_scope() {
        let facts = analyze_artifact(
            "src/decoys.rs",
            r#"
                // fn fabricated() { std::fs::write("x", b"x"); }
                fn first() { std::fs::write("one", b"one"); }
                fn second() { let note = "Command::new(\"not a process\")"; helper(); }
            "#,
        )
        .unwrap();

        assert!(!facts.symbols.iter().any(|item| item.name == "fabricated"));
        assert_eq!(facts.effects.len(), 1);
        assert_eq!(facts.effects[0].symbol.as_deref(), Some("first"));
        assert!(facts
            .call_edges
            .iter()
            .any(|edge| edge.caller == "second" && edge.callee == "helper"));
    }

    #[test]
    fn parser_marks_syntax_and_dynamic_python_calls_uncertain() {
        let facts = analyze_artifact(
            "workers/dynamic.py",
            "@decorator\ndef test_dynamic():\n    getattr(worker, name)()\n    if True\n",
        )
        .unwrap();

        assert!(facts
            .references
            .iter()
            .any(|reference| reference.kind == "decorator"));
        assert!(facts.tests.iter().any(|item| item.symbol == "test_dynamic"));
        assert!(facts
            .uncertainty
            .iter()
            .any(|item| item.reason == "dynamic_python_lookup"));
        assert!(facts
            .uncertainty
            .iter()
            .any(|item| item.reason == "syntax_error"));
    }

    #[test]
    fn wrapper_functions_inherit_effects_through_fixed_point_summary() {
        let facts = analyze_artifact(
            "src/effects.rs",
            r#"
                fn leaf() { std::fs::write("out", b"ok").unwrap(); }
                fn wrapper() { leaf(); }
                fn entry() { wrapper(); }
            "#,
        )
        .unwrap();

        for symbol in ["leaf", "wrapper", "entry"] {
            assert!(facts.effects.iter().any(|effect| {
                effect.symbol.as_deref() == Some(symbol)
                    && effect.effect == EffectKind::FilesystemWrite
            }));
        }
    }

    #[test]
    fn known_environment_accesses_are_configuration_reads() {
        let rust = analyze_artifact(
            "src/config.rs",
            "fn mode(key: &str) { let _ = std::env::var(\"MODE\"); let _ = std::env::var(key); }",
        )
        .unwrap();
        let python = analyze_artifact(
            "workers/config.py",
            "def mode(key):\n    return os.getenv(\"MODE\"), os.environ[\"REGION\"], os.getenv(key)\n",
        )
        .unwrap();

        assert!(rust
            .configuration_reads
            .iter()
            .any(|item| item.access == "std::env::var"
                && item.key.as_deref() == Some("MODE")
                && item.symbol.as_deref() == Some("mode")));
        assert!(python
            .configuration_reads
            .iter()
            .any(|item| item.access == "os.getenv" && item.key.as_deref() == Some("MODE")));
        assert!(python
            .configuration_reads
            .iter()
            .any(|item| item.access == "os.environ" && item.key.as_deref() == Some("REGION")));
        assert_eq!(
            rust.uncertainty
                .iter()
                .filter(|item| item.reason == "dynamic_configuration_key")
                .count(),
            1
        );
        assert_eq!(
            python
                .uncertainty
                .iter()
                .filter(|item| item.reason == "dynamic_configuration_key")
                .count(),
            1
        );
    }

    #[test]
    fn explicit_authority_guard_calls_are_source_bound() {
        let rust = analyze_artifact(
            "src/auth.rs",
            "fn serve() { require_permission(actor, \"write\"); }",
        )
        .unwrap();
        let python = analyze_artifact(
            "workers/auth.py",
            "def serve():\n    user.has_permission(\"write\")\n",
        )
        .unwrap();

        assert!(rust.authority_checks.iter().any(|check| {
            check.check == "require_permission" && check.symbol.as_deref() == Some("serve")
        }));
        assert!(python.authority_checks.iter().any(|check| {
            check.check == "user.has_permission" && check.symbol.as_deref() == Some("serve")
        }));
    }

    #[test]
    fn explicit_state_field_assignments_to_declared_variants_are_transitions() {
        let rust = analyze_artifact(
            "src/state.rs",
            "enum JobState { Queued, Running }\nfn start(job: &mut Job) { job.state = JobState::Running; }",
        )
        .unwrap();
        let python = analyze_artifact(
            "workers/state.py",
            "from enum import Enum\nclass JobStatus(Enum):\n    QUEUED = 1\n    RUNNING = 2\ndef start(job):\n    job.status = JobStatus.RUNNING\n",
        )
        .unwrap();

        assert!(rust.state_transitions.iter().any(|transition| {
            transition.field == "job.state"
                && transition.state == "JobState::Running"
                && transition.symbol.as_deref() == Some("start")
        }));
        assert!(python.state_transitions.iter().any(|transition| {
            transition.field == "job.status"
                && transition.state == "JobStatus.RUNNING"
                && transition.symbol.as_deref() == Some("start")
        }));
    }

    #[test]
    fn simple_bindings_and_direct_call_results_are_typed_data_edges() {
        let rust = analyze_artifact(
            "src/data.rs",
            "fn serve(request: Request) { let payload = request.body; let result = load(payload); }",
        )
        .unwrap();
        let python = analyze_artifact(
            "workers/data.py",
            "def serve(request):\n    payload = request.body\n    result = load(payload)\n    ignored = \"literal\"\n",
        )
        .unwrap();

        for facts in [&rust, &python] {
            assert!(facts.data_edges.iter().any(|edge| {
                edge.from == "request.body"
                    && edge.to == "payload"
                    && edge.symbol.as_deref() == Some("serve")
            }));
            assert!(facts.data_edges.iter().any(|edge| {
                edge.from == "load"
                    && edge.to == "result"
                    && edge.symbol.as_deref() == Some("serve")
            }));
            assert!(!facts.data_edges.iter().any(|edge| edge.to == "ignored"));
        }
    }

    #[test]
    fn syntax_recovery_does_not_create_invalid_persisted_facts() {
        let facts = analyze_artifact("src/broken.rs", "fn () {}").unwrap();

        assert!(facts
            .uncertainty
            .iter()
            .any(|item| item.reason == "syntax_error"));
        validate_static_facts(&facts).unwrap();
    }

    #[test]
    fn expected_fixture_graph_shape_is_stable() {
        #[derive(Deserialize)]
        struct Expected {
            rust_symbols: usize,
            python_symbols: usize,
            rust_effects: usize,
            python_effects: usize,
        }

        let expected: Expected = serde_json::from_str(include_str!(
            "../../../fixtures/phase-5-static/expected.json"
        ))
        .unwrap();
        let rust = analyze_artifact(
            "src/dispatcher.rs",
            include_str!("../../../fixtures/phase-5-static/dispatcher.rs"),
        )
        .unwrap();
        let python = analyze_artifact(
            "workers/runner.py",
            include_str!("../../../fixtures/phase-5-static/runner.py"),
        )
        .unwrap();

        assert_eq!(rust.symbols.len(), expected.rust_symbols);
        assert_eq!(python.symbols.len(), expected.python_symbols);
        assert_eq!(rust.effects.len(), expected.rust_effects);
        assert_eq!(python.effects.len(), expected.python_effects);
    }

    #[test]
    fn target_controlled_paths_fail_closed() {
        assert!(analyze_artifact("../src/lib.rs", "").is_err());
        assert_eq!(
            analyze_artifact("README.md", "").unwrap().artifacts[0].language,
            StaticLanguage::Unsupported
        );
    }

    #[test]
    fn persisted_facts_must_keep_a_single_valid_artifact_binding() {
        let mut facts = analyze_artifact("src/lib.rs", "fn run() {}").unwrap();
        validate_static_facts(&facts).unwrap();

        facts.symbols[0].path = "other.rs".into();
        assert!(validate_static_facts(&facts).is_err());
    }

    #[test]
    fn inventory_batch_analyzes_code_and_keeps_source_drift_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        write_file(&root, "src/lib.rs", b"pub fn run() {}");
        write_file(&root, "workers/runner.py", b"def run():\n    return 1\n");
        write_file(&root, "README.md", b"# ignored by static analysis");
        let inventory = bar_discovery::scan(
            &root,
            &bar_discovery::ScanConfig::default(),
            &bar_discovery::PriorInventory::new(),
        )
        .unwrap();

        let complete = analyze_inventory(&root, &inventory, &revision()).unwrap();
        assert_eq!(complete.facts.len(), 2);
        assert!(complete.failures.is_empty());

        write_file(&root, "src/lib.rs", b"pub fn changed() {}");
        let drifted = analyze_inventory(&root, &inventory, &revision()).unwrap();
        assert_eq!(drifted.facts.len(), 1);
        assert!(drifted
            .failures
            .iter()
            .any(|failure| failure.path == "src/lib.rs"
                && failure.reason == "source_changed_or_unreadable"));
    }

    #[test]
    fn inventory_batch_marks_non_utf8_source_as_unanalyzed() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        write_file(&root, "src/bytes.rs", b"\xff\xfe");
        let inventory = bar_discovery::scan(
            &root,
            &bar_discovery::ScanConfig::default(),
            &bar_discovery::PriorInventory::new(),
        )
        .unwrap();

        let batch = analyze_inventory(&root, &inventory, &revision()).unwrap();
        assert!(batch.facts.is_empty());
        assert_eq!(batch.failures[0].reason, "non_utf8_source");
    }
}
