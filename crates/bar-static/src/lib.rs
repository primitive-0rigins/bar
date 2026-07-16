//! Static architecture facts (spec Appendix I, Phase 5).
//!
//! This crate is intentionally shadow-only: it extracts deterministic facts from
//! a single source artifact and records uncertainty where the adapter cannot
//! prove structure. Tree-sitter adapters can replace the line scanner without
//! changing the public `StaticFacts` shape.

use std::collections::BTreeSet;

use bar_core::{Error, Result};
use serde::{Deserialize, Serialize};

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
    pub data_edges: Vec<String>,
    pub state_definitions: Vec<StaticSymbol>,
    pub state_transitions: Vec<String>,
    pub authority_checks: Vec<String>,
    pub effects: Vec<StaticEffect>,
    pub tests: Vec<StaticTest>,
    pub configuration_reads: Vec<StaticReference>,
    pub uncertainty: Vec<StaticUncertainty>,
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
        StaticLanguage::Rust => Ok(analyze_rust(path, text)),
        StaticLanguage::Python => Ok(analyze_python(path, text)),
        StaticLanguage::Unsupported => {
            let mut facts = StaticFacts::for_artifact(path, StaticLanguage::Unsupported);
            facts.uncertainty.push(StaticUncertainty {
                path: path.to_string(),
                reason: "unsupported_language".to_string(),
                line: 1,
            });
            Ok(facts)
        }
    }
}

fn analyze_rust(path: &str, text: &str) -> StaticFacts {
    let mut facts = StaticFacts::for_artifact(path, StaticLanguage::Rust);
    let module = path
        .strip_suffix(".rs")
        .unwrap_or(path)
        .strip_prefix("src/")
        .unwrap_or_else(|| path.strip_suffix(".rs").unwrap_or(path))
        .replace('/', "::");
    facts.symbols.push(StaticSymbol {
        path: path.to_string(),
        name: module,
        kind: SymbolKind::Module,
        line: 1,
    });

    let mut current_function = None::<String>;
    let mut next_function_is_test = false;
    let mut seen_effects = BTreeSet::new();

    for (index, line) in text.lines().enumerate() {
        let line_no = (index + 1) as u32;
        let trimmed = line.trim();
        if trimmed == "#[test]" || trimmed.starts_with("#[tokio::test") {
            next_function_is_test = true;
            continue;
        }
        if let Some(name) = rust_decl_name(trimmed, "trait ") {
            facts
                .symbols
                .push(symbol(path, &name, SymbolKind::Trait, line_no));
        }
        if let Some(name) = rust_decl_name(trimmed, "impl ") {
            facts
                .symbols
                .push(symbol(path, &name, SymbolKind::Impl, line_no));
        }
        if let Some(name) = rust_decl_name(trimmed, "enum ") {
            let state = symbol(path, &name, SymbolKind::State, line_no);
            facts.state_definitions.push(state.clone());
            facts.symbols.push(state);
        }
        if let Some(name) = rust_function_name(trimmed) {
            facts
                .symbols
                .push(symbol(path, &name, SymbolKind::Function, line_no));
            if next_function_is_test {
                facts.tests.push(StaticTest {
                    path: path.to_string(),
                    symbol: name.clone(),
                    line: line_no,
                });
                next_function_is_test = false;
            }
            current_function = Some(name);
        }
        if trimmed.starts_with("use ") || trimmed.starts_with("pub use ") {
            facts.references.push(StaticReference {
                path: path.to_string(),
                source: current_function.clone(),
                target: trimmed.trim_end_matches(';').to_string(),
                kind: "use".to_string(),
                line: line_no,
            });
        }
        if trimmed.contains("dyn ") {
            facts
                .uncertainty
                .push(uncertainty(path, "dynamic_dispatch", line_no));
        }
        if trimmed.contains('!') && !trimmed.starts_with("#[") {
            facts
                .uncertainty
                .push(uncertainty(path, "macro_invocation", line_no));
        }
        push_effects(
            path,
            current_function.as_deref(),
            trimmed,
            line_no,
            &mut facts,
            &mut seen_effects,
        );
        push_call_edges(
            path,
            current_function.as_deref(),
            trimmed,
            line_no,
            &mut facts,
        );
    }

    facts
}

fn analyze_python(path: &str, text: &str) -> StaticFacts {
    let mut facts = StaticFacts::for_artifact(path, StaticLanguage::Python);
    let module = path.strip_suffix(".py").unwrap_or(path).replace('/', ".");
    facts
        .symbols
        .push(symbol(path, &module, SymbolKind::Module, 1));
    let mut current_function = None::<String>;
    let mut seen_effects = BTreeSet::new();

    for (index, line) in text.lines().enumerate() {
        let line_no = (index + 1) as u32;
        let trimmed = line.trim();
        if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
            facts.references.push(StaticReference {
                path: path.to_string(),
                source: current_function.clone(),
                target: trimmed.to_string(),
                kind: "import".to_string(),
                line: line_no,
            });
        }
        if let Some(name) = python_decl_name(trimmed, "class ") {
            facts
                .symbols
                .push(symbol(path, &name, SymbolKind::Class, line_no));
        }
        if let Some(name) = python_function_name(trimmed) {
            facts
                .symbols
                .push(symbol(path, &name, SymbolKind::Function, line_no));
            if name.starts_with("test_") {
                facts.tests.push(StaticTest {
                    path: path.to_string(),
                    symbol: name.clone(),
                    line: line_no,
                });
            }
            current_function = Some(name);
        }
        if python_state_constant(trimmed).is_some() {
            let name = trimmed
                .split_once('=')
                .map(|(name, _)| name.trim())
                .unwrap_or(trimmed);
            let state = symbol(path, name, SymbolKind::State, line_no);
            facts.state_definitions.push(state.clone());
            facts.symbols.push(state);
        }
        if trimmed.contains("getattr(")
            || trimmed.contains("setattr(")
            || trimmed.contains("__import__(")
        {
            facts
                .uncertainty
                .push(uncertainty(path, "dynamic_python_lookup", line_no));
        }
        push_effects(
            path,
            current_function.as_deref(),
            trimmed,
            line_no,
            &mut facts,
            &mut seen_effects,
        );
        push_call_edges(
            path,
            current_function.as_deref(),
            trimmed,
            line_no,
            &mut facts,
        );
    }

    facts
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

fn uncertainty(path: &str, reason: &str, line: u32) -> StaticUncertainty {
    StaticUncertainty {
        path: path.to_string(),
        reason: reason.to_string(),
        line,
    }
}

fn rust_decl_name(line: &str, token: &str) -> Option<String> {
    let rest = line
        .strip_prefix(token)
        .or_else(|| line.strip_prefix(&format!("pub {token}")))?;
    Some(
        rest.split(|ch: char| ch.is_whitespace() || ch == '<' || ch == '{' || ch == '(')
            .next()
            .unwrap_or("")
            .trim()
            .to_string(),
    )
    .filter(|name| !name.is_empty())
}

fn rust_function_name(line: &str) -> Option<String> {
    for prefix in ["pub async fn ", "async fn ", "pub fn ", "fn "] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return rest
                .split_once('(')
                .map(|(name, _)| name.trim().to_string())
                .filter(|name| !name.is_empty());
        }
    }
    None
}

fn python_decl_name(line: &str, token: &str) -> Option<String> {
    line.strip_prefix(token)
        .and_then(|rest| rest.split(['(', ':']).next())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn python_function_name(line: &str) -> Option<String> {
    line.strip_prefix("def ")
        .or_else(|| line.strip_prefix("async def "))
        .and_then(|rest| rest.split_once('('))
        .map(|(name, _)| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

fn python_state_constant(line: &str) -> Option<()> {
    let (name, value) = line.split_once('=')?;
    let name = name.trim();
    if name.len() > 1
        && name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        && (value.contains('[') || value.contains('{') || value.contains('('))
    {
        Some(())
    } else {
        None
    }
}

fn push_effects(
    path: &str,
    symbol: Option<&str>,
    line: &str,
    line_no: u32,
    facts: &mut StaticFacts,
    seen: &mut BTreeSet<(EffectKind, u32)>,
) {
    let checks = [
        (
            EffectKind::FilesystemWrite,
            ["std::fs::write", "fs::write", "File::create", "open("].as_slice(),
        ),
        (
            EffectKind::DatabaseMutation,
            ["sqlx::query", "execute(", ".execute("].as_slice(),
        ),
        (
            EffectKind::NetworkRequest,
            ["reqwest::", "requests.", "urllib."].as_slice(),
        ),
        (
            EffectKind::ProcessExecute,
            ["Command::new", "subprocess.", "os.system("].as_slice(),
        ),
        (
            EffectKind::SecretRead,
            ["std::env::var", "os.environ", "getenv("].as_slice(),
        ),
        (
            EffectKind::MessagePublish,
            ["publish(", "send_message("].as_slice(),
        ),
        (
            EffectKind::ModelInvoke,
            ["openai", "llm", "model.invoke"].as_slice(),
        ),
    ];
    for (effect, needles) in checks {
        if needles.iter().any(|needle| line.contains(needle)) && seen.insert((effect, line_no)) {
            facts.effects.push(StaticEffect {
                path: path.to_string(),
                symbol: symbol.map(str::to_string),
                effect,
                line: line_no,
            });
        }
    }
}

fn push_call_edges(
    path: &str,
    caller: Option<&str>,
    line: &str,
    line_no: u32,
    facts: &mut StaticFacts,
) {
    let Some(caller) = caller else {
        return;
    };
    if line.starts_with("fn ")
        || line.starts_with("pub fn ")
        || line.starts_with("async fn ")
        || line.starts_with("pub async fn ")
        || line.starts_with("def ")
        || line.starts_with("async def ")
    {
        return;
    }
    for callee in possible_calls(line) {
        if !matches!(
            callee.as_str(),
            "if" | "for" | "while" | "match" | "return" | "Some" | "Ok" | "Err" | "vec" | "println"
        ) {
            facts.call_edges.push(StaticCallEdge {
                path: path.to_string(),
                caller: caller.to_string(),
                callee,
                line: line_no,
                uncertain: line.contains("dyn ") || line.contains("getattr("),
            });
        }
    }
}

fn possible_calls(line: &str) -> Vec<String> {
    let mut calls = Vec::new();
    for prefix in line.split('(').take(line.matches('(').count()) {
        let token = prefix
            .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == ':'))
            .next()
            .unwrap_or("")
            .trim_matches(':');
        if !token.is_empty()
            && token
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        {
            calls.push(token.to_string());
        }
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
