//! Artifact dependency graph and deterministic reparse planning (spec §8,
//! §21 Phase 2).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bar_core::{Error, Result};

/// A directed artifact edge: `dependent_path` consumes `dependency_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDependency {
    dependent_path: String,
    dependency_path: String,
    relation_kind: String,
}

impl ArtifactDependency {
    /// Creates a validated dependency edge.
    pub fn new(
        dependent_path: impl Into<String>,
        dependency_path: impl Into<String>,
        relation_kind: impl Into<String>,
    ) -> Result<Self> {
        let dependent_path = dependent_path.into();
        let dependency_path = dependency_path.into();
        let relation_kind = relation_kind.into();
        validate_logical_path(&dependent_path)?;
        validate_logical_path(&dependency_path)?;
        if relation_kind.is_empty()
            || relation_kind.len() > 64
            || !relation_kind
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
        {
            return Err(Error::Corrupt(format!(
                "invalid artifact dependency relation kind `{relation_kind}`"
            )));
        }
        Ok(Self {
            dependent_path,
            dependency_path,
            relation_kind,
        })
    }

    /// Logical path of the artifact that consumes the dependency.
    pub fn dependent_path(&self) -> &str {
        &self.dependent_path
    }

    /// Logical path of the artifact being consumed.
    pub fn dependency_path(&self) -> &str {
        &self.dependency_path
    }

    /// Stable token describing the edge, such as `imports` or `reads`.
    pub fn relation_kind(&self) -> &str {
        &self.relation_kind
    }
}

/// Reverse-indexed artifact graph used to select changed artifacts and all of
/// their transitive dependents for reparsing.
#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
    dependents: BTreeMap<String, BTreeSet<String>>,
}

impl DependencyGraph {
    /// Builds a reverse index from validated dependency edges.
    pub fn from_edges(edges: &[ArtifactDependency]) -> Self {
        let mut dependents = BTreeMap::<String, BTreeSet<String>>::new();
        for edge in edges {
            dependents
                .entry(edge.dependency_path.clone())
                .or_default()
                .insert(edge.dependent_path.clone());
        }
        Self { dependents }
    }

    /// Selects each invalidated path and all of its transitive dependents.
    /// Cycles and duplicate edges produce each path exactly once.
    pub fn reparse_plan<'a>(
        &self,
        changed_paths: impl IntoIterator<Item = &'a str>,
    ) -> ReparsePlan {
        let mut selected = BTreeSet::new();
        let mut pending = VecDeque::new();
        for path in changed_paths {
            if selected.insert(path.to_string()) {
                pending.push_back(path.to_string());
            }
        }

        while let Some(path) = pending.pop_front() {
            if let Some(direct) = self.dependents.get(&path) {
                for dependent in direct {
                    if selected.insert(dependent.clone()) {
                        pending.push_back(dependent.clone());
                    }
                }
            }
        }

        ReparsePlan {
            paths: selected.into_iter().collect(),
        }
    }
}

/// Validates BAR's portable, target-relative logical path representation.
pub fn validate_logical_path(path: &str) -> Result<()> {
    let invalid = path.is_empty()
        || path.len() > 4096
        || path.contains('\0')
        || path.contains('\\')
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == ".." || part == ".");
    if invalid {
        return Err(Error::Corrupt(format!("invalid artifact path `{path}`")));
    }
    Ok(())
}

/// Deterministically ordered artifact paths selected for reparsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReparsePlan {
    paths: Vec<String>,
}

impl ReparsePlan {
    /// Selected paths in deterministic lexical order.
    pub fn paths(&self) -> &[String] {
        &self.paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(dependent: &str, dependency: &str) -> ArtifactDependency {
        ArtifactDependency::new(dependent, dependency, "imports").unwrap()
    }

    #[test]
    fn one_change_selects_only_transitive_dependents() {
        let graph = DependencyGraph::from_edges(&[
            edge("src/service.rs", "schema/api.json"),
            edge("src/api.rs", "src/service.rs"),
            edge("src/cli.rs", "src/service.rs"),
            edge("src/unrelated.rs", "config/other.toml"),
        ]);

        let plan = graph.reparse_plan(["schema/api.json"]);

        assert_eq!(
            plan.paths(),
            [
                "schema/api.json",
                "src/api.rs",
                "src/cli.rs",
                "src/service.rs"
            ]
        );
        assert!(!plan.paths().iter().any(|p| p == "src/unrelated.rs"));
    }

    #[test]
    fn cycles_terminate_and_duplicate_edges_do_not_duplicate_work() {
        let edge = edge("a.rs", "b.rs");
        let graph = DependencyGraph::from_edges(&[edge.clone(), edge, self::edge("b.rs", "a.rs")]);

        assert_eq!(graph.reparse_plan(["a.rs"]).paths(), ["a.rs", "b.rs"]);
    }

    #[test]
    fn rejects_unsafe_paths_and_relation_tokens() {
        assert!(ArtifactDependency::new("../escape", "a.rs", "imports").is_err());
        assert!(ArtifactDependency::new("a.rs", "/rooted", "imports").is_err());
        assert!(ArtifactDependency::new(r"src\a.rs", "b.rs", "imports").is_err());
        assert!(ArtifactDependency::new("a.rs", "b.rs", "not valid").is_err());
    }
}
