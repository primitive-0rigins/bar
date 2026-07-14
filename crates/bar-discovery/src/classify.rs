//! Deterministic Tier-0 artifact classification (spec §8, model ladder Tier 0).
//!
//! Classification is pure Rust rules over the path and a prefix of the file's
//! content — no model (spec §4.2 Tier 0 is always preferred). Every file gets
//! exactly one [`ArtifactKind`]; ambiguous cases resolve by a fixed precedence
//! so the same input always yields the same kind.

/// The category of a discovered artifact. Persisted as `artifact_kind`;
/// append-only like every stored vocabulary (add variants, never repurpose a
/// token).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    /// Prose: READMEs, specs, ADRs, runbooks, design notes.
    Documentation,
    /// Hand-authored source code.
    Code,
    /// Test code and fixtures.
    Test,
    /// Data/API/protocol schemas.
    Schema,
    /// Configuration and manifests.
    Configuration,
    /// Continuous-integration and pipeline definitions.
    Ci,
    /// Machine-readable diagrams.
    Diagram,
    /// Generated output (not a source of truth).
    Generated,
    /// Anything not otherwise classified.
    Other,
}

impl ArtifactKind {
    /// Stable persisted token.
    pub const fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Documentation => "documentation",
            ArtifactKind::Code => "code",
            ArtifactKind::Test => "test",
            ArtifactKind::Schema => "schema",
            ArtifactKind::Configuration => "configuration",
            ArtifactKind::Ci => "ci",
            ArtifactKind::Diagram => "diagram",
            ArtifactKind::Generated => "generated",
            ArtifactKind::Other => "other",
        }
    }

    /// Parses a kind from its stable token (used when loading artifacts).
    pub fn from_token(token: &str) -> bar_core::Result<Self> {
        Ok(match token {
            "documentation" => ArtifactKind::Documentation,
            "code" => ArtifactKind::Code,
            "test" => ArtifactKind::Test,
            "schema" => ArtifactKind::Schema,
            "configuration" => ArtifactKind::Configuration,
            "ci" => ArtifactKind::Ci,
            "diagram" => ArtifactKind::Diagram,
            "generated" => ArtifactKind::Generated,
            "other" => ArtifactKind::Other,
            other => {
                return Err(bar_core::Error::Parse(format!(
                    "unknown artifact kind: {other}"
                )))
            }
        })
    }

    /// Whether an artifact of this kind is a source of truth (spec §8 step 3).
    /// Everything hand-authored is; generated output is not.
    pub fn is_source_of_truth(self) -> bool {
        self != ArtifactKind::Generated
    }
}

impl core::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classifies an artifact from its target-relative `path` and a prefix of its
/// content (`head`, used only to detect generated-file markers). Deterministic.
///
/// Precedence: a generated marker wins over everything (a generated `.rs` is
/// generated, not code); then CI, test, schema, diagram, documentation,
/// configuration, and finally code, falling back to [`ArtifactKind::Other`].
pub fn classify(path: &str, head: &[u8]) -> ArtifactKind {
    if is_generated(path, head) {
        return ArtifactKind::Generated;
    }
    let lower = path.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('/').collect();
    let file = segments.last().copied().unwrap_or("");

    if is_ci(&segments, file) {
        ArtifactKind::Ci
    } else if is_test(&segments, file) {
        ArtifactKind::Test
    } else if is_schema(file) {
        ArtifactKind::Schema
    } else if is_diagram(file) {
        ArtifactKind::Diagram
    } else if is_documentation(file) {
        ArtifactKind::Documentation
    } else if is_configuration(file) {
        ArtifactKind::Configuration
    } else if is_code(file) {
        ArtifactKind::Code
    } else {
        ArtifactKind::Other
    }
}

/// Detects generated output by well-known path locations and standard in-file
/// markers (checked in `head` only, so a huge file need not be read fully).
fn is_generated(path: &str, head: &[u8]) -> bool {
    let lower = path.to_ascii_lowercase();
    let in_generated_dir = lower.split('/').any(|s| {
        matches!(
            s,
            "target" | "dist" | "build" | "node_modules" | "generated" | ".next" | "__pycache__"
        )
    });
    let generated_suffix = lower.ends_with(".pb.go")
        || lower.ends_with("_pb2.py")
        || lower.ends_with(".min.js")
        || lower.ends_with(".lock");
    if in_generated_dir || generated_suffix {
        return true;
    }
    // Standard generated-code markers, near the top of the file only.
    let window = &head[..head.len().min(2048)];
    contains(window, b"@generated")
        || contains(window, b"DO NOT EDIT")
        || contains(window, b"Code generated by")
}

fn is_ci(segments: &[&str], file: &str) -> bool {
    let in_ci_dir = segments
        .iter()
        .any(|s| matches!(*s, ".github" | ".circleci" | ".gitlab"));
    in_ci_dir
        || matches!(
            file,
            ".gitlab-ci.yml" | "jenkinsfile" | "azure-pipelines.yml" | ".travis.yml"
        )
}

fn is_test(segments: &[&str], file: &str) -> bool {
    let in_test_dir = segments
        .iter()
        .rev()
        .skip(1)
        .any(|s| matches!(*s, "tests" | "test" | "__tests__" | "spec"));
    in_test_dir
        || file.starts_with("test_")
        || file.ends_with("_test.rs")
        || file.ends_with("_test.go")
        || file.ends_with("_test.py")
        || file.contains(".test.")
        || file.contains(".spec.")
        || file == "conftest.py"
}

fn is_schema(file: &str) -> bool {
    has_ext(
        file,
        &["sql", "proto", "graphql", "gql", "avsc", "xsd", "prisma"],
    )
}

fn is_diagram(file: &str) -> bool {
    has_ext(
        file,
        &["mmd", "mermaid", "puml", "plantuml", "dot", "drawio"],
    )
}

fn is_documentation(file: &str) -> bool {
    has_ext(file, &["md", "markdown", "rst", "adoc", "txt"])
        || file == "readme"
        || file == "license"
        || file == "changelog"
}

fn is_configuration(file: &str) -> bool {
    has_ext(
        file,
        &[
            "toml",
            "yaml",
            "yml",
            "ini",
            "cfg",
            "conf",
            "env",
            "json",
            "properties",
        ],
    ) || file.starts_with("dockerfile")
        || file == "makefile"
        || file.starts_with("docker-compose")
        || file == ".gitignore"
}

fn is_code(file: &str) -> bool {
    has_ext(
        file,
        &[
            "rs", "py", "js", "jsx", "ts", "tsx", "go", "java", "kt", "c", "h", "cc", "cpp", "hpp",
            "rb", "php", "cs", "swift", "scala", "sh", "bash", "lua", "ml", "ex", "exs",
        ],
    )
}

/// Whether `file` ends with one of `exts` (each given without the dot).
fn has_ext(file: &str, exts: &[&str]) -> bool {
    file.rsplit_once('.')
        .is_some_and(|(_, ext)| exts.contains(&ext))
}

/// Substring search over bytes.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A best-effort media type from the path extension. Falls back to
/// `text/plain`, or `application/octet-stream` for known-binary extensions.
pub fn media_type(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext {
        "md" | "markdown" => "text/markdown",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "js" | "jsx" | "mjs" => "text/javascript",
        "ts" | "tsx" => "text/typescript",
        "go" => "text/x-go",
        "json" => "application/json",
        "toml" => "application/toml",
        "yaml" | "yml" => "application/yaml",
        "sql" => "application/sql",
        "proto" => "text/x-protobuf",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" | "pdf" | "zip" | "gz" | "wasm" | "so"
        | "a" | "o" | "bin" | "exe" => "application/octet-stream",
        _ => "text/plain",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_token_round_trips_and_rejects_unknown() {
        for kind in [
            ArtifactKind::Documentation,
            ArtifactKind::Code,
            ArtifactKind::Test,
            ArtifactKind::Schema,
            ArtifactKind::Configuration,
            ArtifactKind::Ci,
            ArtifactKind::Diagram,
            ArtifactKind::Generated,
            ArtifactKind::Other,
        ] {
            assert_eq!(ArtifactKind::from_token(kind.as_str()).unwrap(), kind);
        }
        assert!(ArtifactKind::from_token("nonsense").is_err());
    }

    #[test]
    fn classifies_common_paths() {
        assert_eq!(classify("src/main.rs", b""), ArtifactKind::Code);
        assert_eq!(classify("README.md", b""), ArtifactKind::Documentation);
        assert_eq!(classify("tests/it.rs", b""), ArtifactKind::Test);
        assert_eq!(classify("src/user_test.go", b""), ArtifactKind::Test);
        assert_eq!(classify("db/schema.sql", b""), ArtifactKind::Schema);
        assert_eq!(classify("Cargo.toml", b""), ArtifactKind::Configuration);
        assert_eq!(classify(".github/workflows/ci.yml", b""), ArtifactKind::Ci);
        assert_eq!(classify("docs/arch.mmd", b""), ArtifactKind::Diagram);
        assert_eq!(classify("notes.xyz", b""), ArtifactKind::Other);
    }

    #[test]
    fn generated_wins_over_extension() {
        // A generated .rs is generated, not code — by directory and by marker.
        assert_eq!(
            classify("target/debug/build.rs", b""),
            ArtifactKind::Generated
        );
        assert_eq!(
            classify("src/proto.rs", b"// @generated by prost\n"),
            ArtifactKind::Generated
        );
        assert!(!ArtifactKind::Generated.is_source_of_truth());
        assert!(ArtifactKind::Code.is_source_of_truth());
    }

    #[test]
    fn media_types_are_stable() {
        assert_eq!(media_type("a.rs"), "text/x-rust");
        assert_eq!(media_type("a.png"), "application/octet-stream");
        assert_eq!(media_type("a.unknownext"), "text/plain");
    }
}
