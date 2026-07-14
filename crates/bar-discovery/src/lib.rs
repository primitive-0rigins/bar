//! Artifact discovery: boundary-respecting inventory with incremental,
//! cross-revision carry-forward (spec §8, §21 Phase 2).
//!
//! Discovery walks a target's files and produces an [`Inventory`] of classified
//! artifacts. The hard requirement is the Phase-2 exit criterion — *a one-file
//! change reparses only what changed, no full rescan.*
//!
//! ## Why carry-forward is the whole point
//!
//! A target's `RevisionId` is derived from its commit and dirty hash, so **any**
//! content change mints a new revision, and artifacts are unique per
//! `(revision, logical_path)`. A naive "discover everything under the new
//! revision" would therefore re-read and re-hash every file on every change —
//! exactly the full rescan the criterion forbids. Instead [`scan`] takes the
//! prior revision's inventory and, for each file whose size and mtime are
//! unchanged, **carries the stored hash and classification forward** without
//! reading the file. Only added or modified files are hashed. The number
//! actually read is reported as [`ScanSummary::hashed`].
//!
//! ## The mtime heuristic and its limit
//!
//! Incremental mode decides "unchanged" from `(size, mtime)`. That is a
//! heuristic: a content edit that preserves both (same-second edits under mtime
//! granularity, `touch -r`, some checkouts) is a **silent miss**. For an
//! assurance tool a missed change is an integrity fault, so [`ScanMode::Full`]
//! re-hashes every file regardless of mtime — the integrity fallback to run when
//! the heuristic is not trustworthy.

pub mod classify;
pub mod walk;

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use bar_core::{ArtifactId, Result, RevisionId, Sha256Digest};
use sha2::{Digest, Sha256};

pub use classify::ArtifactKind;
pub use walk::FileEntry;

/// Recorded in `content_sha256` for a file that exceeds `max_file_bytes` and is
/// therefore inventoried without being read. Deliberately not a hex digest, so
/// it can never be mistaken for a verified content hash.
pub const UNHASHED_OVERSIZED: &str = "unhashed:oversized";

/// How aggressively a scan re-reads files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Reuse the prior hash for files whose size and mtime are unchanged. Fast;
    /// subject to the mtime heuristic's blind spot.
    Incremental,
    /// Re-hash every file regardless of mtime. The integrity fallback.
    Full,
}

/// Scan policy (spec Appendix C `[scan]`). [`Default`] matches the spec's
/// defaults.
#[derive(Debug, Clone, Copy)]
pub struct ScanConfig {
    /// Files larger than this are inventoried but not read.
    pub max_file_bytes: u64,
    /// Whether to follow symlinks (with boundary and loop protection).
    pub follow_symlinks: bool,
    /// Whether to include hidden entries beyond the significant-CI allowlist.
    pub include_hidden: bool,
    /// Re-read policy.
    pub mode: ScanMode,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 5 * 1024 * 1024,
            follow_symlinks: false,
            include_hidden: false,
            mode: ScanMode::Incremental,
        }
    }
}

/// A classified artifact ready to persist under the current revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredArtifact {
    pub logical_path: String,
    pub content_sha256: String,
    pub media_type: String,
    pub artifact_kind: ArtifactKind,
    pub source_of_truth: bool,
    pub size_bytes: u64,
    pub modified_at_ms: Option<i64>,
}

impl DiscoveredArtifact {
    /// The content-derived [`ArtifactId`] for this artifact under `revision`
    /// (spec §6.1 content-hash id). Deterministic over `(revision, path,
    /// content)`, so persisting the same inventory twice is idempotent. Encoded
    /// length-prefixed, like the audit chain.
    pub fn artifact_id(&self, revision: &RevisionId) -> ArtifactId {
        let mut hasher = Sha256::new();
        update_field(&mut hasher, revision.to_string().as_bytes());
        update_field(&mut hasher, self.logical_path.as_bytes());
        update_field(&mut hasher, self.content_sha256.as_bytes());
        ArtifactId::from_digest(Sha256Digest::from_bytes(hasher.finalize().into()))
    }
}

/// Absorbs a field as `len(u64 big-endian) ‖ bytes`, keeping boundaries
/// unambiguous.
fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// What the store hands back from the prior revision so unchanged files can be
/// carried forward without being read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorArtifact {
    pub content_sha256: String,
    pub media_type: String,
    pub artifact_kind: ArtifactKind,
    pub source_of_truth: bool,
    pub size_bytes: u64,
    pub modified_at_ms: Option<i64>,
}

/// The prior revision's inventory, keyed by logical path.
pub type PriorInventory = HashMap<String, PriorArtifact>;

/// Per-scan counts. `hashed` is the cost metric the exit criterion cares about:
/// how many files were actually read this scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanSummary {
    /// Artifacts in the resulting inventory.
    pub total: usize,
    /// Files present now but not in the prior inventory.
    pub added: usize,
    /// Files whose content hash differs from the prior inventory.
    pub changed: usize,
    /// Files whose content is unchanged from the prior inventory.
    pub unchanged: usize,
    /// Prior files no longer present.
    pub removed: usize,
    /// Files actually read and hashed this scan.
    pub hashed: usize,
    /// Files inventoried without reading because they exceed `max_file_bytes`.
    pub oversized: usize,
    /// Files skipped because they could not be read.
    pub skipped: usize,
}

/// The result of a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub artifacts: Vec<DiscoveredArtifact>,
    pub summary: ScanSummary,
}

/// Scans `root` under `config`, carrying unchanged files forward from `prior`
/// (empty on the first scan of a revision). Only added, changed, or (in
/// [`ScanMode::Full`]) all files are read and hashed.
pub fn scan(root: &Path, config: &ScanConfig, prior: &PriorInventory) -> Result<Inventory> {
    let entries = walk::walk(root, config)?;
    let mut artifacts = Vec::with_capacity(entries.len());
    let mut summary = ScanSummary::default();

    for entry in &entries {
        let prior_art = prior.get(&entry.logical_path);

        // Reuse the stored hash and classification when size and mtime are
        // unchanged (incremental only) — the file is not read.
        let reuse = matches!(config.mode, ScanMode::Incremental)
            && prior_art.is_some_and(|p| {
                p.size_bytes == entry.size_bytes && p.modified_at_ms == entry.modified_at_ms
            });

        let artifact = if reuse {
            let p = prior_art.expect("reuse implies a prior artifact");
            DiscoveredArtifact {
                logical_path: entry.logical_path.clone(),
                content_sha256: p.content_sha256.clone(),
                media_type: p.media_type.clone(),
                artifact_kind: p.artifact_kind,
                source_of_truth: p.source_of_truth,
                size_bytes: entry.size_bytes,
                modified_at_ms: entry.modified_at_ms,
            }
        } else if entry.oversized {
            summary.oversized += 1;
            let kind = classify::classify(&entry.logical_path, b"");
            DiscoveredArtifact {
                logical_path: entry.logical_path.clone(),
                content_sha256: UNHASHED_OVERSIZED.to_string(),
                media_type: classify::media_type(&entry.logical_path).to_string(),
                artifact_kind: kind,
                source_of_truth: kind.is_source_of_truth(),
                size_bytes: entry.size_bytes,
                modified_at_ms: entry.modified_at_ms,
            }
        } else {
            match read_and_hash(&root.join(&entry.logical_path)) {
                Ok((head, content_sha256)) => {
                    summary.hashed += 1;
                    let kind = classify::classify(&entry.logical_path, &head);
                    DiscoveredArtifact {
                        logical_path: entry.logical_path.clone(),
                        content_sha256,
                        media_type: classify::media_type(&entry.logical_path).to_string(),
                        artifact_kind: kind,
                        source_of_truth: kind.is_source_of_truth(),
                        size_bytes: entry.size_bytes,
                        modified_at_ms: entry.modified_at_ms,
                    }
                }
                Err(_) => {
                    summary.skipped += 1;
                    continue;
                }
            }
        };

        // Content-level delta against the prior inventory.
        match prior_art {
            None => summary.added += 1,
            Some(p) if p.content_sha256 == artifact.content_sha256 => summary.unchanged += 1,
            Some(_) => summary.changed += 1,
        }

        artifacts.push(artifact);
    }

    let present: std::collections::HashSet<&str> =
        artifacts.iter().map(|a| a.logical_path.as_str()).collect();
    summary.removed = prior
        .keys()
        .filter(|path| !present.contains(path.as_str()))
        .count();
    summary.total = artifacts.len();

    Ok(Inventory { artifacts, summary })
}

/// Reads a file once, returning a prefix of its content (for classification) and
/// its full SHA-256 as a lowercase hex digest.
fn read_and_hash(path: &Path) -> std::io::Result<(Vec<u8>, String)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut head = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if head.len() < 2048 {
            let take = (2048 - head.len()).min(n);
            head.extend_from_slice(&buf[..take]);
        }
    }
    let digest = Sha256Digest::from_bytes(hasher.finalize().into());
    Ok((head, digest.to_string()))
}

/// Builds a [`PriorInventory`] from a resulting [`Inventory`] — the shape the
/// store persists and reloads. Useful in tests and for callers that keep the
/// last inventory in memory.
pub fn prior_from(inventory: &Inventory) -> PriorInventory {
    inventory
        .artifacts
        .iter()
        .map(|a| {
            (
                a.logical_path.clone(),
                PriorArtifact {
                    content_sha256: a.content_sha256.clone(),
                    media_type: a.media_type.clone(),
                    artifact_kind: a.artifact_kind,
                    source_of_truth: a.source_of_truth,
                    size_bytes: a.size_bytes,
                    modified_at_ms: a.modified_at_ms,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn write(root: &Path, rel: &str, content: &[u8]) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn canon(dir: &tempfile::TempDir) -> PathBuf {
        fs::canonicalize(dir.path()).unwrap()
    }

    #[test]
    fn inventories_and_classifies_a_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(&dir);
        write(&root, "src/main.rs", b"fn main() {}");
        write(&root, "README.md", b"# hi");
        write(&root, "tests/it.rs", b"#[test] fn t() {}");

        let inv = scan(&root, &ScanConfig::default(), &PriorInventory::new()).unwrap();

        assert_eq!(inv.summary.total, 3);
        assert_eq!(inv.summary.added, 3);
        assert_eq!(inv.summary.hashed, 3, "first scan hashes everything");
        let kinds: HashMap<_, _> = inv
            .artifacts
            .iter()
            .map(|a| (a.logical_path.as_str(), a.artifact_kind))
            .collect();
        assert_eq!(kinds["src/main.rs"], ArtifactKind::Code);
        assert_eq!(kinds["README.md"], ArtifactKind::Documentation);
        assert_eq!(kinds["tests/it.rs"], ArtifactKind::Test);
    }

    #[test]
    fn one_file_change_rehashes_only_that_file() {
        // The Phase-2 exit criterion: change one file, reparse only it.
        let dir = tempfile::tempdir().unwrap();
        let root = canon(&dir);
        for i in 0..5 {
            write(&root, &format!("f{i}.txt"), format!("v0-{i}").as_bytes());
        }
        let first = scan(&root, &ScanConfig::default(), &PriorInventory::new()).unwrap();
        assert_eq!(first.summary.hashed, 5);
        let prior = prior_from(&first);

        // Rewrite exactly one file with new content (a fresh mtime).
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write(&root, "f2.txt", b"changed");

        let second = scan(&root, &ScanConfig::default(), &prior).unwrap();
        assert_eq!(second.summary.hashed, 1, "only the changed file is read");
        assert_eq!(second.summary.changed, 1);
        assert_eq!(second.summary.unchanged, 4, "the rest carry forward");
        assert_eq!(second.summary.total, 5);
    }

    #[test]
    fn full_mode_rehashes_everything() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(&dir);
        write(&root, "a.txt", b"a");
        write(&root, "b.txt", b"b");
        let first = scan(&root, &ScanConfig::default(), &PriorInventory::new()).unwrap();
        let prior = prior_from(&first);

        let full = ScanConfig {
            mode: ScanMode::Full,
            ..ScanConfig::default()
        };
        let second = scan(&root, &full, &prior).unwrap();
        assert_eq!(
            second.summary.hashed, 2,
            "full mode ignores the mtime cache"
        );
        assert_eq!(second.summary.unchanged, 2, "content is still unchanged");
    }

    #[test]
    fn detects_added_and_removed_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(&dir);
        write(&root, "keep.txt", b"k");
        write(&root, "gone.txt", b"g");
        let prior =
            prior_from(&scan(&root, &ScanConfig::default(), &PriorInventory::new()).unwrap());

        fs::remove_file(root.join("gone.txt")).unwrap();
        write(&root, "new.txt", b"n");
        let inv = scan(&root, &ScanConfig::default(), &prior).unwrap();

        assert_eq!(inv.summary.added, 1);
        assert_eq!(inv.summary.removed, 1);
        assert_eq!(inv.summary.total, 2);
    }

    #[test]
    fn oversized_files_are_listed_but_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(&dir);
        write(&root, "big.bin", &vec![0u8; 2048]);
        let config = ScanConfig {
            max_file_bytes: 1024,
            ..ScanConfig::default()
        };
        let inv = scan(&root, &config, &PriorInventory::new()).unwrap();

        assert_eq!(inv.summary.oversized, 1);
        assert_eq!(inv.summary.hashed, 0, "oversized files are not read");
        assert_eq!(inv.artifacts[0].content_sha256, UNHASHED_OVERSIZED);
    }

    #[test]
    fn skips_git_and_hidden_but_keeps_significant_dotfiles() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(&dir);
        write(&root, ".git/config", b"[core]");
        write(&root, ".secret", b"nope");
        write(&root, ".github/workflows/ci.yml", b"on: push");
        write(&root, "src/lib.rs", b"");

        let inv = scan(&root, &ScanConfig::default(), &PriorInventory::new()).unwrap();
        let paths: Vec<&str> = inv
            .artifacts
            .iter()
            .map(|a| a.logical_path.as_str())
            .collect();

        assert!(!paths.iter().any(|p| p.starts_with(".git/")), "no .git");
        assert!(!paths.contains(&".secret"), "hidden skipped");
        assert!(
            paths.contains(&".github/workflows/ci.yml"),
            "significant dotfile kept"
        );
        let ci = inv
            .artifacts
            .iter()
            .find(|a| a.logical_path == ".github/workflows/ci.yml")
            .unwrap();
        assert_eq!(ci.artifact_kind, ArtifactKind::Ci);
    }

    #[test]
    #[cfg(unix)]
    fn does_not_descend_into_symlink_loops() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = canon(&dir);
        write(&root, "sub/a.txt", b"a");
        // A symlink pointing back at the root would loop if followed.
        symlink(&root, root.join("sub/loop")).unwrap();

        // Default (no follow) must terminate and ignore the link.
        let inv = scan(&root, &ScanConfig::default(), &PriorInventory::new()).unwrap();
        assert_eq!(inv.summary.total, 1);

        // Following must also terminate thanks to the visited-dir guard.
        let follow = ScanConfig {
            follow_symlinks: true,
            ..ScanConfig::default()
        };
        let inv = scan(&root, &follow, &PriorInventory::new()).unwrap();
        assert!(inv.summary.total >= 1, "terminates without looping");
    }

    #[test]
    fn does_not_descend_into_nested_repositories() {
        let dir = tempfile::tempdir().unwrap();
        let root = canon(&dir);
        write(&root, "app.rs", b"");
        write(&root, "vendor/lib/.git/HEAD", b"ref: x");
        write(&root, "vendor/lib/code.rs", b"");

        let inv = scan(&root, &ScanConfig::default(), &PriorInventory::new()).unwrap();
        let paths: Vec<&str> = inv
            .artifacts
            .iter()
            .map(|a| a.logical_path.as_str())
            .collect();
        assert!(paths.contains(&"app.rs"));
        assert!(
            !paths.iter().any(|p| p.starts_with("vendor/lib/")),
            "nested repo not inventoried"
        );
    }
}
