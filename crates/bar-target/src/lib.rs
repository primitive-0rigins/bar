//! Local target connectors, boundary enforcement, and revision identity
//! (spec §6.2, §8, Appendix AA) — Phase 1.
//!
//! A *target* is a monitored software runtime BAR points at. This crate turns a
//! human-supplied `(name, root)` into a [`ResolvedTarget`]: a canonical root
//! locator, a connector kind (`git` or `filesystem`), and the Phase-1 slice of
//! revision identity (source commit and a content-sensitive dirty hash).
//!
//! ## The boundary is the point
//!
//! BAR must never be tricked into reading or acting outside a target's declared
//! root (spec §8, Appendix AA; Phase-1 exit criterion "symlink/path traversal
//! blocked"). Every path BAR later resolves against a target passes through
//! [`resolve_within`], which canonicalizes both the root and the candidate — so
//! `..` segments, relative paths, and symlinks are all collapsed to their real
//! location — and rejects anything that escapes the root. The file *walk* that
//! consumes this primitive arrives with discovery (Phase 2); Phase 1 establishes
//! and proves the primitive itself.
//!
//! Everything here is **read-only**: no method writes to a target.

pub mod git;

use std::path::{Path, PathBuf};

use bar_core::{Error, Result, RevisionId, Sha256Digest, TargetId};
use sha2::{Digest, Sha256};

/// How BAR reads a target's source. Persisted as `connector_kind`; append-only
/// like every stored vocabulary (add variants, never repurpose a token).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectorKind {
    /// A Git working tree; revision identity comes from commits.
    Git,
    /// A plain directory with no version control; revisions are unbound.
    Filesystem,
}

impl ConnectorKind {
    /// Stable persisted token.
    pub const fn as_str(self) -> &'static str {
        match self {
            ConnectorKind::Git => "git",
            ConnectorKind::Filesystem => "filesystem",
        }
    }

    /// Parses a connector kind from its stable token (used when loading targets).
    pub fn from_token(token: &str) -> Result<Self> {
        Ok(match token {
            "git" => ConnectorKind::Git,
            "filesystem" => ConnectorKind::Filesystem,
            other => return Err(Error::Parse(format!("unknown connector kind: {other}"))),
        })
    }
}

impl core::fmt::Display for ConnectorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle status of a registered target. Persisted as `status`; append-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetStatus {
    /// Registered and monitored.
    Active,
    /// Retired from monitoring (transition emits `target.archived`; the archive
    /// flow itself lands with a later phase).
    Archived,
}

impl TargetStatus {
    /// Stable persisted token.
    pub const fn as_str(self) -> &'static str {
        match self {
            TargetStatus::Active => "active",
            TargetStatus::Archived => "archived",
        }
    }

    /// Parses a status from its stable token (used when loading targets).
    pub fn from_token(token: &str) -> Result<Self> {
        Ok(match token {
            "active" => TargetStatus::Active,
            "archived" => TargetStatus::Archived,
            other => return Err(Error::Parse(format!("unknown target status: {other}"))),
        })
    }
}

impl core::fmt::Display for TargetStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The Phase-1 slice of revision identity (spec §6.2): the source commit and a
/// content-sensitive hash of uncommitted changes. The fuller bundle — build
/// manifest, toolchain, deployment id, topology — arrives with the runtime and
/// build-identity phases.
///
/// A revision is *unbound* (spec §6.2) when no source commit can be proven: a
/// filesystem target, or a git tree BAR cannot read. Unbound identity is
/// recorded honestly, never fabricated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionIdentity {
    /// The HEAD commit, or `None` when unbound.
    pub source_commit: Option<String>,
    /// Content-sensitive hash of uncommitted changes; `None` when the tree is
    /// clean or the revision is unbound.
    pub dirty_hash: Option<String>,
}

impl RevisionIdentity {
    /// A revision with no proven source commit (spec §6.2).
    pub fn unbound() -> Self {
        Self {
            source_commit: None,
            dirty_hash: None,
        }
    }

    /// Whether identity is bound to a proven source commit.
    pub fn is_bound(&self) -> bool {
        self.source_commit.is_some()
    }

    /// Whether the working tree carried uncommitted changes at resolution time.
    pub fn is_dirty(&self) -> bool {
        self.dirty_hash.is_some()
    }

    /// The content-derived [`RevisionId`] for this identity under `target_id`
    /// (spec §6.1 content-hash id). Deterministic and injective — identical
    /// identity yields the same id (so recording a revision is idempotent),
    /// while any change in commit or dirty hash yields a different id. The
    /// encoding is length-prefixed and presence-tagged, exactly like the audit
    /// chain, so `None` and `Some("")` never collide.
    pub fn revision_id(&self, target_id: &TargetId) -> RevisionId {
        let mut hasher = Sha256::new();
        update_field(&mut hasher, target_id.to_string().as_bytes());
        update_optional(&mut hasher, self.source_commit.as_deref());
        update_optional(&mut hasher, self.dirty_hash.as_deref());
        RevisionId::from_digest(Sha256Digest::from_bytes(hasher.finalize().into()))
    }
}

/// Absorbs a field as `len(u64 big-endian) ‖ bytes`, keeping boundaries
/// unambiguous.
fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Absorbs an optional field with a presence byte so `None` and `Some("")` are
/// distinct.
fn update_optional(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        None => hasher.update([0u8]),
        Some(s) => {
            hasher.update([1u8]);
            update_field(hasher, s.as_bytes());
        }
    }
}

/// A target resolved from `(name, root)`: ready to register, with its boundary
/// established and its revision identity read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// Operator-supplied display name (1–255 characters).
    pub name: String,
    /// The canonical target root — the boundary all later path resolution is
    /// confined to. This is the idempotency key for registration.
    pub root_locator: PathBuf,
    /// How BAR reads this target's source.
    pub connector_kind: ConnectorKind,
    /// Revision identity at resolution time.
    pub revision: RevisionIdentity,
}

/// Resolves `(name, root)` into a [`ResolvedTarget`], establishing the canonical
/// boundary and reading revision identity. Read-only.
///
/// Errors ([`Error::Target`]) when the name is out of range, the root does not
/// exist or cannot be canonicalized, or the root is not a directory.
pub fn resolve_target(name: &str, root: &Path) -> Result<ResolvedTarget> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 255 {
        return Err(Error::Target(
            "target name must be 1..=255 characters".to_string(),
        ));
    }

    let root_locator = std::fs::canonicalize(root).map_err(|e| {
        Error::Target(format!(
            "target root {} cannot be resolved: {e}",
            root.display()
        ))
    })?;
    if !root_locator.is_dir() {
        return Err(Error::Target(format!(
            "target root {} is not a directory",
            root_locator.display()
        )));
    }

    let (connector_kind, revision) = if git::is_worktree(&root_locator) {
        (
            ConnectorKind::Git,
            RevisionIdentity {
                source_commit: git::head_commit(&root_locator),
                dirty_hash: git::dirty_hash(&root_locator),
            },
        )
    } else {
        (ConnectorKind::Filesystem, RevisionIdentity::unbound())
    };

    Ok(ResolvedTarget {
        name: name.to_string(),
        root_locator,
        connector_kind,
        revision,
    })
}

/// Resolves `candidate` and confirms it lies within `root`, returning its
/// canonical path (spec §8, Appendix AA). **`root` must already be canonical**
/// (as produced by [`resolve_target`]).
///
/// Because both paths are canonicalized, `..` traversal, relative paths, and
/// symlinks pointing outside the target are all collapsed to their real
/// location before the containment check — a symlink inside the root that aims
/// outside it is rejected. A candidate that does not exist is an error, never a
/// panic.
pub fn resolve_within(root: &Path, candidate: &Path) -> Result<PathBuf> {
    let canonical_root = std::fs::canonicalize(root).map_err(|e| {
        Error::Target(format!(
            "target root {} cannot be resolved: {e}",
            root.display()
        ))
    })?;
    if canonical_root != root || !canonical_root.is_dir() {
        return Err(Error::Target(format!(
            "target root {} is not a canonical directory",
            root.display()
        )));
    }
    let real = std::fs::canonicalize(candidate).map_err(|e| {
        Error::Target(format!(
            "path {} cannot be resolved: {e}",
            candidate.display()
        ))
    })?;
    if real.starts_with(&canonical_root) {
        Ok(real)
    } else {
        Err(Error::Target(format!(
            "path {} escapes target root {}",
            real.display(),
            root.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // --- Security boundary primitive (the Phase-1 exit criterion) ---

    #[test]
    fn resolve_within_accepts_a_path_inside_the_root() {
        let root = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(root.path()).unwrap();
        let inside = root_path.join("file.txt");
        std::fs::write(&inside, b"x").unwrap();

        assert_eq!(resolve_within(&root_path, &inside).unwrap(), inside);
    }

    #[test]
    fn resolve_within_rejects_dotdot_traversal() {
        let root = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(root.path()).unwrap();
        // A sibling file outside the root, reached via `..`.
        let outside = root_path.parent().unwrap().join("outside.txt");
        std::fs::write(&outside, b"secret").unwrap();
        let traversal = root_path.join("..").join("outside.txt");

        assert!(resolve_within(&root_path, &traversal).is_err());
        let _ = std::fs::remove_file(outside);
    }

    #[test]
    #[cfg(unix)]
    fn resolve_within_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(root.path()).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_path = std::fs::canonicalize(outside.path()).unwrap();
        std::fs::write(outside_path.join("secret.txt"), b"secret").unwrap();

        // A symlink *inside* the root that points to a directory outside it.
        let link = root_path.join("escape");
        symlink(&outside_path, &link).unwrap();

        // Canonicalization resolves the symlink to its real (outside) target,
        // so the escape is caught.
        assert!(resolve_within(&root_path, &link.join("secret.txt")).is_err());
    }

    #[test]
    fn resolve_within_errors_on_missing_path_without_panicking() {
        let root = tempfile::tempdir().unwrap();
        let root_path = std::fs::canonicalize(root.path()).unwrap();
        assert!(resolve_within(&root_path, &root_path.join("nope")).is_err());
    }

    #[test]
    fn resolve_within_rejects_a_noncanonical_declared_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("target");
        std::fs::create_dir(&root).unwrap();
        let inside = root.join("file.txt");
        std::fs::write(&inside, b"x").unwrap();
        let noncanonical = root.join("..").join("target");

        assert!(resolve_within(&noncanonical, &inside).is_err());
    }

    // --- Vocabulary (mandated unknown-value tests, spec §22) ---

    #[test]
    fn connector_kind_token_round_trips() {
        for kind in [ConnectorKind::Git, ConnectorKind::Filesystem] {
            assert_eq!(ConnectorKind::from_token(kind.as_str()).unwrap(), kind);
        }
    }

    #[test]
    fn connector_kind_rejects_unknown_token() {
        assert!(ConnectorKind::from_token("svn").is_err());
    }

    #[test]
    fn target_status_rejects_unknown_token() {
        assert!(TargetStatus::from_token("paused").is_err());
    }

    // --- Revision id derivation ---

    #[test]
    fn revision_id_is_deterministic_and_content_sensitive() {
        let target = TargetId::generate();
        let a = RevisionIdentity {
            source_commit: Some("abc123".into()),
            dirty_hash: None,
        };
        let b = RevisionIdentity {
            source_commit: Some("abc123".into()),
            dirty_hash: Some("deadbeef".into()),
        };
        // Same identity → same id (idempotent recording).
        assert_eq!(a.revision_id(&target), a.revision_id(&target));
        // A dirty change → a different id.
        assert_ne!(a.revision_id(&target), b.revision_id(&target));
        // Same identity under a different target → a different id.
        assert_ne!(a.revision_id(&target), a.revision_id(&TargetId::generate()));
    }

    #[test]
    fn revision_id_distinguishes_none_from_empty_dirty_hash() {
        let target = TargetId::generate();
        let unbound = RevisionIdentity::unbound();
        let empty = RevisionIdentity {
            source_commit: None,
            dirty_hash: Some(String::new()),
        };
        assert_ne!(unbound.revision_id(&target), empty.revision_id(&target));
    }

    // --- Resolution and revision identity ---

    #[test]
    fn plain_directory_is_a_filesystem_target_with_unbound_revision() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = resolve_target("plain", dir.path()).unwrap();

        assert_eq!(resolved.connector_kind, ConnectorKind::Filesystem);
        assert!(!resolved.revision.is_bound());
        assert_eq!(
            resolved.root_locator,
            std::fs::canonicalize(dir.path()).unwrap()
        );
    }

    #[test]
    fn missing_root_is_a_target_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(resolve_target("gone", &missing).is_err());
    }

    #[test]
    fn blank_name_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(resolve_target("   ", dir.path()).is_err());
    }

    // Git-backed tests build a real repository in a tempdir. They are skipped
    // when the `git` binary is unavailable so the suite still runs offline.
    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn git_in(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {args:?} failed");
    }

    fn init_repo(dir: &Path) {
        git_in(dir, &["init", "-q"]);
        git_in(dir, &["config", "user.email", "t@bar.test"]);
        git_in(dir, &["config", "user.name", "bar-test"]);
        git_in(dir, &["config", "commit.gpgsign", "false"]);
    }

    #[test]
    fn clean_git_tree_binds_a_commit_and_is_not_dirty() {
        if !git_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        git_in(dir.path(), &["add", "."]);
        git_in(dir.path(), &["commit", "-q", "-m", "init"]);

        let resolved = resolve_target("repo", dir.path()).unwrap();
        assert_eq!(resolved.connector_kind, ConnectorKind::Git);
        assert!(resolved.revision.is_bound());
        assert!(
            !resolved.revision.is_dirty(),
            "clean tree must not be dirty"
        );
    }

    #[test]
    fn dirty_hash_is_content_sensitive() {
        if !git_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"hello").unwrap();
        git_in(dir.path(), &["add", "."]);
        git_in(dir.path(), &["commit", "-q", "-m", "init"]);

        // Two *different* edits to the same tracked file must hash differently —
        // the property `git status --porcelain` would fail (both show " M a.txt").
        std::fs::write(&file, b"hello world").unwrap();
        let hash_one = git::dirty_hash(&std::fs::canonicalize(dir.path()).unwrap());
        std::fs::write(&file, b"hello universe").unwrap();
        let hash_two = git::dirty_hash(&std::fs::canonicalize(dir.path()).unwrap());

        assert!(hash_one.is_some() && hash_two.is_some());
        assert_ne!(
            hash_one, hash_two,
            "different content must hash differently"
        );
    }

    #[test]
    fn untracked_file_makes_the_tree_dirty() {
        if !git_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        git_in(dir.path(), &["add", "."]);
        git_in(dir.path(), &["commit", "-q", "-m", "init"]);

        let root = std::fs::canonicalize(dir.path()).unwrap();
        assert!(git::dirty_hash(&root).is_none(), "clean after commit");
        std::fs::write(root.join("new.txt"), b"untracked").unwrap();
        assert!(git::dirty_hash(&root).is_some(), "untracked file is dirty");
    }
}
