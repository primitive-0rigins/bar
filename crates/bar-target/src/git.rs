//! Read-only Git identity reads (spec §6.2).
//!
//! Phase 1 reads the two revision-identity fields a working tree can supply on
//! its own: the HEAD commit and a content-sensitive hash of any uncommitted
//! changes. Every call shells out to the `git` binary with **read-only**
//! subcommands — nothing here touches the index or working tree, so BAR's
//! read-only policy holds (a content hash via `git add`/`write-tree` would
//! mutate the index and is deliberately avoided).
//!
//! When git cannot answer — not a repository, no commits yet, git absent, or
//! access refused (e.g. "detected dubious ownership" when the daemon monitors
//! another user's checkout) — these return `None`. The caller records an
//! *unbound* revision rather than fabricating identity (spec §6.2).

use std::io::Read;
use std::path::Path;
use std::process::Command;

use bar_core::Sha256Digest;
use sha2::{Digest, Sha256};

/// Whether `root` is inside a Git working tree. Distinguishes the connector
/// kind (`git` vs `filesystem`) independently of whether a commit is resolvable
/// — a freshly `git init`ed tree is a git worktree with no HEAD yet.
pub fn is_worktree(root: &Path) -> bool {
    git(root, &["rev-parse", "--is-inside-work-tree"])
        .and_then(|out| String::from_utf8(out).ok())
        .map(|out| out.trim() == "true")
        .unwrap_or(false)
}

/// The HEAD commit of the working tree at `root`, or `None` when git cannot
/// resolve it. Never errors: an unreadable repository is an unbound revision,
/// not a failure.
pub fn head_commit(root: &Path) -> Option<String> {
    let out = git(root, &["rev-parse", "HEAD"])?;
    let commit = String::from_utf8(out).ok()?.trim().to_string();
    (!commit.is_empty()).then_some(commit)
}

/// A content-sensitive hash of every uncommitted change in the working tree at
/// `root`, or `None` when the tree is clean or is not a resolvable repository.
///
/// The digest covers the unified diff of tracked changes (`git diff HEAD`,
/// which reflects real content, so two different edits to one file hash
/// differently) plus the path and streamed content of every untracked,
/// non-ignored file. All reads are read-only.
pub fn dirty_hash(root: &Path) -> Option<String> {
    // A dirty hash is only meaningful against a resolvable HEAD.
    head_commit(root)?;

    let mut hasher = Sha256::new();
    let mut dirty = false;

    if let Some(diff) = git(root, &["diff", "HEAD"]) {
        if !diff.is_empty() {
            dirty = true;
            hasher.update(b"diff\0");
            hasher.update(&diff);
        }
    }

    // NUL-delimited so filenames with unusual characters cannot be confused.
    if let Some(list) = git(root, &["ls-files", "--others", "--exclude-standard", "-z"]) {
        for name in list.split(|&b| b == 0).filter(|s| !s.is_empty()) {
            dirty = true;
            hasher.update(b"untracked\0");
            hasher.update(name);
            hasher.update(b"\0");
            // The name is git-relative to root; stream its content if the path
            // is representable. A non-UTF-8 name still perturbs the hash above.
            if let Ok(rel) = std::str::from_utf8(name) {
                hash_file(&mut hasher, &root.join(rel));
            }
        }
    }

    dirty.then(|| Sha256Digest::from_bytes(hasher.finalize().into()).to_string())
}

/// Streams a file's bytes into `hasher`. A file that cannot be opened or read
/// contributes nothing beyond its already-hashed name — the caller treats an
/// unreadable untracked file as opaque rather than failing.
fn hash_file(hasher: &mut Sha256, path: &Path) {
    let Ok(mut file) = std::fs::File::open(path) else {
        return;
    };
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => break,
        }
    }
}

/// Runs a read-only `git -C <root> <args>` and returns stdout on success, or
/// `None` when git is missing or exits non-zero (not a repo, refused access).
fn git(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    output.status.success().then_some(output.stdout)
}
