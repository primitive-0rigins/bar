//! Boundary-respecting filesystem walk (spec §8, Appendix AA; scan config in
//! Appendix C `[scan]`).
//!
//! The walk lists files under a target root without hashing them — hashing is
//! deferred so the incremental scan can hash only what changed. It honors the
//! scan policy and refuses to leave the target:
//!
//! - `.git` is never descended, and a subdirectory that is itself a repository
//!   (contains `.git`) is treated as a linked-repo boundary and skipped (spec
//!   Appendix AA — linked repositories are separate targets).
//! - Symlinks are not followed by default; when following is enabled, each
//!   symlink is canonicalized and dropped if it escapes the root, and visited
//!   directories are tracked so a symlink loop cannot spin forever.
//! - Hidden entries are skipped unless `include_hidden`, except a small set of
//!   significant CI/VCS dot-entries (e.g. `.github`) that would otherwise hide
//!   real inventory.
//! - Files larger than `max_file_bytes` are listed but flagged `oversized`, so
//!   the scan records their existence without reading them.

use std::collections::HashSet;
use std::path::Path;
use std::time::UNIX_EPOCH;

use bar_core::{Error, Result};

/// One file found by the walk, with the metadata the incremental scan needs to
/// decide whether it must be re-hashed. Content is not read here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Target-relative path with `/` separators (the `logical_path`).
    pub logical_path: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Modification time as Unix epoch milliseconds, or `None` if unavailable.
    pub modified_at_ms: Option<i64>,
    /// Whether the file exceeds `max_file_bytes` and must not be read.
    pub oversized: bool,
}

/// Dot-entries that are kept even when hidden files are excluded, because they
/// carry real inventory (CI definitions, ignore rules).
fn is_significant_hidden(name: &str) -> bool {
    matches!(
        name,
        ".github" | ".gitlab" | ".circleci" | ".gitlab-ci.yml" | ".travis.yml" | ".gitignore"
    )
}

/// Walks `root` and returns its files, sorted by logical path. Errors only if
/// the root itself cannot be read; unreadable entries deeper in the tree are
/// skipped rather than failing the whole scan.
pub fn walk(root: &Path, config: &super::ScanConfig) -> Result<Vec<FileEntry>> {
    std::fs::read_dir(root)
        .map_err(|e| Error::Target(format!("cannot read target root {}: {e}", root.display())))?;

    let mut entries = Vec::new();
    let mut visited_dirs = HashSet::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };

            if name == ".git" {
                continue;
            }
            if name.starts_with('.') && !config.include_hidden && !is_significant_hidden(&name) {
                continue;
            }

            if file_type.is_symlink() {
                if !config.follow_symlinks {
                    continue;
                }
                let Ok(real) = std::fs::canonicalize(&path) else {
                    continue;
                };
                if !real.starts_with(root) {
                    continue; // escapes the target boundary
                }
                if real.is_dir() {
                    if visited_dirs.insert(real.clone()) {
                        stack.push(real);
                    }
                } else if real.is_file() {
                    push_file(&mut entries, root, &path, config);
                }
                continue;
            }

            if file_type.is_dir() {
                // A nested repository is a separate target; do not descend.
                if path.join(".git").exists() {
                    continue;
                }
                if let Ok(canon) = std::fs::canonicalize(&path) {
                    if !visited_dirs.insert(canon) {
                        continue;
                    }
                }
                stack.push(path);
            } else if file_type.is_file() {
                push_file(&mut entries, root, &path, config);
            }
        }
    }

    entries.sort_by(|a, b| a.logical_path.cmp(&b.logical_path));
    Ok(entries)
}

/// Records a file entry, skipping it if its metadata cannot be read.
fn push_file(entries: &mut Vec<FileEntry>, root: &Path, path: &Path, config: &super::ScanConfig) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    let size_bytes = metadata.len();
    let modified_at_ms = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64);
    entries.push(FileEntry {
        logical_path: relative_path(root, path),
        size_bytes,
        modified_at_ms,
        oversized: size_bytes > config.max_file_bytes,
    });
}

/// The target-relative path of `path` under `root`, joined with `/`.
fn relative_path(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
