//! Typed error foundation.
//!
//! Per spec §20.1, BAR uses typed errors carrying an explicit retry
//! classification, never panics on target-controlled input, and quarantines
//! corrupt evidence rather than trusting it. This module seeds that policy; each
//! crate extends it through [`Error`] as its surface area grows.

/// Whether an operation that produced an [`Error`] is worth retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retryability {
    /// The same call may succeed if retried (a temporary condition).
    Transient,
    /// Retrying will not help; the caller must handle the error another way.
    Permanent,
}

/// The workspace-wide error type. Marked `#[non_exhaustive]` so downstream
/// crates can rely on exhaustive-match resilience as variants are added.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Target-controlled input was malformed or corrupt. Callers quarantine the
    /// item and record a BAR health event rather than failing the daemon.
    Corrupt(String),
    /// A dependency was temporarily unavailable; the operation may be retried.
    Unavailable(String),
    /// A workflow transition conflicted with existing state, e.g. an idempotency
    /// key that was already applied.
    Conflict(String),
    /// A value could not be parsed from its canonical string form (e.g. a
    /// malformed identifier).
    Parse(String),
    /// Configuration could not be read, parsed, or validated. Fatal at startup;
    /// never retried.
    Config(String),
    /// A storage/database operation failed (connection, query, or migration).
    Storage(String),
    /// A target could not be resolved: its root is missing, is not a directory,
    /// or a path escapes the declared target boundary (spec §8, Appendix AA).
    Target(String),
}

impl Error {
    /// Classifies whether this error is worth retrying (spec §20.1).
    pub fn retryability(&self) -> Retryability {
        match self {
            Error::Unavailable(_) | Error::Storage(_) => Retryability::Transient,
            Error::Corrupt(_)
            | Error::Conflict(_)
            | Error::Parse(_)
            | Error::Config(_)
            | Error::Target(_) => Retryability::Permanent,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Corrupt(d) => write!(f, "corrupt input: {d}"),
            Error::Unavailable(d) => write!(f, "dependency unavailable: {d}"),
            Error::Conflict(d) => write!(f, "workflow conflict: {d}"),
            Error::Parse(d) => write!(f, "parse error: {d}"),
            Error::Config(d) => write!(f, "configuration error: {d}"),
            Error::Storage(d) => write!(f, "storage error: {d}"),
            Error::Target(d) => write!(f, "target error: {d}"),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience alias used throughout the workspace.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_classification() {
        assert_eq!(
            Error::Unavailable("db".into()).retryability(),
            Retryability::Transient
        );
        assert_eq!(
            Error::Corrupt("bad json".into()).retryability(),
            Retryability::Permanent
        );
        assert_eq!(
            Error::Conflict("dup key".into()).retryability(),
            Retryability::Permanent
        );
    }
}
