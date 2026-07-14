//! Core types for the Behavioral Assurance Runtime (BAR).
//!
//! This crate holds the vocabulary shared by every other crate in the
//! workspace: the persisted enums that describe contracts, evidence, findings,
//! and repairs, plus the typed error foundation. It has no runtime behaviour of
//! its own and pulls in no dependencies by design — everything here is a stable
//! definition that higher layers build on.
//!
//! See `docs/spec.md` §6 (Data and Identity Model) and §20 (Public Rust
//! Interfaces) for the normative source of these definitions.

pub mod enums;
pub mod error;
pub mod ids;

pub use error::{Error, Result, Retryability};
pub use ids::{ArtifactId, RevisionId, Sha256Digest, TargetId};
