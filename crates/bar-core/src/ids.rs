//! Stable identifiers.
//!
//! Every entity BAR persists has a typed identifier with a fixed namespace
//! prefix, exactly as listed in `docs/spec.md` §6.1. Two families exist:
//!
//! - **UUID identifiers** (`target/<uuid>`, `contract/<uuid>`, …) for entities
//!   BAR mints itself.
//! - **Content-hash identifiers** (`revision/<sha256>`, `artifact/<sha256>`) that
//!   are derived from what they name.
//!
//! Each id is a distinct newtype, so a [`FindingId`] can never be passed where a
//! [`RepairId`] is expected.
//!
//! ## Canonical persisted form
//!
//! The wire/on-disk representation of every id in this module is its
//! [`Display`](core::fmt::Display) string — `"{prefix}/{body}"` — and it is
//! recovered with [`FromStr`](core::str::FromStr). This form is stable and MUST
//! NOT change once persisted. When serde support is added (with the storage
//! crate) it MUST serialize through this string form, **not** a derived
//! representation — a derive would emit a bare UUID (dropping the prefix) or a
//! 32-element byte array for [`Sha256Digest`], neither of which matches the
//! canonical string the audit chain hashes.

use crate::{Error, Result};

/// A raw SHA-256 digest (32 bytes), rendered and parsed as 64 lowercase hex
/// characters. Backs the content-hash identifiers; computation of the digest
/// lives in the crates that read the underlying bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Wraps 32 raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for Sha256Digest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 64 {
            return Err(Error::Parse(format!(
                "sha256 digest must be 64 hex chars, got {}",
                s.len()
            )));
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hex = &s[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(hex, 16)
                .map_err(|e| Error::Parse(format!("invalid sha256 hex: {e}")))?;
        }
        Ok(Self(bytes))
    }
}

/// Splits a `"prefix/body"` string, verifying the namespace prefix.
fn parse_prefixed<'a>(s: &'a str, prefix: &str) -> Result<&'a str> {
    match s.split_once('/') {
        Some((p, body)) if p == prefix => Ok(body),
        _ => Err(Error::Parse(format!("expected `{prefix}/…`, got `{s}`"))),
    }
}

/// Defines a UUID-backed identifier newtype with its namespace prefix.
macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(uuid::Uuid);

        impl $name {
            /// Namespace prefix in the canonical string form.
            pub const PREFIX: &'static str = $prefix;

            /// Mints a fresh random (v4) identifier.
            pub fn generate() -> Self {
                Self(uuid::Uuid::new_v4())
            }

            /// Wraps an existing UUID.
            pub const fn from_uuid(id: uuid::Uuid) -> Self {
                Self(id)
            }

            /// The underlying UUID.
            pub const fn as_uuid(&self) -> &uuid::Uuid {
                &self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}/{}", $prefix, self.0)
            }
        }

        impl core::str::FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self> {
                let body = parse_prefixed(s, $prefix)?;
                let id = uuid::Uuid::parse_str(body)
                    .map_err(|e| Error::Parse(format!("invalid {} uuid: {e}", $prefix)))?;
                Ok(Self(id))
            }
        }
    };
}

/// Defines a SHA-256-backed identifier newtype with its namespace prefix.
macro_rules! hash_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Sha256Digest);

        impl $name {
            /// Namespace prefix in the canonical string form.
            pub const PREFIX: &'static str = $prefix;

            /// Wraps a content digest.
            pub const fn from_digest(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            /// The underlying digest.
            pub const fn digest(&self) -> &Sha256Digest {
                &self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}/{}", $prefix, self.0)
            }
        }

        impl core::str::FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self> {
                let body = parse_prefixed(s, $prefix)?;
                Ok(Self(body.parse()?))
            }
        }
    };
}

uuid_id! {
    /// Identifies a monitored target runtime.
    TargetId, "target"
}
uuid_id! {
    /// Identifies a discovered architectural component.
    ComponentId, "component"
}
uuid_id! {
    /// Identifies a behavioral contract.
    ContractId, "contract"
}
uuid_id! {
    /// Identifies a human interpretation ruling on a contract.
    RulingId, "ruling"
}
uuid_id! {
    /// Identifies a piece of evidence.
    EvidenceId, "evidence"
}
uuid_id! {
    /// Identifies a static execution path.
    PathId, "path"
}
uuid_id! {
    /// Identifies a proof obligation.
    ProofId, "proof"
}
uuid_id! {
    /// Identifies a finding.
    FindingId, "finding"
}
uuid_id! {
    /// Identifies a waiver.
    WaiverId, "waiver"
}
uuid_id! {
    /// Identifies a repair.
    RepairId, "repair"
}
uuid_id! {
    /// Identifies an approval.
    ApprovalId, "approval"
}
uuid_id! {
    /// Identifies a verification run.
    VerificationId, "verification"
}
uuid_id! {
    /// Identifies a BAR health incident.
    IncidentId, "incident"
}
uuid_id! {
    /// Identifies an assurance decision.
    DecisionId, "decision"
}

hash_id! {
    /// Identifies a target revision by content hash.
    RevisionId, "revision"
}
hash_id! {
    /// Identifies an artifact by content hash.
    ArtifactId, "artifact"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_unique() {
        assert_ne!(TargetId::generate(), TargetId::generate());
    }

    #[test]
    fn uuid_id_round_trips_through_string() {
        let id = ContractId::generate();
        let text = id.to_string();
        assert!(text.starts_with("contract/"));
        assert_eq!(text.parse::<ContractId>().unwrap(), id);
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let text = format!("finding/{}", uuid::Uuid::new_v4());
        assert!(text.parse::<ContractId>().is_err());
    }

    #[test]
    fn sha256_digest_hex_round_trips() {
        let digest = Sha256Digest::from_bytes([0xab; 32]);
        let hex = digest.to_string();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "ab".repeat(32));
        assert_eq!(hex.parse::<Sha256Digest>().unwrap(), digest);
    }

    #[test]
    fn sha256_digest_rejects_bad_length_and_chars() {
        assert!("abc".parse::<Sha256Digest>().is_err());
        assert!("zz".repeat(32).parse::<Sha256Digest>().is_err());
    }

    #[test]
    fn hash_id_round_trips_through_string() {
        let id = RevisionId::from_digest(Sha256Digest::from_bytes([1u8; 32]));
        let text = id.to_string();
        assert!(text.starts_with("revision/"));
        assert_eq!(text.parse::<RevisionId>().unwrap(), id);
    }
}
