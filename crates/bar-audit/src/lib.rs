//! Append-only, hash-chained audit log.
//!
//! BAR records security- and workflow-relevant events — approvals, waivers,
//! rulings, access, and lifecycle transitions — in a tamper-evident chain (spec
//! §18, §19). Each record commits to its predecessor's hash, so altering,
//! reordering, inserting, or removing any record breaks [`AuditChain::verify`].
//!
//! This crate is the storage-agnostic chain primitive. In V1 the relational
//! store is authoritative and a JSONL mirror is appended asynchronously from
//! committed rows (spec §6.2, §19); that persistence, the DB index, optional
//! signatures (spec §18, *optional*), and crash replay live in the storage
//! layer, not here.
//!
//! ## Hashing is over canonical bytes, not serde
//!
//! A record's hash is computed from the manual, length-prefixed encoding in
//! [`record_hash`] — deterministic and injective. When serde/JSONL serialization
//! is added downstream it is a **separate representation and must never become
//! the hash basis**: `serde_json` output varies with key order, whitespace, and
//! escaping, which would make historical hashes unstable.

use bar_core::{Error, Result, Sha256Digest};
use sha2::{Digest, Sha256};

/// The category of an audited event.
///
/// Introduced by this crate (it is *not* one of the spec §6.3 canonical enums;
/// spec §17 lists these as audit contents). Like every persisted vocabulary it
/// is append-only: add variants, never repurpose existing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditCategory {
    /// A repair job approval decision.
    Approval,
    /// A waiver of a finding or proof obligation.
    Waiver,
    /// A human interpretation ruling on a contract.
    Ruling,
    /// An access event (authentication, token issue, credential use).
    Access,
    /// A workflow lifecycle transition.
    LifecycleTransition,
}

impl AuditCategory {
    /// Stable string token. This token — not the enum discriminant — is what the
    /// hash commits to, so reordering the variants never rewrites past hashes.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditCategory::Approval => "approval",
            AuditCategory::Waiver => "waiver",
            AuditCategory::Ruling => "ruling",
            AuditCategory::Access => "access",
            AuditCategory::LifecycleTransition => "lifecycle_transition",
        }
    }

    /// Parses a category from its stable token (used when loading persisted
    /// records).
    pub fn from_token(token: &str) -> Result<Self> {
        Ok(match token {
            "approval" => AuditCategory::Approval,
            "waiver" => AuditCategory::Waiver,
            "ruling" => AuditCategory::Ruling,
            "access" => AuditCategory::Access,
            "lifecycle_transition" => AuditCategory::LifecycleTransition,
            other => return Err(Error::Parse(format!("unknown audit category: {other}"))),
        })
    }
}

/// A single audited event. The caller supplies `occurred_at_ms` (Unix epoch
/// milliseconds) so the record is a pure value; a `bar-core` clock provides it
/// in production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub category: AuditCategory,
    /// Who performed the action (operator, agent, or system identity).
    pub actor: String,
    /// Human-readable description of what happened.
    pub summary: String,
    /// The affected entity, if any (e.g. an `approval/…` identifier).
    pub subject: Option<String>,
    /// When the event occurred, Unix epoch milliseconds.
    pub occurred_at_ms: u64,
}

/// An event sealed into the chain: its sequence number, the hash it chains from,
/// the event, and its own hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub prev_hash: Sha256Digest,
    pub event: AuditEvent,
    pub hash: Sha256Digest,
}

/// The hash the empty chain chains from.
pub const GENESIS: Sha256Digest = Sha256Digest::from_bytes([0u8; 32]);

/// Computes the hash a record commits to, over a length-prefixed canonical
/// encoding of every field. Fixed-width fields are written raw; strings are
/// prefixed with their byte length; `Option` is prefixed with a presence byte so
/// `None` and `Some("")` never collide.
pub fn record_hash(seq: u64, prev_hash: &Sha256Digest, event: &AuditEvent) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_be_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(event.occurred_at_ms.to_be_bytes());
    update_str(&mut hasher, event.category.as_str());
    update_str(&mut hasher, &event.actor);
    update_str(&mut hasher, &event.summary);
    match &event.subject {
        None => hasher.update([0u8]),
        Some(s) => {
            hasher.update([1u8]);
            update_str(&mut hasher, s);
        }
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

/// Absorbs a string as `len(u64 big-endian) ‖ bytes`, keeping field boundaries
/// unambiguous.
fn update_str(hasher: &mut Sha256, s: &str) {
    hasher.update((s.len() as u64).to_be_bytes());
    hasher.update(s.as_bytes());
}

/// An append-only chain of audit records.
#[derive(Debug, Default)]
pub struct AuditChain {
    records: Vec<AuditRecord>,
}

impl AuditChain {
    /// Creates an empty chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconstructs a chain from stored records **without recomputing hashes**,
    /// so a subsequent [`verify`](Self::verify) checks each stored hash against
    /// its stored content — detecting storage-level tampering, not just
    /// in-memory mutation. Records must be supplied in sequence order.
    pub fn from_records(records: Vec<AuditRecord>) -> Self {
        Self { records }
    }

    /// The hash new records chain from: the last record's hash, or [`GENESIS`].
    pub fn tip(&self) -> Sha256Digest {
        self.records.last().map_or(GENESIS, |r| r.hash)
    }

    /// Seals an event onto the chain and returns the new record.
    pub fn append(&mut self, event: AuditEvent) -> &AuditRecord {
        let seq = self.records.len() as u64;
        let prev_hash = self.tip();
        let hash = record_hash(seq, &prev_hash, &event);
        self.records.push(AuditRecord {
            seq,
            prev_hash,
            event,
            hash,
        });
        self.records.last().expect("just pushed")
    }

    /// The sealed records, in order.
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Number of records in the chain.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the chain has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Verifies chain integrity: each record's sequence number, its link to the
    /// previous record's hash, and its recomputed content hash. Any deviation —
    /// mutation, reorder, insertion, truncation, or a broken link — returns
    /// [`Error::Corrupt`].
    pub fn verify(&self) -> Result<()> {
        let mut expected_prev = GENESIS;
        for (index, record) in self.records.iter().enumerate() {
            let seq = index as u64;
            if record.seq != seq {
                return Err(Error::Corrupt(format!(
                    "audit record at position {index} has seq {}",
                    record.seq
                )));
            }
            if record.prev_hash != expected_prev {
                return Err(Error::Corrupt(format!(
                    "audit record {seq} does not chain from its predecessor"
                )));
            }
            let recomputed = record_hash(record.seq, &record.prev_hash, &record.event);
            if recomputed != record.hash {
                return Err(Error::Corrupt(format!(
                    "audit record {seq} content does not match its hash"
                )));
            }
            expected_prev = record.hash;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(summary: &str) -> AuditEvent {
        AuditEvent {
            category: AuditCategory::Approval,
            actor: "operator".into(),
            summary: summary.into(),
            subject: Some("approval/1".into()),
            occurred_at_ms: 1_700_000_000_000,
        }
    }

    fn chain_of(n: usize) -> AuditChain {
        let mut chain = AuditChain::new();
        for i in 0..n {
            chain.append(event(&format!("event {i}")));
        }
        chain
    }

    #[test]
    fn empty_chain_tips_at_genesis_and_verifies() {
        let chain = AuditChain::new();
        assert_eq!(chain.tip(), GENESIS);
        chain.verify().unwrap();
    }

    #[test]
    fn clean_chain_verifies_and_links() {
        let chain = chain_of(5);
        chain.verify().unwrap();
        // Each record chains from the previous record's hash.
        for pair in chain.records().windows(2) {
            assert_eq!(pair[1].prev_hash, pair[0].hash);
        }
        assert_eq!(chain.records()[0].prev_hash, GENESIS);
    }

    #[test]
    fn none_and_empty_subject_hash_differently() {
        // The core injectivity property: None must not collide with Some("").
        let base = AuditEvent {
            subject: None,
            ..event("x")
        };
        let empty = AuditEvent {
            subject: Some(String::new()),
            ..event("x")
        };
        assert_ne!(
            record_hash(0, &GENESIS, &base),
            record_hash(0, &GENESIS, &empty)
        );
    }

    #[test]
    fn tamper_value_mutation_is_detected() {
        let mut chain = chain_of(4);
        chain.records[2].event.summary = "forged".into();
        assert!(chain.verify().is_err());
    }

    #[test]
    fn tamper_timestamp_change_is_detected() {
        let mut chain = chain_of(4);
        chain.records[1].event.occurred_at_ms += 1;
        assert!(chain.verify().is_err());
    }

    #[test]
    fn tamper_category_change_is_detected() {
        let mut chain = chain_of(4);
        chain.records[3].event.category = AuditCategory::Access;
        assert!(chain.verify().is_err());
    }

    #[test]
    fn tamper_subject_none_to_empty_is_detected() {
        let mut chain = chain_of(3);
        chain.records[1].event.subject = None; // was Some("approval/1")
        assert!(chain.verify().is_err());
    }

    #[test]
    fn tamper_reorder_is_detected() {
        let mut chain = chain_of(4);
        chain.records.swap(1, 2);
        assert!(chain.verify().is_err());
    }

    #[test]
    fn tamper_truncation_is_detected() {
        let mut chain = chain_of(4);
        // Drop the last record but leave an inconsistent seq by removing a middle
        // record, so the surviving records no longer form a contiguous chain.
        chain.records.remove(1);
        assert!(chain.verify().is_err());
    }

    #[test]
    fn tamper_insertion_is_detected() {
        let mut chain = chain_of(3);
        let forged = chain.records[1].clone();
        chain.records.insert(2, forged);
        assert!(chain.verify().is_err());
    }

    #[test]
    fn tamper_broken_link_is_detected() {
        let mut chain = chain_of(3);
        chain.records[2].prev_hash = GENESIS;
        assert!(chain.verify().is_err());
    }
}
