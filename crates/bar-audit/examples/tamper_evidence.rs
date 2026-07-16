//! Seals a short approval workflow into the audit chain, verifies it, then
//! tampers with the "stored" records three ways — edit, deletion, reorder —
//! and shows that verification refuses each one.
//!
//! ```sh
//! cargo run -p bar-audit --example tamper_evidence
//! ```

use bar_audit::{AuditCategory, AuditChain, AuditEvent, AuditRecord};

fn event(
    category: AuditCategory,
    actor: &str,
    summary: &str,
    subject: Option<&str>,
    occurred_at_ms: u64,
) -> AuditEvent {
    AuditEvent {
        category,
        actor: actor.to_owned(),
        summary: summary.to_owned(),
        subject: subject.map(str::to_owned),
        occurred_at_ms,
    }
}

/// Rebuilds a chain from records as a store would — without recomputing
/// hashes — and reports whether verification accepts it.
fn check(label: &str, records: Vec<AuditRecord>) {
    match AuditChain::from_records(records).verify() {
        Ok(()) => println!("{label}: chain verifies"),
        Err(err) => println!("{label}: REFUSED — {err}"),
    }
}

fn main() {
    // Seal a plausible workflow: a ruling, an approval, and the evidence
    // mutation that approval unlocked.
    let mut chain = AuditChain::new();
    chain.append(event(
        AuditCategory::Ruling,
        "operator:bryce",
        "ruled ambiguous retry contract as intended-once",
        Some("contract/retry-policy"),
        1_700_000_000_000,
    ));
    chain.append(event(
        AuditCategory::Approval,
        "operator:bryce",
        "approved repair job within reviewed scope",
        Some("approval/repair-0001"),
        1_700_000_060_000,
    ));
    chain.append(event(
        AuditCategory::EvidenceMutation,
        "system:bar",
        "invalidated stale coverage evidence after repair",
        Some("evidence/coverage-17"),
        1_700_000_120_000,
    ));

    for record in chain.records() {
        println!(
            "sealed #{} {:<17} {}",
            record.seq,
            record.event.category.as_str(),
            record.event.summary
        );
    }
    println!();

    // The intact chain, reloaded as stored rows, verifies.
    check("intact", chain.records().to_vec());

    // Tamper 1: rewrite history — soften what the approval said.
    let mut edited = chain.records().to_vec();
    edited[1].event.summary = "approved repair job (scope unreviewed)".to_owned();
    check("edited record", edited);

    // Tamper 2: make an inconvenient ruling disappear.
    let mut truncated = chain.records().to_vec();
    truncated.remove(0);
    check("deleted record", truncated);

    // Tamper 3: reorder events so the mutation precedes its approval.
    let mut reordered = chain.records().to_vec();
    reordered.swap(1, 2);
    check("reordered records", reordered);
}
