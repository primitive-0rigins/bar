//! Authoritative SQLite persistence for the audit chain.

use std::str::FromStr;

use bar_audit::{record_hash, AuditCategory, AuditChain, AuditEvent, AuditRecord};
use bar_core::{Error, Result, Sha256Digest};
use sqlx::sqlite::Sqlite;
use sqlx::{FromRow, Transaction};

use crate::{required_sqlite_u64, storage, Store};

impl Store {
    /// Persists a sealed record only when it extends the verified chain.
    pub async fn insert_audit_record(&self, record: &AuditRecord) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let chain = load_verified_audit_chain(&mut tx).await?;
        let expected_seq = u64::try_from(chain.len())
            .map_err(|_| Error::Corrupt("audit sequence overflow".into()))?;
        let expected_prev = chain.tip();
        let expected_hash = record_hash(record.seq, &record.prev_hash, &record.event);
        if record.seq != expected_seq
            || record.prev_hash != expected_prev
            || record.hash != expected_hash
        {
            return Err(Error::Corrupt(
                "audit record does not extend the verified chain".into(),
            ));
        }
        insert_record(&mut tx, record).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }

    /// Loads the stored hashes without recomputing them so verification detects
    /// storage-level tampering.
    pub async fn load_audit_chain(&self) -> Result<AuditChain> {
        let rows: Vec<AuditRow> = sqlx::query_as(
            "SELECT seq, prev_hash, category, actor, summary, subject, occurred_at_ms, hash \
             FROM audit_log ORDER BY seq",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load audit chain"))?;
        Ok(AuditChain::from_records(
            rows.into_iter()
                .map(AuditRow::into_record)
                .collect::<Result<Vec<_>>>()?,
        ))
    }
}

pub(crate) async fn append_audit(
    tx: &mut Transaction<'_, Sqlite>,
    event: AuditEvent,
) -> Result<()> {
    let chain = load_verified_audit_chain(tx).await?;
    let seq =
        u64::try_from(chain.len()).map_err(|_| Error::Corrupt("audit sequence overflow".into()))?;
    let prev_hash = chain.tip();
    let record = AuditRecord {
        seq,
        prev_hash,
        hash: record_hash(seq, &prev_hash, &event),
        event,
    };
    insert_record(tx, &record).await
}

async fn insert_record(tx: &mut Transaction<'_, Sqlite>, record: &AuditRecord) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_log \
         (seq, prev_hash, category, actor, summary, subject, occurred_at_ms, hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(required_sqlite_u64(record.seq, "audit sequence")?)
    .bind(record.prev_hash.to_string())
    .bind(record.event.category.as_str())
    .bind(&record.event.actor)
    .bind(&record.event.summary)
    .bind(record.event.subject.as_deref())
    .bind(required_sqlite_u64(
        record.event.occurred_at_ms,
        "audit timestamp",
    )?)
    .bind(record.hash.to_string())
    .execute(&mut **tx)
    .await
    .map_err(storage("insert audit"))?;
    Ok(())
}

async fn load_verified_audit_chain(tx: &mut Transaction<'_, Sqlite>) -> Result<AuditChain> {
    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT seq, prev_hash, category, actor, summary, subject, occurred_at_ms, hash \
         FROM audit_log ORDER BY seq",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(storage("verify audit history"))?;
    let chain = AuditChain::from_records(
        rows.into_iter()
            .map(AuditRow::into_record)
            .collect::<Result<Vec<_>>>()?,
    );
    chain.verify()?;
    Ok(chain)
}

#[derive(FromRow)]
struct AuditRow {
    seq: i64,
    prev_hash: String,
    category: String,
    actor: String,
    summary: String,
    subject: Option<String>,
    occurred_at_ms: i64,
    hash: String,
}

impl AuditRow {
    fn into_record(self) -> Result<AuditRecord> {
        Ok(AuditRecord {
            seq: u64::try_from(self.seq)
                .map_err(|_| Error::Corrupt("negative audit sequence".into()))?,
            prev_hash: Sha256Digest::from_str(&self.prev_hash)?,
            event: AuditEvent {
                category: AuditCategory::from_token(&self.category)?,
                actor: self.actor,
                summary: self.summary,
                subject: self.subject,
                occurred_at_ms: u64::try_from(self.occurred_at_ms)
                    .map_err(|_| Error::Corrupt("negative audit timestamp".into()))?,
            },
            hash: Sha256Digest::from_str(&self.hash)?,
        })
    }
}
