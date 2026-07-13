//! Relational store and schema migrations (spec §19).
//!
//! In V1 this is the authoritative store: SQLite locally, with PostgreSQL as a
//! production option. Migrations live at the workspace root (`migrations/`, per
//! spec §5) and are embedded at compile time; applying them is idempotent, so a
//! store re-opened over existing data replays cleanly.
//!
//! This Phase-0 slice persists the audit chain (bar-audit) as the DB-indexed
//! audit log and reloads it with its stored hashes intact, so a reloaded chain
//! can be re-verified — a row edited outside BAR fails verification. The broader
//! entity schema and repository API arrive with their respective build phases.
//!
//! Queries use sqlx's runtime-checked `query`/`query_as` functions (not the
//! compile-time macros), so a clean build never needs a live database.

use std::str::FromStr;

use bar_audit::{AuditCategory, AuditChain, AuditEvent, AuditRecord};
use bar_core::{Error, Result, Sha256Digest};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::FromRow;

/// A handle to the BAR relational store.
#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    /// Opens (creating if absent) the SQLite database at `url`, e.g.
    /// `sqlite:///var/lib/bar/bar.db`.
    pub async fn connect(url: &str) -> Result<Self> {
        let options = SqliteConnectOptions::from_str(url)
            .map_err(|e| Error::Storage(format!("invalid database url `{url}`: {e}")))?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .connect_with(options)
            .await
            .map_err(|e| Error::Storage(format!("connect: {e}")))?;
        Ok(Self { pool })
    }

    /// Applies all pending migrations. Idempotent: already-applied migrations are
    /// skipped, so this doubles as the replay path for existing databases.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("migration failed: {e}")))
    }

    /// Persists a sealed audit record.
    pub async fn insert_audit_record(&self, record: &AuditRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_log \
             (seq, prev_hash, category, actor, summary, subject, occurred_at_ms, hash) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(record.seq as i64)
        .bind(record.prev_hash.to_string())
        .bind(record.event.category.as_str())
        .bind(&record.event.actor)
        .bind(&record.event.summary)
        .bind(record.event.subject.as_deref())
        .bind(record.event.occurred_at_ms as i64)
        .bind(record.hash.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("insert audit record: {e}")))?;
        Ok(())
    }

    /// Loads the full audit chain in sequence order, preserving stored hashes so
    /// the result can be re-verified with [`AuditChain::verify`].
    pub async fn load_audit_chain(&self) -> Result<AuditChain> {
        let rows: Vec<AuditRow> =
            sqlx::query_as("SELECT seq, prev_hash, category, actor, summary, subject, occurred_at_ms, hash FROM audit_log ORDER BY seq")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| Error::Storage(format!("load audit chain: {e}")))?;

        let records = rows
            .into_iter()
            .map(AuditRow::into_record)
            .collect::<Result<Vec<_>>>()?;
        Ok(AuditChain::from_records(records))
    }
}

/// One `audit_log` row. Integer columns are `i64` at the DB boundary (SQLite and
/// PostgreSQL do not encode `u64`) and cast back to `u64` on the way out.
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
            seq: self.seq as u64,
            prev_hash: Sha256Digest::from_str(&self.prev_hash)?,
            event: AuditEvent {
                category: AuditCategory::from_token(&self.category)?,
                actor: self.actor,
                summary: self.summary,
                subject: self.subject,
                occurred_at_ms: self.occurred_at_ms as u64,
            },
            hash: Sha256Digest::from_str(&self.hash)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn temp_store() -> (Store, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("bar.db").display());
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        (store, dir)
    }

    fn sample_event(i: u64) -> AuditEvent {
        AuditEvent {
            category: AuditCategory::Approval,
            actor: "operator".into(),
            summary: format!("event {i}"),
            subject: Some(format!("approval/{i}")),
            occurred_at_ms: 1_700_000_000_000 + i,
        }
    }

    #[tokio::test]
    async fn migrations_apply_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("bar.db").display());

        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        // Replaying on the same database is a no-op.
        store.migrate().await.unwrap();
        // A freshly opened store over the existing file also replays cleanly.
        let reopened = Store::connect(&url).await.unwrap();
        reopened.migrate().await.unwrap();
    }

    #[tokio::test]
    async fn audit_chain_persists_reloads_and_verifies() {
        let (store, _dir) = temp_store().await;

        let mut chain = AuditChain::new();
        for i in 0..5 {
            chain.append(sample_event(i));
        }
        for record in chain.records() {
            store.insert_audit_record(record).await.unwrap();
        }

        let loaded = store.load_audit_chain().await.unwrap();
        loaded.verify().unwrap();
        assert_eq!(loaded.records(), chain.records());
    }

    #[tokio::test]
    async fn tampered_row_fails_reloaded_verification() {
        let (store, _dir) = temp_store().await;

        let mut chain = AuditChain::new();
        for i in 0..3 {
            chain.append(sample_event(i));
        }
        for record in chain.records() {
            store.insert_audit_record(record).await.unwrap();
        }

        // Edit a persisted row out from under BAR.
        sqlx::query("UPDATE audit_log SET summary = ? WHERE seq = ?")
            .bind("forged")
            .bind(1_i64)
            .execute(&store.pool)
            .await
            .unwrap();

        let loaded = store.load_audit_chain().await.unwrap();
        assert!(loaded.verify().is_err());
    }
}
