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

use bar_audit::{record_hash, AuditCategory, AuditChain, AuditEvent, AuditRecord, GENESIS};
use bar_core::{Error, Result, RevisionId, Sha256Digest, TargetId};
use bar_target::{ConnectorKind, ResolvedTarget, RevisionIdentity, TargetStatus};
use sqlx::sqlite::{Sqlite, SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::{FromRow, Transaction};

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

    /// Registers a resolved target, idempotently on its canonical root locator
    /// (spec §21 Phase 1 exit criterion). A never-seen root mints a new
    /// [`TargetId`], inserts the target, and records the mandated
    /// `target.registered` audit event (Appendix F) in the same transaction. A
    /// root already registered under the same name is a no-op; the same root
    /// under a new name updates it and bumps `version`. `now_ms` is the caller's
    /// clock (Unix epoch milliseconds).
    pub async fn register_target(
        &self,
        resolved: &ResolvedTarget,
        now_ms: u64,
    ) -> Result<Registration> {
        let root = resolved.root_locator.to_string_lossy();
        let now = now_ms as i64;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;

        let existing: Option<TargetRow> =
            sqlx::query_as("SELECT target_id, name, connector_kind, root_locator, status, version FROM targets WHERE root_locator = ?")
                .bind(root.as_ref())
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage("lookup target"))?;

        let registration = match existing {
            Some(row) => {
                let target_id: TargetId = row.target_id.parse()?;
                if row.name == resolved.name
                    && row.connector_kind == resolved.connector_kind.as_str()
                {
                    Registration {
                        target_id,
                        outcome: RegistrationOutcome::Unchanged,
                    }
                } else {
                    sqlx::query(
                        "UPDATE targets SET name = ?, connector_kind = ?, updated_at_ms = ?, \
                         version = version + 1 WHERE target_id = ?",
                    )
                    .bind(&resolved.name)
                    .bind(resolved.connector_kind.as_str())
                    .bind(now)
                    .bind(&row.target_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("update target"))?;
                    Registration {
                        target_id,
                        outcome: RegistrationOutcome::Updated,
                    }
                }
            }
            None => {
                let target_id = TargetId::generate();
                sqlx::query(
                    "INSERT INTO targets \
                     (target_id, name, connector_kind, root_locator, status, created_at_ms, updated_at_ms, version) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                )
                .bind(target_id.to_string())
                .bind(&resolved.name)
                .bind(resolved.connector_kind.as_str())
                .bind(root.as_ref())
                .bind(TargetStatus::Active.as_str())
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(storage("insert target"))?;

                append_audit(
                    &mut tx,
                    AuditEvent {
                        category: AuditCategory::LifecycleTransition,
                        actor: SYSTEM_ACTOR.to_string(),
                        summary: format!("registered target {}", resolved.name),
                        subject: Some(target_id.to_string()),
                        occurred_at_ms: now_ms,
                    },
                )
                .await?;

                Registration {
                    target_id,
                    outcome: RegistrationOutcome::Registered,
                }
            }
        };

        tx.commit().await.map_err(storage("commit"))?;
        Ok(registration)
    }

    /// Records a target revision, idempotently on its content-derived
    /// [`RevisionId`]. A newly seen revision is inserted and emits the mandated
    /// `revision.discovered` audit event (Appendix F); a repeat is a no-op.
    pub async fn record_revision(
        &self,
        target_id: &TargetId,
        revision: &RevisionIdentity,
        now_ms: u64,
    ) -> Result<RevisionRecord> {
        let revision_id = revision.revision_id(target_id);
        let now = now_ms as i64;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;

        let result = sqlx::query(
            "INSERT INTO target_revisions \
             (revision_id, target_id, source_commit, dirty_hash, discovered_at_ms) \
             VALUES (?, ?, ?, ?, ?) ON CONFLICT(revision_id) DO NOTHING",
        )
        .bind(revision_id.to_string())
        .bind(target_id.to_string())
        .bind(revision.source_commit.as_deref())
        .bind(revision.dirty_hash.as_deref())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(storage("insert revision"))?;

        let newly_recorded = result.rows_affected() > 0;
        if newly_recorded {
            append_audit(
                &mut tx,
                AuditEvent {
                    category: AuditCategory::LifecycleTransition,
                    actor: SYSTEM_ACTOR.to_string(),
                    summary: format!("discovered revision (bound={})", revision.is_bound()),
                    subject: Some(revision_id.to_string()),
                    occurred_at_ms: now_ms,
                },
            )
            .await?;
        }

        tx.commit().await.map_err(storage("commit"))?;
        Ok(RevisionRecord {
            revision_id,
            newly_recorded,
        })
    }

    /// Loads a registered target by id, or `None` if unknown.
    pub async fn get_target(&self, target_id: &TargetId) -> Result<Option<TargetRecord>> {
        let row: Option<TargetRow> =
            sqlx::query_as("SELECT target_id, name, connector_kind, root_locator, status, version FROM targets WHERE target_id = ?")
                .bind(target_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(storage("get target"))?;
        row.map(TargetRow::into_record).transpose()
    }
}

/// Appends one event to the audit chain inside an open transaction, chaining it
/// to the persisted tip so a later [`AuditChain::verify`] still holds. Reads the
/// last row's seq and hash rather than the whole chain.
async fn append_audit(tx: &mut Transaction<'_, Sqlite>, event: AuditEvent) -> Result<()> {
    let tip: Option<(i64, String)> =
        sqlx::query_as("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage("audit tip"))?;
    let (seq, prev_hash) = match tip {
        Some((seq, hash)) => (seq as u64 + 1, Sha256Digest::from_str(&hash)?),
        None => (0, GENESIS),
    };
    let hash = record_hash(seq, &prev_hash, &event);

    sqlx::query(
        "INSERT INTO audit_log \
         (seq, prev_hash, category, actor, summary, subject, occurred_at_ms, hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(seq as i64)
    .bind(prev_hash.to_string())
    .bind(event.category.as_str())
    .bind(&event.actor)
    .bind(&event.summary)
    .bind(event.subject.as_deref())
    .bind(event.occurred_at_ms as i64)
    .bind(hash.to_string())
    .execute(&mut **tx)
    .await
    .map_err(storage("insert audit"))?;
    Ok(())
}

/// The actor recorded for events BAR originates itself.
const SYSTEM_ACTOR: &str = "system";

/// Builds a storage-error mapper tagged with the operation that failed.
fn storage(op: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Storage(format!("{op}: {e}"))
}

/// The outcome of a registration attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationOutcome {
    /// A new target was created.
    Registered,
    /// The root was already registered with identical details; nothing changed.
    Unchanged,
    /// The root was already registered; its name/connector was updated.
    Updated,
}

/// The result of [`Store::register_target`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub target_id: TargetId,
    pub outcome: RegistrationOutcome,
}

/// The result of [`Store::record_revision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRecord {
    pub revision_id: RevisionId,
    /// `true` if this call inserted the revision, `false` if it already existed.
    pub newly_recorded: bool,
}

/// A registered target as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRecord {
    pub target_id: TargetId,
    pub name: String,
    pub connector_kind: ConnectorKind,
    pub root_locator: String,
    pub status: TargetStatus,
    pub version: i64,
}

/// One `targets` row at the DB boundary.
#[derive(FromRow)]
struct TargetRow {
    target_id: String,
    name: String,
    connector_kind: String,
    root_locator: String,
    status: String,
    version: i64,
}

impl TargetRow {
    fn into_record(self) -> Result<TargetRecord> {
        Ok(TargetRecord {
            target_id: self.target_id.parse()?,
            name: self.name,
            connector_kind: ConnectorKind::from_token(&self.connector_kind)?,
            root_locator: self.root_locator,
            status: TargetStatus::from_token(&self.status)?,
            version: self.version,
        })
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

    // --- Phase 1: target registry ---

    const T0: u64 = 1_700_000_000_000;

    fn sample_target(name: &str, root: &str) -> ResolvedTarget {
        ResolvedTarget {
            name: name.into(),
            root_locator: std::path::PathBuf::from(root),
            connector_kind: ConnectorKind::Filesystem,
            revision: RevisionIdentity::unbound(),
        }
    }

    #[tokio::test]
    async fn registration_is_idempotent_on_root() {
        let (store, _dir) = temp_store().await;
        let target = sample_target("app", "/srv/app");

        let first = store.register_target(&target, T0).await.unwrap();
        let second = store.register_target(&target, T0 + 1).await.unwrap();

        assert_eq!(first.outcome, RegistrationOutcome::Registered);
        assert_eq!(second.outcome, RegistrationOutcome::Unchanged);
        assert_eq!(first.target_id, second.target_id, "same root, same id");

        // Exactly one target row, and only the first registration was audited.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(chain.len(), 1, "no duplicate audit event on repeat");
    }

    #[tokio::test]
    async fn reregistering_same_root_new_name_updates_and_bumps_version() {
        let (store, _dir) = temp_store().await;

        let id = store
            .register_target(&sample_target("old", "/srv/app"), T0)
            .await
            .unwrap()
            .target_id;
        let updated = store
            .register_target(&sample_target("new", "/srv/app"), T0 + 1)
            .await
            .unwrap();

        assert_eq!(updated.outcome, RegistrationOutcome::Updated);
        assert_eq!(updated.target_id, id, "same root keeps the id");

        let record = store.get_target(&id).await.unwrap().unwrap();
        assert_eq!(record.name, "new");
        assert_eq!(record.version, 2);
    }

    #[tokio::test]
    async fn registration_emits_a_verifiable_audit_event() {
        let (store, _dir) = temp_store().await;
        let reg = store
            .register_target(&sample_target("app", "/srv/app"), T0)
            .await
            .unwrap();

        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        let event = &chain.records()[0].event;
        assert_eq!(event.category, AuditCategory::LifecycleTransition);
        assert_eq!(
            event.subject.as_deref(),
            Some(reg.target_id.to_string()).as_deref()
        );
        assert!(event.summary.contains("registered target app"));
    }

    #[tokio::test]
    async fn recording_a_revision_is_idempotent_and_content_sensitive() {
        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&sample_target("app", "/srv/app"), T0)
            .await
            .unwrap()
            .target_id;

        let clean = RevisionIdentity {
            source_commit: Some("commit-a".into()),
            dirty_hash: None,
        };
        let dirty = RevisionIdentity {
            source_commit: Some("commit-a".into()),
            dirty_hash: Some("work-in-progress".into()),
        };

        let first = store.record_revision(&target_id, &clean, T0).await.unwrap();
        let repeat = store
            .record_revision(&target_id, &clean, T0 + 1)
            .await
            .unwrap();
        let other = store
            .record_revision(&target_id, &dirty, T0 + 2)
            .await
            .unwrap();

        assert!(first.newly_recorded);
        assert!(
            !repeat.newly_recorded,
            "same identity is not recorded twice"
        );
        assert_eq!(first.revision_id, repeat.revision_id);
        assert!(
            other.newly_recorded,
            "a dirty change is a distinct revision"
        );
        assert_ne!(first.revision_id, other.revision_id);

        // Two distinct revision rows; audit chain (1 register + 2 discover) holds.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM target_revisions")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 2);
        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(chain.len(), 3);
    }

    // End-to-end seam: a target resolved from a real git repo (not a hand-built
    // struct) flows through registration and revision recording, and the bound
    // commit lands in the row. Skipped when `git` is unavailable.
    #[tokio::test]
    async fn resolve_then_register_and_record_a_real_git_target() {
        if !git_available() {
            return;
        }
        let (store, _dir) = temp_store().await;

        let repo = tempfile::tempdir().unwrap();
        init_repo(repo.path());
        std::fs::write(repo.path().join("a.txt"), b"hello").unwrap();
        git_in(repo.path(), &["add", "."]);
        git_in(repo.path(), &["commit", "-q", "-m", "init"]);

        let resolved = bar_target::resolve_target("live", repo.path()).unwrap();
        assert_eq!(resolved.connector_kind, ConnectorKind::Git);
        assert!(resolved.revision.is_bound());

        let reg = store.register_target(&resolved, T0).await.unwrap();
        assert_eq!(reg.outcome, RegistrationOutcome::Registered);
        let record = store.get_target(&reg.target_id).await.unwrap().unwrap();
        assert_eq!(record.connector_kind, ConnectorKind::Git);

        let rev = store
            .record_revision(&reg.target_id, &resolved.revision, T0)
            .await
            .unwrap();
        assert!(rev.newly_recorded);

        // The bound revision persisted its real commit.
        let commit: Option<String> =
            sqlx::query_scalar("SELECT source_commit FROM target_revisions WHERE revision_id = ?")
                .bind(rev.revision_id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(commit, resolved.revision.source_commit);
        assert!(commit.is_some(), "a bound revision persists a commit");
    }

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn git_in(dir: &std::path::Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {args:?} failed");
    }

    fn init_repo(dir: &std::path::Path) {
        git_in(dir, &["init", "-q"]);
        git_in(dir, &["config", "user.email", "t@bar.test"]);
        git_in(dir, &["config", "user.name", "bar-test"]);
        git_in(dir, &["config", "commit.gpgsign", "false"]);
    }
}
