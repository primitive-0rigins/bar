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

use std::collections::HashMap;
use std::str::FromStr;

use bar_audit::{record_hash, AuditCategory, AuditChain, AuditEvent, AuditRecord, GENESIS};
use bar_contract::{ExtractedClaim, SourceRef};
use bar_core::{
    ContractId, ContractLevel, Error, NormativeKind, Result, RevisionId, Sha256Digest, TargetId,
};
use bar_discovery::dependency::ArtifactDependency;
use bar_discovery::{ArtifactKind, Inventory, PriorArtifact, PriorInventory};
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

    /// Persists a scanned [`Inventory`] under `revision_id`, bracketed by
    /// `target.scan.started` / `target.scan.completed` audit events (Appendix F).
    /// Artifact rows are keyed on the content-derived id and inserted
    /// idempotently, so re-persisting the same inventory is a no-op. Per-artifact
    /// delta events are deferred to the evidence-invalidation phase that consumes
    /// them, keeping the initial bulk scan to two audit records rather than one
    /// per file.
    pub async fn persist_inventory(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        inventory: &Inventory,
        now_ms: u64,
    ) -> Result<()> {
        let now = now_ms as i64;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;

        append_audit(&mut tx, scan_event(now_ms, "target.scan.started", None)).await?;

        for artifact in &inventory.artifacts {
            let artifact_id = artifact.artifact_id(revision_id);
            sqlx::query(
                "INSERT INTO artifacts \
                 (artifact_id, target_id, revision_id, logical_path, content_sha256, media_type, \
                  artifact_kind, source_of_truth, size_bytes, modified_at_ms, discovered_at_ms) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            )
            .bind(artifact_id.to_string())
            .bind(target_id.to_string())
            .bind(revision_id.to_string())
            .bind(&artifact.logical_path)
            .bind(&artifact.content_sha256)
            .bind(&artifact.media_type)
            .bind(artifact.artifact_kind.as_str())
            .bind(i64::from(artifact.source_of_truth))
            .bind(artifact.size_bytes as i64)
            .bind(artifact.modified_at_ms)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage("insert artifact"))?;
        }

        let s = &inventory.summary;
        let summary = format!(
            "scan complete: {} artifacts (+{} ~{} -{}), {} hashed",
            s.total, s.added, s.changed, s.removed, s.hashed
        );
        append_audit(
            &mut tx,
            scan_event(now_ms, "target.scan.completed", Some(summary)),
        )
        .await?;

        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }

    /// Loads a revision's persisted inventory as a [`PriorInventory`], the input
    /// the next scan carries unchanged files forward from.
    pub async fn load_inventory(&self, revision_id: &RevisionId) -> Result<PriorInventory> {
        let rows: Vec<ArtifactRow> = sqlx::query_as(
            "SELECT logical_path, content_sha256, media_type, artifact_kind, source_of_truth, \
             size_bytes, modified_at_ms FROM artifacts WHERE revision_id = ?",
        )
        .bind(revision_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load inventory"))?;

        rows.into_iter()
            .map(|row| Ok((row.logical_path.clone(), row.into_prior()?)))
            .collect()
    }

    /// Persists validated dependency edges for artifacts in one revision.
    /// Edges point from the dependent artifact to the artifact it consumes, as
    /// in Appendix E. Repeating the same set is idempotent.
    pub async fn persist_dependencies(
        &self,
        revision_id: &RevisionId,
        dependencies: &[ArtifactDependency],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let revision_exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM target_revisions WHERE revision_id = ?)",
        )
        .bind(revision_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("check dependency revision"))?;
        if revision_exists == 0 {
            return Err(Error::Corrupt(format!(
                "artifact dependencies reference unknown revision {revision_id}"
            )));
        }

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT logical_path, artifact_id FROM artifacts WHERE revision_id = ?")
                .bind(revision_id.to_string())
                .fetch_all(&mut *tx)
                .await
                .map_err(storage("load dependency artifacts"))?;
        let artifact_ids: HashMap<_, _> = rows.into_iter().collect();

        for dependency in dependencies {
            let from_id = artifact_ids
                .get(dependency.dependent_path())
                .ok_or_else(|| {
                    missing_dependency_artifact(revision_id, dependency.dependent_path())
                })?;
            let to_id = artifact_ids
                .get(dependency.dependency_path())
                .ok_or_else(|| {
                    missing_dependency_artifact(revision_id, dependency.dependency_path())
                })?;
            sqlx::query(
                "INSERT INTO artifact_dependencies \
                 (from_artifact_id, to_artifact_id, relation_kind) \
                 VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
            )
            .bind(from_id)
            .bind(to_id)
            .bind(dependency.relation_kind())
            .execute(&mut *tx)
            .await
            .map_err(storage("insert artifact dependency"))?;
        }

        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }

    /// Loads dependency edges for one revision using logical paths, ready to
    /// build a [`bar_discovery::dependency::DependencyGraph`].
    pub async fn load_dependencies(
        &self,
        revision_id: &RevisionId,
    ) -> Result<Vec<ArtifactDependency>> {
        let rows: Vec<DependencyRow> = sqlx::query_as(
            "SELECT dependent.logical_path AS dependent_path, \
                    dependency.logical_path AS dependency_path, edge.relation_kind \
             FROM artifact_dependencies edge \
             JOIN artifacts dependent ON dependent.artifact_id = edge.from_artifact_id \
             JOIN artifacts dependency ON dependency.artifact_id = edge.to_artifact_id \
             WHERE dependent.revision_id = ? AND dependency.revision_id = ? \
             ORDER BY dependent.logical_path, dependency.logical_path, edge.relation_kind",
        )
        .bind(revision_id.to_string())
        .bind(revision_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load artifact dependencies"))?;

        rows.into_iter()
            .map(|row| {
                ArtifactDependency::new(row.dependent_path, row.dependency_path, row.relation_kind)
            })
            .collect()
    }

    /// Persists source-bound shadow contract candidates idempotently. Every
    /// newly inserted contract and its source reference share one transaction
    /// with the `contract.extracted` audit event.
    pub async fn persist_contracts(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        claims: &[ExtractedClaim],
        now_ms: u64,
    ) -> Result<ContractPersistence> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let revision_exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM target_revisions \
             WHERE revision_id = ? AND target_id = ?)",
        )
        .bind(revision_id.to_string())
        .bind(target_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("check contract revision"))?;
        if revision_exists == 0 {
            return Err(Error::Corrupt(format!(
                "contracts reference unknown target revision {revision_id}"
            )));
        }

        let artifact_ids: Vec<String> =
            sqlx::query_scalar("SELECT artifact_id FROM artifacts WHERE revision_id = ?")
                .bind(revision_id.to_string())
                .fetch_all(&mut *tx)
                .await
                .map_err(storage("load contract artifacts"))?;
        let artifact_ids: std::collections::HashSet<_> = artifact_ids.into_iter().collect();
        let mut contract_ids = Vec::with_capacity(claims.len());
        let mut inserted = 0;

        for claim in claims {
            if !artifact_ids.contains(&claim.source.artifact_id.to_string()) {
                return Err(Error::Corrupt(format!(
                    "contract source {} does not belong to {revision_id}",
                    claim.source.artifact_id
                )));
            }
            let fingerprint = claim.fingerprint.to_string();
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT contract_id FROM contracts \
                 WHERE target_id = ? AND revision_id = ? AND fingerprint = ?",
            )
            .bind(target_id.to_string())
            .bind(revision_id.to_string())
            .bind(&fingerprint)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("lookup contract"))?;

            let contract_id = match existing {
                Some(id) => id.parse()?,
                None => {
                    let id = ContractId::generate();
                    sqlx::query(
                        "INSERT INTO contracts \
                         (contract_id, target_id, revision_id, parent_contract_id, level, \
                          normative_kind, statement, scope_json, confidence, freshness, status, \
                          fingerprint, created_at_ms, version) \
                         VALUES (?, ?, ?, NULL, ?, ?, ?, '{}', 'low', 'fresh', 'discovered', ?, ?, 1)",
                    )
                    .bind(id.to_string())
                    .bind(target_id.to_string())
                    .bind(revision_id.to_string())
                    .bind(claim.level.as_str())
                    .bind(claim.normative_kind.as_str())
                    .bind(&claim.statement)
                    .bind(&fingerprint)
                    .bind(now_ms as i64)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("insert contract"))?;

                    sqlx::query(
                        "INSERT INTO contract_sources \
                         (contract_id, artifact_id, start_offset, end_offset, exact_text_sha256) \
                         VALUES (?, ?, ?, ?, ?)",
                    )
                    .bind(id.to_string())
                    .bind(claim.source.artifact_id.to_string())
                    .bind(claim.source.start_offset as i64)
                    .bind(claim.source.end_offset as i64)
                    .bind(claim.source.exact_text_sha256.to_string())
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("insert contract source"))?;

                    append_audit(
                        &mut tx,
                        AuditEvent {
                            category: AuditCategory::EvidenceMutation,
                            actor: SYSTEM_ACTOR.to_string(),
                            summary: "extracted source-bound shadow contract".into(),
                            subject: Some(id.to_string()),
                            occurred_at_ms: now_ms,
                        },
                    )
                    .await?;
                    inserted += 1;
                    id
                }
            };
            contract_ids.push(contract_id);
        }

        tx.commit().await.map_err(storage("commit"))?;
        Ok(ContractPersistence {
            contract_ids,
            inserted,
        })
    }

    /// Reloads source-bound shadow contracts for a revision. Unknown persisted
    /// enum/status tokens are rejected rather than activated.
    pub async fn load_contracts(&self, revision_id: &RevisionId) -> Result<Vec<StoredContract>> {
        let rows: Vec<ContractRow> = sqlx::query_as(
            "SELECT c.contract_id, c.level, c.normative_kind, c.statement, c.fingerprint, \
                    c.confidence, c.freshness, c.status, s.artifact_id, s.start_offset, \
                    s.end_offset, s.exact_text_sha256 \
             FROM contracts c JOIN contract_sources s ON s.contract_id = c.contract_id \
             WHERE c.revision_id = ? ORDER BY c.contract_id, s.start_offset",
        )
        .bind(revision_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load contracts"))?;
        rows.into_iter().map(ContractRow::into_contract).collect()
    }
}

fn missing_dependency_artifact(revision_id: &RevisionId, path: &str) -> Error {
    Error::Corrupt(format!(
        "artifact dependency references missing path `{path}` in {revision_id}"
    ))
}

/// Builds a scan-level audit event.
fn scan_event(now_ms: u64, kind: &str, detail: Option<String>) -> AuditEvent {
    AuditEvent {
        category: AuditCategory::LifecycleTransition,
        actor: SYSTEM_ACTOR.to_string(),
        summary: detail.unwrap_or_else(|| kind.to_string()),
        subject: Some(kind.to_string()),
        occurred_at_ms: now_ms,
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

/// Result of an idempotent contract-persistence call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractPersistence {
    pub contract_ids: Vec<ContractId>,
    pub inserted: usize,
}

/// One persisted shadow contract with its mandatory source binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredContract {
    pub contract_id: ContractId,
    pub claim: ExtractedClaim,
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

/// One `artifacts` row at the DB boundary (the subset needed to reconstruct a
/// [`PriorArtifact`] for carry-forward).
#[derive(FromRow)]
struct ArtifactRow {
    logical_path: String,
    content_sha256: String,
    media_type: String,
    artifact_kind: String,
    source_of_truth: i64,
    size_bytes: i64,
    modified_at_ms: Option<i64>,
}

#[derive(FromRow)]
struct DependencyRow {
    dependent_path: String,
    dependency_path: String,
    relation_kind: String,
}

#[derive(FromRow)]
struct ContractRow {
    contract_id: String,
    level: String,
    normative_kind: String,
    statement: String,
    fingerprint: String,
    confidence: String,
    freshness: String,
    status: String,
    artifact_id: String,
    start_offset: i64,
    end_offset: i64,
    exact_text_sha256: String,
}

impl ContractRow {
    fn into_contract(self) -> Result<StoredContract> {
        if self.confidence != "low" || self.freshness != "fresh" || self.status != "discovered" {
            return Err(Error::Corrupt(format!(
                "unknown shadow contract state: confidence={}, freshness={}, status={}",
                self.confidence, self.freshness, self.status
            )));
        }
        let level = ContractLevel::VARIANTS
            .iter()
            .copied()
            .find(|value| value.as_str() == self.level)
            .ok_or_else(|| Error::Corrupt(format!("unknown contract level `{}`", self.level)))?;
        let normative_kind = NormativeKind::VARIANTS
            .iter()
            .copied()
            .find(|value| value.as_str() == self.normative_kind)
            .ok_or_else(|| {
                Error::Corrupt(format!(
                    "unknown contract normative kind `{}`",
                    self.normative_kind
                ))
            })?;
        let start_offset = usize::try_from(self.start_offset)
            .map_err(|_| Error::Corrupt("negative contract source start offset".into()))?;
        let end_offset = usize::try_from(self.end_offset)
            .map_err(|_| Error::Corrupt("negative contract source end offset".into()))?;
        if start_offset >= end_offset {
            return Err(Error::Corrupt(
                "invalid persisted contract source span".into(),
            ));
        }
        Ok(StoredContract {
            contract_id: self.contract_id.parse()?,
            claim: ExtractedClaim {
                normative_kind,
                level,
                statement: self.statement,
                source: SourceRef {
                    artifact_id: self.artifact_id.parse()?,
                    start_offset,
                    end_offset,
                    exact_text_sha256: self.exact_text_sha256.parse()?,
                },
                fingerprint: self.fingerprint.parse()?,
            },
        })
    }
}

impl ArtifactRow {
    fn into_prior(self) -> Result<PriorArtifact> {
        Ok(PriorArtifact {
            content_sha256: self.content_sha256,
            media_type: self.media_type,
            artifact_kind: ArtifactKind::from_token(&self.artifact_kind)?,
            source_of_truth: self.source_of_truth != 0,
            size_bytes: self.size_bytes as u64,
            modified_at_ms: self.modified_at_ms,
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

    // --- Phase 2: artifact inventory ---

    fn tree_target(root: &std::path::Path) -> ResolvedTarget {
        ResolvedTarget {
            name: "app".into(),
            root_locator: root.to_path_buf(),
            connector_kind: ConnectorKind::Filesystem,
            revision: RevisionIdentity::unbound(),
        }
    }

    fn write_file(root: &std::path::Path, rel: &str, content: &[u8]) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn revision(commit: &str, dirty: Option<&str>) -> RevisionIdentity {
        RevisionIdentity {
            source_commit: Some(commit.into()),
            dirty_hash: dirty.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn inventory_persists_reloads_and_audits_the_scan() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        write_file(&root, "src/main.rs", b"fn main() {}");
        write_file(&root, "README.md", b"# hi");

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let rev_id = store
            .record_revision(&target_id, &revision("c1", None), T0)
            .await
            .unwrap()
            .revision_id;

        let inv = bar_discovery::scan(
            &root,
            &bar_discovery::ScanConfig::default(),
            &PriorInventory::new(),
        )
        .unwrap();
        store
            .persist_inventory(&target_id, &rev_id, &inv, T0)
            .await
            .unwrap();

        let loaded = store.load_inventory(&rev_id).await.unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded["src/main.rs"].artifact_kind, ArtifactKind::Code);

        // Re-persisting the same inventory is idempotent (no duplicate rows).
        store
            .persist_inventory(&target_id, &rev_id, &inv, T0)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM artifacts")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 2);

        // register + record + two scans (each: started + completed) = 6 events.
        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(chain.len(), 6);
    }

    #[tokio::test]
    async fn incremental_rescan_through_store_rehashes_only_the_changed_file() {
        // The Phase-2 exit criterion, end to end: the prior inventory is loaded
        // back from the database and drives carry-forward.
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        for i in 0..4 {
            write_file(&root, &format!("f{i}.txt"), format!("v0-{i}").as_bytes());
        }

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let cfg = bar_discovery::ScanConfig::default();

        let r1 = store
            .record_revision(&target_id, &revision("c", None), T0)
            .await
            .unwrap()
            .revision_id;
        let inv1 = bar_discovery::scan(&root, &cfg, &PriorInventory::new()).unwrap();
        assert_eq!(inv1.summary.hashed, 4);
        store
            .persist_inventory(&target_id, &r1, &inv1, T0)
            .await
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1100));
        write_file(&root, "f1.txt", b"changed-content");

        let r2 = store
            .record_revision(&target_id, &revision("c", Some("dirty")), T0 + 1)
            .await
            .unwrap()
            .revision_id;
        assert_ne!(r1, r2);

        let prior = store.load_inventory(&r1).await.unwrap();
        let inv2 = bar_discovery::scan(&root, &cfg, &prior).unwrap();
        assert_eq!(inv2.summary.hashed, 1, "only the changed file is read");
        assert_eq!(inv2.summary.changed, 1);
        assert_eq!(inv2.summary.unchanged, 3);

        store
            .persist_inventory(&target_id, &r2, &inv2, T0 + 1)
            .await
            .unwrap();
        assert_eq!(store.load_inventory(&r2).await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn persisted_dependencies_select_only_changed_artifact_and_dependents() {
        use bar_discovery::dependency::{ArtifactDependency, DependencyGraph};

        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        write_file(&root, "schema/api.json", br#"{"version":1}"#);
        write_file(&root, "src/service.rs", b"service");
        write_file(&root, "src/api.rs", b"api");
        write_file(&root, "src/unrelated.rs", b"unrelated");

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let r1 = store
            .record_revision(&target_id, &revision("c", None), T0)
            .await
            .unwrap()
            .revision_id;
        let cfg = bar_discovery::ScanConfig::default();
        let first = bar_discovery::scan(&root, &cfg, &PriorInventory::new()).unwrap();
        store
            .persist_inventory(&target_id, &r1, &first, T0)
            .await
            .unwrap();

        let dependencies = vec![
            ArtifactDependency::new("src/api.rs", "src/service.rs", "imports").unwrap(),
            ArtifactDependency::new("src/service.rs", "schema/api.json", "reads").unwrap(),
        ];
        store
            .persist_dependencies(&r1, &dependencies)
            .await
            .unwrap();
        store
            .persist_dependencies(&r1, &dependencies)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM artifact_dependencies")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 2, "repeated edge persistence is idempotent");

        std::thread::sleep(std::time::Duration::from_millis(1100));
        write_file(&root, "schema/api.json", br#"{"version":2}"#);
        let prior = store.load_inventory(&r1).await.unwrap();
        let second = bar_discovery::scan(&root, &cfg, &prior).unwrap();
        assert_eq!(second.summary.hashed, 1);
        assert_eq!(second.invalidated_paths, ["schema/api.json"]);

        let loaded = store.load_dependencies(&r1).await.unwrap();
        assert_eq!(loaded, dependencies);
        let plan = DependencyGraph::from_edges(&loaded)
            .reparse_plan(second.invalidated_paths.iter().map(String::as_str));
        assert_eq!(
            plan.paths(),
            ["schema/api.json", "src/api.rs", "src/service.rs"]
        );
        assert!(!plan.paths().iter().any(|p| p == "src/unrelated.rs"));
    }

    #[tokio::test]
    async fn dependency_persistence_rolls_back_on_missing_endpoint() {
        use bar_discovery::dependency::ArtifactDependency;

        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        write_file(&root, "a.rs", b"a");
        write_file(&root, "b.rs", b"b");

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("c", None), T0)
            .await
            .unwrap()
            .revision_id;
        let inventory = bar_discovery::scan(
            &root,
            &bar_discovery::ScanConfig::default(),
            &PriorInventory::new(),
        )
        .unwrap();
        store
            .persist_inventory(&target_id, &revision_id, &inventory, T0)
            .await
            .unwrap();

        let dependencies = [
            ArtifactDependency::new("a.rs", "b.rs", "imports").unwrap(),
            ArtifactDependency::new("a.rs", "missing.rs", "imports").unwrap(),
        ];
        assert!(store
            .persist_dependencies(&revision_id, &dependencies)
            .await
            .is_err());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM artifact_dependencies")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "the partial graph transaction rolled back");
    }

    #[tokio::test]
    async fn source_bound_contracts_persist_idempotently_and_reload() {
        use bar_contract::{extract_deterministic, ArtifactText};

        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let text = "All effects MUST pass through the dispatcher.\nThe daemon MUST NOT deploy.";
        write_file(&root, "README.md", text.as_bytes());

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("c", None), T0)
            .await
            .unwrap()
            .revision_id;
        let inventory = bar_discovery::scan(
            &root,
            &bar_discovery::ScanConfig::default(),
            &PriorInventory::new(),
        )
        .unwrap();
        store
            .persist_inventory(&target_id, &revision_id, &inventory, T0)
            .await
            .unwrap();
        let artifact = &inventory.artifacts[0];
        let source = ArtifactText::new(
            artifact.artifact_id(&revision_id),
            &artifact.logical_path,
            artifact.content_sha256.parse().unwrap(),
            text,
        )
        .unwrap();
        let claims = extract_deterministic(&source).unwrap();
        assert_eq!(claims.len(), 2);

        let first = store
            .persist_contracts(&target_id, &revision_id, &claims, T0 + 1)
            .await
            .unwrap();
        let replay = store
            .persist_contracts(&target_id, &revision_id, &claims, T0 + 2)
            .await
            .unwrap();
        assert_eq!(first.inserted, 2);
        assert_eq!(replay.inserted, 0);
        assert_eq!(first.contract_ids, replay.contract_ids);

        let mut loaded = store.load_contracts(&revision_id).await.unwrap();
        loaded.sort_by_key(|contract| contract.claim.source.start_offset);
        assert_eq!(
            loaded
                .iter()
                .map(|contract| contract.claim.clone())
                .collect::<Vec<_>>(),
            claims
        );
        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(chain.len(), 6, "replay emits no duplicate contract events");

        sqlx::query(
            "UPDATE contracts SET normative_kind = 'unknown' \
             WHERE contract_id = (SELECT contract_id FROM contracts LIMIT 1)",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(store.load_contracts(&revision_id).await.is_err());
    }

    #[tokio::test]
    async fn contract_persistence_rolls_back_when_any_source_is_missing() {
        use bar_contract::{extract_deterministic, ArtifactText};

        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let text = "The daemon MUST remain model-optional.";
        write_file(&root, "README.md", text.as_bytes());
        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("c", None), T0)
            .await
            .unwrap()
            .revision_id;
        let inventory = bar_discovery::scan(
            &root,
            &bar_discovery::ScanConfig::default(),
            &PriorInventory::new(),
        )
        .unwrap();
        store
            .persist_inventory(&target_id, &revision_id, &inventory, T0)
            .await
            .unwrap();
        let artifact = &inventory.artifacts[0];
        let source = ArtifactText::new(
            artifact.artifact_id(&revision_id),
            &artifact.logical_path,
            artifact.content_sha256.parse().unwrap(),
            text,
        )
        .unwrap();
        let valid = extract_deterministic(&source).unwrap().remove(0);
        let mut missing = valid.clone();
        missing.source.artifact_id =
            bar_core::ArtifactId::from_digest(Sha256Digest::from_bytes([9; 32]));

        assert!(store
            .persist_contracts(&target_id, &revision_id, &[valid, missing], T0 + 1)
            .await
            .is_err());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contracts")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "the partial contract transaction rolled back");
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
