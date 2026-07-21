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
use bar_contract::scope::{validate_declaration, ContractScope, TemporalWindow};
use bar_contract::{
    glossary_ambiguities, validate_extracted_claim, ConflictCandidate, CorpusAnalysis,
    ExtractedClaim, GlossaryAmbiguityCandidate, GlossaryCandidate, HierarchyCandidate, SourceRef,
};
use bar_core::{
    ContractId, ContractLevel, Error, NormativeKind, Result, RevisionId, Sha256Digest, TargetId,
};
use bar_discovery::dependency::{validate_logical_path, ArtifactDependency};
use bar_discovery::{ArtifactKind, DiscoveredArtifact, Inventory, PriorArtifact, PriorInventory};
use bar_target::{ConnectorKind, ResolvedTarget, RevisionIdentity, TargetStatus};
use sqlx::sqlite::{Sqlite, SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::{FromRow, Transaction};

mod attestation;
mod context_resolution;
mod proof_obligations;
mod ruling;
mod scope_context;
mod static_facts;
mod static_findings;
mod traceability;

pub use attestation::{ScopeContextAttestationPersistence, StoredScopeContextAttestation};
pub use proof_obligations::{
    ProofObligationPersistence, StoredProofAssessment, StoredProofObligation,
};
pub use ruling::{RulingPersistence, StoredContractRuling};
pub use scope_context::{ScopeContextPersistence, StoredScopeContextEvidence};
pub use static_facts::{StaticBatchPersistence, StaticFactsPersistence, StoredStaticFacts};
pub use static_findings::{
    StaticFindingCandidateBatchPersistence, StaticFindingCandidatePersistence,
    StaticFindingPromotion, StoredStaticFinding, StoredStaticFindingCandidate,
};
pub use traceability::StoredContractTraceability;

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
        let seq = required_sqlite_u64(record.seq, "audit sequence")?;
        let occurred_at = required_sqlite_u64(record.event.occurred_at_ms, "audit timestamp")?;
        sqlx::query(
            "INSERT INTO audit_log \
             (seq, prev_hash, category, actor, summary, subject, occurred_at_ms, hash) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(seq)
        .bind(record.prev_hash.to_string())
        .bind(record.event.category.as_str())
        .bind(&record.event.actor)
        .bind(&record.event.summary)
        .bind(record.event.subject.as_deref())
        .bind(occurred_at)
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
        let now = required_sqlite_u64(now_ms, "target timestamp")?;
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
        let now = required_sqlite_u64(now_ms, "revision timestamp")?;
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
        let now = required_sqlite_u64(now_ms, "inventory timestamp")?;
        for artifact in &inventory.artifacts {
            validate_logical_path(&artifact.logical_path)?;
            if artifact.modified_at_ms.is_some_and(|value| value < 0) {
                return Err(Error::Corrupt(
                    "artifact modification timestamp is negative".into(),
                ));
            }
            required_sqlite_u64(artifact.size_bytes, "artifact size")?;
            if artifact.content_sha256 != bar_discovery::UNHASHED_OVERSIZED {
                Sha256Digest::from_str(&artifact.content_sha256)?;
            }
        }
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;

        let revision_exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM target_revisions \
             WHERE revision_id = ? AND target_id = ?)",
        )
        .bind(revision_id.to_string())
        .bind(target_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("check inventory revision"))?;
        if revision_exists == 0 {
            return Err(Error::Corrupt(format!(
                "inventory references revision {revision_id} outside target {target_id}"
            )));
        }

        append_audit(
            &mut tx,
            scan_event(target_id, now_ms, "target.scan.started", None),
        )
        .await?;

        for artifact in &inventory.artifacts {
            let artifact_id = artifact.artifact_id(revision_id);
            let size_bytes = required_sqlite_u64(artifact.size_bytes, "artifact size")?;
            let inserted = sqlx::query(
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
            .bind(size_bytes)
            .bind(artifact.modified_at_ms)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage("insert artifact"))?
            .rows_affected();
            if inserted == 0 {
                let persisted: Option<PersistedArtifactRow> = sqlx::query_as(
                    "SELECT target_id, revision_id, content_sha256, media_type, artifact_kind, \
                            source_of_truth, size_bytes, modified_at_ms \
                     FROM artifacts WHERE revision_id = ? AND logical_path = ?",
                )
                .bind(revision_id.to_string())
                .bind(&artifact.logical_path)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage("load persisted artifact"))?;
                let matches_submission = persisted.is_some_and(|persisted| {
                    persisted.matches_submission(target_id, revision_id, artifact, size_bytes)
                });
                if !matches_submission {
                    return Err(Error::Corrupt(format!(
                        "persisted artifact {} does not match inventory submission",
                        artifact.logical_path
                    )));
                }
            }
        }

        let s = &inventory.summary;
        let summary = format!(
            "scan complete: {} artifacts (+{} ~{} -{}), {} hashed",
            s.total, s.added, s.changed, s.removed, s.hashed
        );
        append_audit(
            &mut tx,
            scan_event(target_id, now_ms, "target.scan.completed", Some(summary)),
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
    /// with its audited evidence mutation.
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
            validate_extracted_claim(claim)?;
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
                    .bind(required_sqlite_u64(now_ms, "contract timestamp")?)
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
                    .bind(required_sqlite_usize(
                        claim.source.start_offset,
                        "contract source start",
                    )?)
                    .bind(required_sqlite_usize(
                        claim.source.end_offset,
                        "contract source end",
                    )?)
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

        let persistence = ContractPersistence {
            contract_ids,
            inserted,
        };
        tx.commit().await.map_err(storage("commit"))?;
        let stored = self.load_contracts(revision_id).await?;
        for (contract_id, claim) in persistence.contract_ids.iter().zip(claims) {
            let matches_claim = stored
                .iter()
                .any(|contract| contract.contract_id == *contract_id && contract.claim == *claim);
            if !matches_claim {
                return Err(Error::Corrupt(format!(
                    "persisted contract {contract_id} does not match its source-bound claim"
                )));
            }
        }
        Ok(persistence)
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

    /// Loads source-bound shadow contracts for exactly one target revision.
    /// Traceability uses this stricter form so identical content-derived
    /// revision identifiers cannot cross a target boundary.
    pub async fn load_contracts_for_target(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
    ) -> Result<Vec<StoredContract>> {
        let rows: Vec<ContractRow> = sqlx::query_as(
            "SELECT c.contract_id, c.level, c.normative_kind, c.statement, c.fingerprint, \
                    c.confidence, c.freshness, c.status, s.artifact_id, s.start_offset, \
                    s.end_offset, s.exact_text_sha256 \
             FROM contracts c JOIN contract_sources s ON s.contract_id = c.contract_id \
             WHERE c.target_id = ? AND c.revision_id = ? ORDER BY c.contract_id, s.start_offset",
        )
        .bind(target_id.to_string())
        .bind(revision_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load target contracts"))?;
        rows.into_iter().map(ContractRow::into_contract).collect()
    }

    /// Assigns a contract's scope and validity exactly once and records any
    /// same-target contracts it supersedes. Exact replay is a no-op; a changed
    /// declaration or invalid edge rolls back the complete transaction.
    pub async fn assign_contract_resolution(
        &self,
        contract_id: &ContractId,
        scope: &ContractScope,
        valid_from_ms: Option<u64>,
        valid_until_ms: Option<u64>,
        supersedes: &[ContractId],
        now_ms: u64,
    ) -> Result<ContractResolutionPersistence> {
        validate_declaration(scope, valid_from_ms, valid_until_ms)?;
        let valid_from = sqlite_timestamp(valid_from_ms)?;
        let valid_until = sqlite_timestamp(valid_until_ms)?;
        let now = i64::try_from(now_ms)
            .map_err(|_| Error::Corrupt("timestamp exceeds SQLite integer range".into()))?;
        let scope_json = serde_json::to_string(scope)
            .map_err(|e| Error::Corrupt(format!("serialize contract scope: {e}")))?;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;

        let row: Option<ContractResolutionRow> = sqlx::query_as(
            "SELECT target_id, scope_resolved, scope_json, valid_from_ms, valid_until_ms \
             FROM contracts WHERE contract_id = ?",
        )
        .bind(contract_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("load contract resolution"))?;
        let row = row.ok_or_else(|| {
            Error::Corrupt(format!("scope references unknown contract {contract_id}"))
        })?;

        for superseded in supersedes {
            if superseded == contract_id {
                return Err(Error::Corrupt("a contract cannot supersede itself".into()));
            }
            let target: Option<String> =
                sqlx::query_scalar("SELECT target_id FROM contracts WHERE contract_id = ?")
                    .bind(superseded.to_string())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(storage("load superseded contract"))?;
            if target.as_deref() != Some(row.target_id.as_str()) {
                return Err(Error::Corrupt(format!(
                    "superseded contract {superseded} is missing or belongs to another target"
                )));
            }
        }

        let scope_assigned = match row.scope_resolved {
            0 => {
                sqlx::query(
                    "UPDATE contracts SET scope_json = ?, valid_from_ms = ?, valid_until_ms = ?, \
                     scope_resolved = 1, version = version + 1 WHERE contract_id = ?",
                )
                .bind(&scope_json)
                .bind(valid_from)
                .bind(valid_until)
                .bind(contract_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(storage("assign contract resolution"))?;
                append_audit(
                    &mut tx,
                    AuditEvent {
                        category: AuditCategory::EvidenceMutation,
                        actor: SYSTEM_ACTOR.to_string(),
                        summary: "assigned shadow contract scope and validity".into(),
                        subject: Some(contract_id.to_string()),
                        occurred_at_ms: now_ms,
                    },
                )
                .await?;
                true
            }
            1 => {
                let stored_scope: ContractScope =
                    serde_json::from_str(&row.scope_json).map_err(|e| {
                        Error::Corrupt(format!("invalid persisted contract scope: {e}"))
                    })?;
                validate_declaration(
                    &stored_scope,
                    stored_timestamp(row.valid_from_ms)?,
                    stored_timestamp(row.valid_until_ms)?,
                )?;
                if stored_scope != *scope
                    || row.valid_from_ms != valid_from
                    || row.valid_until_ms != valid_until
                {
                    return Err(Error::Conflict(format!(
                        "contract {contract_id} already has a different scope or validity"
                    )));
                }
                false
            }
            other => {
                return Err(Error::Corrupt(format!(
                    "unknown contract scope state `{other}`"
                )))
            }
        };

        let mut supersessions_inserted = 0;
        for superseded in supersedes {
            let result = sqlx::query(
                "INSERT INTO contract_supersessions \
                 (superseding_contract_id, superseded_contract_id, created_at_ms) \
                 VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
            )
            .bind(contract_id.to_string())
            .bind(superseded.to_string())
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage("insert contract supersession"))?;
            if result.rows_affected() == 1 {
                append_audit(
                    &mut tx,
                    AuditEvent {
                        category: AuditCategory::EvidenceMutation,
                        actor: SYSTEM_ACTOR.to_string(),
                        summary: format!("recorded shadow contract supersession of {superseded}"),
                        subject: Some(contract_id.to_string()),
                        occurred_at_ms: now_ms,
                    },
                )
                .await?;
                supersessions_inserted += 1;
            }
        }
        let persistence = ContractResolutionPersistence {
            scope_assigned,
            supersessions_inserted,
        };
        tx.commit().await.map_err(storage("commit"))?;
        self.load_contract_resolution(contract_id).await?;
        Ok(persistence)
    }

    /// Reloads the immutable resolution inputs for one contract. Superseded
    /// state is derived from incoming edges and malformed storage fails closed.
    pub async fn load_contract_resolution(
        &self,
        contract_id: &ContractId,
    ) -> Result<StoredContractResolution> {
        let row: Option<ContractResolutionRow> = sqlx::query_as(
            "SELECT target_id, scope_resolved, scope_json, valid_from_ms, valid_until_ms \
             FROM contracts WHERE contract_id = ?",
        )
        .bind(contract_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("load contract resolution"))?;
        let row = row.ok_or_else(|| Error::Corrupt(format!("unknown contract {contract_id}")))?;
        if row.scope_resolved != 1 {
            return Err(Error::Corrupt(format!(
                "contract {contract_id} has no resolved scope"
            )));
        }
        let target_id: TargetId = row.target_id.parse()?;
        let target_key = target_id.to_string();
        let scope: ContractScope = serde_json::from_str(&row.scope_json)
            .map_err(|e| Error::Corrupt(format!("invalid persisted contract scope: {e}")))?;
        let valid_from_ms = stored_timestamp(row.valid_from_ms)?;
        let valid_until_ms = stored_timestamp(row.valid_until_ms)?;
        validate_declaration(&scope, valid_from_ms, valid_until_ms)?;
        let incoming: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT s.superseding_contract_id, c.target_id \
             FROM contract_supersessions s \
             LEFT JOIN contracts c ON c.contract_id = s.superseding_contract_id \
             WHERE s.superseded_contract_id = ?",
        )
        .bind(contract_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load incoming supersessions"))?;
        let outgoing: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT s.superseded_contract_id, c.target_id \
             FROM contract_supersessions s \
             LEFT JOIN contracts c ON c.contract_id = s.superseded_contract_id \
             WHERE s.superseding_contract_id = ? ORDER BY s.superseded_contract_id",
        )
        .bind(contract_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load outgoing supersessions"))?;
        for (linked_contract_id, linked_target) in incoming.iter().chain(outgoing.iter()) {
            if linked_target.as_deref() != Some(target_key.as_str()) {
                return Err(Error::Corrupt(format!(
                    "contract supersession {contract_id} crosses target boundary at {linked_contract_id}"
                )));
            }
        }
        Ok(StoredContractResolution {
            contract_id: *contract_id,
            scope,
            temporal: TemporalWindow {
                valid_from_ms,
                valid_until_ms,
                superseded: !incoming.is_empty(),
            },
            supersedes: outgoing
                .into_iter()
                .map(|(id, _)| id.parse())
                .collect::<Result<Vec<_>>>()?,
        })
    }

    /// Persists structural hierarchy, glossary, and conflict candidates after
    /// their claim fingerprints have been resolved to contracts. The complete
    /// candidate set is validated before any row is written.
    pub async fn persist_analysis_candidates(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        analysis: &CorpusAnalysis,
        now_ms: u64,
    ) -> Result<CandidatePersistence> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let revision_exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM target_revisions \
             WHERE revision_id = ? AND target_id = ?)",
        )
        .bind(revision_id.to_string())
        .bind(target_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("check candidate revision"))?;
        if revision_exists == 0 {
            return Err(Error::Corrupt(format!(
                "analysis candidates reference unknown target revision {revision_id}"
            )));
        }

        let artifacts: Vec<String> =
            sqlx::query_scalar("SELECT artifact_id FROM artifacts WHERE revision_id = ?")
                .bind(revision_id.to_string())
                .fetch_all(&mut *tx)
                .await
                .map_err(storage("load candidate artifacts"))?;
        let artifacts: std::collections::HashSet<_> = artifacts.into_iter().collect();
        let contracts: Vec<(String, String)> =
            sqlx::query_as("SELECT fingerprint, contract_id FROM contracts WHERE revision_id = ?")
                .bind(revision_id.to_string())
                .fetch_all(&mut *tx)
                .await
                .map_err(storage("load candidate contracts"))?;
        let contracts: HashMap<_, _> = contracts.into_iter().collect();

        for candidate in &analysis.hierarchy {
            require_contract(&contracts, &candidate.child_fingerprint)?;
            require_source_artifact(&artifacts, revision_id, &candidate.source)?;
        }
        for candidate in &analysis.glossary {
            require_source_artifact(&artifacts, revision_id, &candidate.source)?;
        }
        for candidate in &analysis.conflicts {
            require_contract(&contracts, &candidate.left_fingerprint)?;
            require_contract(&contracts, &candidate.right_fingerprint)?;
        }

        let mut result = CandidatePersistence::default();
        for candidate in &analysis.hierarchy {
            let contract_id = require_contract(&contracts, &candidate.child_fingerprint)?;
            let inserted = sqlx::query(
                "INSERT INTO contract_hierarchy_candidates \
                 (child_contract_id, heading, heading_level, artifact_id, start_offset, \
                  end_offset, exact_text_sha256) VALUES (?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(contract_id)
            .bind(&candidate.heading)
            .bind(i64::from(candidate.heading_level))
            .bind(candidate.source.artifact_id.to_string())
            .bind(required_sqlite_usize(
                candidate.source.start_offset,
                "hierarchy source start",
            )?)
            .bind(required_sqlite_usize(
                candidate.source.end_offset,
                "hierarchy source end",
            )?)
            .bind(candidate.source.exact_text_sha256.to_string())
            .execute(&mut *tx)
            .await
            .map_err(storage("insert hierarchy candidate"))?
            .rows_affected();
            result.hierarchy_inserted += inserted as usize;
        }
        for candidate in &analysis.glossary {
            let aliases = serde_json::to_string(&candidate.aliases)
                .map_err(|e| Error::Corrupt(format!("encode glossary aliases: {e}")))?;
            let inserted = sqlx::query(
                "INSERT INTO glossary_candidates \
                 (fingerprint, target_id, revision_id, canonical, normalized_term, definition, \
                  aliases_json, artifact_id, start_offset, end_offset, exact_text_sha256) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            )
            .bind(candidate.fingerprint.to_string())
            .bind(target_id.to_string())
            .bind(revision_id.to_string())
            .bind(&candidate.canonical)
            .bind(candidate.canonical.to_lowercase())
            .bind(&candidate.definition)
            .bind(aliases)
            .bind(candidate.source.artifact_id.to_string())
            .bind(required_sqlite_usize(
                candidate.source.start_offset,
                "glossary source start",
            )?)
            .bind(required_sqlite_usize(
                candidate.source.end_offset,
                "glossary source end",
            )?)
            .bind(candidate.source.exact_text_sha256.to_string())
            .execute(&mut *tx)
            .await
            .map_err(storage("insert glossary candidate"))?
            .rows_affected();
            result.glossary_inserted += inserted as usize;
        }
        for candidate in &analysis.conflicts {
            let left = require_contract(&contracts, &candidate.left_fingerprint)?;
            let right = require_contract(&contracts, &candidate.right_fingerprint)?;
            let (left, right) = if left <= right {
                (left, right)
            } else {
                (right, left)
            };
            let inserted = sqlx::query(
                "INSERT INTO contract_conflict_candidates \
                 (left_contract_id, right_contract_id, shared_subject, status) \
                 VALUES (?, ?, ?, 'candidate') ON CONFLICT DO NOTHING",
            )
            .bind(left)
            .bind(right)
            .bind(&candidate.shared_subject)
            .execute(&mut *tx)
            .await
            .map_err(storage("insert conflict candidate"))?
            .rows_affected();
            result.conflicts_inserted += inserted as usize;
            if inserted > 0 {
                append_audit(
                    &mut tx,
                    AuditEvent {
                        category: AuditCategory::EvidenceMutation,
                        actor: SYSTEM_ACTOR.to_string(),
                        summary: "detected provisional contract conflict".into(),
                        subject: Some(format!("{left} <> {right}")),
                        occurred_at_ms: now_ms,
                    },
                )
                .await?;
            }
        }

        tx.commit().await.map_err(storage("commit"))?;
        let stored = self.load_analysis_candidates(revision_id).await?;
        if stored.hierarchy != analysis.hierarchy
            || stored.glossary != analysis.glossary
            || stored.glossary_ambiguities != analysis.glossary_ambiguities
            || stored.conflicts != analysis.conflicts
        {
            return Err(Error::Corrupt(
                "persisted analysis candidates do not match submission".into(),
            ));
        }
        Ok(result)
    }

    /// Reloads persisted Phase 3 candidates. Corrupt JSON, spans, hashes, or
    /// candidate states are rejected rather than exposed for review.
    pub async fn load_analysis_candidates(
        &self,
        revision_id: &RevisionId,
    ) -> Result<StoredAnalysisCandidates> {
        let hierarchy_rows: Vec<HierarchyRow> = sqlx::query_as(
            "SELECT c.fingerprint AS child_fingerprint, h.heading, h.heading_level, \
                    h.artifact_id, h.start_offset, h.end_offset, h.exact_text_sha256 \
             FROM contract_hierarchy_candidates h \
             JOIN contracts c ON c.contract_id = h.child_contract_id \
             WHERE c.revision_id = ? ORDER BY c.fingerprint, h.start_offset",
        )
        .bind(revision_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load hierarchy candidates"))?;
        let glossary_rows: Vec<GlossaryRow> = sqlx::query_as(
            "SELECT fingerprint, canonical, definition, aliases_json, artifact_id, \
                    start_offset, end_offset, exact_text_sha256 \
             FROM glossary_candidates WHERE revision_id = ? ORDER BY fingerprint",
        )
        .bind(revision_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load glossary candidates"))?;
        let conflict_rows: Vec<ConflictRow> = sqlx::query_as(
            "SELECT left_contract.fingerprint AS left_fingerprint, \
                    right_contract.fingerprint AS right_fingerprint, \
                    candidate.shared_subject, candidate.status \
             FROM contract_conflict_candidates candidate \
             JOIN contracts left_contract ON left_contract.contract_id = candidate.left_contract_id \
             JOIN contracts right_contract ON right_contract.contract_id = candidate.right_contract_id \
             WHERE left_contract.revision_id = ? AND right_contract.revision_id = ? \
             ORDER BY left_contract.fingerprint, right_contract.fingerprint",
        )
        .bind(revision_id.to_string())
        .bind(revision_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("load conflict candidates"))?;

        let glossary = glossary_rows
            .into_iter()
            .map(GlossaryRow::into_candidate)
            .collect::<Result<Vec<_>>>()?;
        let glossary_ambiguities = glossary_ambiguities(&glossary);
        Ok(StoredAnalysisCandidates {
            hierarchy: hierarchy_rows
                .into_iter()
                .map(HierarchyRow::into_candidate)
                .collect::<Result<_>>()?,
            glossary,
            glossary_ambiguities,
            conflicts: conflict_rows
                .into_iter()
                .map(ConflictRow::into_candidate)
                .collect::<Result<_>>()?,
        })
    }
}

fn require_contract<'a>(
    contracts: &'a HashMap<String, String>,
    fingerprint: &Sha256Digest,
) -> Result<&'a str> {
    contracts
        .get(&fingerprint.to_string())
        .map(String::as_str)
        .ok_or_else(|| Error::Corrupt(format!("candidate references unknown claim {fingerprint}")))
}

fn require_source_artifact(
    artifacts: &std::collections::HashSet<String>,
    revision_id: &RevisionId,
    source: &SourceRef,
) -> Result<()> {
    if artifacts.contains(&source.artifact_id.to_string()) {
        Ok(())
    } else {
        Err(Error::Corrupt(format!(
            "candidate source {} does not belong to {revision_id}",
            source.artifact_id
        )))
    }
}

fn missing_dependency_artifact(revision_id: &RevisionId, path: &str) -> Error {
    Error::Corrupt(format!(
        "artifact dependency references missing path `{path}` in {revision_id}"
    ))
}

/// Builds a scan-level audit event.
fn scan_event(target_id: &TargetId, now_ms: u64, kind: &str, detail: Option<String>) -> AuditEvent {
    AuditEvent {
        category: AuditCategory::LifecycleTransition,
        actor: SYSTEM_ACTOR.to_string(),
        summary: detail.unwrap_or_else(|| kind.to_string()),
        subject: Some(target_id.to_string()),
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
        Some((seq, hash)) => (
            u64::try_from(seq)
                .map_err(|_| Error::Corrupt("negative audit sequence".into()))?
                .checked_add(1)
                .ok_or_else(|| Error::Corrupt("audit sequence overflow".into()))?,
            Sha256Digest::from_str(&hash)?,
        ),
        None => (0, GENESIS),
    };
    let hash = record_hash(seq, &prev_hash, &event);

    sqlx::query(
        "INSERT INTO audit_log \
         (seq, prev_hash, category, actor, summary, subject, occurred_at_ms, hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(required_sqlite_u64(seq, "audit sequence")?)
    .bind(prev_hash.to_string())
    .bind(event.category.as_str())
    .bind(&event.actor)
    .bind(&event.summary)
    .bind(event.subject.as_deref())
    .bind(required_sqlite_u64(
        event.occurred_at_ms,
        "audit timestamp",
    )?)
    .bind(hash.to_string())
    .execute(&mut **tx)
    .await
    .map_err(storage("insert audit"))?;
    Ok(())
}

/// The actor recorded for events BAR originates itself.
const SYSTEM_ACTOR: &str = "system";

fn sqlite_timestamp(value: Option<u64>) -> Result<Option<i64>> {
    value
        .map(|value| {
            i64::try_from(value)
                .map_err(|_| Error::Corrupt("timestamp exceeds SQLite integer range".into()))
        })
        .transpose()
}

fn required_sqlite_u64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Corrupt(format!("{field} exceeds SQLite range")))
}

fn required_sqlite_usize(value: usize, field: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Corrupt(format!("{field} exceeds SQLite range")))
}

fn stored_timestamp(value: Option<i64>) -> Result<Option<u64>> {
    value
        .map(|value| {
            u64::try_from(value).map_err(|_| Error::Corrupt("negative stored timestamp".into()))
        })
        .transpose()
}

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

/// Result of assigning immutable scope inputs and supersession edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractResolutionPersistence {
    pub scope_assigned: bool,
    pub supersessions_inserted: usize,
}

/// Reloaded durable inputs for deterministic applicability resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredContractResolution {
    pub contract_id: ContractId,
    pub scope: ContractScope,
    pub temporal: TemporalWindow,
    pub supersedes: Vec<ContractId>,
}

/// Counts newly inserted candidate rows during an idempotent persistence call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CandidatePersistence {
    pub hierarchy_inserted: usize,
    pub glossary_inserted: usize,
    pub conflicts_inserted: usize,
}

/// Reloaded durable Phase 3 candidate state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAnalysisCandidates {
    pub hierarchy: Vec<HierarchyCandidate>,
    pub glossary: Vec<GlossaryCandidate>,
    pub glossary_ambiguities: Vec<GlossaryAmbiguityCandidate>,
    pub conflicts: Vec<ConflictCandidate>,
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

/// A durable artifact row used to verify an idempotent inventory replay.
#[derive(FromRow)]
struct PersistedArtifactRow {
    target_id: String,
    revision_id: String,
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

#[derive(FromRow)]
struct ContractResolutionRow {
    target_id: String,
    scope_resolved: i64,
    scope_json: String,
    valid_from_ms: Option<i64>,
    valid_until_ms: Option<i64>,
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
        let claim = ExtractedClaim {
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
        };
        validate_extracted_claim(&claim)?;
        Ok(StoredContract {
            contract_id: self.contract_id.parse()?,
            claim,
        })
    }
}

#[derive(FromRow)]
struct HierarchyRow {
    child_fingerprint: String,
    heading: String,
    heading_level: i64,
    artifact_id: String,
    start_offset: i64,
    end_offset: i64,
    exact_text_sha256: String,
}

impl HierarchyRow {
    fn into_candidate(self) -> Result<HierarchyCandidate> {
        let heading_level = u8::try_from(self.heading_level)
            .map_err(|_| Error::Corrupt("invalid hierarchy heading level".into()))?;
        if !(1..=6).contains(&heading_level) {
            return Err(Error::Corrupt("invalid hierarchy heading level".into()));
        }
        Ok(HierarchyCandidate {
            child_fingerprint: self.child_fingerprint.parse()?,
            heading: self.heading,
            heading_level,
            source: stored_source(
                self.artifact_id,
                self.start_offset,
                self.end_offset,
                self.exact_text_sha256,
            )?,
        })
    }
}

#[derive(FromRow)]
struct GlossaryRow {
    fingerprint: String,
    canonical: String,
    definition: String,
    aliases_json: String,
    artifact_id: String,
    start_offset: i64,
    end_offset: i64,
    exact_text_sha256: String,
}

impl GlossaryRow {
    fn into_candidate(self) -> Result<GlossaryCandidate> {
        let aliases: Vec<String> = serde_json::from_str(&self.aliases_json)
            .map_err(|e| Error::Corrupt(format!("invalid glossary aliases: {e}")))?;
        Ok(GlossaryCandidate {
            canonical: self.canonical,
            definition: self.definition,
            aliases,
            source: stored_source(
                self.artifact_id,
                self.start_offset,
                self.end_offset,
                self.exact_text_sha256,
            )?,
            fingerprint: self.fingerprint.parse()?,
        })
    }
}

#[derive(FromRow)]
struct ConflictRow {
    left_fingerprint: String,
    right_fingerprint: String,
    shared_subject: String,
    status: String,
}

impl ConflictRow {
    fn into_candidate(self) -> Result<ConflictCandidate> {
        if self.status != "candidate" {
            return Err(Error::Corrupt(format!(
                "unknown contract conflict candidate status `{}`",
                self.status
            )));
        }
        let left_fingerprint = self.left_fingerprint.parse()?;
        let right_fingerprint = self.right_fingerprint.parse()?;
        let (left_fingerprint, right_fingerprint) = if left_fingerprint <= right_fingerprint {
            (left_fingerprint, right_fingerprint)
        } else {
            (right_fingerprint, left_fingerprint)
        };
        Ok(ConflictCandidate {
            left_fingerprint,
            right_fingerprint,
            shared_subject: self.shared_subject,
        })
    }
}

fn stored_source(
    artifact_id: String,
    start_offset: i64,
    end_offset: i64,
    exact_text_sha256: String,
) -> Result<SourceRef> {
    let start_offset = usize::try_from(start_offset)
        .map_err(|_| Error::Corrupt("negative candidate source start offset".into()))?;
    let end_offset = usize::try_from(end_offset)
        .map_err(|_| Error::Corrupt("negative candidate source end offset".into()))?;
    if start_offset >= end_offset {
        return Err(Error::Corrupt("invalid candidate source span".into()));
    }
    Ok(SourceRef {
        artifact_id: artifact_id.parse()?,
        start_offset,
        end_offset,
        exact_text_sha256: exact_text_sha256.parse()?,
    })
}

impl ArtifactRow {
    fn into_prior(self) -> Result<PriorArtifact> {
        validate_logical_path(&self.logical_path)?;
        if self.content_sha256 != bar_discovery::UNHASHED_OVERSIZED {
            Sha256Digest::from_str(&self.content_sha256)?;
        }
        let source_of_truth = match self.source_of_truth {
            0 => false,
            1 => true,
            other => {
                return Err(Error::Corrupt(format!(
                    "unknown artifact source-of-truth state `{other}`"
                )))
            }
        };
        let size_bytes = u64::try_from(self.size_bytes)
            .map_err(|_| Error::Corrupt("negative artifact size".into()))?;
        if self.modified_at_ms.is_some_and(|value| value < 0) {
            return Err(Error::Corrupt(
                "negative artifact modification timestamp".into(),
            ));
        }
        Ok(PriorArtifact {
            content_sha256: self.content_sha256,
            media_type: self.media_type,
            artifact_kind: ArtifactKind::from_token(&self.artifact_kind)?,
            source_of_truth,
            size_bytes,
            modified_at_ms: self.modified_at_ms,
        })
    }
}

impl PersistedArtifactRow {
    fn matches_submission(
        &self,
        target_id: &TargetId,
        revision_id: &RevisionId,
        artifact: &DiscoveredArtifact,
        size_bytes: i64,
    ) -> bool {
        self.target_id == target_id.to_string()
            && self.revision_id == revision_id.to_string()
            && self.content_sha256 == artifact.content_sha256
            && self.media_type == artifact.media_type
            && self.artifact_kind == artifact.artifact_kind.as_str()
            && self.source_of_truth == i64::from(artifact.source_of_truth)
            && self.size_bytes == size_bytes
            && self.modified_at_ms == artifact.modified_at_ms
    }
}

/// One `audit_log` row. Integer columns are `i64` at the DB boundary (SQLite and
/// PostgreSQL do not encode `u64`) and are checked on the way out.
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

#[cfg(test)]
mod tests {
    use super::*;
    use bar_contract::scope::ScopeContext;
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
    async fn integer_boundaries_and_negative_audit_state_fail_closed() {
        let (store, _dir) = temp_store().await;
        assert!(store
            .register_target(&sample_target("overflow", "/srv/overflow"), u64::MAX)
            .await
            .is_err());

        let mut chain = AuditChain::new();
        chain.append(sample_event(0));
        store
            .insert_audit_record(&chain.records()[0])
            .await
            .unwrap();
        sqlx::query("UPDATE audit_log SET seq = -1 WHERE seq = 0")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.load_audit_chain().await.is_err());
        assert!(store
            .register_target(&sample_target("blocked", "/srv/blocked"), T0)
            .await
            .is_err());
        let targets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(targets, 0, "corrupt audit tip rolls back the mutation");
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
        let target_subject = target_id.to_string();
        assert!(chain.records()[2..]
            .iter()
            .all(|record| record.event.subject.as_deref() == Some(target_subject.as_str())));

        let readme = inv
            .artifacts
            .iter()
            .find(|artifact| artifact.logical_path == "README.md")
            .unwrap();
        sqlx::query("UPDATE artifacts SET media_type = 'forged/type' WHERE revision_id = ? AND logical_path = 'README.md'")
            .bind(rev_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .persist_inventory(&target_id, &rev_id, &inv, T0 + 1)
            .await
            .is_err());
        assert_eq!(store.load_audit_chain().await.unwrap().len(), 6);
        sqlx::query("UPDATE artifacts SET media_type = ? WHERE revision_id = ? AND logical_path = 'README.md'")
            .bind(&readme.media_type)
            .bind(rev_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();

        sqlx::query("UPDATE artifacts SET size_bytes = -1 WHERE revision_id = ?")
            .bind(rev_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.load_inventory(&rev_id).await.is_err());
    }

    #[tokio::test]
    async fn static_facts_are_artifact_bound_replay_safe_and_reload_verified() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let source = b"pub fn write() { std::fs::write(\"out\", b\"ok\").unwrap(); }";
        write_file(&root, "src/main.rs", source);

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("static", None), T0)
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
        let batch = bar_static::analyze_inventory(&root, &inventory, &revision_id).unwrap();
        assert!(batch.failures.is_empty());
        let artifact_id = batch.facts[0].artifact_id;
        let facts = batch.facts[0].facts.clone();
        let first = store
            .persist_static_batch(&target_id, &revision_id, &batch, T0 + 1)
            .await
            .unwrap();
        assert_eq!(first.inserted, 1);
        assert_eq!(first.existing, 0);
        let replay = store
            .persist_static_batch(&target_id, &revision_id, &batch, T0 + 2)
            .await
            .unwrap();
        assert_eq!(replay.inserted, 0);
        assert_eq!(replay.existing, 1);
        let loaded = store.load_static_facts(&artifact_id).await.unwrap();
        assert_eq!(loaded.target_id, target_id);
        assert_eq!(loaded.revision_id, revision_id);
        assert_eq!(loaded.facts, facts);

        assert!(store
            .persist_static_facts(
                &TargetId::generate(),
                &revision_id,
                &artifact_id,
                &facts,
                T0 + 3,
            )
            .await
            .is_err());
        sqlx::query("UPDATE static_facts SET facts_json = ? WHERE artifact_id = ?")
            .bind(r#"{"artifacts":[]}"#)
            .bind(artifact_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.load_static_facts(&artifact_id).await.is_err());

        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(
            chain.len(),
            5,
            "only the first static-facts write is audited"
        );
    }

    #[tokio::test]
    async fn traceability_maps_persisted_contracts_to_revision_bound_static_facts() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let document = "Requests MUST call `authorize`.\n";
        write_file(&root, "README.md", document.as_bytes());
        write_file(&root, "src/auth.rs", b"pub fn authorize() {}\n");

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("traceability", None), T0)
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
        let document_artifact = inventory
            .artifacts
            .iter()
            .find(|artifact| artifact.logical_path == "README.md")
            .unwrap();
        let document_text = bar_contract::ArtifactText::new(
            document_artifact.artifact_id(&revision_id),
            &document_artifact.logical_path,
            document_artifact.content_sha256.parse().unwrap(),
            document,
        )
        .unwrap();
        let contracts = bar_contract::extract_deterministic(&document_text).unwrap();
        let persisted = store
            .persist_contracts(&target_id, &revision_id, &contracts, T0 + 1)
            .await
            .unwrap();
        let batch = bar_static::analyze_inventory(&root, &inventory, &revision_id).unwrap();
        store
            .persist_static_batch(&target_id, &revision_id, &batch, T0 + 2)
            .await
            .unwrap();

        let traces = store
            .map_contract_traceability(&target_id, &revision_id)
            .await
            .unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].contract.contract_id, persisted.contract_ids[0]);
        assert_eq!(
            traces[0].traceability.status,
            bar_coverage::MappingStatus::Mapped
        );
        assert_eq!(traces[0].traceability.mappings[0].reference, "authorize");
        assert_eq!(
            traces[0].traceability.mappings[0].target.path,
            "src/auth.rs"
        );

        let obligation = bar_coverage::ProofObligation {
            proof_id: bar_core::ProofId::generate(),
            contract_id: persisted.contract_ids[0],
            contract_fingerprint: traces[0].contract.claim.fingerprint,
            required_evidence_levels: vec![bar_core::EvidenceKind::Code],
            freshness_revision: revision_id,
            freshness_policy: bar_core::FreshnessPolicy::Pinned,
        };
        assert!(
            store
                .persist_proof_obligation(&target_id, &revision_id, &obligation, T0 + 3,)
                .await
                .unwrap()
                .inserted
        );
        assert!(
            !store
                .persist_proof_obligation(&target_id, &revision_id, &obligation, T0 + 4,)
                .await
                .unwrap()
                .inserted
        );
        let loaded_obligation = store
            .load_proof_obligation(&obligation.proof_id)
            .await
            .unwrap();
        assert_eq!(loaded_obligation.obligation, obligation);
        let assessed = store
            .assess_persisted_proof_obligation(&obligation.proof_id)
            .await
            .unwrap();
        assert_eq!(assessed.proof, loaded_obligation);
        assert_eq!(
            assessed.traceability.status,
            bar_coverage::MappingStatus::Mapped
        );
        assert_eq!(assessed.assessment.status, bar_core::ProofStatus::Mapped);
        assert_eq!(assessed.evaluated_revision, revision_id);
        let later_revision = store
            .record_revision(&target_id, &revision("traceability-later", None), T0 + 5)
            .await
            .unwrap()
            .revision_id;
        let stale = store
            .assess_persisted_proof_obligation_at_revision(&obligation.proof_id, &later_revision)
            .await
            .unwrap();
        assert_eq!(stale.evaluated_revision, later_revision);
        assert_eq!(stale.assessment.status, bar_core::ProofStatus::Stale);
        let other_repo = tempfile::tempdir().unwrap();
        let other_root = std::fs::canonicalize(other_repo.path()).unwrap();
        let other_target = store
            .register_target(&tree_target(&other_root), T0 + 6)
            .await
            .unwrap()
            .target_id;
        let other_revision = store
            .record_revision(&other_target, &revision("other-target", None), T0 + 6)
            .await
            .unwrap()
            .revision_id;
        assert!(store
            .assess_persisted_proof_obligation_at_revision(&obligation.proof_id, &other_revision)
            .await
            .is_err());
        assert!(store
            .persist_proof_obligation(&TargetId::generate(), &revision_id, &obligation, T0 + 7,)
            .await
            .is_err());
        sqlx::query("UPDATE proof_obligations SET required_evidence_json = ? WHERE proof_id = ?")
            .bind(r#"["forged"]"#)
            .bind(obligation.proof_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .load_proof_obligation(&obligation.proof_id)
            .await
            .is_err());

        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(
            chain.len(),
            10,
            "the later revision, other target/revision, and first proof declaration mutate the audit chain"
        );
    }

    #[tokio::test]
    async fn reference_stable_proof_freshness_follows_referenced_symbol() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let document = "Requests MUST call `authorize`.\n";
        write_file(&root, "README.md", document.as_bytes());
        write_file(&root, "src/auth.rs", b"pub fn authorize() {}\n");

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;

        // Declared revision: contract, inventory, and static facts all persisted.
        let declared = store
            .record_revision(&target_id, &revision("declared", None), T0)
            .await
            .unwrap()
            .revision_id;
        let persist_all = |revision: RevisionId, ts: u64, with_contracts: bool| {
            let store = &store;
            let root = &root;
            async move {
                let inventory = bar_discovery::scan(
                    root,
                    &bar_discovery::ScanConfig::default(),
                    &PriorInventory::new(),
                )
                .unwrap();
                store
                    .persist_inventory(&target_id, &revision, &inventory, ts)
                    .await
                    .unwrap();
                if with_contracts {
                    let document_artifact = inventory
                        .artifacts
                        .iter()
                        .find(|artifact| artifact.logical_path == "README.md")
                        .unwrap();
                    let document_text = bar_contract::ArtifactText::new(
                        document_artifact.artifact_id(&revision),
                        &document_artifact.logical_path,
                        document_artifact.content_sha256.parse().unwrap(),
                        document,
                    )
                    .unwrap();
                    let contracts = bar_contract::extract_deterministic(&document_text).unwrap();
                    store
                        .persist_contracts(&target_id, &revision, &contracts, ts + 1)
                        .await
                        .unwrap();
                }
                let batch = bar_static::analyze_inventory(root, &inventory, &revision).unwrap();
                store
                    .persist_static_batch(&target_id, &revision, &batch, ts + 2)
                    .await
                    .unwrap();
            }
        };
        persist_all(declared, T0, true).await;

        let contract_id = store
            .map_contract_traceability(&target_id, &declared)
            .await
            .unwrap()[0]
            .contract
            .contract_id;
        let contract_fingerprint = store
            .map_contract_traceability(&target_id, &declared)
            .await
            .unwrap()[0]
            .contract
            .claim
            .fingerprint;
        let obligation = bar_coverage::ProofObligation {
            proof_id: bar_core::ProofId::generate(),
            contract_id,
            contract_fingerprint,
            required_evidence_levels: vec![bar_core::EvidenceKind::Code],
            freshness_revision: declared,
            freshness_policy: bar_core::FreshnessPolicy::ReferenceStable,
        };
        store
            .persist_proof_obligation(&target_id, &declared, &obligation, T0 + 3)
            .await
            .unwrap();

        // A later revision that still exposes `authorize` keeps the proof fresh.
        write_file(
            &root,
            "src/auth.rs",
            b"pub fn authorize() {} // unchanged behavior\n",
        );
        let kept = store
            .record_revision(&target_id, &revision("kept", None), T0 + 5)
            .await
            .unwrap()
            .revision_id;
        persist_all(kept, T0 + 5, false).await;
        let kept_assessment = store
            .assess_persisted_proof_obligation_at_revision(&obligation.proof_id, &kept)
            .await
            .unwrap();
        assert_eq!(
            kept_assessment.assessment.status,
            bar_core::ProofStatus::Mapped,
            "reference still resolves, so the proof stays fresh across the revision"
        );

        // A later revision where `authorize` is gone makes the proof stale.
        write_file(&root, "src/auth.rs", b"pub fn other() {}\n");
        let removed = store
            .record_revision(&target_id, &revision("removed", None), T0 + 9)
            .await
            .unwrap()
            .revision_id;
        persist_all(removed, T0 + 9, false).await;
        let removed_assessment = store
            .assess_persisted_proof_obligation_at_revision(&obligation.proof_id, &removed)
            .await
            .unwrap();
        assert_eq!(
            removed_assessment.assessment.status,
            bar_core::ProofStatus::Stale,
            "the referenced symbol disappeared, so the proof is stale"
        );

        // An unknown persisted freshness policy fails closed on reload.
        sqlx::query("UPDATE proof_obligations SET freshness_policy = ? WHERE proof_id = ?")
            .bind("bogus")
            .bind(obligation.proof_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .load_proof_obligation(&obligation.proof_id)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn promote_static_findings_aggregate_and_replay() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let document = "Requests MUST call `authorize`.\n";
        write_file(&root, "README.md", document.as_bytes());
        // `authorize` is absent, so the required reference is a missing-implementation.
        write_file(&root, "src/auth.rs", b"pub fn other() {}\n");

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;

        let scan_and_promote = |revision: RevisionId, ts: u64| {
            let store = &store;
            let root = &root;
            async move {
                let inventory = bar_discovery::scan(
                    root,
                    &bar_discovery::ScanConfig::default(),
                    &PriorInventory::new(),
                )
                .unwrap();
                store
                    .persist_inventory(&target_id, &revision, &inventory, ts)
                    .await
                    .unwrap();
                let document_artifact = inventory
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.logical_path == "README.md")
                    .unwrap();
                let document_text = bar_contract::ArtifactText::new(
                    document_artifact.artifact_id(&revision),
                    &document_artifact.logical_path,
                    document_artifact.content_sha256.parse().unwrap(),
                    document,
                )
                .unwrap();
                let contracts = bar_contract::extract_deterministic(&document_text).unwrap();
                store
                    .persist_contracts(&target_id, &revision, &contracts, ts + 1)
                    .await
                    .unwrap();
                let batch = bar_static::analyze_inventory(root, &inventory, &revision).unwrap();
                store
                    .persist_static_batch(&target_id, &revision, &batch, ts + 2)
                    .await
                    .unwrap();
                let candidates = store
                    .missing_implementation_candidates(&target_id, &revision)
                    .await
                    .unwrap();
                store
                    .persist_static_finding_candidates(&target_id, &revision, &candidates, ts + 3)
                    .await
                    .unwrap();
                store
                    .promote_static_findings(&target_id, &revision, ts + 4)
                    .await
                    .unwrap()
            }
        };

        let first = store
            .record_revision(&target_id, &revision("first", None), T0)
            .await
            .unwrap()
            .revision_id;
        let promotion_one = scan_and_promote(first, T0).await;
        assert_eq!(promotion_one.inserted, 1);
        assert_eq!(promotion_one.aggregated, 0);

        // The same symptom at a later revision aggregates into the same finding.
        let second = store
            .record_revision(&target_id, &revision("second", None), T0 + 10)
            .await
            .unwrap()
            .revision_id;
        let promotion_two = scan_and_promote(second, T0 + 10).await;
        assert_eq!(promotion_two.inserted, 0);
        assert_eq!(promotion_two.aggregated, 1);

        let candidate = store
            .missing_implementation_candidates(&target_id, &second)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let fingerprint = bar_findings::promote_candidate(&candidate)
            .unwrap()
            .finding_fingerprint;
        let finding = store
            .load_static_finding(&target_id, &fingerprint)
            .await
            .unwrap();
        assert_eq!(finding.first_seen_revision_id, first);
        assert_eq!(finding.last_seen_revision_id, second);
        assert_eq!(finding.status, bar_core::FindingStatus::Detected);

        // Re-promoting the same revision is an idempotent replay.
        let replay = store
            .promote_static_findings(&target_id, &second, T0 + 20)
            .await
            .unwrap();
        assert_eq!(replay.inserted, 0);
        assert_eq!(replay.aggregated, 0);

        // Re-promoting the earlier revision with a non-advancing timestamp is a
        // no-op and does not drift `last_seen` backward.
        let stale = store
            .promote_static_findings(&target_id, &first, T0)
            .await
            .unwrap();
        assert_eq!(stale.inserted, 0);
        assert_eq!(stale.aggregated, 0);
        assert_eq!(
            store
                .load_static_finding(&target_id, &fingerprint)
                .await
                .unwrap()
                .last_seen_revision_id,
            second
        );

        // A forged status token fails closed on reload.
        sqlx::query("UPDATE static_findings SET status = ? WHERE finding_fingerprint = ?")
            .bind("bogus")
            .bind(fingerprint.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .load_static_finding(&target_id, &fingerprint)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn false_positive_correction_is_retained_across_replay() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let document = "Requests MUST call `authorize`.\n";
        write_file(&root, "README.md", document.as_bytes());
        write_file(&root, "src/auth.rs", b"pub fn other() {}\n");

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;

        let scan_and_promote = |revision: RevisionId, ts: u64| {
            let store = &store;
            let root = &root;
            async move {
                let inventory = bar_discovery::scan(
                    root,
                    &bar_discovery::ScanConfig::default(),
                    &PriorInventory::new(),
                )
                .unwrap();
                store
                    .persist_inventory(&target_id, &revision, &inventory, ts)
                    .await
                    .unwrap();
                let document_artifact = inventory
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.logical_path == "README.md")
                    .unwrap();
                let document_text = bar_contract::ArtifactText::new(
                    document_artifact.artifact_id(&revision),
                    &document_artifact.logical_path,
                    document_artifact.content_sha256.parse().unwrap(),
                    document,
                )
                .unwrap();
                let contracts = bar_contract::extract_deterministic(&document_text).unwrap();
                store
                    .persist_contracts(&target_id, &revision, &contracts, ts + 1)
                    .await
                    .unwrap();
                let batch = bar_static::analyze_inventory(root, &inventory, &revision).unwrap();
                store
                    .persist_static_batch(&target_id, &revision, &batch, ts + 2)
                    .await
                    .unwrap();
                let candidates = store
                    .missing_implementation_candidates(&target_id, &revision)
                    .await
                    .unwrap();
                store
                    .persist_static_finding_candidates(&target_id, &revision, &candidates, ts + 3)
                    .await
                    .unwrap();
                store
                    .promote_static_findings(&target_id, &revision, ts + 4)
                    .await
                    .unwrap()
            }
        };

        let first = store
            .record_revision(&target_id, &revision("first", None), T0)
            .await
            .unwrap()
            .revision_id;
        let promotion = scan_and_promote(first, T0).await;
        assert_eq!(promotion.inserted, 1);

        let candidate = store
            .missing_implementation_candidates(&target_id, &first)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let fingerprint = bar_findings::promote_candidate(&candidate)
            .unwrap()
            .finding_fingerprint;

        // An operator corrects the detection as a false positive.
        store
            .reject_static_finding(
                &target_id,
                &fingerprint,
                "authorize is provided by the router",
                T0 + 5,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .load_static_finding(&target_id, &fingerprint)
                .await
                .unwrap()
                .status,
            bar_core::FindingStatus::Rejected
        );

        // Re-promoting the same revision retains the correction: not aggregated,
        // not reopened, still rejected.
        let replay = store
            .promote_static_findings(&target_id, &first, T0 + 6)
            .await
            .unwrap();
        assert_eq!(
            replay,
            StaticFindingPromotion {
                inserted: 0,
                aggregated: 0,
                retained: 1,
            }
        );

        // The same symptom recurring at a later revision is still retained: a
        // rejected finding neither aggregates its occurrence window nor reopens.
        let second = store
            .record_revision(&target_id, &revision("second", None), T0 + 10)
            .await
            .unwrap()
            .revision_id;
        let later = scan_and_promote(second, T0 + 10).await;
        assert_eq!(
            later,
            StaticFindingPromotion {
                inserted: 0,
                aggregated: 0,
                retained: 1,
            }
        );
        let retained = store
            .load_static_finding(&target_id, &fingerprint)
            .await
            .unwrap();
        assert_eq!(retained.status, bar_core::FindingStatus::Rejected);
        assert_eq!(retained.last_seen_revision_id, first);

        // Re-rejecting is an idempotent no-op; an empty reason and an unknown
        // finding both fail closed.
        store
            .reject_static_finding(&target_id, &fingerprint, "still a false positive", T0 + 11)
            .await
            .unwrap();
        assert!(store
            .reject_static_finding(&target_id, &fingerprint, "   ", T0 + 12)
            .await
            .is_err());
        assert!(store
            .reject_static_finding(
                &target_id,
                &bar_core::Sha256Digest::from_bytes([7; 32]),
                "no such finding",
                T0 + 13,
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn traceability_maps_literal_configuration_keys_from_persisted_static_facts() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let document = "Runtime MUST set `server.port`.\nWorkers MUST set `worker.concurrency`.\n";
        write_file(&root, "README.md", document.as_bytes());
        write_file(&root, "config/runtime.toml", b"[server]\nport = 8080\n");
        write_file(
            &root,
            "config/workers.json",
            b"{\n  \"worker\": {\n    \"concurrency\": 4\n  }\n}\n",
        );

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("config-traceability", None), T0)
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
        let document_artifact = inventory
            .artifacts
            .iter()
            .find(|artifact| artifact.logical_path == "README.md")
            .unwrap();
        let document_text = bar_contract::ArtifactText::new(
            document_artifact.artifact_id(&revision_id),
            &document_artifact.logical_path,
            document_artifact.content_sha256.parse().unwrap(),
            document,
        )
        .unwrap();
        let contracts = bar_contract::extract_deterministic(&document_text).unwrap();
        store
            .persist_contracts(&target_id, &revision_id, &contracts, T0 + 1)
            .await
            .unwrap();
        let batch = bar_static::analyze_inventory(&root, &inventory, &revision_id).unwrap();
        store
            .persist_static_batch(&target_id, &revision_id, &batch, T0 + 2)
            .await
            .unwrap();

        let traces = store
            .map_contract_traceability(&target_id, &revision_id)
            .await
            .unwrap();
        for (reference, path) in [
            ("server.port", "config/runtime.toml"),
            ("worker.concurrency", "config/workers.json"),
        ] {
            let mapping = traces
                .iter()
                .flat_map(|trace| &trace.traceability.mappings)
                .find(|mapping| mapping.reference == reference)
                .unwrap();
            assert_eq!(mapping.target.path, path);
            assert_eq!(
                mapping.target.kind,
                bar_coverage::TraceTargetKind::Configuration
            );
        }
    }

    #[tokio::test]
    async fn missing_implementation_candidates_are_persisted_and_revision_bound() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let document = "Requests MUST call `audit`.\n";
        write_file(&root, "README.md", document.as_bytes());
        write_file(&root, "src/service.rs", b"pub fn serve() {}\n");

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("missing-implementation", None), T0)
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
        let document_artifact = inventory
            .artifacts
            .iter()
            .find(|artifact| artifact.logical_path == "README.md")
            .unwrap();
        let document_text = bar_contract::ArtifactText::new(
            document_artifact.artifact_id(&revision_id),
            &document_artifact.logical_path,
            document_artifact.content_sha256.parse().unwrap(),
            document,
        )
        .unwrap();
        let contracts = bar_contract::extract_deterministic(&document_text).unwrap();
        let persisted = store
            .persist_contracts(&target_id, &revision_id, &contracts, T0 + 1)
            .await
            .unwrap();
        let batch = bar_static::analyze_inventory(&root, &inventory, &revision_id).unwrap();
        store
            .persist_static_batch(&target_id, &revision_id, &batch, T0 + 2)
            .await
            .unwrap();

        let before = store.load_audit_chain().await.unwrap();
        let candidates = store
            .missing_implementation_candidates(&target_id, &revision_id)
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].contract_id, persisted.contract_ids[0]);
        assert_eq!(candidates[0].missing_references, ["audit"]);
        let mut invalid = candidates[0].clone();
        invalid.fingerprint = Sha256Digest::from_bytes([9; 32]);
        assert!(store
            .persist_static_finding_candidates(
                &target_id,
                &revision_id,
                &[candidates[0].clone(), invalid],
                T0 + 3,
            )
            .await
            .is_err());
        assert!(store
            .load_static_finding_candidates_for_revision(&target_id, &revision_id)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(store.load_audit_chain().await.unwrap().len(), before.len());
        sqlx::query("UPDATE contracts SET normative_kind = 'planned' WHERE contract_id = ?")
            .bind(candidates[0].contract_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .persist_static_finding_candidates(&target_id, &revision_id, &candidates, T0 + 4)
            .await
            .is_err());
        sqlx::query("UPDATE contracts SET normative_kind = 'required' WHERE contract_id = ?")
            .bind(candidates[0].contract_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let first = store
            .persist_static_finding_candidates(&target_id, &revision_id, &candidates, T0 + 4)
            .await
            .unwrap();
        let replay = store
            .persist_static_finding_candidates(&target_id, &revision_id, &candidates, T0 + 5)
            .await
            .unwrap();
        assert_eq!(
            first,
            StaticFindingCandidateBatchPersistence {
                inserted: 1,
                existing: 0,
            }
        );
        assert_eq!(
            replay,
            StaticFindingCandidateBatchPersistence {
                inserted: 0,
                existing: 1,
            }
        );
        assert_eq!(
            store
                .load_static_finding_candidate(&candidates[0].fingerprint)
                .await
                .unwrap(),
            StoredStaticFindingCandidate {
                target_id,
                revision_id,
                candidate: candidates[0].clone(),
                created_at_ms: T0 + 4,
            }
        );
        assert_eq!(
            store
                .load_static_finding_candidates_for_revision(&target_id, &revision_id)
                .await
                .unwrap()
                .into_iter()
                .map(|stored| stored.candidate)
                .collect::<Vec<_>>(),
            candidates
        );
        let after = store.load_audit_chain().await.unwrap();
        after.verify().unwrap();
        assert_eq!(after.len(), before.len() + 1);

        assert!(store
            .persist_static_finding_candidate(
                &TargetId::generate(),
                &revision_id,
                &candidates[0],
                T0 + 6,
            )
            .await
            .is_err());
        sqlx::query(
            "UPDATE static_finding_candidates SET missing_references_json = ? WHERE fingerprint = ?",
        )
        .bind(r#"["forged"]"#)
        .bind(candidates[0].fingerprint.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(store
            .load_static_finding_candidate(&candidates[0].fingerprint)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn inventory_rejects_cross_target_paths_and_integer_overflow() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        write_file(&root, "src/main.rs", b"fn main() {}");
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

        assert!(store
            .persist_inventory(&TargetId::generate(), &revision_id, &inventory, T0)
            .await
            .is_err());
        let mut unsafe_path = inventory.clone();
        unsafe_path.artifacts[0].logical_path = "../escape.rs".into();
        assert!(store
            .persist_inventory(&target_id, &revision_id, &unsafe_path, T0)
            .await
            .is_err());
        let mut overflow = inventory;
        overflow.artifacts[0].size_bytes = u64::MAX;
        assert!(store
            .persist_inventory(&target_id, &revision_id, &overflow, T0)
            .await
            .is_err());

        let artifacts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM artifacts")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(artifacts, 0);
        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(chain.len(), 2, "rejected inventories emit no scan events");
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

        sqlx::query("UPDATE contract_sources SET exact_text_sha256 = ? WHERE contract_id = ?")
            .bind("00".repeat(32))
            .bind(first.contract_ids[0].to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .persist_contracts(&target_id, &revision_id, &claims, T0 + 3)
            .await
            .is_err());
        sqlx::query("UPDATE contract_sources SET exact_text_sha256 = ? WHERE contract_id = ?")
            .bind(claims[0].source.exact_text_sha256.to_string())
            .bind(first.contract_ids[0].to_string())
            .execute(&store.pool)
            .await
            .unwrap();

        sqlx::query("UPDATE contracts SET normative_kind = 'unknown' WHERE contract_id = ?")
            .bind(first.contract_ids[0].to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.load_contracts(&revision_id).await.is_err());
        sqlx::query("UPDATE contracts SET normative_kind = ? WHERE contract_id = ?")
            .bind(claims[0].normative_kind.as_str())
            .bind(first.contract_ids[0].to_string())
            .execute(&store.pool)
            .await
            .unwrap();

        let mut tampered_claim = claims.clone();
        tampered_claim[0].fingerprint = Sha256Digest::from_bytes([0; 32]);
        assert!(store
            .persist_contracts(&target_id, &revision_id, &tampered_claim, T0 + 4)
            .await
            .is_err());

        sqlx::query("UPDATE contracts SET fingerprint = ? WHERE contract_id = ?")
            .bind("00".repeat(32))
            .bind(first.contract_ids[0].to_string())
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

    #[tokio::test]
    async fn contract_resolution_persists_reloads_and_fails_closed() {
        use bar_contract::scope::{
            resolve_applicability, ApplicabilityState, ScopeContext, ScopedContract,
        };
        use bar_contract::{extract_deterministic, ArtifactText};

        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let text = "The cache MUST retain entries.\nThe cache MUST NOT retain entries.";
        write_file(&root, "README.md", text.as_bytes());
        let (store, dir) = temp_store().await;
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
        let persisted = store
            .persist_contracts(&target_id, &revision_id, &claims, T0 + 1)
            .await
            .unwrap();
        let old_id = persisted.contract_ids[0];
        let new_id = persisted.contract_ids[1];
        let product_scope = ContractScope::default();
        let deployment_scope = ContractScope {
            deployments: vec!["prod-a".into()],
            source_revision_range: Some(">=1.0.0 <2.0.0".into()),
            ..ContractScope::default()
        };

        let old = store
            .assign_contract_resolution(&old_id, &product_scope, Some(10), Some(30), &[], T0 + 2)
            .await
            .unwrap();
        assert!(old.scope_assigned);

        let missing = ContractId::generate();
        assert!(store
            .assign_contract_resolution(
                &new_id,
                &deployment_scope,
                Some(10),
                Some(30),
                &[missing],
                T0 + 3,
            )
            .await
            .is_err());
        assert!(store.load_contract_resolution(&new_id).await.is_err());

        let first = store
            .assign_contract_resolution(
                &new_id,
                &deployment_scope,
                Some(10),
                Some(30),
                &[old_id],
                T0 + 4,
            )
            .await
            .unwrap();
        let replay = store
            .assign_contract_resolution(
                &new_id,
                &deployment_scope,
                Some(10),
                Some(30),
                &[old_id],
                T0 + 5,
            )
            .await
            .unwrap();
        assert_eq!(first.supersessions_inserted, 1);
        assert_eq!(
            replay,
            ContractResolutionPersistence {
                scope_assigned: false,
                supersessions_inserted: 0,
            }
        );

        let url = format!("sqlite://{}", dir.path().join("bar.db").display());
        let reopened = Store::connect(&url).await.unwrap();
        reopened.migrate().await.unwrap();

        let loaded_new = reopened.load_contract_resolution(&new_id).await.unwrap();
        let loaded_old = reopened.load_contract_resolution(&old_id).await.unwrap();
        assert_eq!(loaded_new.scope, deployment_scope);
        assert_eq!(loaded_new.supersedes, [old_id]);
        assert!(!loaded_new.temporal.superseded);
        assert!(loaded_old.temporal.superseded);
        assert_eq!(
            resolve_applicability(
                ScopedContract {
                    scope: &loaded_new.scope,
                    temporal: &loaded_new.temporal,
                    normative_kind: claims[1].normative_kind,
                },
                &ScopeContext {
                    deployment: Some("prod-a".into()),
                    source_revision: Some("1.5.0".into()),
                    ..ScopeContext::default()
                },
                20,
            )
            .state,
            ApplicabilityState::Applicable
        );

        let changed = ContractScope {
            deployments: vec!["prod-b".into()],
            ..ContractScope::default()
        };
        assert!(store
            .assign_contract_resolution(&new_id, &changed, Some(10), Some(30), &[], T0 + 6,)
            .await
            .is_err());
        assert_eq!(
            store.load_contract_resolution(&new_id).await.unwrap().scope,
            deployment_scope
        );
        assert!(store
            .assign_contract_resolution(
                &new_id,
                &deployment_scope,
                Some(u64::MAX),
                None,
                &[],
                T0 + 7,
            )
            .await
            .is_err());

        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(chain.len(), 9, "failed writes and replay emit no events");

        let other_repo = tempfile::tempdir().unwrap();
        let other_root = std::fs::canonicalize(other_repo.path()).unwrap();
        let other_target = store
            .register_target(&tree_target(&other_root), T0 + 8)
            .await
            .unwrap()
            .target_id;
        sqlx::query("UPDATE contracts SET target_id = ? WHERE contract_id = ?")
            .bind(other_target.to_string())
            .bind(old_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.load_contract_resolution(&new_id).await.is_err());
        assert!(store
            .assign_contract_resolution(&new_id, &deployment_scope, Some(10), Some(30), &[], T0 + 9)
            .await
            .is_err());

        sqlx::query("UPDATE contracts SET scope_json = '{\"unknown\":[]}' WHERE contract_id = ?")
            .bind(new_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.load_contract_resolution(&new_id).await.is_err());
    }

    #[tokio::test]
    async fn scope_context_is_source_bound_target_isolated_and_replay_safe() {
        use bar_contract::scope::{resolve_applicability, ApplicabilityState, ScopedContract};

        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let text = "Production cache configuration. The cache MUST retain entries.";
        write_file(&root, "config/runtime.md", text.as_bytes());
        let (store, dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("commit-a", None), T0)
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
        let source = SourceRef {
            artifact_id: artifact.artifact_id(&revision_id),
            start_offset: 0,
            end_offset: text.len(),
            exact_text_sha256: artifact.content_sha256.parse().unwrap(),
        };
        let supplied = ScopeContext {
            environment: Some("production".into()),
            component: Some("cache".into()),
            source_revision: Some("caller-forged".into()),
            ..ScopeContext::default()
        };

        let mut forged_source = source.clone();
        forged_source.exact_text_sha256 = Sha256Digest::from_bytes([9; 32]);
        assert!(store
            .persist_scope_context_evidence(
                &target_id,
                &revision_id,
                &supplied,
                &forged_source,
                T0 + 1,
                T0 + 2,
            )
            .await
            .is_err());

        assert!(store
            .persist_scope_context_evidence(
                &TargetId::generate(),
                &revision_id,
                &supplied,
                &source,
                T0 + 1,
                T0 + 2,
            )
            .await
            .is_err());
        let first = store
            .persist_scope_context_evidence(
                &target_id,
                &revision_id,
                &supplied,
                &source,
                T0 + 1,
                T0 + 2,
            )
            .await
            .unwrap();
        let replay = store
            .persist_scope_context_evidence(
                &target_id,
                &revision_id,
                &supplied,
                &source,
                T0 + 1,
                T0 + 3,
            )
            .await
            .unwrap();
        assert!(first.inserted);
        assert_eq!(first.evidence_id, replay.evidence_id);
        assert!(!replay.inserted);

        let url = format!("sqlite://{}", dir.path().join("bar.db").display());
        let reopened = Store::connect(&url).await.unwrap();
        reopened.migrate().await.unwrap();
        let loaded = reopened
            .load_scope_context_evidence(&first.evidence_id)
            .await
            .unwrap();
        assert_eq!(loaded.target_id, target_id);
        assert_eq!(loaded.revision_id, revision_id);
        assert_eq!(loaded.source, source);
        assert_eq!(loaded.context.source_revision.as_deref(), Some("commit-a"));
        assert_eq!(loaded.observed_at_ms, T0 + 1);

        let scope = ContractScope {
            environments: vec!["production".into()],
            components: vec!["cache".into()],
            source_revisions: vec!["commit-a".into()],
            ..ContractScope::default()
        };
        assert_eq!(
            resolve_applicability(
                ScopedContract {
                    scope: &scope,
                    temporal: &TemporalWindow::default(),
                    normative_kind: NormativeKind::Required,
                },
                &loaded.context,
                loaded.observed_at_ms,
            )
            .state,
            ApplicabilityState::Applicable
        );
        let chain = reopened.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(chain.len(), 5, "failure and replay emit no evidence events");

        let other_root = tempfile::tempdir().unwrap();
        let other_target = store
            .register_target(&tree_target(other_root.path()), T0 + 4)
            .await
            .unwrap()
            .target_id;
        sqlx::query("UPDATE scope_context_evidence SET target_id = ? WHERE evidence_id = ?")
            .bind(other_target.to_string())
            .bind(first.evidence_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .persist_scope_context_evidence(
                &target_id,
                &revision_id,
                &supplied,
                &source,
                T0 + 1,
                T0 + 4,
            )
            .await
            .is_err());
        sqlx::query("UPDATE scope_context_evidence SET target_id = ? WHERE evidence_id = ?")
            .bind(target_id.to_string())
            .bind(first.evidence_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();

        sqlx::query(
            "UPDATE scope_context_evidence SET exact_text_sha256 = ? WHERE evidence_id = ?",
        )
        .bind("00".repeat(32))
        .bind(first.evidence_id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(reopened
            .load_scope_context_evidence(&first.evidence_id)
            .await
            .is_err());
        sqlx::query(
            "UPDATE scope_context_evidence SET exact_text_sha256 = ? WHERE evidence_id = ?",
        )
        .bind(source.exact_text_sha256.to_string())
        .bind(first.evidence_id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();

        sqlx::query(
            "UPDATE scope_context_evidence SET context_json = '{\"unknown\":true}' \
             WHERE evidence_id = ?",
        )
        .bind(first.evidence_id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(reopened
            .load_scope_context_evidence(&first.evidence_id)
            .await
            .is_err());
        assert!(store
            .persist_scope_context_attestation(
                &first.evidence_id,
                "operator/alice",
                "verified against the deployment manifest",
                T0 + 2,
            )
            .await
            .is_err());
        assert_eq!(
            store.load_audit_chain().await.unwrap().len(),
            6,
            "the second target is audited; failed evidence writes add no events"
        );
    }

    #[tokio::test]
    async fn context_resolution_uses_evidence_time_and_rejects_cross_target_context() {
        use bar_contract::scope::ApplicabilityState;
        use bar_contract::{extract_deterministic, ArtifactText};

        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let text = "The cache MUST retain entries.";
        write_file(&root, "README.md", text.as_bytes());
        let (store, dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("commit-a", None), T0)
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
        let artifact_text = ArtifactText::new(
            artifact.artifact_id(&revision_id),
            &artifact.logical_path,
            artifact.content_sha256.parse().unwrap(),
            text,
        )
        .unwrap();
        let contract_id = store
            .persist_contracts(
                &target_id,
                &revision_id,
                &extract_deterministic(&artifact_text).unwrap(),
                T0 + 1,
            )
            .await
            .unwrap()
            .contract_ids[0];
        store
            .assign_contract_resolution(
                &contract_id,
                &ContractScope::default(),
                Some(T0 + 10),
                Some(T0 + 20),
                &[],
                T0 + 2,
            )
            .await
            .unwrap();
        let source = SourceRef {
            artifact_id: artifact.artifact_id(&revision_id),
            start_offset: 0,
            end_offset: text.len(),
            exact_text_sha256: artifact.content_sha256.parse().unwrap(),
        };
        let observed_during_validity = store
            .persist_scope_context_evidence(
                &target_id,
                &revision_id,
                &ScopeContext::default(),
                &source,
                T0 + 15,
                T0 + 15,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .resolve_contract_in_context(&contract_id, &observed_during_validity.evidence_id)
                .await
                .unwrap()
                .state,
            ApplicabilityState::Applicable
        );
        assert!(store
            .persist_scope_context_attestation(
                &observed_during_validity.evidence_id,
                " ",
                "verified against the deployment manifest",
                T0 + 16,
            )
            .await
            .is_err());
        let attestation = store
            .persist_scope_context_attestation(
                &observed_during_validity.evidence_id,
                "operator/alice",
                "verified against the deployment manifest",
                T0 + 16,
            )
            .await
            .unwrap();
        let attestation_replay = store
            .persist_scope_context_attestation(
                &observed_during_validity.evidence_id,
                "operator/alice",
                "verified against the deployment manifest",
                T0 + 17,
            )
            .await
            .unwrap();
        assert!(attestation.inserted);
        assert_eq!(attestation_replay.evidence_id, attestation.evidence_id);
        assert!(!attestation_replay.inserted);
        sqlx::query(
            "UPDATE scope_context_attestations SET created_at_ms = -1 WHERE evidence_id = ?",
        )
        .bind(attestation.evidence_id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(store
            .persist_scope_context_attestation(
                &observed_during_validity.evidence_id,
                "operator/alice",
                "verified against the deployment manifest",
                T0 + 17,
            )
            .await
            .is_err());
        sqlx::query(
            "UPDATE scope_context_attestations SET created_at_ms = ? WHERE evidence_id = ?",
        )
        .bind(i64::try_from(T0 + 16).unwrap())
        .bind(attestation.evidence_id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
        let loaded_attestation = store
            .load_scope_context_attestation(&attestation.evidence_id)
            .await
            .unwrap();
        assert_eq!(
            loaded_attestation.context_evidence_id,
            observed_during_validity.evidence_id
        );
        assert_eq!(loaded_attestation.operator_id, "operator/alice");
        let url = format!("sqlite://{}", dir.path().join("bar.db").display());
        let reopened = Store::connect(&url).await.unwrap();
        reopened.migrate().await.unwrap();
        assert_eq!(
            reopened
                .load_scope_context_attestation(&attestation.evidence_id)
                .await
                .unwrap(),
            loaded_attestation
        );
        assert_eq!(
            store
                .resolve_contract_in_attested_context(&contract_id, &attestation.evidence_id)
                .await
                .unwrap()
                .state,
            ApplicabilityState::Applicable
        );
        let observed_after_expiry = store
            .persist_scope_context_evidence(
                &target_id,
                &revision_id,
                &ScopeContext::default(),
                &source,
                T0 + 21,
                T0 + 21,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .resolve_contract_in_context(&contract_id, &observed_after_expiry.evidence_id)
                .await
                .unwrap()
                .state,
            ApplicabilityState::NotApplicable
        );

        let other_repo = tempfile::tempdir().unwrap();
        let other_root = std::fs::canonicalize(other_repo.path()).unwrap();
        write_file(&other_root, "README.md", text.as_bytes());
        let other_target = store
            .register_target(&tree_target(&other_root), T0)
            .await
            .unwrap()
            .target_id;
        let other_revision = store
            .record_revision(&other_target, &revision("commit-b", None), T0)
            .await
            .unwrap()
            .revision_id;
        let other_inventory = bar_discovery::scan(
            &other_root,
            &bar_discovery::ScanConfig::default(),
            &PriorInventory::new(),
        )
        .unwrap();
        store
            .persist_inventory(&other_target, &other_revision, &other_inventory, T0)
            .await
            .unwrap();
        let other_artifact = &other_inventory.artifacts[0];
        let other_context = store
            .persist_scope_context_evidence(
                &other_target,
                &other_revision,
                &ScopeContext::default(),
                &SourceRef {
                    artifact_id: other_artifact.artifact_id(&other_revision),
                    start_offset: 0,
                    end_offset: text.len(),
                    exact_text_sha256: other_artifact.content_sha256.parse().unwrap(),
                },
                T0 + 15,
                T0 + 15,
            )
            .await
            .unwrap();
        let other_attestation = store
            .persist_scope_context_attestation(
                &other_context.evidence_id,
                "operator/alice",
                "verified against the other deployment manifest",
                T0 + 16,
            )
            .await
            .unwrap();
        assert!(store
            .resolve_contract_in_context(&contract_id, &other_context.evidence_id)
            .await
            .is_err());
        assert!(store
            .resolve_contract_in_attested_context(&contract_id, &other_attestation.evidence_id)
            .await
            .is_err());

        sqlx::query("UPDATE scope_context_attestations SET rationale = ' ' WHERE evidence_id = ?")
            .bind(attestation.evidence_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .load_scope_context_attestation(&attestation.evidence_id)
            .await
            .is_err());
        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
    }

    #[tokio::test]
    async fn contract_rulings_reuse_supersede_expire_and_reload() {
        use bar_contract::ruling::{ContractRuling, RulingDisposition};
        use bar_contract::{extract_deterministic, ArtifactText};

        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let text = "The cache MUST retain entries.\nThe cache MUST NOT retain entries.";
        write_file(&root, "README.md", text.as_bytes());
        let (store, dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("commit-a", None), T0)
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
        let artifact_text = ArtifactText::new(
            artifact.artifact_id(&revision_id),
            &artifact.logical_path,
            artifact.content_sha256.parse().unwrap(),
            text,
        )
        .unwrap();
        let claims = extract_deterministic(&artifact_text).unwrap();
        let mut contracts = store
            .persist_contracts(&target_id, &revision_id, &claims, T0 + 1)
            .await
            .unwrap()
            .contract_ids;
        contracts.sort_unstable();
        let context_source = SourceRef {
            artifact_id: artifact.artifact_id(&revision_id),
            start_offset: 0,
            end_offset: text.len(),
            exact_text_sha256: artifact.content_sha256.parse().unwrap(),
        };
        let context = store
            .persist_scope_context_evidence(
                &target_id,
                &revision_id,
                &ScopeContext {
                    environment: Some("production".into()),
                    ..ScopeContext::default()
                },
                &context_source,
                T0 + 2,
                T0 + 2,
            )
            .await
            .unwrap();
        let ruling = ContractRuling {
            contract_refs: contracts.clone(),
            disposition: RulingDisposition::Chosen,
            outcome: "retain entries".into(),
            rejected_interpretations: vec!["discard entries".into()],
            rationale: "The production retention requirement controls.".into(),
            scope: ContractScope {
                environments: vec!["production".into()],
                ..ContractScope::default()
            },
            effective_from_ms: T0 + 3,
            expires_at_ms: Some(T0 + 100),
            operator_id: "operator/alice".into(),
        };

        assert!(store
            .persist_contract_ruling(
                &TargetId::generate(),
                &context.evidence_id,
                &ruling,
                None,
                T0 + 3,
            )
            .await
            .is_err());
        let first = store
            .persist_contract_ruling(&target_id, &context.evidence_id, &ruling, None, T0 + 3)
            .await
            .unwrap();
        assert!(first.inserted);

        let mut attempted_edit = ruling.clone();
        attempted_edit.rationale = "A changed rationale must not replace history.".into();
        let reused = store
            .persist_contract_ruling(
                &target_id,
                &context.evidence_id,
                &attempted_edit,
                None,
                T0 + 4,
            )
            .await
            .unwrap();
        assert_eq!(reused.ruling_id, first.ruling_id);
        assert!(!reused.inserted);

        let mut replacement = ruling.clone();
        replacement.disposition = RulingDisposition::Deferred;
        replacement.outcome = "deferred pending a production evidence capture".into();
        replacement.rejected_interpretations.clear();
        replacement.rationale = "The current evidence cannot select an interpretation.".into();
        replacement.effective_from_ms = T0 + 5;
        let second = store
            .persist_contract_ruling(
                &target_id,
                &context.evidence_id,
                &replacement,
                Some(&first.ruling_id),
                T0 + 5,
            )
            .await
            .unwrap();
        assert!(second.inserted);
        let replacement_replay = store
            .persist_contract_ruling(
                &target_id,
                &context.evidence_id,
                &replacement,
                Some(&first.ruling_id),
                T0 + 6,
            )
            .await
            .unwrap();
        assert_eq!(replacement_replay.ruling_id, second.ruling_id);
        assert!(!replacement_replay.inserted);
        sqlx::query("UPDATE contract_rulings SET created_at_ms = -1 WHERE ruling_id = ?")
            .bind(second.ruling_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .persist_contract_ruling(
                &target_id,
                &context.evidence_id,
                &replacement,
                Some(&first.ruling_id),
                T0 + 6,
            )
            .await
            .is_err());
        sqlx::query("UPDATE contract_rulings SET created_at_ms = ? WHERE ruling_id = ?")
            .bind(i64::try_from(T0 + 5).unwrap())
            .bind(second.ruling_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();

        let loaded_first = store.load_contract_ruling(&first.ruling_id).await.unwrap();
        assert_eq!(loaded_first.superseded_by, Some(second.ruling_id));
        assert_eq!(loaded_first.ruling, ruling);
        let loaded_second = store.load_contract_ruling(&second.ruling_id).await.unwrap();
        assert_eq!(loaded_second.ruling, replacement);
        assert_eq!(loaded_second.context_evidence_id, context.evidence_id);
        assert_eq!(loaded_second.superseded_by, None);

        let mut renewal = replacement.clone();
        renewal.effective_from_ms = T0 + 101;
        renewal.expires_at_ms = None;
        let renewed = store
            .persist_contract_ruling(&target_id, &context.evidence_id, &renewal, None, T0 + 101)
            .await
            .unwrap();
        assert!(renewed.inserted, "an expired ruling is not reused");
        assert_ne!(renewed.ruling_id, second.ruling_id);
        sqlx::query("UPDATE contract_rulings SET created_at_ms = -1 WHERE ruling_id = ?")
            .bind(renewed.ruling_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .persist_contract_ruling(&target_id, &context.evidence_id, &renewal, None, T0 + 102)
            .await
            .is_err());
        sqlx::query("UPDATE contract_rulings SET created_at_ms = ? WHERE ruling_id = ?")
            .bind(i64::try_from(T0 + 101).unwrap())
            .bind(renewed.ruling_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();

        let url = format!("sqlite://{}", dir.path().join("bar.db").display());
        let reopened = Store::connect(&url).await.unwrap();
        reopened.migrate().await.unwrap();
        assert_eq!(
            reopened
                .load_contract_ruling(&second.ruling_id)
                .await
                .unwrap(),
            loaded_second
        );
        let chain = reopened.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(
            chain
                .records()
                .iter()
                .filter(|record| record.event.category == AuditCategory::Ruling)
                .count(),
            4,
            "reuse, replay, and failed writes emit no ruling events"
        );

        sqlx::query(
            "UPDATE scope_context_evidence SET context_json = '{\"unknown\":true}' \
             WHERE evidence_id = ?",
        )
        .bind(context.evidence_id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(store
            .persist_contract_ruling(&target_id, &context.evidence_id, &renewal, None, T0 + 102)
            .await
            .is_err());
        assert!(reopened
            .load_contract_ruling(&second.ruling_id)
            .await
            .is_err());
        assert_eq!(
            store
                .load_audit_chain()
                .await
                .unwrap()
                .records()
                .iter()
                .filter(|record| record.event.category == AuditCategory::Ruling)
                .count(),
            4
        );

        sqlx::query("UPDATE contract_rulings SET contract_refs_json = '[]' WHERE ruling_id = ?")
            .bind(second.ruling_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(reopened
            .load_contract_ruling(&second.ruling_id)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn analysis_candidates_persist_reload_and_replay_idempotently() {
        use bar_contract::{analyze_corpus, ArtifactText};

        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let first_text = "# Cache policy\n\n`Cache` means an in-memory layer.\n\nThe cache MUST retain entries.\n";
        let second_text = "# Storage policy\n\n`Cache` means the durable record.\n\nThe cache MUST NOT retain entries.\n";
        write_file(&root, "README.md", first_text.as_bytes());
        write_file(&root, "docs/storage.md", second_text.as_bytes());

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

        let artifact_text = |path: &str, text: &str| {
            let artifact = inventory
                .artifacts
                .iter()
                .find(|artifact| artifact.logical_path == path)
                .unwrap();
            ArtifactText::new(
                artifact.artifact_id(&revision_id),
                path,
                artifact.content_sha256.parse().unwrap(),
                text,
            )
            .unwrap()
        };
        let analysis = analyze_corpus(&[
            artifact_text("README.md", first_text),
            artifact_text("docs/storage.md", second_text),
        ])
        .unwrap();
        assert_eq!(analysis.hierarchy.len(), 2);
        assert_eq!(analysis.glossary.len(), 2);
        assert_eq!(analysis.conflicts.len(), 1);

        store
            .persist_contracts(&target_id, &revision_id, &analysis.claims, T0 + 1)
            .await
            .unwrap();
        let first = store
            .persist_analysis_candidates(&target_id, &revision_id, &analysis, T0 + 2)
            .await
            .unwrap();
        let replay = store
            .persist_analysis_candidates(&target_id, &revision_id, &analysis, T0 + 3)
            .await
            .unwrap();
        assert_eq!(
            first,
            CandidatePersistence {
                hierarchy_inserted: 2,
                glossary_inserted: 2,
                conflicts_inserted: 1,
            }
        );
        assert_eq!(replay, CandidatePersistence::default());

        let loaded = store.load_analysis_candidates(&revision_id).await.unwrap();
        assert_eq!(loaded.hierarchy, analysis.hierarchy);
        assert_eq!(loaded.glossary, analysis.glossary);
        assert_eq!(loaded.glossary_ambiguities, analysis.glossary_ambiguities);
        assert_eq!(loaded.conflicts.len(), 1);
        assert_eq!(
            loaded.conflicts[0].shared_subject,
            "the cache retain entries"
        );
        let chain = store.load_audit_chain().await.unwrap();
        chain.verify().unwrap();
        assert_eq!(
            chain.len(),
            7,
            "register + revision + scan pair + two contracts + one conflict"
        );

        sqlx::query("UPDATE glossary_candidates SET definition = 'forged definition'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .persist_analysis_candidates(&target_id, &revision_id, &analysis, T0 + 4)
            .await
            .is_err());

        sqlx::query("UPDATE contract_conflict_candidates SET status = 'unknown'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.load_analysis_candidates(&revision_id).await.is_err());
    }

    #[tokio::test]
    async fn phase_three_golden_corpus_round_trips_expected_candidates() {
        use bar_contract::{analyze_corpus, ArtifactText};

        let root = std::fs::canonicalize(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/phase-3-contract-corpus"),
        )
        .unwrap();
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("expected.json")).unwrap()).unwrap();
        let expected_strings = |field: &str| {
            expected[field]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };

        let (store, _dir) = temp_store().await;
        let target_id = store
            .register_target(&tree_target(&root), T0)
            .await
            .unwrap()
            .target_id;
        let revision_id = store
            .record_revision(&target_id, &revision("golden-corpus", None), T0)
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

        let sources = expected_strings("source_files")
            .into_iter()
            .map(|path| {
                let artifact = inventory
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.logical_path == path)
                    .unwrap();
                ArtifactText::new(
                    artifact.artifact_id(&revision_id),
                    &path,
                    artifact.content_sha256.parse().unwrap(),
                    std::fs::read_to_string(root.join(&path)).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let analysis = analyze_corpus(&sources).unwrap();
        let mut statements = analysis
            .claims
            .iter()
            .map(|claim| claim.statement.clone())
            .collect::<Vec<_>>();
        statements.sort();
        let mut expected_statements = expected_strings("statements");
        expected_statements.sort();

        assert_eq!(statements, expected_statements);
        assert_eq!(
            analysis.hierarchy.len() as u64,
            expected["hierarchy_count"].as_u64().unwrap()
        );
        assert_eq!(
            analysis.glossary.len() as u64,
            expected["glossary_count"].as_u64().unwrap()
        );
        assert_eq!(
            analysis.glossary_ambiguities.len() as u64,
            expected["glossary_ambiguity_count"].as_u64().unwrap()
        );
        assert_eq!(
            analysis
                .conflicts
                .iter()
                .map(|conflict| conflict.shared_subject.clone())
                .collect::<Vec<_>>(),
            expected_strings("conflict_subjects")
        );

        store
            .persist_contracts(&target_id, &revision_id, &analysis.claims, T0 + 1)
            .await
            .unwrap();
        store
            .persist_analysis_candidates(&target_id, &revision_id, &analysis, T0 + 2)
            .await
            .unwrap();
        let mut stored_statements = store
            .load_contracts(&revision_id)
            .await
            .unwrap()
            .into_iter()
            .map(|contract| contract.claim.statement)
            .collect::<Vec<_>>();
        stored_statements.sort();
        assert_eq!(stored_statements, expected_statements);
        let stored = store.load_analysis_candidates(&revision_id).await.unwrap();
        assert_eq!(stored.hierarchy.len(), analysis.hierarchy.len());
        assert_eq!(stored.glossary, analysis.glossary);
        assert_eq!(stored.glossary_ambiguities, analysis.glossary_ambiguities);
        assert_eq!(stored.conflicts, analysis.conflicts);
    }

    #[tokio::test]
    async fn analysis_candidate_persistence_validates_before_writing() {
        use bar_contract::{analyze_corpus, ArtifactText};

        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let text = "# Policy\n\n`Daemon` means the monitored process.\n\nThe daemon MUST stop.\n";
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
        let mut analysis = analyze_corpus(&[source]).unwrap();
        store
            .persist_contracts(&target_id, &revision_id, &analysis.claims, T0 + 1)
            .await
            .unwrap();
        analysis.hierarchy[0].child_fingerprint = Sha256Digest::from_bytes([9; 32]);

        assert!(store
            .persist_analysis_candidates(&target_id, &revision_id, &analysis, T0 + 2)
            .await
            .is_err());
        let hierarchy: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM contract_hierarchy_candidates")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        let glossary: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM glossary_candidates")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!((hierarchy, glossary), (0, 0));
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
