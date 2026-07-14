-- Phase 1: target registry and revision identity (spec §6.1–6.2, Appendix E).
--
-- Schema follows spec Appendix E. Two deliberate, portable choices:
--   * Timestamps are BIGINT epoch milliseconds, matching audit_log rather than
--     the appendix's TEXT, so the store needs no date/time dependency and
--     timestamps stay unambiguous across SQLite and PostgreSQL.
--   * A UNIQUE index on targets(root_locator) is added (additive to the
--     appendix) so registration is idempotent per canonical root: re-registering
--     the same repository returns the existing target rather than a duplicate.

CREATE TABLE targets (
    target_id      TEXT    PRIMARY KEY,
    name           TEXT    NOT NULL CHECK(length(name) BETWEEN 1 AND 255),
    connector_kind TEXT    NOT NULL,
    root_locator   TEXT    NOT NULL,
    status         TEXT    NOT NULL,
    created_at_ms  BIGINT  NOT NULL,
    updated_at_ms  BIGINT  NOT NULL,
    version        INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX idx_targets_root_locator ON targets(root_locator);

CREATE TABLE target_revisions (
    revision_id      TEXT   PRIMARY KEY,
    target_id        TEXT   NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    source_commit    TEXT,
    dirty_hash       TEXT,
    dependency_hash  TEXT,
    config_hash      TEXT,
    build_digest     TEXT,
    deployment_id    TEXT,
    environment      TEXT,
    discovered_at_ms BIGINT NOT NULL,
    UNIQUE(target_id, source_commit, dirty_hash, config_hash, build_digest)
);

CREATE INDEX idx_target_revisions_target ON target_revisions(target_id);
