-- Phase 2: artifact inventory (spec §8, Appendix E).
--
-- One row per (revision, logical_path): a revision holds a full snapshot of the
-- target's inventory. Unchanged files carry their content hash forward from the
-- prior revision (they are re-inserted, not re-read — see bar-discovery), so row
-- count grows with revisions while scan cost does not; retention/compaction
-- (spec §19) bounds the growth in a later phase.
--
-- Timestamps are BIGINT epoch milliseconds, consistent with earlier migrations.
-- Dependency edges are added by migration 0004.

CREATE TABLE artifacts (
    artifact_id      TEXT    PRIMARY KEY,
    target_id        TEXT    NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    revision_id      TEXT    NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    logical_path     TEXT    NOT NULL,
    content_sha256   TEXT    NOT NULL,
    media_type       TEXT    NOT NULL,
    artifact_kind    TEXT    NOT NULL,
    source_of_truth  INTEGER NOT NULL CHECK(source_of_truth IN (0, 1)),
    size_bytes       INTEGER NOT NULL,
    modified_at_ms   BIGINT,
    discovered_at_ms BIGINT  NOT NULL,
    UNIQUE(revision_id, logical_path)
);

CREATE INDEX idx_artifacts_revision ON artifacts(revision_id);
