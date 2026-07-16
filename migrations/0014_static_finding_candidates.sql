-- Phase 7: immutable, revision-bound shadow static-finding candidates.
--
-- These records preserve detector output for review and later lifecycle work.
-- They do not confer repair authority or represent an adjudicated finding.

CREATE TABLE static_finding_candidates (
    fingerprint                 TEXT   PRIMARY KEY CHECK(length(fingerprint) = 64),
    kind                        TEXT   NOT NULL,
    contract_id                 TEXT   NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
    target_id                   TEXT   NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    revision_id                 TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    contract_fingerprint        TEXT   NOT NULL CHECK(length(contract_fingerprint) = 64),
    source_artifact_id          TEXT   NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    source_start_offset         INTEGER NOT NULL CHECK(source_start_offset >= 0),
    source_end_offset           INTEGER NOT NULL CHECK(source_end_offset > source_start_offset),
    source_exact_text_sha256    TEXT   NOT NULL CHECK(length(source_exact_text_sha256) = 64),
    missing_references_json     TEXT   NOT NULL,
    created_at_ms               BIGINT NOT NULL
);

CREATE INDEX idx_static_finding_candidates_revision
    ON static_finding_candidates(target_id, revision_id);
