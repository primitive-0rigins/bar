-- Phase 4: revision- and artifact-bound scope context evidence.

CREATE TABLE scope_context_evidence (
    evidence_id       TEXT   PRIMARY KEY,
    target_id         TEXT   NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    revision_id       TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    context_json      TEXT   NOT NULL,
    artifact_id       TEXT   NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    start_offset      INTEGER NOT NULL CHECK(start_offset >= 0),
    end_offset        INTEGER NOT NULL CHECK(end_offset > start_offset),
    exact_text_sha256 TEXT   NOT NULL CHECK(length(exact_text_sha256) = 64),
    observed_at_ms    BIGINT NOT NULL,
    created_at_ms     BIGINT NOT NULL,
    UNIQUE(revision_id, context_json, artifact_id, start_offset, end_offset, exact_text_sha256, observed_at_ms)
);

CREATE INDEX idx_scope_context_evidence_target
    ON scope_context_evidence(target_id, observed_at_ms);
