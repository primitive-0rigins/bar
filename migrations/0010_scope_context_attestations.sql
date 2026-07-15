-- Phase 4: immutable operator corroboration of source-bound scope context.

CREATE TABLE scope_context_attestations (
    evidence_id          TEXT   PRIMARY KEY,
    context_evidence_id  TEXT   NOT NULL REFERENCES scope_context_evidence(evidence_id) ON DELETE CASCADE,
    target_id            TEXT   NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    revision_id          TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    operator_id          TEXT   NOT NULL CHECK(length(operator_id) BETWEEN 1 AND 255),
    rationale            TEXT   NOT NULL CHECK(length(rationale) BETWEEN 1 AND 8192),
    created_at_ms        BIGINT NOT NULL,
    UNIQUE(context_evidence_id, operator_id, rationale)
);

CREATE INDEX idx_scope_context_attestations_target
    ON scope_context_attestations(target_id, created_at_ms);
