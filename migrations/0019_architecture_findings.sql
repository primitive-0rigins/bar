-- Phase 7: conservative architecture-level findings.
CREATE TABLE architecture_findings (
    target_id              TEXT   NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    finding_fingerprint    TEXT   NOT NULL CHECK(length(finding_fingerprint) = 64),
    kind                   TEXT   NOT NULL,
    artifact_id            TEXT   NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    path                   TEXT   NOT NULL,
    symbol                 TEXT,
    line                   BIGINT NOT NULL,
    evidence               TEXT   NOT NULL,
    status                 TEXT   NOT NULL DEFAULT 'detected',
    first_seen_revision_id TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    last_seen_revision_id  TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    first_seen_at_ms       BIGINT NOT NULL,
    last_seen_at_ms        BIGINT NOT NULL,
    PRIMARY KEY (target_id, finding_fingerprint)
);

CREATE INDEX idx_architecture_findings_last_seen
    ON architecture_findings(target_id, last_seen_revision_id);
