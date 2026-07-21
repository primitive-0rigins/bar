-- Phase 7: aggregated shadow static findings.
--
-- A finding is the stable, cross-revision aggregation of one or more detector
-- candidates (migration 0014). Its identity is the revision-independent
-- fingerprint (spec Appendix H.5), scoped to one target. The identity columns
-- (kind, contract_exact_text_sha256, missing_references_json) are immutable;
-- promotion advances only last_seen_* and, in a later increment, status. Status
-- uses the canonical finding lifecycle vocabulary and starts at `detected`.

CREATE TABLE static_findings (
    target_id                   TEXT   NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    finding_fingerprint         TEXT   NOT NULL CHECK(length(finding_fingerprint) = 64),
    kind                        TEXT   NOT NULL,
    contract_exact_text_sha256  TEXT   NOT NULL CHECK(length(contract_exact_text_sha256) = 64),
    missing_references_json     TEXT   NOT NULL,
    status                      TEXT   NOT NULL DEFAULT 'detected',
    first_seen_revision_id      TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    last_seen_revision_id       TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    first_seen_at_ms            BIGINT NOT NULL,
    last_seen_at_ms             BIGINT NOT NULL,
    PRIMARY KEY (target_id, finding_fingerprint)
);

CREATE INDEX idx_static_findings_last_seen
    ON static_findings(target_id, last_seen_revision_id);
