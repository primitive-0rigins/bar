-- Phase 7: aggregated shadow documentation-conflict findings.
--
-- A documentation-conflict finding is the stable, cross-revision aggregation of
-- one glossary term carrying two or more conflicting definitions, promoted from
-- the persisted glossary candidates (migration 0006) via the same ambiguity
-- equivalence the extraction layer uses (`bar_contract::glossary_ambiguities`).
-- Its identity is the revision-independent fingerprint (spec Appendix H.5),
-- scoped to one target. The identity columns (normalized_term and the sorted set
-- of distinct lowercased-definition hashes in definition_hashes_json) are
-- immutable; promotion advances only last_seen_*, and an operator's
-- false-positive correction sets status. A documentation conflict is provisional
-- (spec §"Operator can resolve a documentation conflict through a versioned
-- ruling") so it starts at `detected` and is never a definitive label.
--
-- It is a separate table, not a column-generalized reuse of static_findings or
-- contradiction_findings, because a documentation conflict's identity (one term
-- + its distinct definition hashes) has no overlap with the other classes'. A
-- shared abstraction is deferred until several detector classes prove a real
-- commonality rather than a guessed one.

CREATE TABLE documentation_conflict_findings (
    target_id                TEXT   NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    finding_fingerprint      TEXT   NOT NULL CHECK(length(finding_fingerprint) = 64),
    normalized_term          TEXT   NOT NULL CHECK(length(normalized_term) BETWEEN 1 AND 80),
    definition_hashes_json   TEXT   NOT NULL,
    status                   TEXT   NOT NULL DEFAULT 'detected',
    first_seen_revision_id   TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    last_seen_revision_id    TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    first_seen_at_ms         BIGINT NOT NULL,
    last_seen_at_ms          BIGINT NOT NULL,
    PRIMARY KEY (target_id, finding_fingerprint)
);

CREATE INDEX idx_documentation_conflict_findings_last_seen
    ON documentation_conflict_findings(target_id, last_seen_revision_id);
