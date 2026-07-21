-- Phase 7: aggregated shadow contradiction findings.
--
-- A contradiction finding is the stable, cross-revision aggregation of two
-- directly opposing contract claims (one required, one prohibited) over the same
-- normalized subject, promoted from the persisted conflict candidates (migration
-- 0006). Its identity is the revision-independent fingerprint (spec Appendix
-- H.5), scoped to one target. The identity columns (the two sorted cited-text
-- hashes and the shared subject) are immutable; promotion advances only
-- last_seen_*, and an operator's false-positive correction sets status. A
-- contradiction is provisional by construction — the static layer cannot see
-- contract scope — so it starts at `detected` and is never a definitive label.
--
-- It is a separate table, not a column-generalized reuse of static_findings,
-- because a contradiction's identity (two opposing claims + subject) has no
-- overlap with a missing-implementation's (one contract's cited text + missing
-- reference set). A shared abstraction is deferred until several detector
-- classes prove a real commonality rather than a guessed one.

CREATE TABLE contradiction_findings (
    target_id                TEXT   NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    finding_fingerprint      TEXT   NOT NULL CHECK(length(finding_fingerprint) = 64),
    left_exact_text_sha256   TEXT   NOT NULL CHECK(length(left_exact_text_sha256) = 64),
    right_exact_text_sha256  TEXT   NOT NULL CHECK(length(right_exact_text_sha256) = 64),
    shared_subject           TEXT   NOT NULL CHECK(length(shared_subject) BETWEEN 1 AND 4096),
    status                   TEXT   NOT NULL DEFAULT 'detected',
    first_seen_revision_id   TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    last_seen_revision_id    TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    first_seen_at_ms         BIGINT NOT NULL,
    last_seen_at_ms          BIGINT NOT NULL,
    PRIMARY KEY (target_id, finding_fingerprint)
);

CREATE INDEX idx_contradiction_findings_last_seen
    ON contradiction_findings(target_id, last_seen_revision_id);
