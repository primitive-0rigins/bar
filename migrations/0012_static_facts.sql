-- Phase 5: immutable, artifact-bound static architecture facts.
--
-- A row stores exactly one adapter result for one inventoried artifact. The
-- duplicated target/revision binding is validated by the store on every write
-- and reload; the foreign key alone cannot express that composite invariant.

CREATE TABLE static_facts (
    artifact_id    TEXT   PRIMARY KEY REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    target_id      TEXT   NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    revision_id    TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    facts_json     TEXT   NOT NULL,
    created_at_ms  BIGINT NOT NULL
);

CREATE INDEX idx_static_facts_revision ON static_facts(revision_id);
