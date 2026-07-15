-- Phase 2: dependency edges used for incremental reparse planning (spec §8,
-- §21, Appendix E).
--
-- Edges point from the consuming artifact to the artifact it depends on. Both
-- endpoints are revision-scoped ArtifactIds, so a graph is an immutable part of
-- one revision's inventory. Relation kinds are bounded persisted vocabulary;
-- bar-discovery additionally validates their token syntax before insertion.

CREATE TABLE artifact_dependencies (
    from_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    to_artifact_id   TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    relation_kind    TEXT NOT NULL CHECK(length(relation_kind) BETWEEN 1 AND 64),
    PRIMARY KEY(from_artifact_id, to_artifact_id, relation_kind)
);

CREATE INDEX idx_artifact_dependencies_to ON artifact_dependencies(to_artifact_id);
