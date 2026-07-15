-- Phase 3: durable hierarchy, glossary, and conflict candidates.
--
-- These rows remain proposals with no authority. Conflict status is loaded
-- through a closed validator so an unknown persisted state cannot be exposed as
-- reviewable. Glossary definitions remain separate even when canonical terms
-- match; ambiguity is derived from the preserved rows.

CREATE TABLE contract_hierarchy_candidates (
    child_contract_id TEXT    NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
    heading           TEXT    NOT NULL CHECK(length(heading) BETWEEN 1 AND 512),
    heading_level     INTEGER NOT NULL CHECK(heading_level BETWEEN 1 AND 6),
    artifact_id       TEXT    NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    start_offset      INTEGER NOT NULL CHECK(start_offset >= 0),
    end_offset        INTEGER NOT NULL CHECK(end_offset > start_offset),
    exact_text_sha256 TEXT    NOT NULL CHECK(length(exact_text_sha256) = 64),
    PRIMARY KEY(child_contract_id, artifact_id, start_offset, end_offset)
);

CREATE TABLE glossary_candidates (
    fingerprint       TEXT    PRIMARY KEY,
    target_id         TEXT    NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    revision_id       TEXT    NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    canonical         TEXT    NOT NULL CHECK(length(canonical) BETWEEN 1 AND 80),
    normalized_term   TEXT    NOT NULL CHECK(length(normalized_term) BETWEEN 1 AND 80),
    definition        TEXT    NOT NULL CHECK(length(definition) BETWEEN 1 AND 4096),
    aliases_json      TEXT    NOT NULL,
    artifact_id       TEXT    NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    start_offset      INTEGER NOT NULL CHECK(start_offset >= 0),
    end_offset        INTEGER NOT NULL CHECK(end_offset > start_offset),
    exact_text_sha256 TEXT    NOT NULL CHECK(length(exact_text_sha256) = 64),
    UNIQUE(revision_id, artifact_id, start_offset, end_offset)
);

CREATE INDEX idx_glossary_candidates_term
    ON glossary_candidates(revision_id, normalized_term);

CREATE TABLE contract_conflict_candidates (
    left_contract_id  TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
    right_contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
    shared_subject    TEXT NOT NULL CHECK(length(shared_subject) BETWEEN 1 AND 4096),
    status            TEXT NOT NULL,
    PRIMARY KEY(left_contract_id, right_contract_id),
    CHECK(left_contract_id <> right_contract_id)
);
