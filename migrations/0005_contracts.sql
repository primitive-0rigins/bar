-- Phase 3: source-bound shadow contracts (spec §7, Appendix E, Appendix H.1).
--
-- Phase 3 has no active authority. Each discovered contract is revision-bound,
-- starts at low confidence, and must have an exact source row. The additive
-- fingerprint uniqueness constraint makes replay idempotent without changing
-- the canonical UUID ContractId shape.

CREATE TABLE contracts (
    contract_id       TEXT    PRIMARY KEY,
    target_id         TEXT    NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    revision_id       TEXT    NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    parent_contract_id TEXT   REFERENCES contracts(contract_id),
    level             TEXT    NOT NULL,
    normative_kind    TEXT    NOT NULL,
    statement         TEXT    NOT NULL CHECK(length(statement) BETWEEN 1 AND 4096),
    scope_json        TEXT    NOT NULL,
    confidence        TEXT    NOT NULL,
    freshness         TEXT    NOT NULL,
    status            TEXT    NOT NULL,
    fingerprint       TEXT    NOT NULL,
    created_at_ms     BIGINT  NOT NULL,
    version           INTEGER NOT NULL DEFAULT 1,
    UNIQUE(target_id, revision_id, fingerprint)
);

CREATE INDEX idx_contracts_revision ON contracts(revision_id);

CREATE TABLE contract_sources (
    contract_id       TEXT    NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
    artifact_id       TEXT    NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    start_offset      INTEGER NOT NULL CHECK(start_offset >= 0),
    end_offset        INTEGER NOT NULL CHECK(end_offset > start_offset),
    exact_text_sha256 TEXT    NOT NULL CHECK(length(exact_text_sha256) = 64),
    PRIMARY KEY(contract_id, artifact_id, start_offset, end_offset)
);
