-- Phase 4: immutable scope/validity declarations and supersession edges.
--
-- Applicability is deliberately not stored: it is derived from these inputs
-- plus an evidence-bound runtime context and evaluation timestamp.

ALTER TABLE contracts
    ADD COLUMN scope_resolved INTEGER NOT NULL DEFAULT 0
    CHECK(scope_resolved IN (0, 1));

ALTER TABLE contracts ADD COLUMN valid_from_ms BIGINT;
ALTER TABLE contracts ADD COLUMN valid_until_ms BIGINT;

CREATE TABLE contract_supersessions (
    superseding_contract_id TEXT   NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
    superseded_contract_id  TEXT   NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
    created_at_ms            BIGINT NOT NULL,
    PRIMARY KEY(superseding_contract_id, superseded_contract_id),
    CHECK(superseding_contract_id <> superseded_contract_id)
);

CREATE INDEX idx_contract_supersessions_superseded
    ON contract_supersessions(superseded_contract_id);
