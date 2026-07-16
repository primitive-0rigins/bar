-- Phase 6: immutable, revision-bound proof-obligation declarations.

CREATE TABLE proof_obligations (
    proof_id                 TEXT   PRIMARY KEY,
    contract_id              TEXT   NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
    target_id                TEXT   NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    revision_id              TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE CASCADE,
    contract_fingerprint     TEXT   NOT NULL,
    required_evidence_json   TEXT   NOT NULL,
    freshness_revision_id    TEXT   NOT NULL REFERENCES target_revisions(revision_id) ON DELETE RESTRICT,
    created_at_ms            BIGINT NOT NULL
);

CREATE INDEX idx_proof_obligations_contract ON proof_obligations(contract_id);
