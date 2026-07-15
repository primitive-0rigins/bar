-- Phase 4: immutable, evidence-bound operator contract rulings.

CREATE TABLE contract_rulings (
    ruling_id                       TEXT PRIMARY KEY,
    target_id                       TEXT NOT NULL REFERENCES targets(target_id) ON DELETE CASCADE,
    context_evidence_id             TEXT NOT NULL REFERENCES scope_context_evidence(evidence_id) ON DELETE CASCADE,
    contract_refs_json              TEXT NOT NULL,
    chosen_interpretation           TEXT NOT NULL CHECK(length(chosen_interpretation) BETWEEN 1 AND 4096),
    rejected_interpretations_json   TEXT NOT NULL,
    rationale                       TEXT NOT NULL CHECK(length(rationale) BETWEEN 1 AND 8192),
    scope_json                      TEXT NOT NULL,
    effective_from_ms               BIGINT NOT NULL,
    expires_at_ms                   BIGINT,
    operator_id                     TEXT NOT NULL CHECK(length(operator_id) BETWEEN 1 AND 255),
    created_at_ms                   BIGINT NOT NULL,
    CHECK(expires_at_ms IS NULL OR expires_at_ms >= effective_from_ms)
);

CREATE TABLE contract_ruling_contracts (
    ruling_id    TEXT NOT NULL REFERENCES contract_rulings(ruling_id) ON DELETE CASCADE,
    contract_id  TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
    PRIMARY KEY(ruling_id, contract_id)
);

CREATE TABLE contract_ruling_supersessions (
    superseding_ruling_id TEXT NOT NULL REFERENCES contract_rulings(ruling_id) ON DELETE CASCADE,
    superseded_ruling_id  TEXT NOT NULL UNIQUE REFERENCES contract_rulings(ruling_id) ON DELETE CASCADE,
    created_at_ms          BIGINT NOT NULL,
    PRIMARY KEY(superseding_ruling_id, superseded_ruling_id),
    CHECK(superseding_ruling_id <> superseded_ruling_id)
);

CREATE INDEX idx_contract_rulings_context
    ON contract_rulings(target_id, context_evidence_id, effective_from_ms);
