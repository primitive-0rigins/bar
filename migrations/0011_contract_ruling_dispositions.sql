-- Phase 4: durable non-final operator adjudication outcomes.

ALTER TABLE contract_rulings
    ADD COLUMN disposition TEXT NOT NULL DEFAULT 'chosen'
    CHECK(disposition IN ('chosen', 'deferred', 'rejected', 'request_more_evidence'));
