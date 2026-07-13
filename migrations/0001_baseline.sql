-- Phase 0 baseline schema.
--
-- The audit log is the durable, DB-indexed form of the hash-chained audit
-- record (bar-audit). In V1 the relational store is authoritative and this row
-- is written in the same transaction as the workflow change it records
-- (spec §6.2, §19). Types are chosen to be portable across SQLite and
-- PostgreSQL; BIGINT holds the millisecond timestamp without 32-bit overflow.

CREATE TABLE audit_log (
    seq            BIGINT PRIMARY KEY,
    prev_hash      TEXT   NOT NULL,
    category       TEXT   NOT NULL,
    actor          TEXT   NOT NULL,
    summary        TEXT   NOT NULL,
    subject        TEXT,
    occurred_at_ms BIGINT NOT NULL,
    hash           TEXT   NOT NULL
);
