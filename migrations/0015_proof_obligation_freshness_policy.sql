-- Phase 6: per-obligation freshness policy.
--
-- Adds the freshness policy that decides how a proof obligation ages across
-- revisions. Existing rows keep the historical behavior by defaulting to
-- `pinned` (stale at any other revision); `reference_stable` obligations stay
-- fresh while their contract's mapped references still resolve (spec §10.4,
-- §400). The column is immutable per obligation, like the rest of the row.

ALTER TABLE proof_obligations
    ADD COLUMN freshness_policy TEXT NOT NULL DEFAULT 'pinned';
