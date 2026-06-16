-- signer_breaker + signer_issuance: fleet-wide signing circuit breaker (HA fix, ADR 0007
-- Phase 4). signer_issuance records each issuance for the rolling-window rate count;
-- signer_breaker holds the per-lane open latch (once tripped, stays open until an operator
-- resets). Shared across ≥2 Core processes so the ceiling is fleet-wide and a trip halts
-- every Core.
CREATE TABLE signer_breaker (
    lane      TEXT    PRIMARY KEY,
    open      BOOLEAN NOT NULL DEFAULT FALSE,
    opened_at BIGINT  NOT NULL DEFAULT 0
);

CREATE TABLE signer_issuance (
    id   BIGSERIAL PRIMARY KEY,
    lane TEXT   NOT NULL,
    ts   BIGINT NOT NULL
);

CREATE INDEX idx_signer_issuance_lane_ts ON signer_issuance(lane, ts);
