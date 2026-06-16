-- nonce_replays: shared single-use guard for enrollment nonces (HA fix, ADR 0007 Phase 4).
-- The PRIMARY KEY on nonce makes INSERT … ON CONFLICT DO NOTHING the atomic check-and-record;
-- expires_at lets a periodic sweep bound the table size.
CREATE TABLE nonce_replays (
    nonce      TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE INDEX idx_nonce_replays_expires ON nonce_replays(expires_at);
