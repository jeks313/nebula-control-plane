-- gateway_health: runtime health of each pull-based enrollment gateway (ADR 0005). See
-- the sqlite copy for design notes; this is the Postgres-typed equivalent.
CREATE TABLE gateway_health (
    gateway_name         TEXT    NOT NULL PRIMARY KEY,
    last_attempt_at      BIGINT  NOT NULL DEFAULT 0,
    last_success_at      BIGINT  NOT NULL DEFAULT 0,
    last_error           TEXT    NOT NULL DEFAULT '',
    last_error_at        BIGINT  NOT NULL DEFAULT 0,
    consecutive_failures BIGINT  NOT NULL DEFAULT 0,
    updated_at           BIGINT  NOT NULL DEFAULT 0
);
