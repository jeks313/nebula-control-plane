-- gateway_health: runtime health of each pull-based enrollment gateway (ADR 0005),
-- written by harbor-collect's poll loop (one row per gateway, keyed by name) and read
-- by admin-api for the console's Gateways dashboard pane. Separate from the `gateways`
-- registry (config) because this is high-churn runtime state: collect upserts it as its
-- claim/reconcile cycle succeeds or fails, so a wedged gateway (claim timing out, no
-- successful cycle) shows up as a stale last_success_at + climbing consecutive_failures.
CREATE TABLE gateway_health (
    gateway_name         TEXT    NOT NULL PRIMARY KEY,
    last_attempt_at      INTEGER NOT NULL DEFAULT 0,  -- unix ns of the last collect cycle attempt
    last_success_at      INTEGER NOT NULL DEFAULT 0,  -- unix ns of the last error-free cycle
    last_error           TEXT    NOT NULL DEFAULT '', -- last cycle error (truncated)
    last_error_at        INTEGER NOT NULL DEFAULT 0,  -- unix ns of the last failed cycle
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    updated_at           INTEGER NOT NULL DEFAULT 0
);
