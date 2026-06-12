-- Latest heartbeat per device (impl 4.6): fleet visibility (4.7) — one row per
-- overlay IP, upserted on each heartbeat.
CREATE TABLE heartbeats (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    overlay_ip             TEXT    NOT NULL UNIQUE,
    device_name            TEXT    NOT NULL,
    pilot_version          TEXT    NOT NULL DEFAULT '',
    nebula_version         TEXT    NOT NULL DEFAULT '',
    cert_not_after         INTEGER NOT NULL DEFAULT 0,  -- unix ns
    applied_bundle_version INTEGER NOT NULL DEFAULT 0,
    clock_offset_ms        INTEGER NOT NULL DEFAULT 0,
    health                 TEXT    NOT NULL DEFAULT '',
    last_seen              INTEGER NOT NULL
);
