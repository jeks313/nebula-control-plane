-- Latest heartbeat per device (impl 4.6).
CREATE TABLE heartbeats (
    id                     BIGSERIAL PRIMARY KEY,
    overlay_ip             TEXT    NOT NULL UNIQUE,
    device_name            TEXT    NOT NULL,
    pilot_version          TEXT    NOT NULL DEFAULT '',
    nebula_version         TEXT    NOT NULL DEFAULT '',
    cert_not_after         BIGINT  NOT NULL DEFAULT 0,
    applied_bundle_version BIGINT  NOT NULL DEFAULT 0,
    clock_offset_ms        BIGINT  NOT NULL DEFAULT 0,
    health                 TEXT    NOT NULL DEFAULT '',
    last_seen              BIGINT  NOT NULL
);
