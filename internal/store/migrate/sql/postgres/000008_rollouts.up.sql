-- rollouts: staged canary rollout of a new bundle version (impl 6.6, design
-- §4.4). See the sqlite copy for the design notes; Postgres-typed equivalent.
CREATE TABLE rollouts (
    id              BIGSERIAL PRIMARY KEY,
    description     TEXT    NOT NULL DEFAULT '',
    target_version  BIGINT  NOT NULL,
    prev_version    BIGINT  NOT NULL,
    state           TEXT    NOT NULL DEFAULT 'canary',
    active_wave     BIGINT  NOT NULL DEFAULT 0,
    wave_size       BIGINT  NOT NULL DEFAULT 0,
    min_healthy     BIGINT  NOT NULL DEFAULT 0,
    observe_window  BIGINT  NOT NULL,
    missing_after   BIGINT  NOT NULL,
    wave_started_at BIGINT  NOT NULL DEFAULT 0,
    created_at      BIGINT  NOT NULL,
    updated_at      BIGINT  NOT NULL,
    note            TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE rollout_hosts (
    id         BIGSERIAL PRIMARY KEY,
    rollout_id BIGINT  NOT NULL REFERENCES rollouts(id),
    overlay_ip TEXT    NOT NULL,
    wave       BIGINT  NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'waiting',
    updated_at BIGINT  NOT NULL,
    UNIQUE(rollout_id, overlay_ip)
);

CREATE INDEX idx_rollout_hosts_rollout ON rollout_hosts(rollout_id, wave);
