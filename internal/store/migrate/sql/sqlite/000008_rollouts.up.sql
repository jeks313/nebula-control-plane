-- rollouts: staged canary rollout of a new bundle version across the fleet
-- (impl 6.6, design §4.4). A rollout moves hosts from prev_version to
-- target_version in waves (canary first); Core watches heartbeats and either
-- widens to the next wave on convergence or auto-rolls-back + freezes on a
-- failed/missing canary — no operator action. The "current" rollout is the
-- highest id; only one may be active (canary|widening) at a time.
CREATE TABLE rollouts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    description     TEXT    NOT NULL DEFAULT '',
    target_version  INTEGER NOT NULL,
    prev_version    INTEGER NOT NULL,
    state           TEXT    NOT NULL DEFAULT 'canary',  -- canary | widening | completed | rolledback | aborted
    active_wave     INTEGER NOT NULL DEFAULT 0,
    wave_size       INTEGER NOT NULL DEFAULT 0,         -- hosts per post-canary wave; 0 = all remaining
    min_healthy     INTEGER NOT NULL DEFAULT 0,         -- healthy-converged required per wave; 0 = all in wave
    observe_window  INTEGER NOT NULL,                   -- ns to wait for convergence before judging a wave stuck
    missing_after   INTEGER NOT NULL,                   -- ns of heartbeat silence => host considered down
    wave_started_at INTEGER NOT NULL DEFAULT 0,         -- ns the active wave was activated
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    note            TEXT    NOT NULL DEFAULT ''          -- last decision detail (e.g. rollback trigger)
);

-- rollout_hosts: each host's wave assignment + per-host status.
CREATE TABLE rollout_hosts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rollout_id INTEGER NOT NULL REFERENCES rollouts(id),
    overlay_ip TEXT    NOT NULL,
    wave       INTEGER NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'waiting',      -- waiting | converged | failed | reverted
    updated_at INTEGER NOT NULL,
    UNIQUE(rollout_id, overlay_ip)
);

CREATE INDEX idx_rollout_hosts_rollout ON rollout_hosts(rollout_id, wave);
