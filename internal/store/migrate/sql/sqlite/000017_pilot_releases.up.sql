-- pilot_versions: Harbor's registry of distributable PILOT (agent) releases (ADR 0003
-- Phase 3c) — the mirror of nebula_versions (000016) for the pilot binary. Each row is
-- a release with a monotonic GENERATION (the id) that the rollout engine's "pilot" lane
-- canary-stages across the fleet; the (version, sha256, url) tuple is stamped per-host
-- into the signed bundle, and the pilot fetches+verifies+re-execs into it (Phase 3b).
CREATE TABLE pilot_versions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    version    TEXT    NOT NULL,
    sha256     TEXT    NOT NULL,
    url        TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'candidate',
    note       TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_pilot_versions_version ON pilot_versions(version);

-- The host's applied PILOT-lane generation (mapped from its reported running pilot
-- binary sha), tracked like applied_nebula_version so the pilot lane converges
-- independently.
ALTER TABLE heartbeats ADD COLUMN applied_pilot_version INTEGER NOT NULL DEFAULT 0;
