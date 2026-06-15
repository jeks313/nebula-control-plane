-- nebula_versions: Harbor's registry of nebula (data-plane) releases it can
-- distribute (ADR 0003 Phase 1c). Each row is a release with a monotonic
-- GENERATION (the id) that the rollout engine's "nebula" lane stages across the
-- fleet, exactly like a bundle version. The (version, sha256, url) tuple is
-- stamped per-host into the signed bundle; the pilot fetches the artifact,
-- verifies it against sha256 (the integrity anchor — the url/CDN need not be
-- trusted), and atomically swaps the binary (Phase 1b). The registry is the
-- catalog a console lists and an operator manages.
CREATE TABLE nebula_versions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,   -- the generation staged on the nebula lane
    version    TEXT    NOT NULL,                     -- human version, e.g. "1.10.3"
    sha256     TEXT    NOT NULL,                     -- hex sha256 of the artifact (integrity anchor)
    url        TEXT    NOT NULL,                     -- where the pilot fetches the artifact
    status     TEXT    NOT NULL DEFAULT 'candidate', -- candidate | current | superseded
    note       TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_nebula_versions_version ON nebula_versions(version);

-- The host's applied NEBULA-lane generation (mapped from its reported running
-- nebula_version), tracked separately like applied_blocklist_version so the nebula
-- lane converges independently of the policy + blocklist lanes.
ALTER TABLE heartbeats ADD COLUMN applied_nebula_version INTEGER NOT NULL DEFAULT 0;
