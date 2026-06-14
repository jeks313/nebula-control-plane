-- M7.1b fast blocklist propagation. A rollout LANE lets a security/blocklist
-- rollout run concurrently with a policy rollout (the engine refused a 2nd active
-- rollout before) — a blocklist kill must never queue behind a policy canary.
-- Existing rollouts default to the 'policy' lane.
ALTER TABLE rollouts ADD COLUMN lane TEXT NOT NULL DEFAULT 'policy';

-- The host's applied BLOCKLIST-lane bundle version, tracked separately from the
-- policy-lane applied_bundle_version so the two lanes converge independently.
ALTER TABLE heartbeats ADD COLUMN applied_blocklist_version INTEGER NOT NULL DEFAULT 0;
