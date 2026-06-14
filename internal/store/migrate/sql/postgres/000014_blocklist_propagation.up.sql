-- M7.1b fast blocklist propagation. See the sqlite copy for the design notes.
ALTER TABLE rollouts ADD COLUMN lane TEXT NOT NULL DEFAULT 'policy';

ALTER TABLE heartbeats ADD COLUMN applied_blocklist_version INTEGER NOT NULL DEFAULT 0;
