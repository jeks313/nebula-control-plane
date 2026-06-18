-- Device reaper soft-mark (impl 2.12 — the auto-reaping device lifecycle). See the sqlite copy
-- for the design notes; Postgres-typed equivalent. reaped_at is unix ns (0 = never reaped, also
-- the idempotency guard); reap_reason records why. 0/'' for every existing device.
ALTER TABLE devices ADD COLUMN reaped_at   BIGINT NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN reap_reason TEXT   NOT NULL DEFAULT '';
