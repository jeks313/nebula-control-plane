-- Device reaper soft-mark (impl 2.12 — the auto-reaping device lifecycle). The reaper is a
-- DESTRUCTIVE, automated subsystem: on a schedule it finds hosts whose cert has lapsed beyond
-- a grace window (so they are already off the mesh), reclaims their leaked overlay IP, prunes
-- their stale heartbeat, and (where the cert is still live) revokes them. Records are
-- SOFT-pruned (kept for history) rather than hard-deleted: reaped_at stamps WHEN a device was
-- reaped (unix ns; 0 = never reaped — also the idempotency guard so a re-run skips it) and
-- reap_reason records WHY ("cert-expired" | "silent"). 0/'' for every existing device.
ALTER TABLE devices ADD COLUMN reaped_at   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN reap_reason TEXT    NOT NULL DEFAULT '';
