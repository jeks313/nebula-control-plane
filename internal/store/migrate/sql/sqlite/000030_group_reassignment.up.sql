-- Post-enrollment group reassignment (ADR 0002 / ADR 0013). desired_groups is the
-- control-plane-authoritative target group set; the existing `groups` column stays "the
-- groups the live cert was signed with". groups_generation bumps on every desired change;
-- issued_generation records the generation the live cert was issued at. A host with
-- groups_generation > issued_generation is pending a re-issue (it renews on next heartbeat).
-- reduction_pending_enforcement marks a device whose desired set DROPPED a group: the old,
-- higher-privilege cert stays cryptographically valid until reduction_old_not_after (a unix
-- seconds expiry) or it is revoked (Phase 3) — a durable "advisory until enforced" flag.
ALTER TABLE enrollments ADD COLUMN desired_groups TEXT NOT NULL DEFAULT '[]';
ALTER TABLE enrollments ADD COLUMN groups_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE enrollments ADD COLUMN issued_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE enrollments ADD COLUMN reduction_pending_enforcement BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE enrollments ADD COLUMN reduction_old_not_after BIGINT NOT NULL DEFAULT 0;
-- Backfill (load-bearing): every existing enrollment's desired set EQUALS its issued set —
-- NOT the '[]' default — so the first edit diffs against the real groups, not empty (which
-- would strip all groups). generations stay 0 == 0 (not pending re-issue).
UPDATE enrollments SET desired_groups = groups;
