-- Per-join-key enrollment rate quota (impl 3.10): max accepted enrollments per
-- hour for this key. 0 = no rate quota (only max_uses applies). Distinct from
-- the fleet-wide signing circuit-breaker (2.5).
ALTER TABLE join_keys ADD COLUMN quota_per_hour INTEGER NOT NULL DEFAULT 0;
