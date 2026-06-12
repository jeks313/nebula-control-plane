-- Per-join-key enrollment rate quota (impl 3.10).
ALTER TABLE join_keys ADD COLUMN quota_per_hour BIGINT NOT NULL DEFAULT 0;
