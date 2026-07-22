-- M8.4 retirement: track that a RETIRED CA's non-exportable signing key has been scheduled for
-- deletion in its custody backend (KMS), with the actual deletion date the backend returned. The
-- backend enforces a pending window (KMS: 7-30 days) during which the deletion can be cancelled --
-- the safety net before the key is destroyed. Both 0 -> not scheduled.
ALTER TABLE ca_certs ADD COLUMN key_deletion_scheduled_at BIGINT NOT NULL DEFAULT 0; -- unix ns; 0 = not scheduled
ALTER TABLE ca_certs ADD COLUMN key_deletion_date         BIGINT NOT NULL DEFAULT 0; -- unix ns; backend-returned deletion date
