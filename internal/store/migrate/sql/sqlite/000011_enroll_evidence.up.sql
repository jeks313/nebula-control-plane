-- Cloud-attestation evidence captured at enrollment time (M5). Provider-agnostic so
-- AWS (account/ARN), Azure (subscription/principal), GCP (project/service-account),
-- etc. share one shape. Empty/0 for token-method enrollments.
ALTER TABLE enrollments ADD COLUMN attest_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollments ADD COLUMN attest_account TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollments ADD COLUMN attest_principal TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollments ADD COLUMN attest_region TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollments ADD COLUMN verified_at INTEGER NOT NULL DEFAULT 0;
