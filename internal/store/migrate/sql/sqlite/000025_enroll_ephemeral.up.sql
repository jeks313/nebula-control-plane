-- Record ephemeral-ness at enrollment time (foundation for the auto-reaping device
-- lifecycle, impl 2.12). The join key carries an `ephemeral` flag (join_keys.ephemeral);
-- from now on a join via an ephemeral key stamps that fact onto the enrollment row so an
-- operator can SEE which hosts are ephemeral and the issue path can shorten their cert TTL.
-- 0 (false) for every existing/non-ephemeral enrollment. Cloud/SSO enrollments are always
-- non-ephemeral for now (ephemeral is a join-key concept).
ALTER TABLE enrollments ADD COLUMN ephemeral INTEGER NOT NULL DEFAULT 0;
