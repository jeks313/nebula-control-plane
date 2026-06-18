-- Record ephemeral-ness at enrollment time (foundation for the auto-reaping device
-- lifecycle, impl 2.12). See the sqlite copy for the design notes; Postgres-typed
-- equivalent. 0 (false) for every existing/non-ephemeral enrollment.
ALTER TABLE enrollments ADD COLUMN ephemeral BOOLEAN NOT NULL DEFAULT FALSE;
