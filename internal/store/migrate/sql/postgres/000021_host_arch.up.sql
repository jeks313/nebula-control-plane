-- Host architecture (per-arch release URL support). See the sqlite copy for the design notes;
-- Postgres-typed equivalent. The pilot reports runtime.GOOS/GOARCH; Core records it on the
-- enrollment row for per-host, per-arch bundle stamping. Empty = unknown → linux/amd64 default.
ALTER TABLE enrollments ADD COLUMN goos   TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollments ADD COLUMN goarch TEXT NOT NULL DEFAULT '';
