-- Host architecture (per-arch release URL support): the pilot reports runtime.GOOS/GOARCH
-- at enrollment and on each heartbeat, and Core records it on the enrollment row so the
-- per-host bundle (assembleBundle, which already has the enrollment) can stamp the artifact
-- matching the host's arch. Empty = unknown (a pre-arch enrollment or an old pilot that does
-- not report yet) → treated as the historical linux/amd64 default at release lookup, so
-- existing hosts keep working until their (upgraded) pilot reports a real arch on heartbeat.
ALTER TABLE enrollments ADD COLUMN goos   TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollments ADD COLUMN goarch TEXT NOT NULL DEFAULT '';
