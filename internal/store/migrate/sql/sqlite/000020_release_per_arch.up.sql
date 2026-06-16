-- Per-arch release artifacts (ADR 0003 — per-arch release URL support). A release
-- GENERATION can now carry a different (sha256, url) per (goos, goarch), so a single
-- staged generation serves a mixed-arch fleet (linux/amd64 cloud + darwin/arm64 iMac).
--
-- The parent nebula_versions / pilot_versions row remains the DEFAULT artifact: its new
-- goos/goarch columns default to linux/amd64, so every existing row is unchanged and keeps
-- serving exactly as before. The *_artifacts child tables hold the OTHER platforms for a
-- generation; coreapi serves each host the artifact matching its reported goos/goarch, and
-- falls back to leaving the host alone when its arch isn't registered (never a wrong binary).
ALTER TABLE nebula_versions ADD COLUMN goos   TEXT NOT NULL DEFAULT 'linux';
ALTER TABLE nebula_versions ADD COLUMN goarch TEXT NOT NULL DEFAULT 'amd64';
ALTER TABLE pilot_versions  ADD COLUMN goos   TEXT NOT NULL DEFAULT 'linux';
ALTER TABLE pilot_versions  ADD COLUMN goarch TEXT NOT NULL DEFAULT 'amd64';

CREATE TABLE nebula_artifacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL REFERENCES nebula_versions(id), -- the generation this artifact belongs to
    goos       TEXT    NOT NULL,                                -- runtime.GOOS, e.g. "darwin"
    goarch     TEXT    NOT NULL,                                -- runtime.GOARCH, e.g. "arm64"
    sha256     TEXT    NOT NULL,                                -- hex sha256 of THIS arch's artifact (integrity anchor)
    url        TEXT    NOT NULL,                                -- where the pilot fetches this arch's artifact
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_nebula_artifacts_gen_arch ON nebula_artifacts(version_id, goos, goarch);
CREATE INDEX idx_nebula_artifacts_sha ON nebula_artifacts(sha256);

CREATE TABLE pilot_artifacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL REFERENCES pilot_versions(id),
    goos       TEXT    NOT NULL,
    goarch     TEXT    NOT NULL,
    sha256     TEXT    NOT NULL,
    url        TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_pilot_artifacts_gen_arch ON pilot_artifacts(version_id, goos, goarch);
CREATE INDEX idx_pilot_artifacts_sha ON pilot_artifacts(sha256);
