-- Per-arch release artifacts (ADR 0003 — per-arch release URL support). See the sqlite copy
-- for the design notes; Postgres-typed equivalent. The parent *_versions row stays the DEFAULT
-- artifact (goos/goarch default to linux/amd64); the *_artifacts child tables hold the other
-- platforms for a generation.
ALTER TABLE nebula_versions ADD COLUMN goos   TEXT NOT NULL DEFAULT 'linux';
ALTER TABLE nebula_versions ADD COLUMN goarch TEXT NOT NULL DEFAULT 'amd64';
ALTER TABLE pilot_versions  ADD COLUMN goos   TEXT NOT NULL DEFAULT 'linux';
ALTER TABLE pilot_versions  ADD COLUMN goarch TEXT NOT NULL DEFAULT 'amd64';

CREATE TABLE nebula_artifacts (
    id         BIGSERIAL PRIMARY KEY,
    version_id BIGINT  NOT NULL REFERENCES nebula_versions(id),
    goos       TEXT    NOT NULL,
    goarch     TEXT    NOT NULL,
    sha256     TEXT    NOT NULL,
    url        TEXT    NOT NULL,
    created_at BIGINT  NOT NULL
);
CREATE UNIQUE INDEX idx_nebula_artifacts_gen_arch ON nebula_artifacts(version_id, goos, goarch);
CREATE INDEX idx_nebula_artifacts_sha ON nebula_artifacts(sha256);

CREATE TABLE pilot_artifacts (
    id         BIGSERIAL PRIMARY KEY,
    version_id BIGINT  NOT NULL REFERENCES pilot_versions(id),
    goos       TEXT    NOT NULL,
    goarch     TEXT    NOT NULL,
    sha256     TEXT    NOT NULL,
    url        TEXT    NOT NULL,
    created_at BIGINT  NOT NULL
);
CREATE UNIQUE INDEX idx_pilot_artifacts_gen_arch ON pilot_artifacts(version_id, goos, goarch);
CREATE INDEX idx_pilot_artifacts_sha ON pilot_artifacts(sha256);
