-- nebula_versions: Harbor's registry of distributable nebula releases (ADR 0003
-- Phase 1c). See the sqlite copy for the design notes; Postgres-typed equivalent.
CREATE TABLE nebula_versions (
    id         BIGSERIAL PRIMARY KEY,
    version    TEXT    NOT NULL,
    sha256     TEXT    NOT NULL,
    url        TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'candidate',
    note       TEXT    NOT NULL DEFAULT '',
    created_at BIGINT  NOT NULL
);

CREATE INDEX idx_nebula_versions_version ON nebula_versions(version);

ALTER TABLE heartbeats ADD COLUMN applied_nebula_version INTEGER NOT NULL DEFAULT 0;
