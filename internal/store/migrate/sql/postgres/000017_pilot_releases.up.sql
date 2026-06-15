-- pilot_versions: registry of distributable pilot releases (ADR 0003 Phase 3c). See the
-- sqlite copy for design notes; Postgres-typed equivalent.
CREATE TABLE pilot_versions (
    id         BIGSERIAL PRIMARY KEY,
    version    TEXT    NOT NULL,
    sha256     TEXT    NOT NULL,
    url        TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'candidate',
    note       TEXT    NOT NULL DEFAULT '',
    created_at BIGINT  NOT NULL
);

CREATE INDEX idx_pilot_versions_version ON pilot_versions(version);

ALTER TABLE heartbeats ADD COLUMN applied_pilot_version INTEGER NOT NULL DEFAULT 0;
