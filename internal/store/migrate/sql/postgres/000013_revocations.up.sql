-- revocations: the cert blocklist (design §8, impl 7.1). See the sqlite copy for
-- the design notes; this is the Postgres-typed equivalent.
CREATE TABLE revocations (
    id          BIGSERIAL PRIMARY KEY,
    fingerprint TEXT    NOT NULL UNIQUE,
    reason      TEXT    NOT NULL DEFAULT '',
    bulk        BOOLEAN NOT NULL DEFAULT false,
    state       TEXT    NOT NULL DEFAULT 'active',
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  BIGINT  NOT NULL,
    updated_at  BIGINT  NOT NULL
);

CREATE INDEX idx_revocations_state ON revocations(state);

ALTER TABLE enrollments ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
