-- sessions: Harbor's own server-side admin sessions (2.11 admin SSO). See the
-- sqlite copy for the design notes; this is the Postgres-typed equivalent.
CREATE TABLE sessions (
    id          TEXT    PRIMARY KEY,
    principal   TEXT    NOT NULL,
    roles       TEXT    NOT NULL DEFAULT '[]',
    idp         TEXT    NOT NULL,
    subject     TEXT    NOT NULL DEFAULT '',
    email       TEXT    NOT NULL DEFAULT '',
    name        TEXT    NOT NULL DEFAULT '',
    csrf_token  TEXT    NOT NULL,
    mfa_at      BIGINT  NOT NULL DEFAULT 0,
    created_at  BIGINT  NOT NULL,
    expires_at  BIGINT  NOT NULL
);

CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
