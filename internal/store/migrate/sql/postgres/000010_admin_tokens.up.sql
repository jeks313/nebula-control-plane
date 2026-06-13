-- admin_tokens: non-interactive machine credentials for the admin API (A0.8). See
-- the sqlite copy for the design notes; this is the Postgres-typed equivalent.
CREATE TABLE admin_tokens (
    id           TEXT    PRIMARY KEY,
    name         TEXT    NOT NULL,
    principal    TEXT    NOT NULL,
    roles        TEXT    NOT NULL DEFAULT '[]',
    created_by   TEXT    NOT NULL DEFAULT '',
    created_at   BIGINT  NOT NULL,
    expires_at   BIGINT  NOT NULL DEFAULT 0,
    last_used_at BIGINT  NOT NULL DEFAULT 0,
    revoked_at   BIGINT  NOT NULL DEFAULT 0
);

CREATE INDEX idx_admin_tokens_name ON admin_tokens(name);
