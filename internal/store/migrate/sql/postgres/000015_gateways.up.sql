-- gateways: the pull-based enrollment-gateway registry (ADR 0005). See the sqlite
-- copy for the design notes; this is the Postgres-typed equivalent.
CREATE TABLE gateways (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    url        TEXT    NOT NULL,
    cert_pem   TEXT    NOT NULL,
    state      TEXT    NOT NULL DEFAULT 'active',
    created_at BIGINT  NOT NULL,
    updated_at BIGINT  NOT NULL
);

CREATE INDEX idx_gateways_state ON gateways(state);
