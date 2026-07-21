-- ca_certs: CA trust-root registry for online CA rotation (design §4.6, impl M8). See the
-- sqlite copy for the design notes; this is the Postgres-typed equivalent.
CREATE TABLE ca_certs (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    fingerprint TEXT    NOT NULL UNIQUE,
    cert_pem    TEXT    NOT NULL,
    kms_key_id  TEXT    NOT NULL DEFAULT '',
    state       TEXT    NOT NULL,
    not_after   BIGINT  NOT NULL,
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  BIGINT  NOT NULL,
    updated_at  BIGINT  NOT NULL
);

CREATE UNIQUE INDEX ux_ca_certs_one_active ON ca_certs(state) WHERE state = 'active';
CREATE INDEX idx_ca_certs_state ON ca_certs(state);
