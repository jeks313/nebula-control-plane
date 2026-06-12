-- join_keys: the off-cloud / non-attested identity proof (design §4.1c). A
-- bearer secret, stored only as a hash; scoped, capped, revocable. auto_issue
-- defaults to false -> joins via this key require manual approval.
CREATE TABLE join_keys (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    secret_hash BYTEA   NOT NULL UNIQUE,
    groups      TEXT    NOT NULL DEFAULT '[]',
    sub_range   TEXT    NOT NULL DEFAULT '',
    max_uses    BIGINT  NOT NULL DEFAULT 1,
    used_count  BIGINT  NOT NULL DEFAULT 0,
    expires_at  BIGINT  NOT NULL DEFAULT 0,
    auto_issue  BOOLEAN NOT NULL DEFAULT FALSE,
    ephemeral   BOOLEAN NOT NULL DEFAULT FALSE,
    state       TEXT    NOT NULL DEFAULT 'active',
    created_at  BIGINT  NOT NULL
);

CREATE TABLE enrollments (
    id            BIGSERIAL PRIMARY KEY,
    enrollment_id TEXT    NOT NULL UNIQUE,
    device_name   TEXT    NOT NULL,
    pubkey_hash   TEXT    NOT NULL,
    pubkey        BYTEA   NOT NULL,
    method        TEXT    NOT NULL,
    join_key_id   BIGINT  NOT NULL DEFAULT 0,
    groups        TEXT    NOT NULL DEFAULT '[]',
    status        TEXT    NOT NULL,
    cert_pem      BYTEA,
    overlay_ip    TEXT    NOT NULL DEFAULT '',
    created_at    BIGINT  NOT NULL,
    decided_at    BIGINT  NOT NULL DEFAULT 0,
    approver      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX idx_enrollments_status ON enrollments(status);
