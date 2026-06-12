-- join_keys: the off-cloud / non-attested identity proof (design §4.1c). A
-- bearer secret, stored only as a hash; scoped, capped, revocable. auto_issue
-- defaults to 0 (false) -> joins via this key require manual approval.
CREATE TABLE join_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    secret_hash BLOB    NOT NULL UNIQUE,
    groups      TEXT    NOT NULL DEFAULT '[]',  -- JSON array of group names
    sub_range   TEXT    NOT NULL DEFAULT '',    -- optional pool sub-range name
    max_uses    INTEGER NOT NULL DEFAULT 1,     -- 0 = unlimited (reusable)
    used_count  INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER NOT NULL DEFAULT 0,     -- unix ns; 0 = no expiry
    auto_issue  INTEGER NOT NULL DEFAULT 0,     -- 0 = manual approval required
    ephemeral   INTEGER NOT NULL DEFAULT 0,
    state       TEXT    NOT NULL DEFAULT 'active', -- active | revoked
    created_at  INTEGER NOT NULL
);

-- enrollments: one row per enrollment attempt; the PENDING queue and the issued
-- result both live here.
CREATE TABLE enrollments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    enrollment_id TEXT    NOT NULL UNIQUE,       -- gateway-issued ticket id
    device_name   TEXT    NOT NULL,
    pubkey_hash   TEXT    NOT NULL,
    pubkey        BLOB    NOT NULL,              -- 65-byte P256 point (to issue at approval)
    method        TEXT    NOT NULL,
    join_key_id   INTEGER NOT NULL DEFAULT 0,
    groups        TEXT    NOT NULL DEFAULT '[]',
    status        TEXT    NOT NULL,              -- pending | issued | denied
    cert_pem      BLOB,
    overlay_ip    TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    decided_at    INTEGER NOT NULL DEFAULT 0,
    approver      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX idx_enrollments_status ON enrollments(status);
