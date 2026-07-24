-- config_signing_keys: the CONFIG-SIGNING-key trust registry for online config-key rotation
-- (design §4.6/§4.8, impl M8.5). See the postgres copy for the full design notes; this is the
-- sqlite-typed equivalent. The config-signing key signs the JWS config bundle Pilot pins; it is a
-- co-equal TCB root DISTINCT from the CA, rotated by the identical staged->active->draining->retired
-- overlap. A row holds a RAW P256 public key (not a cert) and has NO not_after; the fingerprint is
-- wire.PubkeyHash(pub) = base64url(sha256(pub)), the SAME value stamped as the JWS Kid.
CREATE TABLE config_signing_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    fingerprint TEXT    NOT NULL UNIQUE,            -- wire.PubkeyHash(pub); also the JWS Kid (case-sensitive)
    pub_pem     TEXT    NOT NULL,                   -- SubjectPublicKeyInfo PEM of the P256 config-signing PUBLIC key
    kms_key_id  TEXT    NOT NULL DEFAULT '',        -- KMS ARN / PKCS#11 URI / "software"; empty = trust-only
    state       TEXT    NOT NULL,                   -- staged | active | draining | retired
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL DEFAULT 0,         -- unix ns
    updated_at  INTEGER NOT NULL DEFAULT 0,         -- unix ns
    key_deletion_scheduled_at INTEGER NOT NULL DEFAULT 0,
    key_deletion_date         INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX ux_config_signing_keys_one_active ON config_signing_keys(state) WHERE state = 'active';
CREATE INDEX idx_config_signing_keys_state ON config_signing_keys(state);
