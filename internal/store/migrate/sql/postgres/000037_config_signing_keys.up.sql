-- config_signing_keys: the CONFIG-SIGNING-key trust registry for online config-key rotation
-- (design §4.6/§4.8, impl M8.5). The config-signing key signs the JWS config bundle that Pilot
-- PINS and verifies before trusting anything inside; it is a co-equal TCB root, DISTINCT from the
-- CA. Rotation uses the identical staged->active->draining->retired overlap the CA uses (internal/ca):
-- stage K2 (trusted, advertised in every bundle's config_signing_keys), distribute [K1,K2] to the
-- fleet and confirm 100% adoption, cut signing over to K2 (active), then retire K1 once the whole
-- LIVE fleet trusts K2. Each row is one config-signing key in that lifecycle. Unlike ca_certs a row
-- holds a RAW P256 public key (not a cert) and has NO not_after (a bare pubkey never expires); the
-- fingerprint is wire.PubkeyHash(pub) = base64url(sha256(pub)), the SAME value stamped as the JWS Kid.
-- The state machine + invariants live in internal/configkey; the schema enforces AT MOST ONE active
-- key (the signing key) via the partial unique index below.
CREATE TABLE config_signing_keys (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,            -- human label, e.g. "config-2026"
    fingerprint TEXT    NOT NULL UNIQUE,            -- wire.PubkeyHash(pub) = base64url(sha256(pub)); also the JWS Kid (case-sensitive)
    pub_pem     TEXT    NOT NULL,                   -- SubjectPublicKeyInfo PEM of the P256 config-signing PUBLIC key
    kms_key_id  TEXT    NOT NULL DEFAULT '',        -- how to reach its signing backend (KMS ARN / PKCS#11 URI / "software"); empty = trust-only
    state       TEXT    NOT NULL,                   -- staged | active | draining | retired
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  BIGINT  NOT NULL DEFAULT 0,         -- unix ns
    updated_at  BIGINT  NOT NULL DEFAULT 0,         -- unix ns
    key_deletion_scheduled_at BIGINT NOT NULL DEFAULT 0, -- unix ns; 0 = not scheduled (M8.4-style key deletion)
    key_deletion_date         BIGINT NOT NULL DEFAULT 0  -- unix ns; backend-returned deletion date
);

-- At most ONE active config-signing key at a time (the signing key), enforced at the DB layer so a
-- racing cut-over can never leave two.
CREATE UNIQUE INDEX ux_config_signing_keys_one_active ON config_signing_keys(state) WHERE state = 'active';
CREATE INDEX idx_config_signing_keys_state ON config_signing_keys(state);
