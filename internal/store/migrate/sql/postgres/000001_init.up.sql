-- keys: references to signing keys (CA, config-signing, release). The private
-- key material never lives here — only its backend pointer + public key.
CREATE TABLE keys (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    kind       TEXT    NOT NULL,            -- ca | config-signing | release
    backend    TEXT    NOT NULL,            -- kms | softhsm | local
    uri        TEXT    NOT NULL DEFAULT '', -- KMS ARN / PKCS#11 URI / path
    curve      TEXT    NOT NULL DEFAULT '',
    public_key BYTEA,
    state      TEXT    NOT NULL DEFAULT 'staged', -- staged|active|draining|retired
    created_at BIGINT  NOT NULL             -- unix nanoseconds (portable)
);

-- audit_log: append-only, hash-chained. Each row commits to the previous row's
-- hash, so any mutation/reorder/truncation breaks verification (M2.2).
CREATE TABLE audit_log (
    seq       BIGINT  PRIMARY KEY,          -- explicit, monotonic, part of the hash
    ts        BIGINT  NOT NULL,             -- unix nanoseconds
    actor     TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    target    TEXT    NOT NULL DEFAULT '',
    details   TEXT    NOT NULL DEFAULT '',
    prev_hash BYTEA   NOT NULL,             -- 32 bytes (zeros for the genesis row)
    hash      BYTEA   NOT NULL              -- 32 bytes
);
