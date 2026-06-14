-- revocations: the cert blocklist (design §8, impl 7.1). Each row names a Nebula
-- cert FINGERPRINT (hex sha256) to refuse mesh-wide. Core sources every host
-- bundle's pki.blocklist from the active rows here, so a revocation propagates to
-- the healthy fleet via the next signed bundle (3.6/6.4) and is enforced
-- PEER-SIDE: every other node refuses to handshake with a blocklisted fingerprint
-- (design §4.7), so a compromised host cannot un-block itself. A lifted revocation
-- is kept as state='lifted' for audit/history but is no longer distributed. The
-- P10 "cannot blocklist control-plane/lighthouses" invariant and bulk-revoke
-- dual-control (7.2) live in internal/revocation + the admin layer, not the schema.
CREATE TABLE revocations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT    NOT NULL UNIQUE,            -- hex sha256 cert fingerprint
    reason      TEXT    NOT NULL DEFAULT '',
    bulk        INTEGER NOT NULL DEFAULT 0,         -- part of a bulk revoke (7.2)?
    state       TEXT    NOT NULL DEFAULT 'active',  -- active | lifted
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,                   -- unix ns
    updated_at  INTEGER NOT NULL
);

CREATE INDEX idx_revocations_state ON revocations(state);

-- The current cert fingerprint per device, so a host can be blocklisted by name /
-- overlay IP (resolved to its live fingerprint) and so 7.1b/7.3 can target it.
-- Set at issue and on every renewal (the fingerprint rotates with the key).
ALTER TABLE enrollments ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
