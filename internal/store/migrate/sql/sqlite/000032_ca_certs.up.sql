-- ca_certs: the CA trust-root registry for ONLINE CA rotation (design §4.6, impl M8).
-- Nebula hosts trust a BUNDLE of CA certs, which is what makes zero-downtime rotation
-- possible: mint CA2 (staged), distribute [CA1, CA2] trust to every host and confirm 100%
-- adoption, cut signing over to CA2 (active), let leaf certs drain onto CA2 as they renew,
-- then retire CA1 once it has no live dependents and its leaves have expired. Each row is
-- one CA in that lifecycle. Core sources every host bundle's ca_bundle from the NON-RETIRED
-- rows here (staged+active+draining) and signs new leaves with the ACTIVE one. The state
-- machine + the "cannot retire a CA with live dependents" invariant live in internal/ca;
-- the schema enforces AT MOST ONE active CA at a time (the partial unique index below).
CREATE TABLE ca_certs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,            -- human label, e.g. "ca-2026"
    fingerprint TEXT    NOT NULL UNIQUE,            -- nebula cert fingerprint (hex sha256)
    cert_pem    TEXT    NOT NULL,                   -- the CA certificate (public)
    kms_key_id  TEXT    NOT NULL DEFAULT '',        -- how to reach its signing backend (KMS ARN / PKCS#11 URI / "software"); empty = trust-only
    state       TEXT    NOT NULL,                   -- staged | active | draining | retired
    not_after   INTEGER NOT NULL,                   -- CA cert expiry, unix ns (retire-when-expired check)
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,                   -- unix ns
    updated_at  INTEGER NOT NULL
);

-- At most ONE active CA at a time (the signing CA), enforced at the DB layer so a racing
-- cut-over can never leave two active CAs.
CREATE UNIQUE INDEX ux_ca_certs_one_active ON ca_certs(state) WHERE state = 'active';
CREATE INDEX idx_ca_certs_state ON ca_certs(state);
