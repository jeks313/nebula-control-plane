-- The fingerprint of the CA that signed this host's CURRENT leaf (the cert's Issuer(),
-- byte-identical to ca_certs.fingerprint), stamped at issue and re-stamped on every renewal
-- (it changes when signing cuts over to a new active CA, M8.3). Lets Harbor count live leaves
-- per CA for drain tracking / Retire. Empty on pre-8.3 rows -> ca.LiveDependents falls back to
-- the leaf's true Issuer(), so a pre-8.3 fleet is never miscounted as zero dependents.
ALTER TABLE enrollments ADD COLUMN ca_fingerprint TEXT NOT NULL DEFAULT '';
