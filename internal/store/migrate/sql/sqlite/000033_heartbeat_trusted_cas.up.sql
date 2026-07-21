-- M8.1 CA-rotation adoption tracking (design §4.6): each host reports on its heartbeat
-- the set of CA fingerprints it currently trusts (from its VERIFIED applied ca_bundle).
-- ca.Registry.AdoptionStatus reads this to gate a CA cut-over on 100% of LIVE hosts
-- trusting the staged CA before signing moves to it. JSON array of lowercase-hex sha256
-- fingerprints (the same value ca_certs.fingerprint stores). Default '[]' so existing
-- rows + pre-M8.1 pilot beats both read as a valid empty set (counted as not-yet-adopted).
ALTER TABLE heartbeats ADD COLUMN trusted_cas TEXT NOT NULL DEFAULT '[]';
