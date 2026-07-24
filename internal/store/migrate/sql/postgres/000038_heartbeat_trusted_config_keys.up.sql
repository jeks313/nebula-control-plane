-- M8.5 config-key-rotation adoption tracking (design §4.6/§4.8): each host reports on its heartbeat
-- the set of config-signing-key fingerprints it currently trusts (from its VERIFIED applied bundle's
-- config_signing_keys UNION its permanent pinned key). configkey.Registry.AdoptionStatus reads this to
-- gate a config-key cut-over on 100% of LIVE hosts trusting the staged key before signing moves to it
-- (and to gate retire on the fleet trusting the new active key). JSON array of base64url wire.PubkeyHash
-- fingerprints (the SAME value config_signing_keys.fingerprint stores) -- CASE-SENSITIVE, matched exactly
-- (not case-folded like trusted_cas hex). Default '[]' so existing rows + pre-M8.5 pilot beats both read
-- as a valid empty set (counted as not-yet-adopted / fail-closed laggard until the host re-reports).
ALTER TABLE heartbeats ADD COLUMN trusted_config_keys TEXT NOT NULL DEFAULT '[]';
