-- M8.5 config-key-rotation adoption tracking (design §4.6/§4.8). See the postgres copy for the full
-- notes. Each host reports the config-signing-key fingerprints it trusts (VERIFIED applied
-- config_signing_keys UNION its pinned key); AdoptionStatus gates the cut-over + retire on 100% of
-- LIVE hosts. JSON array of base64url wire.PubkeyHash fingerprints, matched CASE-SENSITIVELY.
ALTER TABLE heartbeats ADD COLUMN trusted_config_keys TEXT NOT NULL DEFAULT '[]';
