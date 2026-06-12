-- lighthouses: the fleet's lighthouse registry (impl 6.8). Core sources the
-- bundle's static_host_map / lighthouse.hosts from the active rows here, so
-- adding, re-addressing, or removing a lighthouse propagates to every host via
-- the next signed bundle. A removed lighthouse is kept as state='removed' (for
-- audit/history) but is no longer advertised. The "discovery is never lost"
-- invariant (6.3) — at least one active lighthouse must always remain — is
-- enforced in internal/lighthouse, not by the schema.
CREATE TABLE lighthouses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    overlay_ip   TEXT    NOT NULL UNIQUE,
    public_addrs TEXT    NOT NULL DEFAULT '[]',     -- JSON array of host:port
    hostname     TEXT    NOT NULL DEFAULT '',        -- optional friendly name
    state        TEXT    NOT NULL DEFAULT 'active',   -- active | removed
    created_at   INTEGER NOT NULL,                    -- unix ns
    updated_at   INTEGER NOT NULL
);

CREATE INDEX idx_lighthouses_state ON lighthouses(state);
