-- lighthouses: the fleet's lighthouse registry (impl 6.8). See the sqlite copy
-- for the design notes; this is the Postgres-typed equivalent.
CREATE TABLE lighthouses (
    id           BIGSERIAL PRIMARY KEY,
    overlay_ip   TEXT    NOT NULL UNIQUE,
    public_addrs TEXT    NOT NULL DEFAULT '[]',
    hostname     TEXT    NOT NULL DEFAULT '',
    state        TEXT    NOT NULL DEFAULT 'active',
    created_at   BIGINT  NOT NULL,
    updated_at   BIGINT  NOT NULL
);

CREATE INDEX idx_lighthouses_state ON lighthouses(state);
