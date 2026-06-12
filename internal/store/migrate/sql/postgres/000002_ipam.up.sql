-- devices: one row per enrolled host identity. Lifecycle/state (2.12) is added
-- later; IPAM (2.6) only needs identity here.
CREATE TABLE devices (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    created_at BIGINT  NOT NULL              -- unix nanoseconds
);

-- ip_allocations: sparse — a row exists only while an overlay IP is in use or in
-- quarantine. The UNIQUE(ip) constraint is the concurrency guard: two racing
-- allocators that pick the same IP can't both insert; the loser retries.
CREATE TABLE ip_allocations (
    id               BIGSERIAL PRIMARY KEY,
    ip               TEXT    NOT NULL UNIQUE,
    device_id        BIGINT  NOT NULL REFERENCES devices(id),
    state            TEXT    NOT NULL DEFAULT 'allocated', -- allocated | quarantined
    allocated_at     BIGINT  NOT NULL,
    released_at      BIGINT  NOT NULL DEFAULT 0,
    quarantine_until BIGINT  NOT NULL DEFAULT 0            -- unix ns; 0 when allocated
);

CREATE INDEX idx_ip_alloc_state ON ip_allocations(state, quarantine_until);
