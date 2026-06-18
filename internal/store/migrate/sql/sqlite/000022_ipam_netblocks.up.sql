-- netblocks (ADR 0010 — IPAM): named, non-overlapping CIDRs carved from the mesh pool.
-- A join source (join-key row, cloud-trust scope, future SSO entry) references a netblock
-- by NAME; the allocator resolves name -> CIDR and fills sequentially within it, so related
-- hosts cluster. Two protected blocks are seeded at genesis: 'central' (kind reserved — the
-- control-plane space holding lighthouse/core + backend headroom) and 'default' (kind default
-- — the bounded fallback an unbound join method draws from). Admin-carved blocks are kind
-- 'named'. CIDRs are stored as text; the non-overlap, in-pool, and no-stranded-allocation
-- invariants are enforced in internal/netblock (the registry), not by the schema.
CREATE TABLE netblocks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    cidr        TEXT    NOT NULL,                    -- "10.44.10.0/24"
    kind        TEXT    NOT NULL,                    -- 'reserved' | 'default' | 'named'
    description TEXT    NOT NULL DEFAULT '',
    protected   INTEGER NOT NULL DEFAULT 0,          -- central/default cannot be deleted (bool 0/1)
    created_at  INTEGER NOT NULL,                    -- unix nanoseconds
    created_by  TEXT    NOT NULL DEFAULT ''
);
