-- netblocks (ADR 0010 — IPAM): named, non-overlapping CIDRs carved from the mesh pool.
-- See the sqlite copy for the design notes; Postgres-typed equivalent. central/default
-- are seeded at genesis (kind reserved/default, protected); named blocks are admin-carved
-- and bind join sources. The non-overlap + in-pool invariants are enforced in
-- internal/netblock, not by the schema (CIDRs are stored as text).
CREATE TABLE netblocks (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    cidr        TEXT    NOT NULL,                    -- "10.44.10.0/24"
    kind        TEXT    NOT NULL,                    -- 'reserved' | 'default' | 'named'
    description TEXT    NOT NULL DEFAULT '',
    protected   BOOLEAN NOT NULL DEFAULT FALSE,      -- central/default cannot be deleted
    created_at  BIGINT  NOT NULL,                    -- unix nanoseconds
    created_by  TEXT    NOT NULL DEFAULT ''
);
