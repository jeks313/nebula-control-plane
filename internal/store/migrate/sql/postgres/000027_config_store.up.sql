-- config store (ADR 0011 Phase 1, P1.0): see the sqlite copy for the design notes.
-- Postgres-typed equivalent — one row per kind (kind is the primary key); payload is
-- the canonical, validated config bytes; version is a monotonic counter Store.Set
-- bumps inside the same tx that appends the audit row. Provenance/hash columns are
-- DEFERRED to Phase 2 (no drift yet).
CREATE TABLE config (
    kind       TEXT   NOT NULL PRIMARY KEY,           -- 'policy.publish' | 'cloudtrust.publish' | 'usertrust.publish'
    payload    BYTEA  NOT NULL,                        -- canonical, validated config bytes
    version    BIGINT NOT NULL,                        -- monotonic; bumped on every Set
    updated_at BIGINT NOT NULL,                        -- unix nanoseconds
    updated_by TEXT   NOT NULL                         -- actor who last wrote the row
);
