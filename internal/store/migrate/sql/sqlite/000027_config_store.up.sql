-- config store (ADR 0011 Phase 1, P1.0): the first-class set/get store for the three
-- declarative singletons (policy, cloudtrust, usertrust). Until now the "active config"
-- of each kind was DERIVED — the latest committed dual-control change on the shared
-- approvals ledger. Phase 1 makes the config FIRST-CLASS: enforcement reads this table,
-- and both the single-operator PUT path and the privileged two-person commit path
-- converge here (the single source of truth).
--
-- One row per kind (kind is the primary key). payload is the canonical, validated
-- bytes the kind's Parse accepts. version is a monotonic counter bumped on every Set
-- (Store.Set increments it inside the same tx that writes the audit row). Provenance/
-- hash columns (source, last_applied_hash) are DEFERRED to Phase 2 (no drift yet).
CREATE TABLE config (
    kind       TEXT    NOT NULL PRIMARY KEY,         -- 'policy.publish' | 'cloudtrust.publish' | 'usertrust.publish'
    payload    BLOB    NOT NULL,                      -- canonical, validated config bytes
    version    INTEGER NOT NULL,                      -- monotonic; bumped on every Set
    updated_at INTEGER NOT NULL,                      -- unix nanoseconds
    updated_by TEXT    NOT NULL                       -- actor who last wrote the row
);
