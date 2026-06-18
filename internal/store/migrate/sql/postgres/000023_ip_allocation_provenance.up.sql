-- ip_allocation provenance (ADR 0010 — IPAM): every allocation becomes traceable to the
-- netblock it came from and the join method that drove it. See the sqlite copy for the
-- design notes; Postgres-typed equivalent. Defaults keep existing rows valid (netblock_id 0
-- = the legacy/unbound pool; method '' = pre-provenance).
ALTER TABLE ip_allocations ADD COLUMN netblock_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ip_allocations ADD COLUMN method      TEXT   NOT NULL DEFAULT '';
