-- ip_allocation provenance (ADR 0010 — IPAM): record WHICH netblock an address came from
-- and WHICH join method drove the allocation, so the overlay/heat data can break allocations
-- down per netblock and per method (token | aws-sigv4 | sso | genesis). netblock_id references
-- netblocks(id); 0 = none recorded (legacy/unbound). method '' = pre-provenance. Defaults make
-- this a no-op for any existing row (the poc mesh assumes a fresh genesis anyway).
ALTER TABLE ip_allocations ADD COLUMN netblock_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ip_allocations ADD COLUMN method      TEXT    NOT NULL DEFAULT '';
