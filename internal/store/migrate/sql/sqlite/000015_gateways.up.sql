-- gateways: the registry of pull-based enrollment gateways (ADR 0005). Harbor's
-- collector polls the active rows over leaf-pinned mTLS — claim candidates, issue,
-- push results back — so each gateway is an off-mesh sink Harbor drains. cert_pem
-- is the gateway's self-signed server cert; Harbor pins its leaf (SHA-256 of the
-- DER) for the mTLS dial. A removed gateway is kept as state='removed' for
-- audit/history but no longer polled. (No "last active" invariant: removing the
-- last gateway just pauses public enrollment — it cannot sever the mesh.)
CREATE TABLE gateways (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    url        TEXT    NOT NULL,                    -- https://host:port (collect API)
    cert_pem   TEXT    NOT NULL,                    -- pinned server cert (PEM)
    state      TEXT    NOT NULL DEFAULT 'active',   -- active | removed
    created_at INTEGER NOT NULL,                    -- unix ns
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_gateways_state ON gateways(state);
