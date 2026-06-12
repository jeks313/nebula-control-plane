-- approvals: Harbor's reusable dual-control / two-person change record
-- (impl 2.11, first consumer policy publish 6.5). A privileged change is
-- proposed once and committed only after a second, distinct admin signs off.
-- Generic over `kind` so policy publish, bulk revoke (7.2), group grants and
-- CA/key rotation reuse one audited maker-checker workflow. `payload` carries
-- the content being approved (e.g. the firewall policy DSL); `payload_hash` is
-- its SHA-256 so the approved bytes are pinned.
CREATE TABLE approvals (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL,
    target       TEXT    NOT NULL DEFAULT '',
    payload      BLOB    NOT NULL,
    payload_hash BLOB    NOT NULL,
    state        TEXT    NOT NULL DEFAULT 'pending', -- pending | committed | denied | failed
    quorum       INTEGER NOT NULL DEFAULT 2,
    proposer     TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,                   -- unix ns
    decided_at   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_approvals_kind_state ON approvals(kind, state);

-- One sign-off row per (change, actor). The proposer is recorded as the first
-- 'approve' sign-off, so the UNIQUE(change_id, actor) constraint mechanically
-- blocks self-approval: the same identity cannot both propose and approve.
CREATE TABLE approval_signoffs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    change_id  INTEGER NOT NULL REFERENCES approvals(id),
    actor      TEXT    NOT NULL,
    decision   TEXT    NOT NULL,                     -- approve | deny
    created_at INTEGER NOT NULL,
    UNIQUE(change_id, actor)
);
