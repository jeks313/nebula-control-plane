-- approvals: Harbor's reusable dual-control / two-person change record
-- (impl 2.11, first consumer policy publish 6.5). See the sqlite copy for the
-- design notes; this is the Postgres-typed equivalent.
CREATE TABLE approvals (
    id           BIGSERIAL PRIMARY KEY,
    kind         TEXT    NOT NULL,
    target       TEXT    NOT NULL DEFAULT '',
    payload      BYTEA   NOT NULL,
    payload_hash BYTEA   NOT NULL,
    state        TEXT    NOT NULL DEFAULT 'pending',
    quorum       BIGINT  NOT NULL DEFAULT 2,
    proposer     TEXT    NOT NULL,
    created_at   BIGINT  NOT NULL,
    decided_at   BIGINT  NOT NULL DEFAULT 0
);

CREATE INDEX idx_approvals_kind_state ON approvals(kind, state);

CREATE TABLE approval_signoffs (
    id         BIGSERIAL PRIMARY KEY,
    change_id  BIGINT  NOT NULL REFERENCES approvals(id),
    actor      TEXT    NOT NULL,
    decision   TEXT    NOT NULL,
    created_at BIGINT  NOT NULL,
    UNIQUE(change_id, actor)
);
