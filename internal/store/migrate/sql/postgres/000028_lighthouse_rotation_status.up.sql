-- lighthouse_rotations: rotation run-record for liveness metrics. See the sqlite copy for the
-- design notes; Postgres-typed equivalent. Times are unix seconds.
CREATE TABLE lighthouse_rotations (
    name            TEXT   PRIMARY KEY,
    last_run_at     BIGINT NOT NULL DEFAULT 0,
    last_result     TEXT   NOT NULL DEFAULT '',
    last_rotated_at BIGINT NOT NULL DEFAULT 0,
    last_error      TEXT   NOT NULL DEFAULT '',
    runs_ok         BIGINT NOT NULL DEFAULT 0,
    runs_skip       BIGINT NOT NULL DEFAULT 0,
    runs_fail       BIGINT NOT NULL DEFAULT 0
);
