-- lighthouse_rotations: the run-record the scheduled lighthouse cert-rotation writes (one row
-- per lighthouse name), so harbor can expose rotation LIVENESS as Prometheus metrics
-- (ncp_lighthouse_rotation_last_run_seconds / _runs_total) — the rotation job is a systemd
-- oneshot on harbor, not a scrape target, so it records each run here and core-api/collect
-- surface it on /metrics. last_run_at = any run (skip|ok|fail) => detects a dead timer;
-- last_rotated_at = an ACTUAL rotate+inject+deploy; last_result + last_error = the latest
-- outcome (for the RotationFailed alert); the runs_* counters feed _runs_total{result}. Times
-- are unix SECONDS (so time() - last_run_at = age, matching Prometheus). This is liveness only;
-- the BACKSTOP is ncp_lighthouse_cert_expiry_seconds (read live from the issued lighthouse certs).
CREATE TABLE lighthouse_rotations (
    name            TEXT    PRIMARY KEY,          -- lighthouse device name (e.g. lighthouse-2)
    last_run_at     INTEGER NOT NULL DEFAULT 0,   -- unix seconds of the last rotation-check run (any result)
    last_result     TEXT    NOT NULL DEFAULT '',  -- ok | skip | fail
    last_rotated_at INTEGER NOT NULL DEFAULT 0,   -- unix seconds of the last ACTUAL rotation (0 = never)
    last_error      TEXT    NOT NULL DEFAULT '',  -- error detail when last_result='fail' (else '')
    runs_ok         INTEGER NOT NULL DEFAULT 0,
    runs_skip       INTEGER NOT NULL DEFAULT 0,
    runs_fail       INTEGER NOT NULL DEFAULT 0
);
