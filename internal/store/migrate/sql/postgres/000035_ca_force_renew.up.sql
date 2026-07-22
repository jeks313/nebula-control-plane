-- M8.3c accelerated drain: mark a DRAINING CA to force its remaining leaf holders to renew (onto
-- the active CA) in deterministic widening waves, so an operator can drain + retire it in ~a window
-- instead of waiting a full cert lifetime. Both 0 -> no accelerated drain (natural renewal only).
ALTER TABLE ca_certs ADD COLUMN force_renew_started_at BIGINT NOT NULL DEFAULT 0; -- unix ns; 0 = off
ALTER TABLE ca_certs ADD COLUMN force_renew_window_ns  BIGINT NOT NULL DEFAULT 0; -- drain window (ns)
