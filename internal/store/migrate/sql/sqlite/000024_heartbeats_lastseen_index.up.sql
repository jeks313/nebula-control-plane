-- Index for the fresh-heartbeats scan behind the per-netblock `used` utilization
-- (collector + admin-api list): freshAddrs/freshOverlayIPs filter WHERE last_seen >=
-- (now - StaleAfter) to find hosts heartbeated within the fleet stale window. The
-- heartbeats table was unindexed on last_seen and is never pruned, so that scan was a
-- full table scan; this index serves the range predicate.
CREATE INDEX idx_heartbeats_last_seen ON heartbeats(last_seen);
