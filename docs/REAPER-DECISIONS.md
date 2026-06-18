# Device reaper — decisions log (for Chris's review)

The reaper turns today's passive cert-expiry into active reclamation: on a schedule, find
hosts that are gone, reclaim their leaked overlay IPs, prune their stale records, and (where
the cert is still live) revoke them. It is **destructive + automated**, so the defaults are
conservative. R# = the default taken; flagged here for review.

## Conservative defaults (taken)

- **R1 — Trigger = cert EXPIRED + grace.** A host is a reap candidate only once its issued
  cert has lapsed beyond a grace window — i.e. it is **already off the mesh** (nebula refuses
  an expired cert), so reaping is low-risk cleanup, never a kick of a connectable host. Grace
  is ephemeral-aware (the `enrollments.ephemeral` flag): `-reap-ephemeral-grace` (default 1h
  past expiry — torn-down CI/scratch hosts go fast) vs `-reap-grace` (default 168h / 7d past
  expiry for persistent hosts — very conservative).
- **R2 — Optional aggressive trigger OFF by default.** `-reap-silent-after` (default 0 =
  disabled) would also reap a host silent longer than this *even with a still-valid cert*
  (then the revoke matters). Off unless an operator sets it.
- **R3 — Actions per reap:** reclaim the IP (`ipam.Release`); if the cert is still valid at
  reap time, blocklist it (`revocation.Registry.Add`) — moot/skipped for an already-expired
  cert; delete the stale heartbeat (drops it from the fleet view); stamp the device
  `reaped_at` + reason; write an audit entry. Records are **soft-pruned** (kept for history,
  marked reaped) — not hard-deleted.
- **R4 — Never reap:** control-plane / lighthouse hosts (groups via `policy.IsReservedGroup`)
  and anything in the `central` reserved netblock; already-reaped hosts (idempotent); any host
  whose cert is NOT expired (unless R2's aggressive trigger is enabled and fires).
- **R5 — Schedule:** a background loop in **core-api** (holds the signer + revocation +
  allocator), `-reap-interval` default 1h. **Enabled by default but conservative** (R1).
  `-reap-disable` turns it off; `-reap-dry-run` logs what *would* be reaped without acting
  (preview before trusting it).
- **R6 — Observability:** `ncp_reaper_*` metrics (runs, candidates, reaped_total{reason},
  ips_reclaimed_total, errors, last_run_seconds) + a per-reap audit entry (+ a "would-reap"
  audit/log line in dry-run); surfaced in the dashboard (a recent-reaps panel).
- **R7 — Scope:** ephemeral fast / persistent slow (R1). Hard-delete of reaped records, and
  tying IdP-offboarding / renewal-denial to reaping (SSO P4), are deferred follow-ons.

## Defaults taken during the build

- **R8 — Candidate SQL = heartbeats ⋈ issued-enrollment, LEFT JOIN devices.** The candidate query
  inner-joins `heartbeats` to `enrollments` on `overlay_ip` filtered to `status='issued'` (the row
  carrying the live fingerprint / ephemeral flag / groups; overlay_ip is unique per issued host, so
  1:1), and LEFT JOINs `devices` on `name = device_name` to drop already-reaped hosts in SQL
  (`d.reaped_at IS NULL OR d.reaped_at = 0`). A heartbeat with NO matching issued enrollment is
  therefore NOT a candidate (we never reap a host we hold no issue record for). All timestamps are
  unix **nanoseconds** (matching `cert_not_after` / `last_seen` storage).
- **R9 — SQL pre-filter is a coarse superset; Go is authoritative.** The WHERE clause filters on
  `cert_not_after < now - min(persistentGrace, ephemeralGrace)` (the *shortest* grace, so an
  ephemeral host past its short grace is never missed) OR — only when `SilentAfter>0` — `last_seen <
  now - SilentAfter`. The exact, per-row, ephemeral-aware trigger + the never-reap exclusions are
  then re-evaluated in Go per candidate, so a row that slips through the coarse SQL is still held to
  the precise rule. The cert-expired trigger takes precedence over silent when both would fire.
- **R10 — Never-reap exclusions computed in Go, not SQL.** Reserved-group exclusion reuses
  `policy.GrantsReservedGroup` over the JSON-decoded `enrollments.groups` (a malformed groups JSON
  decodes to nil → not excluded on the group basis, which is safe; control-plane groups are written
  by Harbor itself). Central-netblock exclusion parses `overlay_ip` and tests
  `centralPrefix.Contains(ip)`, where the `central` CIDR is resolved ONCE at wiring via
  `netblock.Resolve(ctx, "central")` (an unresolved central → the guard is OFF, logged at startup,
  rather than failing the reaper). Both run after the SQL pre-filter so they cannot be defeated by
  an odd row.
- **R11 — Soft-mark = `devices.reaped_at` (unix ns) + `reap_reason`.** Migration `000026` adds both
  to `devices` (BIGINT/INTEGER `reaped_at NOT NULL DEFAULT 0`, `reap_reason TEXT NOT NULL DEFAULT
  ''`). `reaped_at != 0` is BOTH the history stamp and the idempotency guard; the stamp UPDATE is
  conditioned `WHERE name=? AND reaped_at=0` so a repeat/concurrent run never re-stamps. Records are
  kept (R3), never hard-deleted.
- **R12 — Reap step order + tolerances.** Per host: (1) `ipam.Release` the overlay IP —
  `ipam.ErrNotAllocated` is tolerated as a no-op (already free, e.g. a re-run); (2) revoke the
  fingerprint ONLY when the cert is still valid at reap time (`cert_not_after >= now`), tolerating
  `revocation.ErrAlreadyActive` as success; (3) `DELETE` the heartbeat row; (4) stamp `reaped_at` +
  reason; (5) audit. Any per-host step failure is logged + counted (`ncp_reaper_errors_total`) and
  the run continues; the host is still counted reaped (the next idempotent run reconciles).
- **R13 — Metric label set.** `ncp_reaper_reaped_total` is labelled `{reason}` with exactly two
  values, `cert-expired` and `silent` (low cardinality). `ncp_reaper_candidates` and
  `ncp_reaper_last_run_seconds` are gauges; `ncp_reaper_runs_total`, `ncp_reaper_ips_reclaimed_total`,
  and `ncp_reaper_errors_total` are unlabelled counters. Dry-run increments `runs_total` and sets
  `candidates`/`last_run_seconds` but NEVER the reaped/ips/errors counters (it mutates nothing).
- **R14 — Wiring lives in core-api only.** `cmd/harbor serve.go cmdCoreAPI` starts `reaper.Run` in a
  goroutine bound to the server ctx (joined on shutdown via the same WaitGroup as the audit
  verifier), with a freshly-built resolver-backed allocator + a `revocation.Registry` + the shared
  audit func. Flags: `-reap-disable`, `-reap-dry-run`, `-reap-interval` (1h), `-reap-grace` (168h),
  `-reap-ephemeral-grace` (1h), `-reap-silent-after` (0=off). Effective config is logged at startup
  with the mode (ENABLED / DRY-RUN) prominent. admin-api/collect do not run it.

## Admin-console surface (impl 2.12 UI)

- **R15 — Dashboard "recent reaps" panel sources the audit feed, filtered on action
  `reaper-reap`.** A reaped host's heartbeat is DELETED (R3), so it drops out of the
  heartbeat-driven Devices/fleet list — the natural surface is the audit log, exactly like the
  IPAM "recent grows / exhaustion" panel. The new `RecentReapsCard` (ui/src/components/fleet.tsx,
  wired into ui/src/pages/Dashboard.tsx) reuses the dashboard's existing `useAudit` feed (limit 50,
  same feed the IPAM card filters for `netblock-autogrow`/`netblock-exhausted`) and filters for the
  reaper's per-reap action string `reaper-reap` (the literal in `reaper.reapOne`; the dry-run
  `reaper-would-reap` action is intentionally NOT surfaced — dry-run mutates nothing). It shows host
  (overlay_ip from the detail JSON, falling back to target), reason (`cert-expired` | `silent` as a
  tone chip), a `revoked` chip when the cert was blocklisted, and when (`ts`). The detail JSON
  (`{overlay_ip,reason,ip_reclaimed,revoked}`) is parsed best-effort (a malformed/absent detail
  degrades to target + no chips, never throws). No new endpoint was needed — the existing audit feed
  already carries the row.
- **R16 — Device API exposes `reaped_at` / `reap_reason` for completeness.** Added to the `Device`
  schema in internal/adminapi/openapi.yaml (both `omitempty`/optional, `reaped_at` as date-time) and
  regenerated into ui/src/api/schema.d.ts via `gen:api`. The device list is heartbeat-driven, but
  the soft-mark lives on `devices` (R11), so a new `deviceReapMarks` read (internal/adminapi/
  device_provenance.go) loads `reaped_at`/`reap_reason` from `devices` keyed by name (only rows with
  `reaped_at != 0`), mirroring `deviceProvenance`; `handleDevices` enriches each row by device name.
  Because a reaped host's heartbeat is deleted, a reaped device normally won't appear in the list —
  the field is there for completeness and a future "include reaped" view. Both fields are absent for
  live hosts, so existing responses still conform to the OpenAPI schema (the contract guard passes).
- **R17 — `seed-demo` seeds one sample reap audit row** so the dashboard panel isn't empty in the
  demo, mirroring the IPAM `netblock-autogrow`/`netblock-exhausted` seed rows: a `reaper`-actor
  `reaper-reap` entry for an ephemeral CI host (`ci-runner-03`, overlay 100.64.64.31, `cert-expired`,
  `ip_reclaimed:true`, `revoked:false`). It is audit-only (no heartbeat row for that host — exactly
  the real reaper outcome, and why the reap surfaces via the audit log rather than the fleet list).

<!-- appended as the build lands: R# — <title>. <what + why> -->
