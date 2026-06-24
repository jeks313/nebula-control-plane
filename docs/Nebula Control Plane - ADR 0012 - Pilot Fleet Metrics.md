---
title: "ADR 0012 — Pilot Fleet Metrics"
created: 2026-06-24
status: proposed
tags: [nebula, adr, observability, metrics, pilot, heartbeat, prometheus, console, architecture]
---

# ADR 0012 — Pilot Fleet Metrics

**Status:** Proposed — the design and the subsystem map are captured here; the three forks (transport, re-emit granularity, v1 metric scope) are deliberately left **open** for the owner to decide before building. Implementation parked (was the long-standing task #99 / [[Nebula Control Plane - ADR 0007 - Production Deploy|ADR 0007]] "pilot `/metrics`, parked").
**Date:** 2026-06-24
**Decision owners:** Chris Hyde

## Context

Pilot/client **leaf nodes are the last observability gap.** Logs already ship from every node (Grafana Alloy → Loki, [[Nebula Control Plane - ADR 0007 - Production Deploy|ADR 0007]] Phase 7c), and harbor's own components (core-api, admin-api, lighthouse, collect, ipam, signer, reaper) all expose Prometheus metrics. But the **pilots** — the fan-out tier where the real scale lives — expose nothing harbor can see centrally. We have shipped observability for everything *except* the most numerous component.

The hard constraint is the **client install**: it must stay a single, dependency-free binary. A pilot must **not** become a Prometheus scrape target — no per-host service discovery, no extra long-lived listener to manage, no node_exporter to distribute and run. The owner's framing: **harbor collects the pilots' metrics and re-emits them** (so the single install stays dependency-free), **and the console shows a fleet overview.**

What the code gives us to work with (grounded against the current tree):

- **Pilots already heartbeat harbor every 60 s.** `POST /v1/heartbeat` → core-api (`internal/coreapi/coreapi.go:383`), mesh-only, authenticated **purely by the source overlay IP** (the cert/mesh binding *is* the auth — nothing in the body is trusted for identity). The handler UPSERTs **one row per host** into the `heartbeats` table. The wire struct (`internal/wire/wire.go:111`) already carries versions/SHAs/health/cert-expiry/GOOS/GOARCH and has a precedent for optional, unused-until-needed fields (`ClockOffsetMs`). Adding an optional metrics payload is a well-trodden, backward-compatible path.
- **Each pilot's nebula already serves Prometheus on `:4280`** (handshakes, tunnels, tx/rx, relays — namespace `nebula`, subsystem `node`), and the rendered firewall *opens that port over the overlay* (`internal/nebulaconfig/template.yml.tmpl`). So harbor *could* reach it today — but pulling it makes every pilot a scrape target again, which is exactly the dependency we're avoiding.
- **`internal/collect` is a false friend.** Despite the name it is the pull-based **enrollment-gateway transport** ([[Nebula Control Plane - ADR 0005 - Pull-Based Enrollment Gateways|ADR 0005]]), instrumented with `ncp_collect_*` about its *own* operation. It is **not** a metrics-aggregation subsystem and must **not** be extended for pilot metrics — that would be a category error.
- **The house re-emit pattern** is the scrape-time `prometheus.Collector`: read the store at each `/metrics` hit and emit derived gauges, registered idempotently on the default registry and exposed via `obs.Mount` on **both** core-api and admin-api. See `internal/ipam/collector.go` ([[Nebula Control Plane - ADR 0010 - IPAM|ADR 0010]]) and `internal/lighthouse/collector.go`.
- **The console never reads Prometheus.** It reads `/admin/v1` JSON only (`ui/src/pages/Dashboard.tsx` polls `/admin/v1/fleet/health` every 15 s; the verdict is computed server-side in `internal/fleet`). So the "console overview" is a **separate delivery path** — a new admin-api endpoint + a dashboard card, not an embedded Grafana.

## Proposed direction — push-on-heartbeat + dual delivery

The realization that dissolves the hard part: **the two outputs want different granularities.**

- **Prometheus `/metrics` → fleet / per-group AGGREGATES.** Bounded cardinality regardless of fleet size, alertable, scales to any N.
- **Console → per-host detail via the admin-api JSON.** The devices endpoint is already keyset-paginated and filterable (`internal/adminapi/adminapi.go:509`), so per-host richness here costs **nothing** in Prometheus cardinality.

Harbor stores the latest sample per host **once** and serves it two ways.

```
pilot:  read own nebula :4280 in-process → curate a small fixed subset
          └─ attach to the heartbeat it already sends (optional wire field)
harbor core-api (handleHeartbeat):
          persist latest sample → host_metrics table (overlay_ip PK, updated-in-place)
          ├─ Prometheus: new scrape-time Collector re-emits ncp_fleet_* AGGREGATES on /metrics
          └─ Console:    new GET /admin/v1/fleet/metrics → aggregates + top-N hosts (JSON)
ui:     useFleetMetrics() hook + a dashboard overview card
reaper: cascade-delete host_metrics rows when it prunes a host (it already deletes heartbeat rows)
```

Pilots gain **zero** new ports, listeners, or scrape exposure; Prometheus gains **zero** new targets (it already scrapes harbor). That is the dependency-free / single-install property the owner is after.

## The three forks (to resolve before building)

### Fork 1 — transport (how a sample gets from pilot to harbor)

| Option | Verdict | One-line |
|---|---|---|
| **A — piggyback on the existing 60 s heartbeat** (optional `wire.HeartbeatRequest` field) | **Recommended** | No new ports/endpoints/SD; mesh-auth for free; backward-compatible; correlated 60 s snapshots. |
| B — harbor pulls each pilot's `:4280` over the overlay | Alternative | Zero pilot/wire change (firewall already allows it), but harbor must do service-discovery + N scrapes and each pilot is effectively a target again — works against the dependency-free goal and scales worse. |
| C — separate `POST /v1/metrics` push endpoint on its own cadence | Rejected (for v1) | More flexible interval, but a new endpoint + auth surface + moving parts for little gain over A. |

### Fork 2 — Prometheus re-emit granularity

| Option | Verdict | One-line |
|---|---|---|
| **A — fleet + per-group aggregates only** | **Recommended** | Cardinality-safe at any scale; per-host richness lives in the console JSON path instead. |
| B — per-host gauges with `{host}`/`{overlay_ip,name}` labels | Alternative | Great Grafana drill-down and fine for the POC's small fleet, but a scale landmine (hosts × metrics series) — would need a fleet-size cap or a feature flag. |

### Fork 3 — metric scope for v1

| Option | Verdict | One-line |
|---|---|---|
| **A — nebula data-plane metrics only** | **Recommended** | tunnels/active peers, handshakes, tx/rx bytes, relay use — all free from nebula's own `:4280`; truly zero new pilot deps. |
| B — also host/system (CPU, memory, disk) | Fast-follow | More operationally useful, but needs real host-metric collection in pilot (gopsutil or `/proc` reads) — better as a later phase once A proves the pipe. |

**Owner's default if "just run with it": A / A / A.**

## The model in detail

- **Pilot side (Fork 1=A, Fork 3=A).** Add a small in-process reader that scrapes the pilot's *own* nebula `:4280` (loopback) each beat, parses the handful of curated series, and fills a new optional `Metrics` field on the heartbeat. No new listener; reuses the existing 60 s cadence and the existing `cachedFileSHA`-style "cheap each beat" discipline. Falls open: if the scrape fails or `:4280` is disabled (the `statsport.go` conflict path), the field is simply omitted.
- **Wire + storage.** Add an optional `Metrics` payload to `wire.HeartbeatRequest` (omitempty → old pilots and old cores interop). New `host_metrics` table (sqlite + postgres migrations), `overlay_ip` PRIMARY KEY, updated-in-place like `heartbeats` (latest sample per host, no time-series sprawl in the control DB — Prometheus is the TSDB). `handleHeartbeat` persists it after the existing UPSERT, keyed by the same authoritative overlay IP.
- **Prometheus re-emit (Fork 2=A).** A new scrape-time `prometheus.Collector` (e.g. `internal/fleetmetrics`) that, at each `/metrics` hit, reads the **fresh** `host_metrics` rows (join the `heartbeats` last-seen stale window, exactly as `ipam/collector.go` does for `netblock_used`) and emits `ncp_fleet_*` **aggregates** — sums, counts, and a few quantile/bucket gauges, plus an optional `{group}` label (bounded). Registered idempotently on core-api + admin-api, same as ipam/lighthouse.
- **Console overview.** New `GET /admin/v1/fleet/metrics` returning the fleet aggregates **plus top-N hosts** (e.g. highest tx, most peers) — computed server-side from `host_metrics`, consistent with the server-owns-truth pattern. OpenAPI schema, a `useFleetMetrics()` hook (poll ~15 s like `useFleetHealth`), and a dashboard overview card.
- **Reaper cascade.** The reaper already deletes a host's `heartbeats` row on reap (`internal/reaper/reaper.go:379`); extend it to drop the `host_metrics` row too (or rely on a FK cascade).

## Phased plan

1. **Wire + storage** — optional `Metrics` on `HeartbeatRequest`; `host_metrics` migrations (sqlite + postgres); persist latest-per-host in `handleHeartbeat`; reaper cascade. *(backward-compatible — old pilots omit it.)*
2. **Pilot collection** — in-process reader of the pilot's own nebula `:4280`, curate the subset, fill the heartbeat field. No new deps. (Fork 3=A.)
3. **Prometheus re-emit** — `ncp_fleet_*` aggregate collector, registered on core-api + admin-api like the others. (Fork 2=A.)
4. **Console overview** — `/admin/v1/fleet/metrics` + OpenAPI + `useFleetMetrics` hook + dashboard card.
5. **Alerts + dashboard + this ADR → accepted** — Prometheus alerts on the new aggregates, a Grafana panel, flip the status, record what shipped.

## Consequences

- **+** The single client install stays **dependency-free**: no scrape target, no extra port/listener, no node_exporter to distribute. Prometheus adds **no new targets** (it already scrapes harbor).
- **+** **Mesh-auth for free** — metrics ride the heartbeat, identity is the overlay IP, no new auth surface.
- **+** **Cardinality-safe** by construction: aggregates to Prometheus, per-host detail to the paginated console JSON.
- **+** Closes the last observability gap; harbor becomes the single fleet-metrics vantage point.
- **−** **60 s granularity** and metrics are only as live as the heartbeat (a silent pilot's sample goes stale with its last-seen — acceptable, and visible via the stale window).
- **−** A **wire-protocol change** (optional, but a new field to version and document in the Protocol Spec) and a new control-DB table.
- **−** Per-host time-series is **not** retained in the control DB by design — if deep per-host history is later wanted, that's the host-label Prometheus path (Fork 2=B) or a real TSDB, a future decision.

## Open questions to resolve before building

These are the **forks above**, left open deliberately (the owner wants to think more):

1. **Transport** — A (push on heartbeat) vs B (harbor pulls `:4280`) vs C (separate push endpoint). *Leaning A.*
2. **Re-emit granularity** — A (fleet/group aggregates) vs B (per-host gauges, with a scale cap). *Leaning A; per-host detail via the console JSON regardless.*
3. **v1 metric scope** — A (nebula data-plane only) vs B (+ host/system CPU/mem/disk). *Leaning A; B as a fast-follow.*
4. Secondary, once the above settle: exact curated metric list and their `ncp_fleet_*` names/units; whether `{group}` labelling is in v1; top-N size and sort for the console; retention/staleness semantics for a reaped host's last sample.

## Relationship to other work

- **[[Nebula Control Plane - ADR 0007 - Production Deploy|ADR 0007]] (observability)** — this is the explicitly-parked "pilot `/metrics`" item; accepting + building this ADR closes that gap.
- **Heartbeat wire protocol / [[Nebula Control Plane - Protocol Spec]]** — the optional `Metrics` field must be documented there and versioned.
- **[[Nebula Control Plane - ADR 0003 - Pilot and Nebula Self-Update and Distribution|ADR 0003]] (rollout lanes)** — if metric-collection config ever needs fleet-wide convergence (enable/disable, change the curated set), the existing `apply_bundle` lane is the vehicle; almost certainly **not** needed for v1 (the subset is compiled into pilot).
- **`internal/collect` ([[Nebula Control Plane - ADR 0005 - Pull-Based Enrollment Gateways|ADR 0005]])** — **naming caution:** this is the enrollment-gateway transport, *not* where pilot metrics belong.
- **`internal/ipam/collector.go` ([[Nebula Control Plane - ADR 0010 - IPAM|ADR 0010]]) + `internal/lighthouse/collector.go`** — the scrape-time `prometheus.Collector` template the re-emit collector follows, including the `heartbeats` stale-window join for "fresh" filtering.
- **`internal/reaper`** — the cascade-delete owner for a reaped host's metrics row.
