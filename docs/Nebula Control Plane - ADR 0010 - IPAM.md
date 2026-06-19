---
title: "ADR 0010 — IPAM: Named Netblocks & Per-Join-Method Allocation"
created: 2026-06-17
status: shipped
tags: [nebula, adr, ipam, enrollment, networking, allocation]
---

# ADR 0010 — IPAM: Named Netblocks & Per-Join-Method Allocation

**Status (2026-06-18):** SHIPPED & LIVE on the poc. All five phases are built and merged:
named netblocks with a DB-backed `NetblockResolver` (`internal/netblock`, `internal/ipam`),
per-join-method binding (join-key `sub_range` / cloud-trust `AWSAccount.Netblock` / SSO
usertrust netblock), allocation provenance (`ip_allocations.netblock_id` + `method`),
auto-grow into the buddy, genesis-seeded `central`/`default` reservations, the growth-envelope
`Suggest` placement, live used% utilization, the IPAM admin API (`ipam_ops.go`,
`PermIPAMManage`) + React console page (`ui/src/pages/IPAM.tsx`) + dashboard IPAM panel, and
`ncp_ipam_*` Prometheus gauges. Decision log: `IPAM-DECISIONS.md` (D1–D23). The text below is
the original design rationale; status annotations note where reality moved past the original
plan. Remaining optional refinements are in *Open questions*.
**Date:** 2026-06-17 (shipped 2026-06-18)
**Decision owners:** Chris Hyde (+ a future second approver, per dual-control)

## Context

Harbor allocates an overlay IP for every enrolled host out of one large pool
(`internal/ipam`, `Allocate(ctx, deviceName, subRange)` → sequential first-free over the
whole prefix). Today **every** join path — token join-keys, AWS attestation, and the
future SSO path ([[ADR 0004 - SSO-Driven User Enrollment]]) — converges on
`enrollment.Consumer.issue()` and calls `Allocate(ctx, name, "")` with an **empty**
sub-range (`internal/enrollment/enrollment.go:592`). So the whole fleet is interleaved
sequentially across one flat space, regardless of how a host joined.

The foundations for something better already exist but are **unwired**:

- `ipam.Pool` has a `SubRanges map[string]netip.Prefix` and a `Reserved []netip.Addr`,
  and `Allocate` takes a `subRange` argument — but **no caller ever populates SubRanges**
  (all six construct `Pool{Prefix, QuarantineTTL}` with empty maps).
- `join_keys.sub_range` is a real, persisted column (`000003_enroll`) and is editable —
  but **nothing reads it** at allocation time.
- Genesis assigns the lighthouse (`.1`) and core (`.2`) via `AllocateSpecific`, but those
  are one-off positional reservations, not a durable reserved block.

### Why now

1. **Humans reason about address space.** Sequential global allocation scatters related
   hosts; operators want "everything from the office join-key lives in `10.44.20.0/24`"
   and "this AWS account's hosts cluster together."
2. **Per-join-method scoping is half-built and inert.** The `subRange` plumbing and the
   `join_keys.sub_range` column imply an intent that was never finished.
3. **No reserved space for the control plane.** A blank/regenesis system has no durable
   block protecting lighthouse/core/backend IPs, and no default area distinct from
   carve-able space.

### Current behavior (as built)

*(Pre-ADR baseline, the flat-pool state this ADR replaced — all of these have since been
addressed by the shipped IPAM work.)*

| Concern | Today (pre-ADR) |
|---|---|
| Allocation order | Global sequential first-free over the whole pool |
| Per-join routing | None — all methods pass empty `subRange` |
| Named netblocks | `SubRanges` type exists; never populated; not persisted |
| Join-key → CIDR | `join_keys.sub_range` column exists; never read |
| Cloud-trust → CIDR | `cloudtrust.AWSAccount` has no netblock field |
| Central reservation | Lighthouse/core spot-allocated at genesis; no durable block |
| Default area | No concept — the whole pool is the only area |
| Admin surface | None for address space |
| Provenance | `ip_allocations` doesn't record netblock or join method |

## Decision

Introduce **netblocks** — named CIDRs carved from the mesh pool, persisted in the DB and
managed from a new **IPAM** admin area. Each join source (join-key row, cloud-trust scope
entry, future SSO entry) references a netblock **by name** for a specific CIDR, or falls
back to a **default** netblock. Confirmed decisions:

1. **Sequential fill** everywhere (lowest-free). No randomization. Locality comes from
   *which block* a host draws from, plus sequential fill within it.
2. **Cloud-trust binds per scope** — a netblock attaches to each `cloudtrust.AWSAccount`
   entry (the "scope" shown in the UI), not per-account-globally.
3. **SSO is a distinct join method** ([[ADR 0004 - SSO-Driven User Enrollment]]):
   usertrust entries (AD-group → mesh-groups), peer to join-keys and cloud-trusts. The
   netblock binding was **designed in** here (the `issue()` hook is generic) and is now
   **built** as part of ADR 0004 (code-complete, off by default until SSO is rolled out).
4. **`default` is a fixed-size CIDR** carved at genesis. Named netblocks carve from the
   remaining free space; an unbound join method draws from the bounded `default` block.

## The decision driver (the fork): fixed-size `default` vs complement

Two ways to define the fallback area:

- **(A) Fixed-size `default` block** — genesis carves an explicit, bounded CIDR (e.g.
  `10.44.64.0/18`). Named netblocks come from *separate* free space. Fallback fills only
  within `default`. **← chosen.**
- (B) Complement — `default` = "pool − central − all named carves"; named carves subtract
  from an unbounded fallback. More flexible, no genesis sizing, but `default`'s real
  capacity shifts every time a netblock is carved, which is harder to reason about and to
  render.

We take **(A)**: a bounded `default` block is predictable, easy to visualize, and capacity
planning is explicit. The cost — operators size `default` at genesis and carve named
blocks from the remaining space — is acceptable and matches how people think about subnets.

## The model in detail

A **netblock** is a named, non-overlapping CIDR inside the mesh pool, with a `kind`:

- `reserved` — control-plane space. One seeded at genesis: **`central`** (small, at the
  pool start) holding lighthouse/core and headroom for backends (monitoring, etc.).
  Protected from deletion.
- `default` — the bounded fallback. One seeded at genesis (operator-sized). Protected.
- `named` — admin-carved via the IPAM UI, each bindable to join sources.

```
main mesh pool   10.44.0.0/16
┌──────────────────────────────────────────────────────────────┐
│ central   10.44.0.0/27    reserved (genesis, protected)        │  lighthouse .1, core .2, backends
│ default   10.44.64.0/18   default  (genesis, protected)        │  fallback fill, bounded
│ named "aws-prod"    10.44.10.0/24  → cloud-trust acct 1111…    │  carved from free space
│ named "office-vpn"  10.44.20.0/24  → join-key "office"         │
│ … free / uncarved space (carve more here) …                    │
└──────────────────────────────────────────────────────────────┘
```

**Allocation:** a join method bound to netblock *X* → sequential first-free within *X*
(related hosts cluster). Unbound → sequential first-free within `default`. Central
entities → `central` (genesis). Non-overlap is enforced across all netblocks.

### Per-join-method binding

| Method | Netblock reference | Wiring |
|---|---|---|
| **Join-key** | `join_keys.sub_range` (exists; → rename `netblock` later) | At `enrollment.go:303`, read `jk.Netblock`; thread into `issue(..., jk.Netblock, "token")`. |
| **Cloud-trust** | new `cloudtrust.AWSAccount.Netblock`; returned by `MatchAWS` | At `enrollment.go:383`, thread into `issue(..., netblock, "aws-sigv4")`. Rides the existing `cloudtrust.propose/active` dual-control publish. |
| **SSO** | usertrust entry carries a `Netblock` field | `issue(..., netblock, providerSSO)` — now WIRED (`enrollment.go:601`) as part of ADR 0004; the SSO path is code-complete but off by default until an operator publishes a usertrust config. |

`issue()` gains `(netblockName, method, ephemeral)` and all four call sites
(`enroll-auto`/token, `enroll-attested`/aws-sigv4, `enroll-sso`/sso, and the approve path)
pass their values (`enrollment.go:926`). This is the central change that makes per-method
CIDRs real. *(Shipped 2026-06-18: built across all four methods, including the SSO hook.)*

## Data model & migrations

`gormigrate`, dual SQLite + Postgres, `internal/store/migrate/sql/{postgres,sqlite}/`
(current max `000021`). Append, never edit shipped migrations.

**`000022_ipam_netblocks`**:
```sql
CREATE TABLE netblocks (
  id          BIGSERIAL PRIMARY KEY,           -- INTEGER PK AUTOINCREMENT (sqlite)
  name        TEXT UNIQUE NOT NULL,
  cidr        TEXT NOT NULL,                   -- "10.44.10.0/24"
  kind        TEXT NOT NULL,                   -- 'reserved' | 'default' | 'named'
  description TEXT NOT NULL DEFAULT '',
  protected   BOOLEAN NOT NULL DEFAULT FALSE,  -- central/default cannot be deleted
  created_at  BIGINT NOT NULL,
  created_by  TEXT NOT NULL DEFAULT ''
);
```

**`000023_ip_allocation_provenance`** — add to `ip_allocations`:
```sql
ALTER TABLE ip_allocations ADD COLUMN netblock_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ip_allocations ADD COLUMN method      TEXT   NOT NULL DEFAULT '';  -- token|aws-sigv4|sso|genesis
```
Every allocation becomes traceable to its netblock + join method (powers the overlay's
per-method breakdown).

**Config:** add `Netblock string \`json:"netblock,omitempty"\`` to `cloudtrust.AWSAccount`
(flows through `cloudtrust.propose/active`). Reuse `join_keys.sub_range` as the join-key
netblock reference (optional later rename to `netblock`).

## Allocator changes (`internal/ipam`)

- Replace the static `SubRanges` map with a **`NetblockResolver`** the allocator consults
  at allocation time (keeps `ipam` storage-agnostic; the static map stays available for
  tests/CLI):
  ```go
  type NetblockResolver interface {
      Resolve(ctx context.Context, name string) (netip.Prefix, error) // "" → default
      Carves(ctx context.Context) ([]netip.Prefix, error)             // named CIDRs, for overlap checks
  }
  ```
  A DB-backed impl reads `netblocks` (cached, invalidated on CRUD).
- `Allocate(ctx, deviceName, netblockName, method)` — resolve name→CIDR (empty →
  `default`); sequential `firstFree` within the resolved CIDR; persist `netblock_id` +
  `method`. `firstFree` (`ipam.go:219`) is otherwise unchanged.
- **Auto-grow on exhaustion:** when `firstFree` returns `ErrPoolExhausted` for a `named`
  netblock, attempt to grow into its free immediate buddy (transactional, audited) and
  retry; otherwise return the exhaustion error that denies the enrollment. See *Auto-grow,
  exhaustion & surfacing*.
- **`netblock.Registry`** (mirrors `lighthouse.Registry`): `Add/Update/Remove/List`,
  validating valid IPv4 CIDR inside the pool, non-overlap with existing netblocks, and on
  remove/edit: not `protected` and no stranded live allocations.

## Genesis changes (`internal/genesis`, `cmd/harbor/ca.go`)

- New flags: `-central-cidr` (default first `/27`) and `-default-cidr` (operator-sized,
  the bounded fallback). Seed `central` + `default` protected netblock rows at genesis.
- Lighthouse (`.1`) / core (`.2`) move under `central` (`AllocateSpecific`,
  `method="genesis"`), leaving headroom for monitoring/backends without a ceremony re-run.
- `deploy/prod/bootstrap-genesis.sh`: pass `-central-cidr`/`-default-cidr`; surface them in
  the genesis manifest (which already records `Pool`).

## Admin API & UI

**API** (`internal/adminapi`, following the lighthouse/join-key pattern — `routeTable()` +
new `ipam_ops.go`, RBAC + audit + step-up MFA):
- `GET/POST /admin/v1/ipam/netblocks`, `PATCH/DELETE /admin/v1/ipam/netblocks/{name}`,
  `GET /admin/v1/ipam/allocations?netblock=…` (overlay/heat data),
  `GET /admin/v1/ipam/netblocks/suggest?prefix=N` (growth-aware placement suggestion).
- New `PermIPAMManage` (`rbac.go`) for admin/operator; reads for viewer. Mutations
  step-up + audit. Update `openapi.yaml` (guarded) + regen `ui/src/api/schema.d.ts`.
- Join-key/cloud-trust netblock bindings ride their existing create/update + propose APIs
  (add `netblock` to the relevant schemas).

**UI** (`ui/src/pages/IPAM.tsx`, React 19 + Tailwind + react-query; nav in `Shell.tsx`,
route in `app.tsx`, hooks in `ui/src/api/hooks.ts`):
- Netblock table — name, CIDR, kind, bound sources, used/free utilization bars; create /
  edit / delete.
- Visual overlay + live selector — an SVG address-map of the pool (`central`, `default`,
  named carves) colored by growth headroom (green / purple / red / yellow), updated live as
  the operator picks a size, with the suggester pre-filling a growth-aware placement. See
  *Growth-aware placement & the live visual selector* below.
- Binding selectors on `JoinKeys.tsx` / `CloudTrust.tsx` (dropdown of named netblocks +
  "Default"). SSO selector added with the SSO feature.
- Dashboard IPAM panel (`Dashboard.tsx`) — per-netblock utilization: **red > 90%**, **yellow
  > 75%** (threshold on *allocated*; the *used*/live % from heartbeats is shown alongside, so
  high-allocated-low-used reads as "reclaim," high-both as "grow"), plus recent auto-grows
  and any exhausted netblocks. Note: this red/yellow is *utilization* — a different axis from
  the create-overlay's *growth-headroom* red/yellow.

## Growth-aware placement & the live visual selector

A naive sequential first-free places a second `/27` immediately after the first
(`10.44.0.32/27`), stranding both with no room to grow. The IPAM create UI instead
**pre-suggests** placement that leaves existing blocks room to grow, and visualizes that
room with color. It is a **guide only**: the persisted carve is exactly the requested `/P`;
non-overlap, `central`, and the fixed `default` block are always enforced; the operator may
drag/retype any non-overlapping CIDR.

**Algorithm — Growth-Envelope with Worst-Fit Fallback.** Round the requested `/P` up to a
coarser CIDR-aligned *growth envelope* `/E`, where
`E = clamp(P − MARGIN_BITS, lower = max(ENVELOPE_FLOOR, pool), upper = P)` (defaults
`MARGIN_BITS = 3`, `ENVELOPE_FLOOR = /24`, so a `/27 → /24` envelope = 8× headroom). Scan
envelope-aligned slots lowest-address-first and place the block at the **start** of the
first envelope wholly free of reservations and carves. Placing at the *start* is
load-bearing: the block keeps its network address as it grows `/27→/26→/25→/24`, so growth
never relocates a live allocation (honors the edit-stranding guard). Under pressure: when no
fresh envelope remains, pack into the partial envelope with the **most** free `/P` slots
(worst-fit — keeps remaining headroom maximal), then relax the margin, then plain first-free
packing; return "pool full for this size" only when no aligned `/P` slot exists anywhere.
The result is a pure deterministic function of `(P, pool, reserved, carves)`, so the overlay
redraws without jitter and the **same function** is the authoritative server-side default at
create time (recomputed against live carves on submit to defeat stale-view collisions).

Two consecutive `/27`s thus land in **separate `/24`s** (`10.44.1.0/27`, `10.44.2.0/27`),
each free to grow to a full `/24` in place. (Sparse-bisection placement was rejected: it
spreads blocks too, but lands on un-readable mid-block addresses and pre-fragments coarse
free regions, fighting the cluster-by-join-source intent.)

**The color overlay is the growth envelope made visible.** Each allocated block's envelope
is the red/yellow zone; everything outside any envelope is green — exactly where the
suggester places. Walking up an allocated block's buddy chain:

| Color | Meaning |
|---|---|
| 🟩 green | free **and** clear — allocating here restricts no block's growth; the suggester's target |
| 🟪 purple | allocated (the carved `/P`) |
| 🟥 red | the block's immediate doubling buddy — taking it caps the block at its current size (the next `/27`, which would have completed its `/26`) |
| 🟨 yellow | the rest of the block's growth envelope — allocatable, but taking it caps growth below the full envelope (the further `/27`s up to the soft-claimed `/24`) |

A single knob — `MARGIN_BITS` (default `3` → `/24` envelope) — drives both *where the
suggester places* and *how far the red/yellow growth zone extends* (lower it, e.g. `2` →
`/25` zone, for tighter spacing). Red is always the first doubling buddy; yellow is the
remaining envelope; green is beyond. The envelope is **advisory** — not carved or locked —
so its other slots stay allocatable to other requests under pressure; the colors warn
rather than forbid.

## Auto-grow, exhaustion & surfacing

The growth envelope a block soft-claims (its red/yellow zone) exists so a block can grow
without a re-carve. **Auto-grow** cashes that in at allocation time.

**Auto-grow.** When an enrollment needs an address from a `named` netblock that is full, the
allocator checks the block's immediate doubling **buddy** (the `/P → /P-1` extension — the
red zone). If that buddy is wholly free (no reservation, carve, or allocation), the
allocator **grows the block in place** (`/P → /P-1`, *same network address* — guaranteed by
start-of-envelope placement), then allocates. Growth repeats on later exhaustion events, one
doubling at a time, consuming successive buddies up the envelope, until the next buddy is
occupied. `central` and `default` are deliberately sized and do **not** auto-grow (see Open
Questions).

**Exhaustion.** If the buddy is not free (or the block doesn't auto-grow), the allocation
**fails** and the enrollment is errored out with a terminal "no addresses available" result
(a clean denial, acked — not retried), so the host re-enrolls only after the operator makes
room.

**Surfacing — every path is observable:**
- **Audit** (hash-chained, `store.AppendAudit`): one entry per auto-grow (`netblock X
  10.44.1.0/27 → /26, triggered by enrollment E`) and one per exhaustion denial (`netblock X
  exhausted, buddy occupied, enrollment E denied`).
- **Metrics** (`promauto`, default registry, scraped like the rest of `ncp_*`):
  `ncp_ipam_netblock_capacity{netblock}`, `ncp_ipam_netblock_allocated{netblock}`,
  `ncp_ipam_netblock_used{netblock}` (gauges → utilization, dashboard, Prometheus alerts at
  >75% warn / >90% crit); `ncp_ipam_autogrow_total{netblock}`;
  `ncp_ipam_exhausted_total{netblock}` (enrollment-denied-no-address).
- **Dashboard:** the IPAM health panel (Admin API & UI, above) flags red/yellow netblocks
  and recent auto-grows/exhaustions.

**Concurrency.** Auto-grow runs in a transaction that re-checks the buddy is free, extends
`netblocks.cidr`, and invalidates the resolver cache; the existing `UNIQUE(ip)` + retry loop
then completes the allocation. Two racing growers serialize on the row.

## Phased plan

*All five phases SHIPPED & LIVE on the poc (2026-06-18).*

1. ✅ **Backend core** — migrations (`000022_ipam_netblocks`, `000023_ip_allocation_provenance`);
   `netblock.Registry`; allocator `NetblockResolver` + provenance; **auto-grow on exhaustion**
   (`Registry.Grow`); genesis `central`/`default`; wire `join_keys.sub_range` + `issue()`
   threading; the `ncp_ipam_*` utilization/grow/exhaustion metrics + audit entries. Per-join-key
   CIDRs, central reservation, and auto-grow work end-to-end.
2. ✅ **Cloud-trust binding** — `AWSAccount.Netblock` through propose/active + enrollment.
3. ✅ **Admin API + UI table** — netblock CRUD (`ipam_ops.go`, `PermIPAMManage`), utilization,
   binding selectors.
4. ✅ **Visual overlay + suggester + dashboard** — the growth-aware placement function
   (`netblock.Suggest`, shared by the `suggest` endpoint and the submit-time default), the live
   SVG selector with the green/purple/red/yellow growth-headroom coloring, and the Dashboard
   IPAM health panel (red >90% / yellow >75% utilization + recent grows/exhaustions).
5. ✅ **SSO** (with [[ADR 0004 - SSO-Driven User Enrollment]]) — usertrust netblock binding wired
   into the SSO `issue()` path; code-complete and off by default until SSO is rolled out.

## Consequences

- **Good:** related hosts cluster by join source; the control plane has durable reserved
  space; address space is operator-managed and visible; allocations gain provenance;
  per-method routing is finally wired. Builds on the existing allocator, migration, admin
  API, dual-control, and UI patterns — little net-new infrastructure.
- **Costs:** operators must size `default` at genesis and carve named blocks from the
  remaining free space; editing a netblock that would strand live allocations is blocked
  (operator reclaims first); a new admin surface to maintain.
- **No back-compat needed:** the poc mesh is disposable, so a fresh genesis is assumed; no
  migration of existing allocations.

## Open questions (resolved as built; remaining refinements)

*Resolved during the build (see `IPAM-DECISIONS.md`, D1–D23):*

- **Netblock resize/edit semantics (decided & built):** an edit that would strand live
  allocations outside the new range is **blocked** — the operator reclaims/renumbers those
  hosts first. No quarantine-and-migrate.
- **`central`/`default` auto-grow (decided & built):** **off** — their sizing is a deliberate
  genesis decision; exhaustion is an operator signal. Only `named` blocks auto-grow.
- **Utilization "used" definition (decided & built):** the red/yellow threshold keys off
  *allocated* %; the live *used* % (heartbeats, the same `internal/fleet` stale window) is
  computed by the IPAM collector and shown alongside to distinguish "grow" from "reclaim".
- **Netblock change control (decided & built):** RBAC (`PermIPAMManage`) + step-up + audit,
  matching join-key/lighthouse management — not full dual-control publish.

*Still open — optional refinements (not blocking):*

- **Growth-margin per-block override:** `MARGIN_BITS = 3` is a global default (a `/27`
  soft-claims a `/24`). A per-block override (or a hint from expected host count) is a possible
  later refinement.
- **`central` headroom convention:** a small documented role-map of which `central` IPs are
  reserved for which backend roles (monitoring, future services) — vs the current ad-hoc layout.
- **`sub_range` → `netblock` rename:** cosmetic; `join_keys.sub_range` is still the column name;
  deferred to avoid churn.

## Relationship to other work

- **[[ADR 0005 - Pull-Based Enrollment Gateways]]** — enrollment converges on
  `enrollment.Consumer`; the `issue()` allocation hook this ADR extends is the same one the
  pull collector drives.
- **[[ADR 0004 - SSO-Driven User Enrollment]]** — SSO becomes the third netblock-bindable
  join method; this ADR designs the hook, ADR 0004 builds the source.
- **[[ADR 0009 - Control-Plane Trust-Zone Separation]]** — `central` reserved space aligns
  with keeping control-plane entities in a known, protected range.
