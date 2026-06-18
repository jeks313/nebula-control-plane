# IPAM build — decisions log (for Chris's review)

Autonomous build of ADR 0010. Each decision below was taken with a reasonable default so the
build could proceed; flagged here for review. **D#** = decided-by-default during the build.

## Seeded from ADR 0010 open questions

- **D1 — SSO binding (phase 5) NOT built.** SSO enrollment doesn't exist (ADR 0004 future).
  The netblock binding is designed generically (`issue(..., netblock, method)` is method-agnostic),
  so SSO slots in later with zero IPAM rework. *Default: defer; build phases 1–4 only.*
- **D2 — `central`/`default` do NOT auto-grow.** Their sizing is a deliberate genesis decision;
  exhaustion is surfaced (audit + metric + dashboard) for operator action, not auto-grown.
  *Default per ADR open question.*
- **D3 — utilization threshold keys off allocated %.** Red >90% / yellow >75% on *allocated*
  (the binding constraint); live *used* % (heartbeats) shown alongside for grow-vs-reclaim context.
- **D4 — `MARGIN_BITS = 3`** (a /27 soft-claims a /24; red/yellow zone spans the /24).
- **D5 — netblock change control = RBAC + step-up MFA + audit** (`PermIPAMManage`), matching
  join-key/lighthouse management — not full dual-control publish (carving address space is
  sensitive but not signer-grade).
- **D6 — reuse `join_keys.sub_range`** as the netblock-name reference; no column rename (cosmetic, deferred).

## Decisions taken during the build

- **D7 — Column types match dialect convention.** `netblocks.id` = `BIGSERIAL` (pg) /
  `INTEGER PRIMARY KEY AUTOINCREMENT` (sqlite); `protected` = `BOOLEAN` (pg) / `INTEGER 0|1`
  (sqlite); CIDR stored as `TEXT` (no native inet type — keeps SQLite/Postgres identical, and
  the non-overlap/in-pool invariants live in `internal/netblock`, not the schema).
  `000023` adds `netblock_id BIGINT/INTEGER NOT NULL DEFAULT 0` + `method TEXT NOT NULL DEFAULT ''`;
  `netblock_id 0` = none recorded (legacy/unbound), `method ''` = pre-provenance. Down migrations
  use `DROP COLUMN` (works on the project's modernc sqlite ≥ 3.35).
- **D8 — `Allocator.WithResolver()` (copy) rather than a constructor change.** `NewAllocator`
  keeps its signature (static `SubRanges`, for tests/CLI); production wiring calls
  `alloc.WithResolver(reg)` to attach the DB-backed `netblock.Registry`. If the resolver also
  implements `NetblockGrower` (the registry does), auto-grow is enabled. Keeps every existing
  caller compiling and `ipam` free of an import cycle on `netblock`.
- **D9 — `netblock` imports `ipam`, not the reverse.** `Resolve`/`Carves` are the storage-agnostic
  interface (`ipam.NetblockResolver`); `ResolveFull` (`ipam.IDResolver`) hands back
  `ipam.Resolved{ID,Name,CIDR,Named}` so the allocator records `netblock_id` provenance and decides
  auto-grow eligibility without `ipam` ever importing `netblock`.
- **D10 — Registry CRUD is read-then-conditional-write, NOT a wrapping transaction.** SQLite runs
  one writer (`SetMaxOpenConns(1)`); a nested read on `r.db` inside an open `tx` deadlocks. So
  validation/stranding/buddy reads run first, then a CIDR-conditional `UPDATE ... WHERE cidr =
  oldCIDR` provides atomicity — a racing edit/grow changes the CIDR, the loser sees
  `RowsAffected == 0`, and the allocator's existing `UNIQUE(ip)` retry loop completes the alloc.
- **D11 — Auto-grow buddy = the `/P → /P-1` upper half, in place.** Start-of-envelope placement
  guarantees a named block is the LOWER half of its next-coarser prefix, so growing keeps the
  network address (no live allocation relocates). `Grow` re-checks the buddy is clear of
  reservations/carves/live-allocs, then widens `netblocks.cidr` one bit. `central`/`default`
  (kind ≠ named) never grow.
- **D12 — `default`-fill skips nested named carves.** When filling the bounded `default` block,
  `firstFree` skips any address inside a `named` carve that overlaps the default range, so a carve
  nested in default is never bled into. Named/central fills don't apply this (they fill their own
  CIDR directly).
- **D13 — Genesis seeds `central` = pool's first `/27`, `default` = a `/18` placed clear of central**
  (via the same `Suggest` placement, treating central as a carve → `10.44.64.0/18` for a `/16`
  pool, matching the ADR diagram). Both flags (`-central-cidr`, `-default-cidr`) override. Seeding
  is idempotent on name (re-genesis is a no-op). Lighthouse/core allocate via
  `AllocateSpecific(..., "genesis")`; the allocator records central's `netblock_id` by resolving
  the `central`/`default` names that contain the address.
- **D14 — Metric label set = `{netblock}` only** (low cardinality: central/default + the few
  carves). Gauges `ncp_ipam_netblock_capacity` (CIDR host count, minus the network address) and
  `ncp_ipam_netblock_allocated` refresh best-effort after each successful alloc;
  `ncp_ipam_netblock_used` is declared but left 0 (fleet/heartbeat wiring is a later phase);
  `ncp_ipam_autogrow_total` / `ncp_ipam_exhausted_total` are bumped on those events. All via
  `promauto` on the default registry (signer/collect style).
- **D15 — Approve re-derives the netblock from the pending row.** A join-key enrollment
  (`JoinKeyID != 0`) draws from the key's `sub_range` (the netblock name); aws-sigv4 draws from
  default (cloud→netblock is Phase 2). The wire method recorded on the row (`token`/`aws-sigv4`)
  is the provenance `method`. An exhaustion denial at `issue()` audits `enroll-exhausted` and
  returns the terminal error (the allocator already bumped the exhaustion metric + audited the
  per-grow events).
- **D16 — `cloudtrust.AWSAccount.Netblock` deliberately NOT added** (Phase 2, per the ADR). The
  aws-sigv4 path passes netblock `""`; no `cloudtrust` change was needed for compilation.
- **D17 — Cloud-trust netblock binding wired (Phase 2).** Added `Netblock string \`json:"netblock,omitempty"\``
  to `cloudtrust.AWSAccount` and extended `MatchAWS` to return it:
  `MatchAWS(id) (groups []string, netblock string, autoIssue, ok bool)` — netblock slots in
  before the two existing bools (so the matched scope's binding rides alongside the groups/auto-issue
  it already resolves). **Validate stays lenient on the name** (no format/existence check at
  config-publish time): the netblock may be carved *after* the trust config is published, and an
  unknown name resolves to `default` at allocation time anyway (the resolver's empty→default
  fallback), so validating at publish would create an ordering trap. The enrollment auto-issue path
  threads the matched netblock into `issue(..., netblock, "aws-sigv4")`. For the **Approve** path,
  rather than add an `enrollments.netblock` column (out of Phase-2 scope, no migration), `approveNetblock`
  re-resolves the binding from the active `CloudTrust` config + the row's stored attestation evidence
  (`AttestAccount`/`AttestPrincipal` via `MatchAWS`), so a pending attested enrollment lands in the
  SAME block its auto-issue sibling would have; a since-removed scope or absent config falls back to
  `""`→default (approval never blocks). Propagation is just JSON: `omitempty` keeps old payloads
  identical, `cloudtrust.Parse`'s `DisallowUnknownFields` now accepts the field, and propose/active
  marshal the struct directly — round-trip verified by a `TestParseValid` assertion. `openapi.yaml`'s
  `CloudTrustAccount` schema gains a `netblock` string property (contract guard stays green).
- **D18 — Phase-3 admin IPAM API shapes & wiring.** The netblock admin surface follows the
  join-key/lighthouse pattern (RBAC + step-up + audit per D5), with these defaults:
  - **Perm split:** `PermIPAMManage = "ipam:manage"` granted to admin (superuser) + operator;
    the GET endpoints (`netblocks` list, `allocations`, `suggest`) are read-only and allowed
    for any authenticated principal (viewer included) — matching how the existing read endpoints
    (joinkeys list, lighthouses, approvals) carry no perm gate. Suggest is a pure read (no DB
    write) so it is ungated like the policy analysis endpoints. Mutations (POST/PATCH/DELETE)
    require `PermIPAMManage` AND `requireStepUp` (carving address space is sensitive; matches
    policy-publish/approve gating).
  - **Routes:** `GET/POST /admin/v1/ipam/netblocks`, `PATCH/DELETE /admin/v1/ipam/netblocks/{name}`,
    `GET /admin/v1/ipam/netblocks/suggest?prefix=N`, `GET /admin/v1/ipam/allocations?netblock=NAME`.
    The literal `/netblocks/suggest` route is registered alongside `/netblocks/{name}`; Go's 1.22
    ServeMux prefers the more-specific literal segment, so `suggest` is never captured as `{name}`.
  - **Utilization:** per-netblock `capacity` = CIDR host count minus the network address;
    `allocated` = count of `ip_allocations` rows whose IP falls inside the block's CIDR (a single
    pluck of all allocation IPs, bucketed in Go — the fleet is small); `used` = 0 (the live/heartbeat
    wiring is Phase 4, matching the `ncp_ipam_netblock_used` gauge left at 0 per D14); `pct` =
    allocated/capacity * 100 rounded to one decimal (0 when capacity is 0). The list is unpaginated
    (the netblock set is small — central/default + a handful of carves, like lighthouses).
  - **Allocations endpoint:** `?netblock=NAME` is required (400 if absent); returns every allocation
    inside that block's CIDR as `{ip, device, method, allocated_at}` (device name joined from
    `devices`, RFC3339 timestamp). Unpaginated for Phase 3 (a single block is bounded by its CIDR;
    the React overlay reads the whole block). A `netblock=NAME` that doesn't exist → 404.
  - **Create body:** `{name, cidr, description}` where `cidr` is `"a.b.c.d/NN"`; an empty/invalid
    CIDR → 400. **Patch body:** `{cidr?, description}` — both optional; an omitted `cidr` keeps the
    current CIDR (the handler re-passes the stored value to `Update`), so a description-only edit
    never trips the stranding guard.
  - **Error mapping:** `ErrNotFound`→404; `ErrExists`/`ErrOverlap`/`ErrProtected`→409;
    `ErrBadCIDR`/`ErrOutOfPool`/`ErrNoName`/`ErrReservedKind`/`ErrBadPrefixLen`→400; `ErrStranded`→422
    (well-formed but unprocessable against live state — the same 422 convention as a dual-control
    commit failure); `ErrPoolFull` (from Suggest)→409.
  - **Wiring:** `adminapi.Config` gains `Netblocks *netblock.Registry` and `Allocator *ipam.Allocator`.
    In `cmd/harbor/serve.go` they are constructed from `-pool` (already on the admin-api command via
    `addCoreFlags`) exactly as enroll/genesis do: `NewAllocator` → `netblock.New(db, pool, nil, alloc,
    audit)` → `alloc.WithResolver(reg)`. Both are optional in `Config` — when nil, the list returns an
    empty set and mutations 503 (mirroring the `Lighthouses == nil` guard) — but `New` defaults them
    from the store + `-pool` so the live server always has them.
  - **Join-key `sub_range`:** already fully exposed (view + create + update handlers and the
    `JoinKey`/`JoinKeyCreate`/`JoinKeyUpdate` openapi schemas). Confirmed; no change needed (D6).
- **D19 — Phase-4 admin console UI (IPAM page, live selector, binding selectors, dashboard).**
  Built against the regenerated `ui/src/api/schema.d.ts` (re-ran `npm --prefix ui run gen:api`),
  matching the existing console idioms (react-query hooks, `Dialog`/`Card`/`Button`/`Chip`,
  per-call `onError` + central `MutationCache`, perm-gated controls). Decisions:
  - **Page + nav + route:** `ui/src/pages/IPAM.tsx`, route `/ipam` in `app.tsx`, nav entry "IPAM"
    in `Shell.tsx` (placed between Cloud Trust and Policy). Create/edit/delete are gated on
    `ipam:manage`; the client perms mirror (`ui/src/api/perms.ts`) gains `ipam:manage` for
    admin (superuser) + operator, matching `rbac.go`. The server still enforces perm + step-up,
    so a stale mirror can only hide controls, never grant authority.
  - **Hooks (`ui/src/api/hooks.ts`):** `useNetblocks` (plain list, like joinkeys/lighthouses — the
    netblock set is tiny), `useNetblockSuggest(prefix)` (enabled only for prefix 1–32; `retry:false`
    so a 409 "pool full" is treated as a real answer, not a transient failure),
    `useNetblockAllocations(name)` (enabled only when a name is given), and create/update/delete
    mutations that `onSettled`-invalidate both `['netblocks']` and `['netblock-suggest']` (a carve
    shifts where the next block would land).
  - **"Bound sources" derived client-side (no new API).** The netblock row's bound sources are
    joined in the browser from the existing join-key list (`sub_range`) and active cloud-trust
    config (`aws[].netblock`) — the netblock API surfaces no back-references. Shown as chips
    `key:NAME` / `aws:ACCOUNT`; revoked join-keys are excluded; `default` shows "unbound fallback".
  - **Live visual selector = a horizontal proportional address-bar (not a 2-D grid).** A pure,
    unit-tested address-math module (`ui/src/lib/ipam.ts`, with `ipam.test.ts`) computes the
    overlay segments; `IPAM.tsx` is a thin render. The bar tiles the whole pool by address count;
    segments are coalesced colored runs. Picking the prefix-size slider re-pulls the `suggest`
    endpoint and pre-fills the CIDR field (operator can override — `overridden` pins their value,
    with a "↺ use suggested" reset); the pending carve is overlaid live as purple with its own
    red/yellow envelope. Guide only — the create call re-validates server-side.
  - **Pool extent derived from the netblock list** (the API returns no bare pool prefix): the
    smallest aligned power-of-two CIDR enclosing all blocks. Caveat: free space *above* the highest
    block is invisible until a block reaches that far — acceptable for a guide, and the server is
    authoritative on bounds anyway. If a bare-pool field is later added to the API, swap it in.
    **RESOLVED in D21:** the list response now carries `pool`; the overlay prefers it and the
    block-derived extent is now only a fallback for an older server.
  - **The four overlay colors** are explicit `@theme` tokens in `index.css`, deliberately distinct
    from the status hues (permit/warn/danger) so the *growth-headroom* overlay never reads as a
    *health* signal: `--color-ipam-green #3fb950` (free+clear, the suggester's target),
    `--color-ipam-purple #a371f7` (carved /P), `--color-ipam-red #f85149` (immediate doubling buddy
    — caps the block), `--color-ipam-yellow #d29922` (rest of the growth envelope). Semantics are
    faithful to the ADR: `MARGIN_BITS=3`, `ENVELOPE_FLOOR=/24`, start-of-envelope placement, so a
    /27 soft-claims a /24 (red = the next /27, yellow = the remaining six /27s). Yellow is stored
    as an explicit half-open range, NOT a Cidr — the envelope remainder (e.g. 192 of 256 addresses)
    isn't a single power-of-two block.
  - **Binding selectors:** `JoinKeys.tsx` gains a netblock `<select>` bound to `sub_range` (shared
    create/edit form, plus a read-only "Netblock" table column); `CloudTrust.tsx` gains a per-account
    netblock `<select>` bound to the new `netblock` field (editor row + table column). Both selects
    list named netblocks + a "Default (the bounded fallback block)" option (value `''`), and keep a
    stale binding (a since-removed named block) selectable + labeled rather than silently dropping it.
  - **Dashboard IPAM health panel derives from the netblock list (no dedicated endpoint).** The
    panel (`IPAMHealthCard` in `components/fleet.tsx`, added to the Dashboard grid) lists blocks over
    the *utilization* threshold (red >90%, yellow >75% on the *allocated* %), showing the live
    *used* % alongside (now wired — see D23; the heartbeat-confirmed `used` count was the Phase-4
    backend and is live). Recent auto-grows / exhaustions are pulled from the audit log by action name
    (`netblock-autogrow` / `netblock-exhausted`) — the API exposes no dedicated grows/exhaustion
    endpoint (those are audit + Prometheus per the ADR), and the card hint notes this. This
    utilization red/yellow is a DIFFERENT axis from the create-overlay's growth-headroom red/yellow
    (`utilizationTone()` vs the overlay segments), as the ADR calls out.
  - **Gates:** `tsc --noEmit` clean; `npm run build` succeeds; full vitest suite green (61 tests,
    incl. the new 15 `ipam.test.ts` cases). No eslint/biome/prettier is configured in the repo, so
    `tsc` is the static-check gate.

## Review-fix decisions (post phases 1–4)

- **D20 — Unknown/deleted netblock name falls back to `default` at resolution time (runtime,
  not publish-time).** `Resolve`/`ResolveFull` resolve a non-empty name that no longer exists
  (deleted block, typo'd binding) to the `default` netblock instead of returning `ErrNotFound`,
  and emit a `slog` warning so the fallback is visible. This makes the documented
  `AWSAccount.Netblock` contract true: deleting or mis-typing a netblock that a join-key
  `sub_range` or cloud-trust scope references must NOT break enrollment — the host simply draws
  from the bounded fallback. `ResolveFull` returns the resolved block's own identity, so an
  unknown name surfaces as `Named=false` (kind=default): it must **not** become auto-grow-eligible
  as if it were a named block — it draws from `default`, which deliberately never auto-grows (D2).
  Only a missing `default` itself (shouldn't happen post-genesis) still yields `ErrNotFound`.
  **Delete-time reference checking was considered and deferred:** scanning every join-key
  `sub_range` + cloud-trust scope on each netblock delete (and refusing the delete, or cascading)
  is brittle against the publish-ordering trap already noted in D17 (a binding may name a block
  carved later) and races config edits. The runtime fallback is the robust, ordering-independent
  choice; an operator-facing "bound sources" view (D19) already surfaces references for awareness.
- **D21 — List response carries the configured `pool` prefix; supersedes the D19 extent workaround.**
  `GET /admin/v1/ipam/netblocks` now returns a top-level `pool` string (from `adminapi.Config.Pool`)
  alongside `netblocks`/`count`; the `NetblockList` schema + regenerated `schema.d.ts` follow. The
  UI overlay (`resolvePoolExtent`) uses this as the address-map extent, so free space *above* the
  highest block is now visible. The block-derived `poolExtent` (D19) is retained only as a fallback
  for a server that omits `pool` (forward/back compat). `pool` is `omitempty`/optional, so the
  contract guard stays green and an unconfigured-pool server simply returns `""` → UI falls back.

- **D22 — Boot-seed `central`/`default` when the netblocks table is empty — the existing-mesh
  upgrade path; genesis-only seeding left a deployability gap.** `central`/`default` were seeded
  only during `harbor genesis` (the netblock registry's `Seed`). An ALREADY-genesis'd mesh that
  upgrades to the IPAM build runs migrations `000022`/`000023` (creating an empty `netblocks`
  table) but never re-runs genesis — so `default` is missing and `ipam.Allocate` (which resolves
  unbound enrollments to `default`) breaks every new enrollment. The feature must be deployable
  onto an existing mesh, so harbor's long-running services now boot-seed:
  - **Where it hooks in:** `cmd/harbor/serve.go` — both `cmdAdminAPI` (after it builds the
    netblock `Registry` + allocator from `-pool`) and `cmdCoreAPI` (which builds a registry just
    for the seed, right after `openStore`), AFTER migrations have run (the serve commands assume
    `harbor migrate up` already ran — admin-api already fails fast on a missing `sessions` table).
    Either or both services may boot first; whichever wins seeds, the other no-ops.
  - **Empty-only:** a new `(*Registry).Count` does a `COUNT(*)`; `genesis.BootSeedNetblocks` seeds
    only when the count is 0. A genesis'd or operator-curated set (any rows) is left untouched —
    boot-seeding never re-derives or "repairs" an existing layout.
  - **Race/duplicate-tolerant:** `Seed` is already idempotent on the name and folds a lost
    `UNIQUE(name)` race back to the existing row (`gorm.ErrDuplicatedKey` → re-`Get`), so two
    services boot-seeding at once is safe — a concurrent insert is swallowed as success, not a
    crash.
  - **Fail-soft, not fatal:** a seed failure is logged as a `Warn` but does NOT abort startup. A
    missing `default` surfaces as enrollment errors that are already audited + metered, and the
    next boot retries — taking the whole control plane down over a transient seed error would be
    strictly worse. Seeding success logs an `Info` line so the upgrade is visible in operator logs.
  - **No CIDR math duplicated:** the placement math (`central` = pool's first `/27`, `default` =
    the `/18` placed clear of central via `Suggest`) was extracted from `genesis.Run`'s inline body
    into a shared `genesis.SeedNetblocks` helper (with `centralBlock`/`defaultBlock`); `Run` and
    `BootSeedNetblocks` both call it, so the seeded values are byte-for-byte what genesis would use.
    The serve commands carry only `-pool` (no `-central-cidr`/`-default-cidr`), so boot-seeding uses
    the genesis defaults — exactly the values a genesis run without those override flags produces.
  - **Test:** `genesis.TestBootSeedNetblocksUpgradePath` — a migrated-but-not-genesis'd store has
    an empty table; after the first boot-seed it holds `central` (`/27`, reserved, protected) +
    `default` (kind=default, protected, clear of central); a second invocation (modelling the other
    service booting) reports `seeded=false`, leaves the count at 2, and does not churn the rows.

- **D23 — `used` (live utilization) = fresh-heartbeat ∩ allocated; the per-netblock utilization
  gauges move to a scrape-time custom collector.** The netblock list + `ncp_ipam_netblock_*` gauges
  previously reported `used` as a hardcoded `0` (the API) / never set it (the metric), so the
  dashboard's used-vs-allocated signal was dead. `used` is now computed for real, and the gauges are
  emitted at scrape time rather than imperatively.
  - **`used` definition:** an allocation is "used" (live) iff its `overlay_ip` has a heartbeat with
    `last_seen >= now - StaleAfter` — i.e. the host is NOT stale. The window is the fleet freshness
    window (`fleet.Thresholds.StaleAfter`, default 5m), so "used" and the fleet/devices "stale"
    verdict are computed against the SAME threshold and can never disagree. `allocated` = allocations
    whose IP is in the netblock CIDR; `used` ⊆ `allocated`. The `heartbeats` table is keyed by
    `overlay_ip` (= the allocated IP), so `used` joins directly to allocations with no device hop.
  - **API (`internal/adminapi/ipam_ops.go`):** the list handler plucks the fresh overlay-IP set once
    (`heartbeats WHERE last_seen >= now - StaleAfter`, via `s.cfg.Thresholds.StaleAfter` which `New`
    defaults to 5m) and, per per-CIDR allocation bucket, counts how many IPs are in that fresh set →
    fills `NetblockView.Used`. `netblockView` (create/update responses) does the same.
  - **Gauges → scrape-time collector (`internal/ipam/collector.go`).** The three imperative
    `promauto` GaugeVecs (`ncp_ipam_netblock_{capacity,allocated,used}`) and `refreshNetblockMetrics`
    (+ its call site in `Allocate`) are REMOVED. `used`/`allocated` decay between allocation events
    (a host going stale drops `used` with no alloc to hang an `Inc` on; a quarantine purge drops
    `allocated`), so an imperative-set gauge is structurally wrong for them. A `NetblockCollector`
    (a `prometheus.Collector`) computes, per netblock at `Collect` time, capacity (CIDR host count
    minus the network address, reusing `hostCapacity`), allocated (allocations in CIDR), and used
    (allocated ∩ fresh heartbeats), reading the store + the netblock set live. It depends on a
    minimal `ipam.NetblockLister` interface (returning `[]NamedCIDR`) that `*netblock.Registry`
    implements via a new `NetblockCIDRs` method — avoiding the ipam←netblock import cycle (same
    pattern as `NetblockResolver`/`allocationLister`).
  - **The EVENT counters `ncp_ipam_autogrow_total` / `ncp_ipam_exhausted_total` are UNCHANGED**
    (still imperative `promauto` CounterVecs `Inc`'d at the grow/denial — a counter at a moment is
    exactly right; only the decaying utilization gauges moved).
  - **Where it's registered + why:** `ipam.RegisterNetblockCollector` registers the collector on the
    default Prometheus registry in BOTH long-running servers — `cmd/harbor/serve.go` `cmdAdminAPI`
    (using its `-stale-after` flag, so the gauge window matches that server's fleet verdict) and
    `cmdCoreAPI` (no stale flag → the collector defaults a zero window to the fleet-default 5m, the
    same default admin-api applies). Each is a separate process exposing its own `/metrics` via the
    `obs.Mount` already wired there, so whichever a Prometheus scrapes reports correct utilization.
    A failed registration is logged `Warn` (gauges absent), never fatal.
  - **Dedup / no-panic guard:** registration is wrapped in a process-level `sync.Mutex` + once-flag
    (`collectorRegDone`) so a second call in the same process is a cheap no-op, and a
    `prometheus.AlreadyRegisteredError` (duplicate name/collector) is swallowed as success — a
    process that already allocates (and thus already owns the metric names) cannot panic on register.
  - **Determinism / nil-safety:** `Collect` runs a few small queries per scrape (fine for the small
    fleet) and is robust to a nil store/registry or nil receiver (emits nothing, never panics); a
    transient query error skips that scrape's emission rather than emitting a partial/wrong series.
  - **Tests:** `adminapi.TestNetblockUsedCountsOnlyFreshHeartbeats` (two allocations in `office`, one
    fresh + one 10-min-stale heartbeat → API list reports `allocated=2`, `used=1`) and
    `ipam.TestNetblockCollectorUsedCountsOnlyFresh` (same setup → the collector's
    `ncp_ipam_netblock_used` series gathered from a registry = 1, `_allocated` = 2, `_capacity` = 255)
    + `TestNetblockCollectorNilSafe` and `TestRegisterNetblockCollectorDedup` for the guards.

## Review fixes applied (correctness/robustness, no behavior regressions)

- **Resolver cache lost-update race (FIX 1).** `snapshot()` rebuilt the cache outside the lock and
  stored it unconditionally, so a concurrent `invalidate()` from Add/Update/Remove/Grow could be
  overwritten by a stale snapshot — `Resolve`/`Carves`/`ResolveFull` could then return stale
  CIDRs/carves indefinitely after a mutation. Fixed with a `gen uint64` generation counter:
  `invalidate()` does `cache=nil; gen++` under the lock; `snapshot()` captures `startGen` before the
  unlocked `List`, and only publishes the rebuilt cache if `gen == startGen` on re-acquire (else it
  returns the fresh snapshot to its caller but leaves `cache=nil` so the next reader rebuilds). No
  lock is held across `List` (avoids the single-writer SQLite deadlock).
- **Double audit on netblock CRUD (FIX 4).** Create/update/remove were audited twice — once by the
  registry (`recordAudit`) and once by the handler (which carries the principal). Removed the
  registry's audit for Add/Update/Remove (the handler's is authoritative — it has the principal),
  keeping the registry's audit for `Grow` (auto-grow has no handler/principal and must stay audited)
  and for `Seed` (genesis, no handler). CRUD now produces exactly one audit entry, with the principal.
- **Stranding guard counted expired quarantine (FIX 5).** `LiveAddrs` returned every `ip_allocations`
  row, so an expired-but-unpurged quarantine row could falsely trip `ErrStranded` on a netblock
  edit/remove. Now filtered to `state='allocated' OR quarantine_until > now`.
