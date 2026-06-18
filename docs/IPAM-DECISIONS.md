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
