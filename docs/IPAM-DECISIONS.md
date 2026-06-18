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
