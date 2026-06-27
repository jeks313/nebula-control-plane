---
created: 2026-06-27
source: claude-code
status: proposed
project: nebula-control-plane
tags: [nebula, implementation, groups, devices, bulk, rbac, ui]
---

# Implementation Plan — Device Group Reassignment (ADR 0002 + ADR 0013)

**Status:** Proposed — scopes [[Nebula Control Plane - ADR 0002 - Post-Enrollment Group Reassignment|ADR 0002]] (single-device substrate, accepted but unbuilt) and [[Nebula Control Plane - ADR 0013 - Bulk Device Group Reassignment by Name Pattern|ADR 0013]] (bulk/pattern/UI layer) into one ordered build. Phase 1 incorporates an adversarial plan review that caught a genesis-seeding fleet-brick and several correctness gaps; those fixes are folded in below.
**Date:** 2026-06-27
**Decision owners:** Chris Hyde

## Goal & shape

Let an operator change a device's nebula groups after enrollment — one device, or a pattern-selected set — server-side, audited, taking effect on the host's next heartbeat-triggered renew (hot-reload, same overlay IP). Built on the **desired-vs-issued generation model** (ADR 0002): set `desired_groups` + bump `groups_generation`; the host renews when `desired_generation > issued_generation`; `handleRenew` re-signs from `desired_groups` and writes back `issued_generation`. Bulk (ADR 0013) is a **dry-run → explicit-set apply** that resolves the operator's delta to per-device *absolute targets + `(overlay_ip, enrollment_id, base_generation)` identity tokens*, committed each as an absolute set under optimistic concurrency.

**Build order:** Phase 1 (single-device substrate, independently shippable) → Phase 2 (bulk + UI) → Phase 3 (enforceable reductions) → Phase 4 (hardening). Additions are effective; reductions are *soft* (advisory) until Phase 3.

### Invariants every phase must hold (ADRs + review)
- **Authority is server-side** — host supplies only a CSR; groups come from the device record (`coreapi.go:558-560`). Never accept host-supplied groups.
- **Reserved groups (`control-plane`/`lighthouse`) are untouchable in both directions, guarded at the renew CHOKEPOINT, not only the perimeter.** The endpoint/bulk paths reject targets that add OR strip a reserved group (`policy.GrantsReservedGroup`, `policy.go:33`), AND `handleRenew` itself (the only place a cert is signed) refuses to drop a reserved group the *issued* cert holds — keep it + alarm. Stripping `control-plane` off a live harbor/lighthouse drops its baseline-accept rule (`policy.go:193-202`) and bricks the fleet; the chokepoint guard is the backstop that holds even if a bad `desired_groups` is set by any path (incl. an un-seeded genesis row).
- **Every renew must persist the rotated fingerprint** (the cert rotates on every renew; the blocklist's only fingerprint source) — the fingerprint write-back stays UNCONDITIONAL; only `groups`+`issued_generation` are generation-guarded.
- **`overlay_ip` is a reusable, reclaimable slot** — bind apply to `(overlay_ip, enrollment_id, base_generation)`; `device()` resolves "latest issued at IP, id DESC" and ignores `reaped_at` (`coreapi.go:230-232`). Exclude `reaped_at != 0`.
- **No new convergence machinery** — reuse renew + `CmdRenew` + the absolute-set write; no control-plane push, no IP move.

---

## Phase 1 — Single-device substrate (ADR 0002 Phase 1) — *reworked per review*

Independently shippable. Additions effective; reductions soft.

- **P1.1 — Migration `000030_group_reassignment` (postgres + sqlite), registered, reversible.**
  - Add to `enrollments`: `desired_groups TEXT NOT NULL DEFAULT '[]'`, `groups_generation BIGINT NOT NULL DEFAULT 0`, `issued_generation BIGINT NOT NULL DEFAULT 0`, and **`reduction_pending_enforcement` / `reduction_old_not_after`** (durable soft-reduction state — ADR 0013 §6; nullable/`0` default).
  - **Backfill (load-bearing): `UPDATE enrollments SET desired_groups = groups`** for every existing row (NOT the `'[]'` default — else the first edit diffs against empty and strips all groups), generations `0`.
  - **Register the migration in the ordered slice** `internal/store/migrate/migrate.go:28-58` (`sqlMigration("000030_group_reassignment")`) — migrations are not auto-discovered; without this the columns silently never apply.
  - Ship `000030_…down.sql` dropping the five columns (rollback discards in-flight `desired` changes — safe, `groups` holds authority).
  - *Operational:* migration is transactional (column invisible until ADD+UPDATE commit); **deploy the P1.4 code only after 000030 commits** (else a renew reads un-backfilled `'[]'` and strips groups); batch the backfill for a large fleet.
  - *Accept:* post-migration `desired_groups == groups` (set-equal) for every pre-existing row; `harbor migrate up`/`down` clean.
- **P1.2 — Enrollment model fields + seeding at BOTH creation paths.** Add `DesiredGroups string` (gorm `column:desired_groups;default:'[]'`), `GroupsGeneration int64`, `IssuedGeneration int64`, `ReductionPendingEnforcement bool`, `ReductionOldNotAfter int64` to the enrollment struct (`internal/enrollment/enrollment.go:~84`). Seed `desired_groups = groups`, gens `0` at `record()` (`~1113`) **and at the genesis direct-insert** (`genesis.go:~520`, which bypasses `record()` for harbor-core/lighthouses). The GORM `default` tag is belt-and-suspenders for any future creation path.
- **P1.3 — `commandsFor` trigger** (`coreapi.go:484-506`). **Change the signature** to receive `dev` (or the two generations) — today it takes `(ctx, overlayIP, appliedVersion, appliedBlocklist, appliedNebula, appliedPilot, certNotAfter)`; `dev` is resolved only at the caller `handleHeartbeat` (`coreapi.go:389`) (touches the `pilot_test.go`/`nebula_test.go` callers). Emit `CmdRenew` when `GroupsGeneration > IssuedGeneration`, **deduped** with the existing near-expiry `CmdRenew` (`:486-489`) — at most one.
- **P1.4 — `handleRenew`: read desired, chokepoint-guard, race-safe write-back, durable reduction state** (`coreapi.go:508-611`).
  - Capture `(desiredGroups, gen)` atomically at read; sign the cert from `desiredGroups` (replacing the static `dev.Groups` read at `:559`); recompile firewall from the new groups.
  - **Chokepoint reserved guard:** if the *issued* groups satisfy `policy.GrantsReservedGroup` and `desiredGroups` does not, refuse to drop it (sign with the reserved group retained, or skip the re-issue) and alarm — the fleet-brick backstop.
  - **Write-back, two statements:** (a) fingerprint UNCONDITIONALLY (`Update("fingerprint", fp) WHERE id=?`, as today `:593-594` — every renew rotates the cert); (b) `groups = desiredGroups`, `issued_generation = gen` **guarded `WHERE id=? AND issued_generation < gen`** (so a near-expiry renew with `gen==issued` doesn't 0-row-match and lose the fingerprint, and a concurrent operator bump can't false-converge). Do NOT fold the fingerprint into the guarded statement.
  - When `desiredGroups` drops a group vs issued, set `reduction_pending_enforcement=true`, `reduction_old_not_after=<old cert notAfter>` (durable; cleared in Phase 3).
  - **Authority audit** (the cert-issue is the authority event, today a bare `cert-renewed` at `:607`): record `groups` + `issued_generation` + (Phase 2) the originating batch id, in the same transaction as the write-back — see P1.4b.
- **P1.4b — `AppendAuditTx(tx, …)`.** Today `store.AppendAudit` (`internal/store/audit.go:66-107`) opens its own transaction + global `auditMu` + advisory lock and takes no caller `tx`, so "write + audit in one transaction" is impossible. Add a tx-aware append that links the hash-chain inside the caller's transaction (acquiring the advisory lock on that tx); route the P1.4 write-back + authority audit (and P2.7 per-device entries) through it. Tradeoff: holds the audit advisory-lock across the (longer) renew tx — acceptable given the §2.5 cap bounds concurrent volume; documented. (If this proves too contended, fall back to ordered write-then-append and accept a crash-window no worse than today's handlers — but the atomic path is preferred for an authority change.)
- **P1.5 — RBAC `device:manage`** (`rbac.go:25-42`, matrix `:57-71`). Add `PermDeviceManage`. admin (superuser) has it; grant operator (day-2 ops) — the dangerous bulk paths gate on dual-control, which operator can't self-approve. Mirror in `ui/src/api/perms.ts`. Note `requireStepUp` is a no-op when `MFAFreshness<=0` (`rbac.go:111-113`).
- **P1.6 — Single-device endpoint.** `PATCH /admin/v1/devices/{ip}/groups {groups:[…]}` in a new `internal/adminapi/device_groups.go`, registered in `routeTable` (`adminapi.go:~276`; `{ip}` path-params already precedented by `lighthouses/{ip}`). Resolve the same row `device()` reads; reject if the target adds a reserved group OR the device's current groups satisfy `GrantsReservedGroup`; set `desired_groups`, bump generation; `device:manage` + step-up; audit (old→new, actor). **Edit `internal/adminapi/openapi.yaml` in the SAME commit** — `contract_test.go:TestRoutesMatchSpec` fails on any served-but-unspecified route — then `npm --prefix ui run gen:api`.
- **P1.7 — Expose state on `GET /devices`** (`handleDevices`, `adminapi.go:514`). Add `desired_groups`, `pending` (`groups_generation > issued_generation`), and `reduction_pending_enforcement` to the `Device` response. Thread the columns through the authoritative-enrollment read chain: `provRow`/`enrollProv`/`provSelect` (`device_provenance.go:20-45`) → `handleDevices` (`:649-659`). Update `openapi.yaml` (gates `TestResponsesConformToSpec`) + `gen:api`.
- **P1.8 — Single-device UI** (after P1.7 — the badge needs the API field + regenerated `schema.d.ts`). "Edit groups" row action on `ui/src/pages/Devices.tsx` (Dialog modal), reserved guardrail, removal-is-advisory warning, pending-re-issue badge clearing on `issued==desired`, step-up handled by the API.
- **P1.9 — Tests.** set→trigger→renew→write-back→converge; **a freshly-genesis'd harbor-core renews to a cert that still carries `control-plane`** (the brick regression); **chokepoint refuses to strip a reserved group**; the generation guard under a concurrent operator bump AND a concurrent-renew fingerprint-desync; backfill **copy-correctness** (`desired==groups`, and a subsequent add/remove resolves against real groups); reserved current/resulting rejection at the endpoint; an openapi contract assertion for the new route/fields.

**Phase 1 exit:** single-device group changes work end-to-end; genesis/replace can't brick the fleet; reductions persist a durable advisory attribute.

---

## Phase 2 — Bulk + pattern selection + UI (ADR 0013 Phase A)

Fan-out over the Phase-1 primitive. New surface: selection, dry-run, identity/generation guarding, exclusions, dual-control routing, the regroup-specific cap/rate-limit, correlated audit, UI.

- **P2.1 — `name_pattern` filter on `GET /devices`.** Glob → SQL `LIKE` on `heartbeats.device_name`, applied as a SQL `WHERE` like the **condition** filter (keyset-safe), NOT the Go-side scope allow-set. Escape `%`/`_`; `*`→`%`, `?`→`_`.
- **P2.2 — Dry-run resolver.** `POST /admin/v1/devices/regroup?dry_run=true` `{name_pattern?, overlay_ips?, add?, remove?, replace?, include_stale?}`. Resolve the matched **live** set (exclude `stale`, `ephemeral`, **`reaped_at != 0`**, and current-reserved → per-device `disposition`); per device compute the **absolute target** from the delta over `desired_groups`; return `[{overlay_ip, enrollment_id, name, origin, desired(from), target(to), groups_generation, will_reduce, disposition}]`. **No writes.** Whole-request rejects (before any consideration): malformed pattern, `add∩remove≠∅`, a target adding a reserved group, empty effective set, over-cap.
- **P2.3 — Apply (absolute-set, optimistic, identity-bound).** Body = the dry-run's explicit `[{overlay_ip, enrollment_id, target_groups, base_generation}]`. Per device: re-resolve the authoritative enrollment at `overlay_ip`; if `enrollment_id` differs, `groups_generation != base_generation`, or `reaped_at != 0` → `skip:changed_since_preview` (no write). **Re-derive add-vs-remove** by diffing `target` vs the re-resolved current `desired_groups` (the apply body has no operands — the handler can't trust the client for the routing gate or reduction labeling). Else write via the P1.4 absolute-set + generation-guard path. No-op by **set equality** (sort+dedup). Best-effort; whole-request validation re-checked before the first write.
- **P2.4 — Exclusions + `include_stale` ghost-state handling.** Default-exclude stale/ephemeral/reaped. `include_stale` is opt-in and **gated on ghost-state GC**: opted-in stale `desired_groups` must expire/be reaper-collected (ADR 0013 §4/OQ2), or the fleet `pending` metric (P1.7) must be scoped to live hosts before `include_stale` ships — otherwise dead hosts permanently inflate pending. Never-heartbeated enrollments are absent from the list (state in UI).
- **P2.5 — Regroup-specific cap + rate limit (decision; do NOT reuse revocation's).** Define `DeviceRegroupMaxSet` (≈100) and `DeviceRegroupMaxPerWindow` (≈3/hr) — purpose is bounding the renew/KMS burst (each renew = 2 KMS signs, no canary/wave), distinct from blocklist size. **Enforce at the dry-run/Propose boundary** (the dual-control path writes later, in the committer). The rate-limit counter must cover **both** paths (the perm+step-up path creates no dualcontrol `Change`, so a Change-row count misses it) — back it with the P2.7 bulk-op records. Over-cap → "N more, narrow the pattern," never truncate.
- **P2.6 — Dual-control for elevating/large ops.** Route through `internal/dualcontrol` (new `device.groups` change kind + committer, mirroring policy/cloudtrust publish, 202+`Change` per `adminapi.go:1004-1010`) when the op **adds** a group OR the resolved set exceeds the threshold; payload = the explicit `(overlay_ip, enrollment_id, target, base_generation)` set. Single-device + pure-reduction stay on perm+step-up. **The committer (runs at approval time on the frozen payload) must re-resolve `enrollment_id` + re-check `base_generation` + `reaped_at` per device**, applying absolute-sets and writing the correlated audit; devices changed since propose are skipped — surface that partial/no-op outcome to the operator (a legit interim edit can silently shrink an approved elevation).
- **P2.7 — Correlated audit.** A bulk-op record (batch id, actor, the **committed** `(overlay_ip, enrollment_id)` set, the delta, per-device disposition incl. skips/failures), written before the first device write on the synchronous path; on the **202 path** the dualcontrol `Change` is the pre-commit intent and the committed-set record is written by the committer before its first write. Batch id stamped into each per-device `device-regroup` entry and the P1.4 authority audit, via `AppendAuditTx`. Volume bounded by P2.5.
- **P2.8 — Bulk UI.** `Devices.tsx`: glob name filter + "Re-group…" action (`device:manage`) → modal: add/remove (or replace) → dry-run preview list (`HostLabel` name+overlay_ip, origin, current desired, target diff-highlighted, per-device disposition incl. skipped-stale/ephemeral/reaped/reserved) → confirmation restating committed count, skipped counts, the **durable** reductions-advisory + grants-not-promptly-undoable caveats, and a "routes to a second approver" note when elevating/large → commit; `202` → "awaiting approval." `api/hooks.ts`: `useDeviceRegroup` (dry-run + apply). Surface `reduction_pending_enforcement` on device rows after convergence.
- **P2.9 — Tests.** Absolute-set + generation-guard concurrency (overlapping bulks; single+bulk); **identity-token skip on a re-handled slot AND a reaper soft-marked host** (the reaper soft-marks `reaped_at`, it does NOT hard-delete and `device()` ignores `reaped_at` — the guard alone won't catch it); reserved current+resulting exclusion; stale/ephemeral/reaped exclusion; dry-run↔apply equivalence; cap + **rate-limit on the perm+step-up path**; `add∩remove` reject + dedup; **dual-control commit-time re-resolution + stale-at-commit no-op**; an openapi contract test for the 200/202 + per-device-disposition shape.

**Phase 2 exit:** pattern-select bulk re-group from the Devices view; additions effective, reductions durably labeled.

---

## Phase 3 — Enforceable reductions (ADR 0002 Phase 2 / ADR 0013 Phase B)

Security-completing; **a real milestone**.

- **P3.1 — Snapshot the pre-reduction fingerprint** in `handleRenew` on a reduction (the in-memory `dev.Fingerprint` read at `:515` is the old value and is not overwritten — available directly; the DB row is updated separately).
- **P3.2 — Convergence-gated revoke.** Blocklist the old fingerprint **after** the host installs the reduced cert. Define the "installed" signal: a group-reduction renew is not a bundle-version bump, so detection rides the next heartbeat's reported `cert_not_after`/applied state matching the new cert (or `issued==desired` + a confirmed post-renew heartbeat). Wire to `internal/revocation` + the blocklist rollout lane.
- **P3.3 — Reconcile with revocation guardrails.** A bulk of N reductions must respect `MaxBulkFingerprints=100`, `MaxBulkPerWindow=3/hr`, **dual-control on `BulkRevokeKind`** (`revocation.go:60-67`) — batch through bulk-revoke, do NOT fan N uncapped single-host `Add`s around them. Bound peer-bundle blocklist growth.
- **P3.4 — Clear `reduction_pending_enforcement`** once the old cert is revoked fleet-wide; API/UI drop the advisory.
- **P3.5 — Tests.** reduction → snapshot → convergence-gated add → peer bundles carry it; no premature revoke; the unguarded-fingerprint desync from P1.4 must be closed (Phase 3 blocklists the recorded fingerprint, so it must match the issued groups); bulk reduction vs the revocation cap/dual-control.

---

## Phase 4 — Hardening (ADR 0013 Phase C)

- **P4.1 — Group catalog + privilege tiers** (fat-finger guard; refine which additions need dual-control). Cf. [[Nebula Control Plane - ADR 0001 - Policy Scoping|ADR 0001]].
- **P4.2 — First-class undo** ("undo batch `<id>`": replay each device's recorded `from` under the identity-token guard; an over-grant undo inherits the Phase-3 revoke path).
- **P4.3 — Convergence observability** — a bulk-scoped "X of N pending re-issue" signal via the [[Nebula Control Plane - ADR 0012 - Pilot Fleet Metrics|ADR 0012]] `ncp_fleet_*` surface (scoped to live hosts per P2.4).

---

## Dependencies & sequencing

- P1.1 → P1.2 → {P1.3, P1.4 (+P1.4b)} → P1.6 → P1.7 → P1.8; P1.5 before P1.6/P1.8.
- Phase 2 requires all of Phase 1. P2.1+P2.2 → P2.3; P2.4/P2.5/P2.6/P2.7 fold into the handler; P2.8 last.
- Phase 3 requires Phase 1 (P1.4 write-back + the fingerprint/desync fix) + the shipped blocklist; bulk reductions need P3.3. Independent of Phase 2.
- Phase 4 optional, after 1–3.

## Cross-cutting

- **`internal/adminapi/openapi.yaml` is load-bearing for `make test`** (`contract_test.go` route+response conformance), not just the TS client — edit it in the **same commit** as any route/`Device`-struct change (P1.6, P1.7, P2.2/P2.3), then `npm --prefix ui run gen:api` (the `gen:api` is an npm script, there is no `make gen:api`). `make harbor-ui` for UI builds; deploy via the usual swap + `ncp-admin` recreate.
- **Migrate-before-deploy:** 000030 must commit before the P1.4 code ships (a renew reading un-backfilled `'[]'` strips groups).
- **No IP/netblock movement** ([[Nebula Control Plane - ADR 0010 - IPAM|ADR 0010]] untouched).
- **Limitations to document in UI/help:** (1) a per-device re-group does not survive a host rebuild — re-enrollment reseeds from join-method defaults; durable class-level grouping belongs at the trust layer (cloudtrust/usertrust/join-key defaults), not here. (2) A regroup renew does **not** re-verify cloud attestation — the operator is the authority (ADR 0002 OQ5 / ADR 0013 non-goal).

## Risks (with the review's corrections folded in)

- **Genesis fleet-brick (was a blocker).** Un-seeded genesis CP/lighthouse rows + the near-expiry backstop would strip `control-plane`. Mitigated by P1.2 genesis seeding + the P1.4 chokepoint guard + the P1.9 regression test. **Highest-priority Phase-1 item.**
- **Reserved-group eviction via `replace`/reduction.** Mitigated by perimeter (P1.6/P2.4) AND chokepoint (P1.4) current+resulting guards.
- **Lost update / false-convergence.** Absolute-set apply + `WHERE … issued_generation < gen`; fingerprint stays unconditional so routine renews don't desync the recorded fingerprint from the issued groups (which Phase 3 revokes).
- **Reaper race.** The reaper **soft-marks** (`reaped_at`), it does not hard-delete; `device()` ignores `reaped_at`, so the identity/generation guard passes on a reaped host → ghost pending. Mitigated by excluding `reaped_at != 0` at dry-run AND apply re-resolution (P2.2/P2.3/P2.4).
- **Renew/KMS burst.** Bounded by the P2.5 cap; consider staggering `CmdRenew` emission if even the capped burst spikes signing.
- **Regroup × rollout in one heartbeat.** `commandsFor` can return a regroup `CmdRenew` + a rollout `apply_bundle`; `handleConfig` rebuilds from *issued* groups, so a host may briefly apply old-groups firewall + new-groups cert in some order. Converges; P2.9 asserts benign interleaving.
- **Audit atomicity/contention.** `AppendAuditTx` (P1.4b) enables atomic write+audit; the cap bounds the serialized-chain burst.

## Relationship to other work

- [[Nebula Control Plane - ADR 0002 - Post-Enrollment Group Reassignment|ADR 0002]] / [[Nebula Control Plane - ADR 0013 - Bulk Device Group Reassignment by Name Pattern|ADR 0013]] — the decisions this plan implements.
- Master roadmap: [[Nebula Control Plane - Implementation Plan|Implementation Plan (v2)]] — the M7-adjacent / Phase-3 deferral, now concretely scoped.
- M7 revocation/blocklist + `internal/dualcontrol` — reused in Phases 2–3.
