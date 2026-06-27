---
created: 2026-06-27
source: claude-code
status: proposed
project: nebula-control-plane
tags: [nebula, implementation, groups, devices, bulk, rbac, ui]
---

# Implementation Plan — Device Group Reassignment (ADR 0002 + ADR 0013)

**Status:** Proposed — scopes [[Nebula Control Plane - ADR 0002 - Post-Enrollment Group Reassignment|ADR 0002]] (single-device substrate, accepted but unbuilt) and [[Nebula Control Plane - ADR 0013 - Bulk Device Group Reassignment by Name Pattern|ADR 0013]] (bulk/pattern/UI layer) into one ordered build. Incorporates the ADR 0013 adversarial-review decisions.
**Date:** 2026-06-27
**Decision owners:** Chris Hyde

## Goal & shape

Let an operator change a device's nebula groups after enrollment — one device, or a pattern-selected set — server-side, audited, with the change taking effect on the host's next heartbeat-triggered renew (hot-reload, same overlay IP). Built on the **desired-vs-issued generation model** (ADR 0002): set `desired_groups` + bump `groups_generation`; the host renews when `desired_generation > issued_generation`; `handleRenew` re-signs from `desired_groups` and writes back `issued_generation`. Bulk (ADR 0013) is a **dry-run → explicit-set apply** that resolves the operator's delta to per-device *absolute targets + `(overlay_ip, enrollment_id, base_generation)` identity tokens*, then commits each as an absolute set under optimistic concurrency — so bulk is literally fan-out over the single-device primitive.

**Build order:** Phase 1 (single-device substrate, independently shippable) → Phase 2 (bulk + UI) → Phase 3 (enforceable reductions) → Phase 4 (hardening). Phases 1–2 are additive and low-risk; reductions are *soft* (advisory) until Phase 3.

**Invariants every phase must hold** (from the ADRs + review):
- **Authority is server-side** — the host supplies only a CSR; groups come from the device record (`coreapi.go:558-560`). Never accept host-supplied groups.
- **Reserved groups (`control-plane`/`lighthouse`) are untouchable** via this surface in *either* direction — guard on a device's **current and resulting** membership, not just the operator's operands (`policy.GrantsReservedGroup`, `policy.go:33`). A reduction/`replace` must never strip `control-plane` off a live harbor/lighthouse → that drops its baseline-accept firewall (`policy.go:193-202`) and bricks the fleet.
- **`overlay_ip` is a reusable slot, not an identity** — bind apply to `(overlay_ip, enrollment_id, base_generation)`; `device()` resolves "latest issued at IP, id DESC" (`coreapi.go:230-232`).
- **No new convergence machinery** — reuse renew + `CmdRenew` + the absolute-set write; no control-plane push, no IP move.

---

## Phase 1 — Single-device substrate (ADR 0002 Phase 1)

Independently shippable: an operator can change one device's groups; additions effective, reductions soft.

- **P1.1 — Migration `000030_group_reassignment` (postgres + sqlite).** Add to `enrollments`: `desired_groups TEXT NOT NULL DEFAULT '[]'`, `groups_generation BIGINT NOT NULL DEFAULT 0`, `issued_generation BIGINT NOT NULL DEFAULT 0`. Backfill existing rows: `desired_groups = groups`, both generations `0`. (Next free number is 000030; migrations are at 000029.) `internal/store/migrate/sql/{postgres,sqlite}/`.
  - *Accept:* `harbor migrate up` clean on a populated DB; existing devices unaffected (`desired==issued`, gen 0 → no re-issue triggered).
- **P1.2 — Enrollment model fields.** Add `DesiredGroups string`, `GroupsGeneration int64`, `IssuedGeneration int64` to the enrollment struct (`internal/enrollment/enrollment.go:~84`); seed them at `record()` (`~1113`): `desired_groups = groups`, gens `0`.
- **P1.3 — `commandsFor` trigger** (`internal/coreapi/coreapi.go:484-506`). Emit `CmdRenew` when `dev.GroupsGeneration > dev.IssuedGeneration` (a third trigger beside near-expiry and rollout). Requires the resolved enrollment in `commandsFor` (it already runs per-heartbeat with the device in scope). Coexists with the rollout-lane command in the same beat (benign — see Risks).
  - *Accept:* setting `desired>issued` causes the next heartbeat to return `CmdRenew`; equal generations do not.
- **P1.4 — `handleRenew` reads desired + race-safe write-back** (`coreapi.go:508-611`). **Capture `(desiredGroups, gen)` atomically at read**; sign the cert from `desiredGroups` (replaces the static `dev.Groups` read at `:559`); recompile firewall from the new groups. Write back `groups = desiredGroups`, `issued_generation = gen` **guarded by `WHERE issued_generation < gen`** so a slow renew can't clobber a newer issue and a concurrent operator bump can't false-converge. **Audit the authority event**: the existing `cert-renewed` audit gains `groups` + `issued_generation` + (Phase 2) the originating batch id, in the *same transaction* as the write-back.
  - *Accept:* a device with `desired=[a,b]`, `issued=[a]` renews to a cert carrying `[a,b]`, `issued_generation` advances, the audit row shows the new groups; a generation bump mid-renew does not mark it converged.
- **P1.5 — RBAC `device:manage`** (`internal/adminapi/rbac.go:25-42`, role matrix `:57-71`). Add `PermDeviceManage = "device:manage"`. admin (superuser) has it; grant to operator for single-device + small bulk (the dangerous bulk paths gate on dual-control, which operator can't self-approve). Mirror in the UI perms (`ui/src/api/perms.ts`).
- **P1.6 — Single-device endpoint.** `PATCH /admin/v1/devices/{ip}/groups {groups:[…]}` in a new `internal/adminapi/device_groups.go`, registered in `routeTable` (`adminapi.go:~276`). Resolve the enrollment at `ip` (the same row `device()` reads, id DESC); reject if the target adds a reserved group **or** the device currently holds one (`policy.GrantsReservedGroup`); set `desired_groups`, bump `groups_generation`; `device:manage` + step-up; loud audit (old→new, actor). openapi.yaml + `make gen:api`.
  - *Accept:* operator sets groups on one device; reserved add/strip rejected; audit recorded; host converges on next heartbeat.
- **P1.7 — Expose state on the device read** (`GET /admin/v1/devices`, `adminapi.go:514`). Add `desired_groups` + a `pending` flag (`groups_generation > issued_generation`) to the `Device` response so the console can show issued-vs-desired and a "pending re-issue" badge. openapi + `gen:api`.
- **P1.8 — Single-device UI.** An "Edit groups" row action on `ui/src/pages/Devices.tsx` (Dialog modal, like JoinKeys), with a reserved-group guardrail, the **removal-is-advisory** warning, and a pending-re-issue badge that clears when `issued==desired`.
- **P1.9 — Tests + adversarial review.** Integration: set→trigger→renew→write-back→converge; the generation guard under a concurrent bump; reserved current/resulting rejection; backfill idempotency.

**Phase 1 exit:** single-device group changes work end-to-end; reductions documented as advisory.

---

## Phase 2 — Bulk + pattern selection + UI (ADR 0013 Phase A)

Fan-out over the Phase-1 primitive; the only new surface is selection, the dry-run, identity/generation guarding, exclusions, dual-control routing, and the UI.

- **P2.1 — `name_pattern` filter on `GET /devices`.** Glob → SQL `LIKE` on `heartbeats.device_name`, applied as a SQL `WHERE` like the **condition** filter (NOT the Go-side scope allow-set; keyset-safe). Escape `%`/`_`; `*`→`%`, `?`→`_`.
- **P2.2 — Dry-run resolver.** `POST /admin/v1/devices/regroup?dry_run=true` with `{name_pattern?, overlay_ips?, add?, remove?, replace?, include_stale?}`. Resolve the matched live set; per device compute the **absolute target** from the delta over `desired_groups`; return `[{overlay_ip, enrollment_id, name, origin, desired(from), target(to), groups_generation, disposition}]` where disposition ∈ `will_apply|skip:stale|skip:ephemeral|skip:reserved|no_op`. **No writes.** Validation that fails the whole request: malformed pattern, `add∩remove≠∅`, a target adding a reserved group, empty effective set, over-cap.
- **P2.3 — Apply (absolute-set, optimistic).** `POST /admin/v1/devices/regroup` body = the dry-run's explicit `[{overlay_ip, enrollment_id, target_groups, base_generation}]`. Per device: re-resolve the authoritative enrollment at `overlay_ip`; if `enrollment_id` differs or current `groups_generation != base_generation` → `skip:changed_since_preview` (no write); else write `desired_groups = target` + bump generation **as an absolute set** (no server-side read-modify-write). No-op detection by **set equality** (sort+dedup) → no spurious bump. Per-device result array; best-effort (no rollback of applied devices); whole-request validation re-checked before the first write.
- **P2.4 — Reserved/stale/ephemeral exclusion.** Exclude any device whose **current** groups satisfy `GrantsReservedGroup` (`skip:reserved`); exclude `stale` and `ephemeral` by default (`include_stale` opt-in only, shown as pending). Never-heartbeated enrollments are absent from the list (state in UI).
- **P2.5 — Cap + rate limit (decision).** Cap the resolved set (mirror `revocation.MaxBulkFingerprints` = 100) and rate-limit per window (mirror `MaxBulkPerWindow` = 3/hr) — primarily to bound the renew/KMS burst (each renew = 2 KMS signs; no canary/wave). Over-cap → preview says "N more — narrow the pattern," never truncates silently.
- **P2.6 — Dual-control for elevating/large ops.** Route through `internal/dualcontrol` (new `device.groups` change kind + committer, mirroring policy/cloudtrust publish) when the op **adds** a group OR the resolved set exceeds the threshold; payload = the explicit `(overlay_ip, enrollment_id, target, base_generation)` set. Single-device + pure-reduction stay on perm+step-up. Apply returns `202` + `Change` for the dual-control path, `200` otherwise.
- **P2.7 — Correlated audit.** One bulk-op record (batch id, actor, the *committed* `(overlay_ip, enrollment_id)` set, the delta, per-device disposition incl. skips/failures) written **before** the first device write; the batch id stamped into each per-device `device-regroup` audit entry and threaded into the Phase-1 `handleRenew` authority audit. Per-device audit volume bounded by P2.5 (the audit chain is globally serialized).
- **P2.8 — Bulk UI.** `Devices.tsx`: a glob name filter + a "Re-group…" action (`device:manage`) → modal: add/remove (or replace) inputs → dry-run preview list (`HostLabel` name+overlay_ip, origin, current desired, target diff-highlighted, per-device disposition) → confirmation restating committed count, skipped counts, *reductions-advisory* + *grants-not-promptly-undoable* caveats, and a "routes to a second approver" note when elevating/large → commit; `202` → "awaiting approval" state. `api/hooks.ts`: `useDeviceRegroup` (dry-run + apply).
- **P2.9 — Tests.** Absolute-set + generation-guard concurrency (two overlapping bulks, single+bulk); identity-token skip-on-change (reaped+re-handed slot); reserved current+resulting exclusion; stale/ephemeral exclusion; dry-run↔apply equivalence; cap/rate-limit; `add∩remove` reject + dedup; dual-control routing.

**Phase 2 exit:** pattern-select bulk re-group from the Devices view; additions effective, reductions soft + durably labeled.

---

## Phase 3 — Enforceable reductions (ADR 0002 Phase 2 / ADR 0013 Phase B)

The security-completing step. **Not "just wiring"** — the fingerprint rotates at renew and bulk reductions must respect the revocation guardrails.

- **P3.1 — Snapshot the pre-reduction fingerprint.** In `handleRenew`, when the new groups are a reduction of the issued set, capture `dev.Fingerprint` (the *old* cert) **before** the write-back overwrites it (`coreapi.go:587-594`).
- **P3.2 — Convergence-gated revoke.** Add the old fingerprint to the blocklist **after** the host has installed the reduced cert (revoking before convergence cuts off a cooperative host still on the old cert). Wire to `internal/revocation` + the blocklist rollout lane.
- **P3.3 — Reconcile with revocation guardrails.** A bulk of N reductions must respect `MaxBulkFingerprints=100`, `MaxBulkPerWindow=3/hr`, and **dual-control on `BulkRevokeKind`** (`revocation.go:60-67`) — batch through the bulk-revoke path, do **not** fan N uncapped single-host `Add`s around them. Bound peer-bundle blocklist growth for large reductions.
- **P3.4 — Drop the advisory caveat** in API/UI for a reduction once its old cert is revoked fleet-wide; the durable `reduction_pending_enforcement` attribute clears.
- **P3.5 — Tests.** Reduction → fingerprint snapshot → convergence-gated blocklist add → peer bundles carry it; ordering (no premature revoke); bulk reduction vs the revocation cap/dual-control.

---

## Phase 4 — Hardening (ADR 0013 Phase C)

- **P4.1 — Group catalog + privilege tiers** (so bulk can't fat-finger a typo'd group fleet-wide; refine *which* additions need dual-control). Cf. [[Nebula Control Plane - ADR 0001 - Policy Scoping|ADR 0001]].
- **P4.2 — First-class undo** ("undo batch `<id>`": replay each device's recorded `from` under the identity-token guard; an over-grant undo inherits the Phase-3 revoke path).
- **P4.3 — Convergence observability** — a bulk-scoped "X of N pending re-issue" signal via the [[Nebula Control Plane - ADR 0012 - Pilot Fleet Metrics|ADR 0012]] `ncp_fleet_*` surface.

---

## Dependencies & sequencing

- P1.1 → P1.2 → {P1.3, P1.4} → P1.6 → {P1.7, P1.8}; P1.5 before P1.6/P1.8.
- Phase 2 requires all of Phase 1. P2.1 + P2.2 before P2.3; P2.4/P2.5/P2.6/P2.7 fold into the P2.2/P2.3 handler; P2.8 last.
- Phase 3 requires Phase 1 (P1.4 write-back) + the shipped blocklist; independent of Phase 2 (applies to single-device reductions too) but bulk reductions need P3.3.
- Phase 4 is optional, after 1–3.

## Cross-cutting

- **openapi.yaml + `make gen:api`** after every endpoint/field change (P1.6, P1.7, P2.2/P2.3) so the TS client types track.
- **`make harbor-ui`** for any UI change; deploy per the usual swap + `ncp-admin` recreate.
- **No IP/netblock movement** anywhere ([[Nebula Control Plane - ADR 0010 - IPAM|ADR 0010]] untouched).
- **Limitation to document in UI/help:** a per-device re-group does not survive a host rebuild (re-enrollment reseeds from join-method defaults). Durable class-level grouping belongs at the trust layer (cloudtrust/usertrust/join-key defaults), not here.

## Risks

- **Reserved-group eviction (highest).** Mitigated by P2.4 / P1.6 current+resulting guard. Add a test that a `replace` excluding `control-plane` against a pattern matching harbor-core is rejected.
- **Lost-update under concurrency.** Avoided by absolute-set apply + the `WHERE … generation` guard (P2.3, P1.4) — never a read-modify-write.
- **Renew/KMS burst.** Bounded by P2.5 cap; consider staggering `CmdRenew` emission if even the capped burst spikes signing.
- **Regroup × rollout in one heartbeat.** `commandsFor` can return both a regroup `CmdRenew` and a rollout `apply_bundle`; `handleConfig` rebuilds from *issued* groups, so the host may briefly apply old-groups firewall + new-groups cert in some order. It converges; add a test asserting benign interleaving.
- **Reaper/hard-delete race.** A target reaped between dry-run and apply may be hard-deleted; the identity-token guard (P2.3) turns this into a clean `skip`.

## Relationship to other work

- [[Nebula Control Plane - ADR 0002 - Post-Enrollment Group Reassignment|ADR 0002]] / [[Nebula Control Plane - ADR 0013 - Bulk Device Group Reassignment by Name Pattern|ADR 0013]] — the decisions this plan implements.
- Master roadmap: [[Nebula Control Plane - Implementation Plan|Implementation Plan (v2)]] — group reassignment was the M7-adjacent / Phase-3 deferral; this plan is its concrete scoping.
- M7 revocation/blocklist + `internal/dualcontrol` — reused in Phases 2–3.
