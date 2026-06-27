---
title: "ADR 0013 — Bulk Device Group Reassignment by Name Pattern"
created: 2026-06-27
status: proposed
tags: [nebula, adr, groups, devices, bulk, rbac, ui, architecture]
---

# ADR 0013 — Bulk Device Group Reassignment by Name Pattern

**Status:** Proposed — extends [[Nebula Control Plane - ADR 0002 - Post-Enrollment Group Reassignment|ADR 0002]] (accepted, not yet built) with a select-by-name-pattern, dry-run-then-apply bulk operation surfaced from the Devices view. Depends on the ADR 0002 Phase-1 substrate; promotes the "bulk membership management" line item ADR 0002 deferred to its Phase 3. This draft incorporates an adversarial review (security, mechanism-vs-code, bulk-safety, completeness).
**Date:** 2026-06-27
**Decision owners:** Chris Hyde (+ a second approver per dual-control, where it applies)

## Context

Operators need to re-group **sets** of devices at once — "move every `db-*` host into `prod` and `monitored`" — not one at a time. The request: from the Devices view, select devices by a **device-name pattern**, then re-group the selection.

The single-device mechanism this rides on is decided in [[Nebula Control Plane - ADR 0002 - Post-Enrollment Group Reassignment|ADR 0002]] but **not yet built** (verified: no `desired_groups`/`groups_generation`/`issued_generation` columns, no `PATCH /admin/v1/devices/{ip}/groups`, no `device:manage`; `coreapi.handleRenew` still re-signs static `enrollments.groups`, `internal/coreapi/coreapi.go:558-560`). ADR 0002 itself lists **"bulk membership management" as Phase-3 (optional)**. This ADR specifies it and therefore requires the ADR 0002 Phase-1 substrate as a prerequisite (delivered first, or in the same effort).

Four properties of the system shape the design, and three of them only bite at *bulk* scale:

1. **Group changes are per-device, asynchronous, eventually consistent.** ADR 0002's model: set `desired_groups` + bump `groups_generation`; the host's next heartbeat sees `desired_generation > issued_generation`, gets a `CmdRenew` (`commandsFor`, `coreapi.go:484`), re-keys, and `handleRenew` re-signs from `desired_groups` and writes back `issued_generation`. The change lands on the host's *next heartbeat-triggered renew* and hot-reloads via SIGHUP (same overlay IP, same curve → `reconcile.Classify` `ReloadOnly`, `reconcile.go:53-62`). **There is no control-plane push.** A bulk op is *N independent per-device requests fanned out from one operator action* — not a transaction.
2. **`overlay_ip` is a reusable IPAM slot, not a stable device identity.** `coreapi.device()` resolves an IP to the *latest issued enrollment* at that IP (`ORDER BY id DESC`, `coreapi.go:230-232`); the same resolution backs `deviceProvenance`. A rebuilt host re-enrolls (new row, new `id`), and a reaped IP can be re-handed to a different device — the codebase fails closed on exactly this (`coreapi.go:322-333`). So an `overlay_ip` captured at preview may point at a *different* device by apply time.
3. **Device names are NOT unique.** Re-enrollment under the same name leaves the old row in place (the duplicate `aws-client`/`monitoring` rows the dashboard live/stale split surfaced). A pattern matches multiple devices, including stale ghosts. The **unit of action is the device, identified by `(overlay_ip, enrollment_id)`, never the name.**
4. **Authority is server-side and absolute.** `handleRenew` reads groups from the device record; a host can never supply its own groups (`coreapi.go:558-560`). The bulk path must never weaken this.

`GET /admin/v1/devices` (`handleDevices`, `internal/adminapi/adminapi.go:514`) is heartbeat-driven, keyset-paginated on `overlay_ip`, exposes `name`/`overlay_ip`/issued `groups`/`stale`/`ephemeral`/provenance, supports scope (Go-side allow-set) + condition (SQL) filters — but **no name filter, and it does not expose `desired_groups`**. An enrolled host that has never heartbeated has no row at all (a third bucket beyond live/stale).

## Decision

A **dry-run-then-apply bulk re-group** built on the ADR 0002 substrate. The delta the operator expresses (`add`/`remove`/`replace`) is resolved **at preview into a per-device absolute target set + identity/generation tokens**; apply commits those exact per-device absolute sets through the ADR 0002 set primitive under optimistic concurrency. This makes "bulk = fan-out over the per-device set primitive" literally true and closes the concurrency and identity gaps the review found.

### 1. Selection and the dry-run preview

- **Pattern: glob** (`*`, `?`) → SQL `LIKE` on the server-set `heartbeats.device_name` (`*`→`%`, `?`→`_`, literals escaped). Glob is bounded and intuitive; regex is rejected (backtracking-DoS, backend-dependent). `GET /admin/v1/devices` gains a `name_pattern` filter (a SQL `WHERE` like the existing `condition` filter — *not* the Go-side scope filter), ANDable with the existing scope/condition chips. This powers raw browsing.
- **The authoritative preview is a delta-aware dry run: `POST /admin/v1/devices/regroup?dry_run=true`** with the same body as apply. The server resolves the matched live set and returns, per device: `overlay_ip`, **`enrollment_id`**, `name`, `provider`/origin, `desired_groups` (the *from* — see §6), the computed **absolute target** (the *to*), the current **`groups_generation`**, and a disposition flag (`will_apply` / `skip:stale` / `skip:ephemeral` / `skip:reserved` / `no_op`). Resulting groups are computed here, against `desired_groups`, never against issued groups.
- **Apply binds to the previewed identity, not the slot.** The apply body is the explicit per-device list the dry run returned: `[{overlay_ip, enrollment_id, target_groups, base_generation}]`. The server, per device, re-resolves the authoritative enrollment at `overlay_ip`; if its `enrollment_id` differs from the submitted one, or its `groups_generation` ≠ `base_generation`, it returns `skip:changed_since_preview` and writes nothing. This closes both TOCTOU windows (a *new* device swept in **and** the *same slot re-handed to a different device*) and gives optimistic concurrency against a racing single-device edit or overlapping bulk op.

### 2. Apply semantics: per-device absolute set, optimistic, best-effort, bounded

- **Each device is written as an absolute set** (`desired_groups := target_groups`, bump `groups_generation`) — the literal ADR 0002 primitive. The `add`/`remove`/`replace` delta exists only at preview to *compute* each target; the committed unit is the absolute target + generation guard. (This avoids the lost-update race a per-device server-side read-modify-write would introduce — that the absolute-set substrate never had.) `add ∩ remove ≠ ∅` is rejected at validation; the `overlay_ip` list is de-duplicated; no-op detection uses **set equality** (sorted, de-duplicated) so reordered/duplicate JSON never triggers a spurious generation bump or fleet renew.
- **Per-device, best-effort, not atomic.** Whole-request validation (malformed pattern, `add∩remove`, a target touching a reserved group, empty effective set) fails **before any write**; per-device runtime outcomes (`applied`/`skipped:<reason>`/`failed:<reason>`) never roll back already-applied devices. The bulk-op record (see §8) is written **before** the first device write so a dropped connection leaves a queryable intent + partial-disposition trail.
- **Bounded by a hard cap and a rate limit (decision, not deferred).** The resolved set is capped (mirror revocation's `MaxBulkFingerprints` = 100) and the operation is rate-limited per window (mirror `MaxBulkPerWindow` = 3/hour). The cap's real purpose is **bounding the renew/KMS burst**: arming `CmdRenew` on a large set makes every matched host renew on its next heartbeat with no canary/wave (each renew = two KMS signs — leaf cert + bundle), bypassing the rollout engine's pacing. Over the cap, the preview says "N more — narrow the pattern" and never silently truncates.

### 3. Reserved groups: guard current AND resulting membership (corrects the review blocker)

Reserved groups (`control-plane`, `lighthouse`) are **never reachable through this surface, in either direction**:
- A target that *adds* a reserved group is rejected (whole request) — `policy.GrantsReservedGroup` / `IsReservedGroup` (`internal/policy/policy.go:28-33`), the same predicate self-heal uses (`coreapi.go:311`). (Note: ADR 0002 mis-cites `policy.CheckInvariants`, which validates a *policy's rules*, not a group-assignment — this ADR cites the correct helper.)
- **Any device whose *current* authoritative groups satisfy `GrantsReservedGroup` is excluded from the set (`skip:reserved`)** — baseline-owned nodes (harbor-core, lighthouses) are not operator-manageable via this endpoint.
- Any computed target that would *drop* a reserved group a device currently holds is rejected.

This is the load-bearing correction: the input-operand check alone is **insufficient**, because a `replace:[prod]` (or any reduction) that never names `control-plane` would otherwise strip it from a live, non-stale harbor-core → `CompileHost` drops the control-plane baseline-accept rule (`policy.go:193-202`) → the fleet can no longer heartbeat/renew (the failure [[Nebula Control Plane - ADR 0009 - Control-Plane Trust-Zone Separation|ADR 0009]] / the PR that made the CP firewall invariant exists to prevent). The guard is on each device's current and resulting set, not the operator's operands.

### 4. Stale, ephemeral, never-seen hosts

- **Stale hosts are excluded by default** (`skip:stale`): a stale host can't heartbeat to pick up the change, so writing `desired_groups` just creates `desired>issued` that never clears and permanently inflates the fleet pending-re-issue count. The dry run reports the split ("3 of 5 matched are stale and will be skipped"). `include_stale` is an explicit opt-in; opted-in hosts are shown as `pending — applies if/when the host returns`, and their pending state is scoped/expired so dead ghosts don't pollute the live metric (ties to the reaper — Open Question).
- **Ephemeral hosts are excluded by default** (`skip:ephemeral`) — they're destined for reaping; re-grouping one is wasted work and another pending ghost.
- **Never-heartbeated enrollments are invisible** to the preview (no `heartbeats` row); a pattern matches only devices that have checked in. The UI states this so "pattern matches all enrolled devices" is not assumed.

### 5. Authorization: perm + step-up for small/removal, dual-control for elevating or large sets

- **`device:manage` + step-up MFA** (the permission ADR 0002 introduces) gate single-device and *small* bulk operations. Note `requireStepUp` is a no-op when `MFAFreshness<=0` (`rbac.go:111-113`) — on such a deployment the perm is the only gate, which is exactly why bulk needs more.
- **Dual-control is required in Phase A — not deferred** — for any bulk op that (a) **adds** a group (an elevation) **or** (b) exceeds a small resolved-set threshold (blast radius). It routes through the shipped `internal/dualcontrol` as a `device.groups` change kind (payload = the explicit `(overlay_ip, enrollment_id, target, base_generation)` set), mirroring policy/cloudtrust publish and bulk-revoke. Single-device and pure-reduction stay on perm+step-up. Gating on add-vs-remove + set size (both computed at preview) avoids depending on a privilege catalog that doesn't exist yet; a catalog can later refine *which* additions need it (Phase C).

### 6. Additions vs reductions; reduction is a durable advisory state

Per device, the fork is ADR 0002's:
- **Additions are complete in Phase A** — the re-issued cert is a superset; peers re-evaluate groups from the cert it presents, no peer re-issue.
- **Reductions are *soft* until the old cert is revoked, and that is a durable per-device fact, not a pre-commit warning.** The old higher-privilege cert stays cryptographically valid until expiry; a cooperative pilot stops using it, a hostile host need not. The API/UI carry a per-device `reduction_pending_enforcement` attribute ("old cert valid until `<notAfter>`") that **persists after the badge clears**, until the cert expires or Phase B revokes it — so the console never states a reduction as enforced fact while the old cert lives. `replace` that drops any group **is** a reduction for that device and inherits this treatment (promoted from an open question to a decision).

The dry-run/`from` baseline is **`desired_groups`**, not issued groups, so an already-in-flight device shows the correct before/after (issued-vs-desired surfaced when they differ).

### 7. No IPAM movement

Re-grouping changes only the groups the cert is signed with — never the overlay IP or netblock (keyed on the stable IP; renew is same-IP/same-curve → `ReloadOnly`). Affirmed for the bulk set: across the whole selection only the groups field changes; IPAM allocations are untouched ([[Nebula Control Plane - ADR 0010 - IPAM|ADR 0010]] is unaffected).

### 8. Audit: correlated, committed-set, and capturing the authority event

- One **bulk-op record** (a batch id, the actor, the *committed* `(overlay_ip, enrollment_id)` set — not the pattern — the delta, and per-device disposition incl. skips/failures), written before the first device write.
- Each per-device `desired_groups` write and its audit entry are **one transaction** (no silent un-audited authority change), stamped with the batch id so batch and per-device entries correlate (`AppendAudit` is `(actor, action, target, details)` — the batch id goes in details).
- The actual authority-granting event is the **cert issue in `handleRenew`**, which today audits a generic `cert-renewed` with no groups/generation/operator (`coreapi.go:607`). ADR 0002's write-back is extended to audit the issued `groups` + `issued_generation` + the originating batch id, so the issued-authority event joins back to the operator's intent. Per-device audit volume is bounded by the §2 cap (the audit chain is a globally-serialized hash chain; an uncapped bulk would be a lock-contending write amplification, `coreapi.go:272`).

### 9. API

- `GET /admin/v1/devices?name_pattern=<glob>[&condition=…&provider=…]` — raw lister, new `name_pattern` SQL filter; now also exposes `desired_groups` + a `pending` flag.
- `POST /admin/v1/devices/regroup` — body `{ name_pattern?, overlay_ips?, add?, remove?, replace?, include_stale? }`.
  - `?dry_run=true` → resolves and returns the per-device disposition (§1) — **no writes**.
  - apply → body is the dry-run's explicit `[{overlay_ip, enrollment_id, target_groups, base_generation}]`. `200` with the per-device result array for the perm+step-up path; **`202` with a dual-control `Change`** for the elevating/large path (§5); `400` on reserved-group target / `add∩remove` / over-cap / empty effective set. Idempotent on re-submit (absolute-set + generation guard).

### 10. UI (Devices view)

- A **glob name filter** on the Devices table.
- A **"Re-group…" action** (gated on `device:manage`) → modal consistent with the create-button + `Dialog` + `HostLabel` (name + overlay_ip) patterns: add/remove (or replace) inputs → a **dry-run preview list** (`name overlay_ip`, origin, current `desired` groups, computed target diff-highlighted, per-device disposition incl. skipped-stale/ephemeral/reserved) → a confirmation restating the committed count, skipped counts, the *reductions-are-advisory* and *grants-cannot-be-promptly-undone* caveats, and (when the op is elevating/large) that it will route to a second approver → commit. Per-device success/failure surfaced on completion; pending-re-issue badges clear independently as hosts converge.

## Scope / non-goals

- **In scope:** the dry-run preview + explicit-set apply, the `name_pattern` filter, the `device:manage`-gated (and dual-control-for-elevation) bulk endpoint, per-device absolute-set-from-delta semantics, reserved/stale/ephemeral exclusion, correlated audit, and the Devices-view UI — *on top of* the ADR 0002 Phase-1 substrate (a hard prerequisite).
- **Not in scope / explicit limits:**
  - **Durable group identity across host recycle.** A re-enrolled host gets fresh groups from its join-method defaults; a per-device bulk re-group does **not** survive a rebuild. By-name fleets (`db-*`, `worker-*`) are exactly the auto-scaled/ephemeral populations that churn, so the durable answer for "this *class* of host always gets these groups" is the **trust/join-method defaults** (cloudtrust / usertrust / join-key default groups), not per-device bulk. Bulk-by-name is for *ad-hoc* reassignment of existing hosts, and the ADR says so.
  - **Undo.** There is no auto-rollback (unlike the rollout engine's canary/wave). Undo = the inverse bulk op, and undoing an over-**grant** inherits the reduction soft/Phase-B dependency — i.e. a mistaken elevation is **not promptly reversible** before Phase B; the confirmation says so. An optional first-class "undo bulk op `<batch id>`" (replay each device's recorded `from` under the same identity guard) is a Phase-C nicety.
  - Re-deciding the single-device mechanism (ADR 0002); a group catalog/privilege tiers (deferred); moving overlay IPs (ADR 0010); control-plane push (rejected in ADR 0002).
  - **Re-attestation:** a group change is operator-driven; the operator is the authority, so a regroup renew does not re-verify cloud attestation (inherited from ADR 0002 — restated for the bulk-of-attested-hosts reader).

## Phases

- **Phase A — substrate + additive bulk + UI.** Implement (or co-deliver) the ADR 0002 Phase-1 substrate; add the dry-run + explicit-set apply, the `name_pattern` filter, reserved/stale/ephemeral exclusion, the cap + rate limit, dual-control for elevating/large ops, correlated audit, and the Devices-view modal. Additions effective; reductions soft + durably labeled. Named tests: the absolute-set + generation-guard concurrency, reserved-current/resulting exclusion, stale/ephemeral exclusion, identity-token skip-on-change, dry-run/apply equivalence.
- **Phase B — enforceable reductions (a real milestone, not "just wiring").** Revoking the *old* cert is non-trivial because the enrollment fingerprint **rotates at renew** (`handleRenew` overwrites it, `coreapi.go:587-594`) and the reduction takes effect *at* that renew. Phase B must: snapshot the pre-reduction fingerprint; sequence the blocklist-add to fire **after** the host installs the reduced cert (revoking earlier cuts off a cooperative host still on the old cert); and reconcile a bulk of N reductions with the revocation subsystem's deliberate guardrails — `MaxBulkFingerprints=100`, `MaxBulkPerWindow=3/hr`, **dual-control** on `BulkRevokeKind` (`internal/revocation/revocation.go:60-67`) — rather than fanning N uncapped single-host `Add`s around them. Also bound peer-bundle blocklist growth for large bulk reductions.
- **Phase C — hardening.** A group catalog (so bulk can't fat-finger a typo'd group fleet-wide) + privilege tiers refining which *additions* need dual-control; first-class undo; richer convergence observability.

## Alternatives considered

- **Per-device server-side delta (read-modify-write) at apply.** Rejected: two overlapping writers race and silently lose an update; the absolute-set substrate never had this hazard. Resolving the delta to an absolute target at preview + a generation guard keeps the safe last-writer-wins set semantics.
- **Apply against the pattern, or against bare `overlay_ip`.** Rejected: the pattern re-evaluates to a different set; a bare IP is a reusable slot that can be re-handed to a different device between preview and apply. Binding to `(overlay_ip, enrollment_id, base_generation)` is the only way "the committed change equals what the operator reviewed" is server-enforced, not a client convention.
- **`replace` as the default semantic; reserved-check on operands only.** Rejected: `replace` clobbers heterogeneous selections and, checked only on operands, can strip a reserved group off a CP/lighthouse host. `add`/`remove` deltas are the default; reserved is guarded on current+resulting membership.
- **Perm+step-up for all of Phase A (dual-control fully deferred).** Rejected on review: a single actor could elevate the fleet in one request with the cheapest, already-shipped control deferred. Dual-control gates elevating/large ops from Phase A.
- **Regex; client-side selection as the committed set; a bespoke bulk re-issue path.** Rejected (DoS surface; stale/paginated client selection; the per-device renew path is reused, not rebuilt).

## Consequences

- **+** Operators re-group fleets in one reviewed, server-validated action; the dry run makes blast radius explicit and the committed set is provably what was reviewed.
- **+** Reuses the ADR 0002 absolute-set primitive and the shipped blocklist/dual-control — no new convergence, revocation, or maker-checker machinery; only the bulk resolution, identity/generation guard, and UI are new.
- **+** Forces the long-deferred ADR 0002 substrate to ship; designs out same-named-ghost and re-handed-slot confusion.
- **−** Asynchronous and eventually consistent: the operator commits, then watches pending-re-issue badges clear over seconds-to-minutes; no instantaneous fleet apply, no auto-rollback.
- **−** Mistaken **elevations are not promptly reversible** before Phase B (undo is a soft reduction); mitigated by dual-control + the cap + the explicit confirmation.
- **−** Bulk reductions remain advisory against a hostile host until Phase B, which is a real milestone (fingerprint timing + revocation guardrails), not a quick wire-up.
- **−** A per-device bulk result evaporates if the host recycles; durable class-level grouping belongs at the trust/join-method layer (stated non-goal).

## Open questions

1. **Dual-control thresholds.** What set-size threshold flips a bulk op to dual-control, and should *every* addition require it regardless of size? *(Leaning: dual-control for any addition OR set size > a small N; tune N with the cap; refine per-group once a catalog exists.)*
2. **`include_stale` / ghost lifecycle.** Should opted-in stale `desired_groups` expire or be reaper-collected so dead ghosts don't accrue permanent pending state? *(Leaning: yes — scope the pending metric to live hosts and GC ghost desired-state with the reaper.)*
3. **Group catalog vs free-form (inherited ADR 0002 Q3).** A bulk typo lands a whole set in a junk group — strengthens the case for a constrained catalog + namespacing (cf. [[Nebula Control Plane - ADR 0001 - Policy Scoping|ADR 0001]]). *(Leaning: free-form + confirm for Phase A; catalog in Phase C.)*
4. **First-class undo.** Worth a dedicated "undo batch `<id>`" op, or is the inverse-bulk-op + audit trail enough? *(Leaning: audit trail for Phase A; undo op in Phase C.)*

## Relationship to other work

- **[[Nebula Control Plane - ADR 0002 - Post-Enrollment Group Reassignment|ADR 0002]]** — the substrate (desired-vs-issued, per-device set endpoint, renew-time re-issue). ADR 0013 specifies the bulk/pattern/UI layer it deferred and requires its Phase 1 first.
- **M7 revocation / blocklist** (`internal/revocation`, blocklist rollout lane, `BulkRevokeKind` with its cap/rate-limit/dual-control) — Phase B wires bulk reductions to it, respecting those guardrails.
- **`internal/dualcontrol`** — reused for the elevating/large-bulk path (a `device.groups` change kind).
- **[[Nebula Control Plane - ADR 0012 - Pilot Fleet Metrics|ADR 0012]]** — the pending-re-issue / `ncp_fleet_*` surface is how an operator watches a bulk converge; the cap bounds the renew/KMS burst those metrics would show.
- **[[Nebula Control Plane - ADR 0010 - IPAM|ADR 0010]]** — unaffected; re-grouping never moves a host's overlay IP/netblock.
- **[[Nebula Control Plane - ADR 0001 - Policy Scoping|ADR 0001]]** — group namespacing/catalog context for the fat-finger open question.
- **Dashboard live/stale split** (Fleet convergence / Version landscape) — the same `splitByLiveness` + `HostLabel` (name + overlay_ip) primitives the preview reuses to keep ghosts distinct from live hosts.
