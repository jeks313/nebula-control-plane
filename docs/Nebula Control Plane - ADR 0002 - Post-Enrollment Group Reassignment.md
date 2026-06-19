---
title: "ADR 0002 — Post-Enrollment Group Reassignment"
created: 2026-06-13
status: accepted
tags: [nebula, adr, groups, enrollment, renewal, revocation, architecture]
---

# ADR 0002 — Post-Enrollment Group Reassignment

**Status:** Accepted (Phase 1 is the direction; Phase 2 gated on M7 revocation)
**Date:** 2026-06-13
**Decision owners:** Chris Hyde (+ a future second approver, per dual-control)

**Status (2026-06-18):** PLANNED — none of the group-reassignment feature is built
yet (no `desired_groups` columns/migration, no `POST/PATCH /admin/v1/devices/{ip}/groups`
endpoint, no `device:manage` permission; `coreapi.handleRenew` still reads the static
`dev.Groups`). What HAS changed since this ADR was written: **M7 revocation is no longer
unbuilt** — the cert blocklist is SHIPPED & LIVE (`internal/revocation`, migrations
000013/000014, `pki.blocklist` rendered + propagated via renew/config bundles and a
`blocklist` rollout lane, `harbor blocklist add/remove/list/status`). So Phase 2's hard
dependency now exists; the remaining Phase-2 work is wiring a group *reduction* to revoke
the old cert. (Console blocklist view + dual-control bulk-revoke is the separate 7.2/UI-5
item; single-host CLI revoke is live.)

## Context

A host's **groups** are the unit of authority in the mesh: the firewall policy is
group → group (`internal/policy`), `CompileHost` resolves a host's per-host firewall
from its groups, and Nebula evaluates a *remote* peer's groups from the cert it presents
at handshake. Today groups are assigned **once, by join method** — join-key groups (token
enroll) or the cloud-trust per-account groups (attestation, M5.3) — and **baked into the
issued certificate**. They are effectively immutable after enrollment: certificate
renewal (`coreapi.handleRenew`, `coreapi.go:224`) deliberately "re-sign[s] the SAME
identity (IP + groups from the device record)" — it reads `dev.Groups` from the static
enrollment row (`coreapi.go:275`).

The requirement: an operator must be able to **change a device's groups after
enrollment**, and that change must cause Pilot to **regenerate its key with the new
groups and resubmit for signing**, then apply the result with no outage.

The encouraging finding from tracing the code: **most of the machinery already exists.**

- **Renewal already re-keys and re-signs with groups + recompiles the firewall.**
  `handleRenew` accepts a fresh-key CSR (renewal "rotates the key", `renew.go:6`),
  re-signs the cert with the device's groups, recompiles the per-host firewall
  (`bundle.CompileFirewall(policy, groups)`, `coreapi.go:303`), and returns a single
  **signed bundle** (cert + firewall + lighthouses + CA).
- **The heartbeat is a typed command channel.** `commandsFor` (`coreapi.go:206`) already
  returns `CmdRenew` (the near-expiry backstop) and the rollout `apply_bundle` command;
  Pilot already acts on a Core-issued renew via `RenewNow` (`renew.go:146`).
- **A group re-issue is a hot reload, not a restart.** `reconcile.Classify`
  (`reconcile.go:53`) treats a same-IP/same-curve PKI refresh as `ReloadOnly` (SIGHUP);
  groups change neither the overlay IP nor the curve.
- **Authority is already server-side.** The renew request carries only a CSR; Core reads
  the groups, the host never supplies them — so a host cannot self-elevate.
- **Provenance already surfaces a device's current groups** (from its latest issued
  enrollment; the device-provenance slice), so the new groups appear in the console after
  re-issue with no extra work.

The *only* reason groups are immutable is that renew reads them from a **static** source.
The feature is therefore: give a device a **mutable "desired groups," make renew read
that, and trigger a renew when it changes** — plus the genuinely hard part, making a
group *removal* enforceable against a malicious host.

## Decision

**Adopt a desired-vs-issued groups model and ride the existing renew + heartbeat-command
path** rather than building a new re-issue mechanism. Per device (keyed on the stable
`overlay_ip`):

- **`desired_groups` + `groups_generation`** — control-plane-authoritative, set by an
  operator (seeded at enrollment from the join-method defaults), generation bumped on
  every change.
- **issued groups + `issued_generation`** — what the current cert was actually signed
  with (the enrollment row's `groups`, stamped with the generation it was issued at).

`desired_generation > issued_generation` is the single, race-safe predicate that means
"this host is pending a re-issue." It drives the heartbeat trigger and the console badge.

Execute in **phases**, gated on the threat the change must defend against:

- **Phase 1 — reassignment via re-issue (additive, low-risk).** The desired-groups model,
  the admin endpoint, renew reading `desired_groups`, the `commandsFor` trigger, the
  write-back, and the UI. Delivers working group changes that take effect on the host's
  next re-issue. Group **additions** are fully effective; group **removals** are *soft*
  (documented as such).
- **Phase 2 — enforceable removals (M7 revocation).** Revoke the old cert on a reduction
  and distribute the blocklist in peer bundles. This is the security-completing step and
  is a milestone in its own right.
- **Phase 3 — hardening (optional).** Dual-control for group changes; a group catalog with
  privilege tiers; bulk membership management.

## The decision driver (the fork)

Everything hinges on **add vs. remove**:

- **Adding** a group → the new cert is a superset; effective the moment the host renews and
  presents it. Peers re-evaluate the host's groups from the new cert live (no peer
  re-issue). **Safe and complete in Phase 1.**
- **Removing** a group → the host installs the reduced cert, but the **old cert (with the
  removed group) stays cryptographically valid until it expires.** A cooperative Pilot
  stops using it, but a **compromised or malicious host can keep presenting the old cert**
  and retain the higher privilege. Truly enforcing a reduction requires **revoking the old
  cert (M7 blocklist)** and propagating the blocklist to peers.

**M7 was unbuilt when this ADR was written; it is now SHIPPED & LIVE** (cert blocklist
in `internal/revocation`, rendered into `pki.blocklist` and propagated via renew/config
bundles + a `blocklist` rollout lane; `harbor blocklist add/remove/list/status`). The
fork's reasoning still holds for the *unbuilt Phase 1*: until a reduction is wired to
revoke the old cert, a removal would be *advisory* (trust-on-cooperation), with a residual
window equal to the old cert's remaining lifetime — shrinkable with short cert TTLs,
closeable only by tying the reduction into the now-existing blocklist. This fork is the
reason the work is phased rather than shipped whole: the cheap, valuable half
(reassignment) does not wait on the expensive, security-load-bearing half (revocation),
but the UI and the docs must not overstate what a removal does until the reduction→revoke
wiring lands. *(Note 2026-06-18: the revocation primitive now exists, so Phase 2 is a wiring
step rather than a new milestone.)*

## Considered options

| Option | Verdict | One-line |
|---|---|---|
| **A. Reuse renew + desired-groups model** | **Chosen** | Renew already re-keys, re-signs with groups, recompiles the firewall, and returns a bundle; the heartbeat already commands renews — flip the groups source from static→desired and add one trigger. |
| **B. Dedicated `/v1/certs/reissue` endpoint** | Rejected | Duplicates ~all of `handleRenew` (re-key, sign, firewall compile, bundle, audit) for no behavioural difference; a group change *is* a renew with a different groups source. |
| **C. Control-plane pushes new config to the host** | Rejected | Violates P3 (control plane off the data path). The host is reached only via its own heartbeat/renew polling; the command channel already exists for exactly this. |
| **D. Mutate the enrollment `groups` directly, no generation** | Rejected | A set-comparison trigger churns on identical sets and races an in-flight renew (a stale write-back can clobber a newer desired). A monotonic generation makes the trigger and the write-back race-safe and gives a clean "pending re-issue" indicator. |

## Data model

Add to the per-device control-plane record (the issued enrollment row resolved by
`overlay_ip` in `coreapi.device()`, `coreapi.go:128`, or a sibling `device_state` table):

- `desired_groups` (JSON array) — operator intent; seeded = issued groups at enrollment.
- `groups_generation` (int) — bumped on every operator change.
- `issued_generation` (int) — the generation the current cert was signed at.

The enrollment row's existing `groups` column remains "the groups in the current cert"
(what the provenance/Devices view reads). On re-issue it is set to `desired_groups`.
A new migration (the next free number — migrations are at 000026 as of 2026-06-18; this
ADR originally said "after 000012") adds the columns in both dialects.

## The workflow, end to end

1. **Operator changes groups** → `POST /admin/v1/devices/{overlay_ip}/groups {groups:[…]}`
   → validate (reject reserved `control-plane`/`lighthouse`), set `desired_groups`, bump
   `groups_generation`, **audit loudly** (old → new, who).
2. **Host heartbeats** → `commandsFor` sees `desired_generation > issued_generation` →
   appends `CmdRenew` (a third trigger alongside near-expiry and rollout).
3. **Pilot runs `RenewNow`** → generates a fresh keypair, CSRs `/v1/certs/renew`
   (authenticated by the existing tunnel's source overlay IP + proof-of-possession of the
   new key).
4. **`handleRenew` reads `desired_groups`** (not the static enrollment groups), signs the
   new cert, recompiles the firewall for the new groups, returns the signed bundle, and
   **writes back** `groups = desired_groups`, `issued_generation = desired_generation`.
5. **Pilot installs cert + bundle → SIGHUP hot-reload** (same IP/curve → `ReloadOnly`). No
   restart.
6. **Console reflects the new groups** (provenance reads the issued enrollment); the
   "pending re-issue" badge clears once `issued == desired`.
7. **Peers need nothing** — they evaluate the host's groups from the cert it now presents.
   *(Exception: a not-yet-revoked removal; see the fork.)*

## Security model

- **Authority stays server-side.** The host supplies only a CSR; Core reads the groups
  from the device record. A host can never grant itself a group. This invariant must be
  preserved — the renew request must never accept a host-supplied groups field.
- **Reduction ≠ revocation.** Until M7, a removal is advisory; the console and audit must
  say so explicitly and never imply a removal is enforced against a hostile host.
- **Authority-affecting → gate it.** A group change can elevate a host into any group, so
  Phase 1 requires a new `device:manage` permission + **step-up MFA** + a loud audit
  entry. Phase 3 may promote high-privilege target groups to **dual-control** (a
  `device.groups` change kind, mirroring policy/cloudtrust publish) — the same
  "two people to grant authority" principle, applied selectively.
- **Reserved groups** (`control-plane`/`lighthouse`) are rejected on input (their
  reachability is baseline-owned; cf. `policy.CheckInvariants`).
- **Eventual consistency on live tunnels.** A change is effective on the next handshake,
  not instantaneously on established tunnels (Pilot's reload re-forms them; Nebula also
  re-handshakes periodically) — seconds to minutes.
- **Group divergence from join-method defaults is intentional and visible.** "Joined via"
  (the immutable origin — join key or attested account) and the current groups (now
  mutable) can differ; the console already shows them separately, which is the correct
  model — provenance is *how it joined*, not *what it may currently do*.

## Phased plan

- **Phase 1 — reassignment via re-issue (mostly wiring):**
  - migration: `desired_groups` + `groups_generation` + `issued_generation`; seed at enrollment.
  - admin API: `POST/PATCH /admin/v1/devices/{ip}/groups` (`device:manage` + step-up +
    reserved-group validation + audit); new RBAC perm; openapi + `gen:api`.
  - `coreapi.handleRenew`: read `desired_groups`; write back issued groups + generation.
  - `coreapi.commandsFor`: emit `CmdRenew` when `desired_generation > issued_generation`.
  - Pilot: **no change** — it already acts on `CmdRenew` and hot-reloads.
  - UI: an "Edit groups" action on the device (gated + step-up), the current-groups editor
    with the **removal-is-soft** warning, and a "pending re-issue" badge while desired ≠
    issued.
  - Tests + adversarial review; document removals as advisory.
- **Phase 2 — enforceable removals (M7):** on a reduction, revoke the old cert and
  distribute the blocklist in peer bundles so peers reject it. Closes the malicious-host
  window. Re-run the adversarial review for the revocation path. *(2026-06-18: the M7
  revocation/blocklist machinery is now SHIPPED & LIVE — `internal/revocation`, the
  `pki.blocklist` render + bundle propagation + `blocklist` rollout lane, and the `harbor
  blocklist` CLI. The remaining Phase-2 work is just calling it from the reduction path,
  not building revocation itself.)*
- **Phase 3 — hardening (optional):** dual-control for sensitive group changes; a group
  catalog with privilege tiers; bulk/group-membership management.

## Consequences

- **+** Operators can re-scope a host without re-enrolling it; the change re-keys,
  re-signs, recompiles the firewall, and hot-reloads with no outage — almost entirely on
  existing machinery.
- **+** Authority remains server-side and auditable; the provenance UI reflects the new
  groups for free.
- **+** Additions are fully effective in Phase 1.
- **−** Removals are **soft until Phase 2** — the single biggest caveat; the residual
  window is the old cert's remaining lifetime. Short cert TTLs mitigate; only revocation
  closes it. *(2026-06-18: the M7 revocation primitive now exists, so Phase 2 is a wiring
  step — removals stay soft only until the reduction path calls the existing blocklist.)*
- **−** RBAC grows a `device:manage` permission and (Phase 3) potentially a per-host
  dual-control kind — new authority surface to govern.
- **−** Group membership becomes a mutable, per-host fact diverging from the join-method
  defaults; the model must keep "origin" and "current authority" distinct everywhere.

## Open questions to resolve before building

1. **Authz strength for Phase 1** — is `device:manage` + step-up + audit sufficient, or do
   even *additions* warrant dual-control from the start? (Leaning: perm + step-up for
   Phase 1; dual-control selectively in Phase 3.)
2. **Where the desired-state lives** — extra columns on the enrollment row (minimal) vs. a
   dedicated `device_state` table (cleaner separation of host-reported vs.
   control-plane-authoritative). The enrollment row is already the per-device
   control-plane record resolved by `overlay_ip`.
3. **Group validation** — free-form strings (today) vs. a constrained **catalog** so the
   editor can't fat-finger a host into a privileged group; ties into a future
   privilege-tier model and ADR 0001's namespacing.
4. **Reduction UX before M7** — block reductions entirely until revocation exists, or allow
   them with a prominent "advisory until the old cert expires (`<remaining>`)" warning?
5. **Re-attestation** — a plain renew does not re-verify cloud attestation
   (`coreapi.go:225`); a group change is operator-driven, so no re-attestation is needed —
   confirm that stays true (the operator, not the host, is the authority for the change).

## Relationship to other work

- **M7 revocation / blocklist** — the hard dependency for enforceable removals (Phase 2).
  *(2026-06-18: now SHIPPED & LIVE — `internal/revocation`, `pki.blocklist` render + bundle
  propagation + `blocklist` rollout lane, `harbor blocklist` CLI. No longer a blocker;
  Phase 2 just has to call it.)*
- **Device-provenance slice** — already surfaces a device's groups + "Joined via" origin;
  the editor and the "pending re-issue" badge build directly on it.
- **ADR 0001 (policy scoping / namespacing)** — namespaced groups (`scope:name`) make a
  group catalog and privilege tiers cleaner; a per-host override should respect namespacing.
- **Dual-control (`internal/dualcontrol`)** — the ready-made primitive for Phase 3's
  optional `device.groups` change kind.
