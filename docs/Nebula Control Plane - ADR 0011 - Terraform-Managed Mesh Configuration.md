---
title: "ADR 0011 — Terraform-Managed Mesh Configuration (GitOps for Trust & Policy)"
created: 2026-06-19
status: proposed
tags: [nebula, adr, terraform, gitops, dual-control, policy, cloudtrust, usertrust, ipam]
---

# ADR 0011 — Terraform-Managed Mesh Configuration (GitOps for Trust & Policy)

**Status (2026-06-19):** PROPOSED — design only, nothing built. Moves the declarative trust &
policy configuration to a Terraform provider + GitOps and **retires the in-app dual-control
(propose/approve) UI** for those config types. Amends [[ADR 0004 - SSO-Driven User Enrollment]]
(usertrust publish) and the dual-control decisions in the cloudtrust/policy paths; relates to
[[ADR 0009 - Control-Plane Trust-Zone Separation]] and [[ADR 0010 - IPAM]].
**Date:** 2026-06-19
**Decision owners:** Chris Hyde

> **Honesty note.** This ADR moves a security-critical control (the two-person rule for
> trust & policy) off the running system and onto an external GitOps pipeline. The first draft
> overclaimed in two places that this revision corrects: (1) it called branch protection
> "the dual-control" and "a stronger two-person control" while the change actually *removes*
> harbor's server-side distinct-actor enforcement for these kinds and lets an apply-token holder
> bypass the PR gate entirely; and (2) it invented `*:manage` permissions and a config-storage
> model that **do not exist today**. Several hard problems are left as explicit Open Questions
> with the tradeoff named rather than solved — that is intentional for a *proposed* ADR — but the
> two overclaims are corrected inline below.

## Context

Harbor's declarative trust & policy configuration — the **firewall policy** (`internal/policy`,
`policy.Policy{Version int, Rules[]{FromGroup,ToGroup,Proto,Port}}`), **cloud trusts**
(`cloudtrust.Config`: AWS account/ARN-patterns → groups + netblock + auto-issue), **user trusts**
(`usertrust.Config`: AD directory-group → mesh groups + netblock + auto-issue,
[[ADR 0004 - SSO-Driven User Enrollment]]), and **IPAM netblock definitions** (`netblock.Netblock`,
[[ADR 0010 - IPAM]]) — is edited today through the admin console and the harbor CLI. Three of those
(`policy.publish`, `cloudtrust.publish`, `usertrust.publish`) are gated by an **in-app
dual-control** flow: operator A *proposes* a change, a distinct operator B *approves* it, then it
commits (`internal/dualcontrol`, via `POST /admin/v1/{policy,cloudtrust,usertrust}/propose` +
`/admin/v1/approvals/{id}/approve` and the console's propose/approve screens). Join keys and IPAM
netblocks are already plain single-operator CRUD.

What this dual-control flow enforces today, server-side, is more than a UI:

- **Distinct-actor two-person rule.** `dualcontrol` rejects self-approval (`ErrSelfApproval`,
  proposer ≠ approver) and duplicate sign-off (`ErrDuplicateActor`); a change commits only when a
  distinct second actor approves and quorum is met.
- **Commit-time validators run on every committed change.** Each kind registers a committer via
  `RegisterCommitter` (`dualcontrol.Controller.Register(kind, Committer)`,
  `Committer func(ctx, Change) error`) that re-parses the payload at commit and re-runs its
  validator: `usertrust.Parse → usertrust.Validate` (incl. `ErrAutoIssuePrivileged` — an
  `auto_issue` entry may not grant a reserved/privileged group, via `policy.IsReservedGroup`),
  `cloudtrust.Parse → cloudtrust.Validate`, and `policy.Parse → policy.Validate + CheckInvariants`
  (no user rule may reference a reserved group). **These validators fire from the dualcontrol
  commit path that this ADR removes for these kinds.**
- **Step-up MFA.** `requireStepUp` gates all four propose/approve handlers
  (`handlePolicyPropose`, `handleCloudTrustPropose`, `handleUserTrustPropose`, `handleApprove`)
  plus the three netblock-mutating handlers. A machine/API token **can never** satisfy step-up:
  `TokenProvider` always returns `MFAAt: nil`.

Two problems motivate a change:

1. **The in-app dual-control UI is complex and under-tested.** Propose/approve screens, a
   pending-change inbox, self-approval / duplicate-actor guards, and step-up MFA add significant
   console surface for a workflow that is only partially implemented and not well exercised. It
   reimplements — inside the product — a review-and-approve workflow that operators already run
   **far more maturely in their DevOps tooling**.

2. **This config is exactly "infrastructure as code."** Firewall rules, trust grants, and netblock
   carve-ups are declarative, low-churn, diff-reviewable artifacts. Editing them imperatively
   (even with two-operator approval) forgoes what teams expect for infra: version history,
   peer-reviewed diffs, CI validation, environment promotion, reproducibility, and rollback.

**Stated precondition.** This decision assumes the mesh operators run standard Git/PR/CI processes
and administer their own branch protection. That precondition is load-bearing — see *Who this serves
/ who it burdens* in Consequences — and is **not** universally true of every operator profile this
product targets.

## Decision

Introduce a **Terraform provider for harbor** that owns the declarative trust & policy
configuration, and make **the GitOps pipeline the routine approval control**, retiring the in-app
propose/approve flow for these config types while leaving the rest of the system imperative — with
explicit server-side carry-overs (validators, distinct-actor for the privileged subset) so the
move does not silently drop security guarantees.

### 0. Foundation: a config-storage model (UNBUILT today)

Everything below rests on a storage primitive **that does not exist yet**. Today the "active config"
of each kind is *derived*, not stored: `dualcontrol.LatestCommitted(kind)` selects the most recent
`state=committed` row of `policy.publish`/`cloudtrust.publish`/`usertrust.publish` from the shared
`approvals` ledger; the payload column carries the data. There is **no standalone config table and
no `source` / `last_applied_hash` / `last_applied_by` columns**.

**P1 must therefore build a first-class config store** for the three singletons (and extend the
existing `netblock` rows) with provenance columns: `source`, `last_applied_by`, `last_applied_hash`,
`version`/`updated_at`. This is the foundation the declarative API, provenance, and drift detection
all depend on; it is sequenced first deliberately.

### 1. A Terraform provider (`terraform-provider-harbor`)

A real provider (on `terraform-plugin-framework`), **not** a `null_resource`+CLI "module" (which has
no real state, drift, or import). One resource per declarative config type, mapped to the existing
harbor models:

| Resource | Cardinality | Maps to | Fields |
|---|---|---|---|
| `harbor_firewall_policy` | singleton / mesh | `policy.Policy` | `version`, ordered `rule { from, to, proto, port }` |
| `harbor_cloud_trust` | singleton | `cloudtrust.Config` | `default_groups[]`, `aws { account, arn_patterns[], groups[], auto_issue, netblock }` |
| `harbor_user_trust` | singleton | `usertrust.Config` | `default_groups[]`, ordered `idp_entry { realm, directory_group, mesh_groups[], auto_issue, netblock }` |
| `harbor_netblock` | per-name | `netblock.Netblock` | `name`, `cidr` (see below), `kind`, `description` |

Policy/cloudtrust/usertrust are **singletons** because they are published as a whole today (atomic)
and **ordering is semantically load-bearing** — usertrust is first-match-wins
([[ADR 0004 - SSO-Driven User Enrollment]]) and firewall rules compose as an ordered allow-list. A
single resource holding an ordered list preserves atomic apply + deterministic order; per-entry
resources would lose ordering and complicate first-match semantics. `harbor_netblock` is per-name
because netblocks are independent, named objects.

Provider auth is a harbor **admin API token** (RBAC-scoped to the minimal config-write permissions;
see Decision 3 for the blast-radius scoping) from provider config / env. The genesis-managed
**protected** netblocks (`central`, `default` — `Protected=true`; note "protected" is a *flag*, not
a `kind`, since `kind` is `reserved`/`default`/`named`) are **not** TF-managed: the provider may
`import`/read them but refuses to manage protected blocks (they belong to genesis), and exports them
read-only/unmanaged so a later out-of-band protected seed is expected, never drift.

**`harbor_netblock.cidr` vs server-side auto-grow.** `netblock.Grow` mutates a named block's CIDR
`/P → /P-1` **automatically during allocation** (`ipam` allocator calls `Grow` on
`ErrPoolExhausted`), out of band and unattended. A naively TF-managed `cidr` would therefore
spuriously *drift* the moment the pool grows, and the next apply would *shrink it back* — corrupting
live allocations. So `harbor_netblock.cidr` MUST be **Computed/server-authoritative** (the provider
reads it and ignores server growth), or operators declare only a **floor/envelope** while the server
owns the live size. Either way, the drift hash for netblocks MUST exclude server-grown bits of the
CIDR (see Decision 5).

### 2. A declarative, single-approver admin API

Replace propose/approve for these types with a **declarative, idempotent set/get API** the provider
drives:

- `PUT /admin/v1/config/{policy|cloudtrust|usertrust}` — set the *entire* config for that type
  (validates, replaces, idempotent). `GET` returns the current config + a content hash + provenance.
  `harbor_netblock` uses the existing `/admin/v1/ipam/netblocks` CRUD, extended with the same
  provenance/hash.

**Invariant — the PUT MUST re-run the commit-time validators on EVERY write path, including
break-glass.** This is the single most load-bearing carry-over. Today `usertrust.Validate` (incl.
`ErrAutoIssuePrivileged`), `policy.CheckInvariants` (+ `policy.Validate`), and `cloudtrust.Validate`
fire from the *dualcontrol commit path* (registered via `RegisterCommitter`) that this ADR removes
for these kinds. The PUT handler MUST therefore call the same `Parse`/`Validate`/`CheckInvariants`
chain inline for terraform, CLI, UI, **and** break-glass writes alike. If this wiring is not moved to
the PUT, the S8 guarantee — *one operator cannot mint a privileged auto-issue trust* — is silently
dropped. There is no acceptable variant of this item: it is folded into the decision, not deferred.

**Permission model (corrected — `*:manage` does not exist today).** There is **no**
`policy:manage` / `cloudtrust:manage` / `usertrust:manage`. The RBAC permissions that exist are
`policy:propose`, `cloudtrust:propose`, `usertrust:propose`, `ipam:manage`, and `approval:decide`
(`PermApprovalDecide`); `admin` (`RoleAdmin`) is an **unconditional superuser** (`roleHasPerm`
returns true for `admin` without consulting the matrix). This ADR must therefore define new
permission(s) explicitly. The chosen model:

- Define **config-manage** permissions `policy:manage`, `cloudtrust:manage`, `usertrust:manage` (new)
  that authorize the declarative PUT. (Reusing `:propose` is rejected: `:propose` is half of a
  maker-checker pair and collapsing both halves onto it muddies audit semantics.)
- The CI/terraform token principal carries a **dedicated role** holding *only* the three config-manage
  perms (plus `ipam:manage` for netblocks) — and nothing else (see Decision 3).
- Collapsing propose+approve into a single manage permission **removes the RBAC maker-checker split**
  for these kinds. That split is *not* recreated inside harbor by this design; it is relocated to
  GitOps (Decision 3) — except for the privileged subset, which retains a server-side second control
  (Decision 3, regression-fix).
- Whether a human **operator** also gains direct config-write authority via this API is a deliberate
  product choice tied to the single-operator fallback question (Consequences); the default here is
  that routine writes go through the token/CI, and human direct writes are **break-glass** (Decision 5).

**Step-up MFA is DROPPED on the declarative path — stated, with a compensating control.** A machine
token can never satisfy `requireStepUp` (`MFAAt` is always nil for tokens), so the declarative PUT
cannot carry the step-up gate that protects all four propose/approve handlers today. Compensating
control: the no-MFA token path is restricted to **non-privileged** config, and any **privileged**
grant (reserved-group grant or `auto_issue`) requires a distinct second control recorded server-side
(Decision 3 regression-fix). The residual — that routine non-privileged trust/policy changes lose the
human-MFA gate they have today — is an **accepted risk** named here, not silently dropped.

**Optimistic concurrency (new primitive — none exists today).** The PUT MUST take an `If-Match` on
`last_applied_hash` (or a monotonic `version`) and return **412 Precondition Failed** on mismatch.
Harbor has no such conflict primitive today. Without it, two near-simultaneous applies, or an apply
of stale Terraform state, silently clobber or revert each other with no conflict detection. The
provider sends the hash it read at plan/refresh time; a 412 forces a `terraform refresh` + re-plan.

**Provenance.** Every write records `last_applied_by` (API principal / TF), `last_applied_hash`, and
`source = terraform | cli | ui | break-glass`. This powers drift (Decision 5). See Decision 5 for the
critical rule that **only terraform-sourced writes may advance the drift baseline**.

The `internal/dualcontrol` engine is **kept** — it still backs `bulk-revoke`
(`revocation.BulkRevokeKind`), an emergency operation that must stay imperative
(`REVOCATION-GUARDS-DECISIONS.md`). Only the propose/approve wiring for
`policy`/`cloudtrust`/`usertrust` is removed; and for the **privileged subset** the dualcontrol path
is retained (Decision 3).

### 3. GitOps is the dual-approver for the non-privileged path — with explicit limits

The two-person control for routine, **non-privileged** changes moves to the config repo's pipeline:

- **Branch protection** on the config repo: ≥1 required reviewer, no self-merge, PR-only. A change
  is authored in a PR, reviewed by a distinct person, merged.
- **CI-only apply:** `terraform apply` runs in CI with the harbor config token; the token lives **only
  in the CI secret store**, never in human hands; CI applies merged `main` only.
- `terraform plan` on the PR gives reviewers the diff. (Fidelity caveat: `policy.CompileHost` always
  injects a mandatory baseline — control-plane/lighthouse reachability + ICMP — that is **not** part
  of `policy.Policy` and not representable in `harbor_firewall_policy`. So `plan` shows the *editable*
  diff, not the compiled-host firewall. `harbor config export` MUST surface this invariant baseline as
  a non-editable note so reviewers aren't misled into thinking the plan is the full effective policy.)

**Honest statement of the regression (corrects the earlier "this is the dual-control" /
"stronger two-person control" overclaim).** This design **removes** harbor's server-side distinct-actor
enforcement (`ErrSelfApproval` / `ErrDuplicateActor`) for these kinds, and the **apply-token holder can
write config directly, bypassing the PR gate entirely**. For *non-privileged* changes that is an
acceptable trade for the GitOps benefits. For **privileged** changes it is a real regression: a
reserved-group grant (`policy.IsReservedGroup` — control-plane/lighthouse) or any `auto_issue` grant
could be minted by a single token with no distinct second human. Calling branch protection a "stronger"
control while a single token bypasses it would be dishonest.

**Resolution for the privileged subset (chosen: option a, with b/c named as alternatives).** A
privileged grant — any reserved-group grant or any `auto_issue=true` entry — MUST still require a
**distinct second harbor sign-off recorded server-side, regardless of write source**. Concretely:

- **(a, chosen)** Keep the `dualcontrol` distinct-actor path on the **direct write path for the
  privileged subset**: the PUT detects (via the same validators) that the incoming config introduces or
  modifies a privileged grant and routes that change through a propose/approve two-person commit rather
  than applying it under the single token. (Trade: a slice of the propose/approve machinery and its
  console affordance survives — the product is *less* "smaller" than the first draft claimed.)
- **(b, alternative)** A harbor-side invariant that any privileged/`auto_issue` grant requires a second
  distinct sign-off recorded in harbor's audit chain *regardless of source* (terraform, CLI, UI), via an
  out-of-band approval token rather than the full propose inbox. (Trade: bespoke, but avoids reviving the
  full UI.)
- **(c, accepted-risk Open Question)** Accept that privileged grants ride the GitOps two-person control
  only, with the threat-model tradeoff named: *a leaked or misused config token can mint a privileged
  trust unattended, and the only second-person record lives in mutable GitHub PR history outside harbor's
  tamper-evident chain.* (See Open Question 7.)

This ADR proposes **(a)** as the default and records **(c)** as the named fallback if (a) proves too
heavy. It does **not** assert a "stronger" control while a single-token bypass exists.

**Apply-token blast radius and scoping.** The apply token is the new trust anchor: **one leaked CI
secret = a full mesh trust rewrite, unattended.** It MUST be scoped to contain that blast radius:

- Holds **only** the minimal config-write perms (the new config-manage perms + `ipam:manage`).
- MUST **NOT** be `RoleAdmin` — admin is an unconditional RBAC superuser and would grant the token
  the entire control plane, not just config.
- MUST **NOT** carry `approval:decide` (`PermApprovalDecide`) or any break-glass authority — so a
  leaked config token cannot also self-approve the privileged-subset second control (Decision 3a) or
  perform bulk-revoke.
- **Compensating controls:** short-TTL CI-minted token (per-run, not a long-lived secret); bind the
  token to the **CI OIDC identity** (the token is issued only to the CI workload, not exportable);
  and **audit-alert** on any `source=terraform` write that grants a reserved group or sets `auto_issue`.

**Reviewer population ≠ harbor approver population.** A GitHub reviewer is whoever holds repo review
access — governed by the *forge* (CODEOWNERS / branch protection), not by harbor RBAC, the IdP, or
MFA. The config-repo CODEOWNERS / required-reviewer set MUST be **constrained to, and kept in sync
with, the harbor operators who would hold `approval:decide`**, this synchronization MUST be audited,
and the design MUST name **who administers branch protection** — that administrator is *inside the
trust boundary* (they can weaken the only routine two-person control) and must be treated as such.

### 4. Revert the in-app dual-control UI (for the non-privileged path)

Remove the console's propose/approve screens, pending-change inbox, and approve actions for routine
policy/cloudtrust/usertrust changes, and remove the `/propose` + `/approvals/.../approve` API for
those kinds **for the non-privileged path**. The console for these types becomes **read-only**: it
shows the live config (the source of truth Terraform writes) plus a **drift badge** (Decision 5). This
deletes a large, under-tested UI/flow surface. `bulk-revoke`, per-host enrollment approvals, and the
privileged-subset second control (Decision 3a) are unaffected and retain their dualcontrol path.

### 5. Soft drift detection + a console drift badge (with a hard caveat for the privileged subset)

Terraform is the source of truth, but out-of-band writes are **allowed and flagged**, not rejected
(soft drift) — *except* for security-relevant drift, which gates the next apply (below).

- **Pipeline:** `terraform plan` detects drift canonically (live ≠ state); CI surfaces it.
- **Harbor-side:** each config object records `last_applied_hash` + `source`; harbor computes
  `drifted = current content hash ≠ last_applied_hash`. **Baseline-advance rule (critical):**
  `last_applied_hash` MUST be advanceable **only** by writes whose authenticated `source` is the
  terraform/CI principal. A non-terraform write (CLI / UI / break-glass) updates content + `source` +
  `last_applied_by` but **MUST NOT** advance `last_applied_hash`. Otherwise a CLI or break-glass writer
  would suppress its *own* drift badge — defeating the sole out-of-band-write control.
- **Drift signalling (mandatory).** Any transition to `drifted=true` MUST emit (a) a row in harbor's
  **hash-chained audit log** (`store.Audit`, `prev_hash`/`hash` chain, verified by `VerifyAudit`) and
  (b) an alertable Prometheus signal `ncp_config_drifted{kind}` (note: harbor metrics use the `ncp_`
  prefix — e.g. `ncp_ipam_autogrow_total`, `ncp_auditverify_tampered_total` — *not* `harbor_`).
- **Apply audit (mandatory).** The apply path MUST record the **merge commit SHA + reviewer identity**
  into harbor's audit log. Otherwise the only "second approver" record lives in mutable GitHub PR
  history, outside harbor's tamper-evident chain — and is not admissible evidence that the two-person
  rule held.
- **Console:** a **drift badge** on any config type changed outside Terraform ("modified outside
  Terraform — `terraform apply` will revert"), so operators see drift without running `plan`.
- A documented **break-glass** path: a direct CLI/API write (emergency) is permitted, loudly audited,
  re-runs the validators (Decision 2 invariant), does **not** advance the baseline, and shows as drift
  until reconciled.

**Soft drift is the wrong default for the root of trust — and contradicts what we already ship.**
Trust config is read **live per enrollment**, so an out-of-band privileged write *actively mints certs*
until reverted, and an apply-revert does **NOT un-issue** the interim certs. Worse, soft drift has no
guaranteed revert and an unbounded live window. There is a direct internal contradiction:
`internal/drift/drift.go` already ships **continuous (1-minute) detect-and-AUTO-REVERT** for *per-host*
config, yet this design would give the far-more-sensitive *root of trust* a weaker, manual soft-drift
badge. Resolution for the **privileged subset** (one of):

- **Hard-reject** out-of-band privileged writes (they must go through the privileged-subset control,
  Decision 3a) — preferred; or
- **Bounded auto-revert / quarantine SLA** with a stated maximum drift window; or
- **Open Question** (Open Question 8) naming the **maximum drift TTL** and the **no-un-issue caveat**.

At a **minimum** this ADR requires a **scheduled CI apply** (not only on-merge) with a stated maximum
drift window, so even non-privileged drift cannot persist indefinitely. And see *Scope / non-goals* for
the rule that a **security-relevant drift (especially a trust removal) GATES the next apply** until
reconciled, rather than being silently reverted.

## Cross-resource references & ordering (Decision 1)

`cloudtrust.Config` and `usertrust.Config` reference a netblock by **free-string name**, and harbor
**silently falls back to `default`** on an unknown name (`netblock.Resolve` / `ResolveFull`, IPAM
decision D20). With netblocks as a *separate* Terraform resource, a hardcoded netblock *name* in a
trust resource gives Terraform **no dependency edge** → an apply can create the trust **before/without**
the netblock, silently re-homing hosts into the broad `default` block — and `plan` + the drift badge
both report **clean**. This is a quiet security downgrade (broad default scope instead of the intended
narrow block).

Required mitigations:

- The provider models netblock refs as **Terraform references** (e.g. `netblock = harbor_netblock.x.name`)
  so Terraform enforces **create-before-reference** and **delete-after-dereference** ordering.
- The trust PUT **validates referenced netblock names** (reject, or at minimum loud-warn + audit)
  instead of silently falling back to `default`.
- **Netblock deletion MUST be blocked while ANY referencer names it.** Today `netblock.Remove` guards
  only `Protected` blocks + live allocations — **not** references. The reference scan MUST span **both**
  the declarative referencers (cloudtrust/usertrust entries) **and** the imperative ones (join-key
  bindings).

## Canonical serialization (PREREQUISITE — P1/P2, was Open Q4)

Promoted from an open question to a **prerequisite**, because the failure modes are security-relevant,
not cosmetic:

- A **false-negative** is the dangerous direction: a malicious or unintended change that happens to
  hash *equal* would never trip drift and would ride live undetected.
- A **spurious import→plan diff** invites operators to "apply to silence it" — silently reordering
  first-match `usertrust` entries (changing who matches) or bumping `policy.version`.

Therefore define **one canonical, ORDER-PRESERVING serialization** shared by the `harbor config export`
helper, the provider, and the `last_applied_hash` computation. The hash MUST span exactly:

- **usertrust:** entry **order** (first-match-wins), and per entry `realm`, `directory_group`,
  `mesh_groups` (set semantics decided explicitly), `auto_issue`, `netblock`; plus `default_groups`.
- **cloudtrust:** per `aws` entry `account`, `arn_patterns`, `groups`, `auto_issue`, `netblock`; plus
  `default_groups`.
- **policy:** every firewall rule tuple `{from, to, proto, port}` **and its order**; and a decision on
  whether `policy.version` is **operator-owned** (part of the hash, operator bumps it) or
  **provider-computed** (excluded from the semantic hash) — pick one and document it.
- **netblock:** `name`, `kind`, `description`, and a CIDR representation that **excludes server-grown
  bits** (Decision 1, auto-grow caveat).

Acceptance test (required): a fresh `import → plan` is **byte-clean** (no spurious diff), AND **any**
semantic change flips the hash (no false-negative).

## Scope / non-goals

**In Terraform (declarative):** firewall policy, cloud trusts, user trusts, IPAM netblock definitions.

**Stays imperative (NOT Terraform):**
- **Revocation / bulk-revoke** — emergency; can't wait for PR→plan→apply. Keeps `dualcontrol`.
- **Enrollment approvals** — per-host operational decisions.
- **IPAM allocations** — assigned dynamically at enroll; only netblock *definitions* are TF.
- **Join keys** — ephemeral/operational secrets; awkward as long-lived TF state. (A future
  `harbor_standing_join_key` for long-lived host-class keys is an open question; ephemeral minting
  stays imperative.)

**Urgent trust REMOVAL is distinct from low-churn addition — and must not be silently undone.** Cutting
a compromised AWS account or disabling an AD-group `auto_issue` is **time-critical** and read **live**;
forcing it through PR→CI→apply is a regression on response time. Worse, because the trust configs are
**full-replace singletons** and drift is soft, a break-glass trust **removal** can be **silently UNDONE**
by the next routine apply of stale `main` — re-admitting the attacker. Therefore:

- Provide a **fast disable path** for trust cuts (or explicitly designate break-glass as the runbooked
  emergency path for removals), AND
- A **security-relevant drift — especially a removal — GATES the next apply** until an operator reconciles
  it, rather than being silently reverted. A routine apply MUST refuse to re-add a trust that a break-glass
  removal cut, until the removal is reflected in `main`.

## Migration / import

1. **Build the P1 foundation first** (Decision 0): the config store + provenance/hash columns. Nothing
   below is possible without it.
2. Ship the provider + the declarative API **alongside** the existing propose/approve (both work).
3. **Verify boot-seed before import.** `BootSeedNetblocks` seeds `central`/`default` **only when the
   netblock table is empty**. An `import` *before* boot-seed would see zero netblocks; a *later* seed
   would then appear as **drift** on blocks Terraform was told not to manage. Precondition: confirm
   `central`/`default` are seeded before import; export protected blocks **read-only/unmanaged**; treat
   a later out-of-band protected seed as expected, **never** drift.
4. `terraform import` the live config into a new config repo (provider supports `import` + a
   `harbor config export` helper to seed the initial `.tf`).
5. Move operators onto PR→CI→apply; verify `plan` is **byte-clean** (no spurious diff) post-import,
   using the canonical serialization above.

### P3.5 — cutover gate (NEW)

P4 (removing propose/approve for a mesh) **MUST NOT proceed** for that mesh until **all** of:

- (a) every Terraform-managed object is **imported**;
- (b) `terraform plan` is verified **empty** in CI (using canonical serialization);
- (c) `source=terraform` is the recorded **last writer** for all three config kinds **and** every
  non-protected netblock.

Expose a **per-kind readiness signal** (e.g. `managed_by_terraform{kind}` / a `GET` field) so the gate
is machine-checkable, not eyeballed.

## Rollback (NEW)

P4 deletes the **audited dualcontrol fallback** in favour of a newly-built PUT path. To avoid stranding a
mesh on an unbuilt or buggy PUT:

- Keep propose/approve **feature-flagged OFF (not deleted)** for **≥1 release after P4**, with a
  **documented revert procedure** (flip the flag back on, re-enable console screens).
- Cutover is **not considered safe** until the PUT path is confirmed to re-run the commit-time validators
  (Decision 2 invariant) and to enforce the privileged-subset second control (Decision 3a) — verified by
  test, not assumed.

## Phasing

- **P0 / P1 — foundation & prerequisites.** Config store + provenance/hash columns (Decision 0);
  declarative set/get API with the validator invariant (Decision 2), `If-Match`/412 concurrency, and the
  baseline-advance rule; netblock CRUD provenance; the **canonical serialization** + its acceptance test;
  `harbor config export` (incl. the non-editable baseline note).
- **P2** — the Terraform provider (resources + cross-resource references + `import` + acceptance tests,
  incl. import→plan byte-clean).
- **P3** — console: read-only config views + drift badge; remove non-privileged propose/approve screens;
  drift transition → audit row + `ncp_config_drifted{kind}`.
- **P3.5** — cutover gate (above): readiness signal green for the mesh.
- **P4** — remove the non-privileged propose/approve API for the 3 kinds (keep `dualcontrol` for
  bulk-revoke **and** the privileged-subset control; keep non-privileged flow flag-off for ≥1 release —
  see Rollback); scheduled CI apply with a stated max drift window; document the GitOps controls (branch
  protection, CODEOWNERS↔operator sync, CI-only OIDC-bound token, who administers branch protection) in
  the prod deploy runbook.

## Alternatives considered

- **Keep in-app dual-control, just polish the UI.** Rejected: reimplements a review workflow the operators
  already run better in Git; keeps a complex, under-tested surface.
- **A `null_resource`+CLI Terraform module (no provider).** Rejected: no real state, drift, or import;
  brittle; can't show meaningful `plan` diffs.
- **Per-entry resources** (`harbor_cloud_trust_account`, `harbor_user_trust_entry`). Rejected as the
  default: loses atomic apply + deterministic first-match ordering. (Revisit if ordering is made explicit
  via an index.)
- **Hard drift enforcement** (API rejects non-TF writes). Adopted *for the privileged subset* (Decision 5);
  deferred as the global default (blocks break-glass, heavier) — soft drift + badge + scheduled apply first.
- **(NEW) Delete the dual-control UI; keep single-operator RBAC + MFA CRUD; NO provider.** Captures *most*
  of the "smaller product" win with *little* added surface: it deletes the propose/approve screens and the
  distinct-actor machinery but adds no provider, no GitOps pipeline, no provenance/hash store. **Lost vs the
  full provider:** `plan` diffs, version history in Git, state-backed drift, reproducibility, environment
  promotion. **Why the larger surface may still be justified:** those losses are exactly the IaC benefits
  in the Context; but for a **near-term single-mesh / single-operator** profile this simpler path likely
  *wins* and the full provider is over-built.
- **(NEW) Keep in-app CRUD + an optional `harbor config export` / import to Git, no provider.** A
  middle option: edits happen in-app (with whatever RBAC/MFA controls are kept), and `export`/`import`
  give a Git-backed audit trail and reproducibility without a stateful provider. **Lost vs the full
  provider:** no `terraform plan` diff on the PR, no state-backed drift, no apply-time enforcement — Git is
  a *mirror*, not the *source of truth*. **Why a provider may still be justified:** only the provider makes
  Git the authoritative source with enforced drift; if the goal is genuinely GitOps-as-control rather than
  GitOps-as-record, this option doesn't deliver it.

> The honest tie-breaker: **for a single-mesh, GitOps-mature operator the full provider is justified; for a
> single-operator / CLI-first shop the first NEW alternative likely wins.** This ADR should either commit to
> a first-class single-operator RBAC CRUD fallback (Consequences) or scope itself to GitOps-mature operators.

## Consequences

- **Controls move and change shape — not strictly "stronger."** PR review + CI apply gives diff review,
  history, rollback, and CI validation, and operators already run it. But for these kinds it **removes**
  harbor's server-side distinct-actor enforcement and lets the apply-token holder bypass the PR gate.
  The two-person rule is therefore *equivalent-or-weaker* for non-privileged changes (depends on forge
  config) and is **explicitly preserved server-side for the privileged subset** (Decision 3a). It is not
  honest to call this "a stronger two-person control" wholesale.
- **Surface RELOCATES and GROWS — honest ledger (replaces the "smaller product" claim).**
  - *Deleted:* the non-privileged propose/approve **handlers** + their **console screens**. (NOT the
    `dualcontrol` engine — kept for bulk-revoke and the privileged subset; NOT the privileged-subset
    propose/approve path.)
  - *Added:* a whole **`terraform-provider-harbor` codebase**; a new **declarative API** (PUT/GET +
    `If-Match`/412); a **config store + provenance/hash columns** (Decision 0); **drift detection + badge +
    metric + audit rows**; `harbor config export`; the **canonical serialization** + acceptance tests; and an
    **external GitOps pipeline** (branch protection, CODEOWNERS sync, OIDC-bound CI token).
  - *Net:* surface **relocates and grows**. If the real argument is "move the control **off the running
    system / onto better-tested ground** (Git/CI operators already trust)," make **that** argument — do not
    sell it as a smaller product.
- **Trust shifts to the pipeline + a single token.** The security boundary is now branch protection + the
  CI-only apply token + the forge's reviewer administration, not harbor's server-side approval. The token's
  blast radius (full mesh trust rewrite) is scoped per Decision 3; the second-approver *record* must be
  written into harbor's audit chain (Decision 5), not left in mutable PR history.
- **Who this serves / who it burdens.** *Serves:* GitOps-mature, multi-operator shops that already live in
  PR/CI. *Burdens:* **single-operator / CLI-first shops** — they gain the least (no second reviewer exists)
  and pay the most (must stand up Git/CI/branch protection). With the token "never in human hands," such a
  shop has **no non-break-glass write path at all**. This ADR must therefore EITHER commit to a **first-class
  single-operator RBAC CRUD fallback via the declarative API** (human writes allowed, validators enforced,
  drift tracked) OR **scope the ADR to GitOps-mature operators** and say so. (Open Question 9.)
- **Step-up MFA dropped on the declarative path** (Decision 2), with the named compensating control.
- **Two write paths during migration**, and a flag-off-not-deleted fallback for ≥1 release after P4
  (Rollback).

## Open questions

1. **Standing join keys as TF?** Add `harbor_standing_join_key` for long-lived host-class keys, or keep all
   join-key minting imperative? (Leaning: imperative for now.)
2. **Provider distribution** — private registry vs in-repo; provider versioning vs harbor API versioning.
3. **One config repo per mesh, or a module with per-mesh workspaces** for multi-mesh operators.
4. **Break-glass UX** — exactly how a direct emergency write is flagged, audited, and reconciled; does the
   console offer a "copy current config as Terraform" to ease reconciliation?
5. **Pre-PR local preview** — keep a thin `harbor policy diff` CLI, or rely solely on `terraform plan`?
6. **`policy.version` ownership** — operator-owned (in the hash) vs provider-computed (excluded). Tied to the
   canonical-serialization prerequisite; pick one before P2.
7. **Privileged-subset second control — accepted-risk fallback (option c).** If Decision 3a (keep
   dualcontrol on the privileged direct-write path) proves too heavy, the named fallback is: privileged
   grants ride GitOps two-person control only, accepting that *a leaked/misused config token can mint a
   privileged trust unattended* and the second-person record lives only in mutable PR history. Decide
   explicitly before P4.
8. **Maximum drift TTL for the privileged subset.** If neither hard-reject nor bounded auto-revert is
   adopted (Decision 5), name the **maximum drift window** a privileged out-of-band write may persist, and
   restate the **no-un-issue caveat** (apply-revert does not retract certs already minted during the window).
9. **Single-operator fallback vs scoped ADR.** Commit to a first-class single-operator RBAC CRUD path via
   the declarative API, or scope this ADR to GitOps-mature operators only? (Consequences.)
