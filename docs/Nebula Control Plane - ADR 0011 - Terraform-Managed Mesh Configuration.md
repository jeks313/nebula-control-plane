---
title: "ADR 0011 — Phased Declarative / GitOps Mesh Configuration (console CRUD → config-as-code → optional Terraform provider)"
created: 2026-06-19
status: accepted (phase 1 shipped)
tags: [nebula, adr, terraform, gitops, dual-control, policy, cloudtrust, usertrust, ipam]
---

# ADR 0011 — Phased Declarative / GitOps Mesh Configuration (console CRUD → config-as-code → optional Terraform provider)

**Status (2026-06-20):** ACCEPTED, phased. **Phase 1 — SHIPPED & DEPLOYED** (commit `5106646`,
merged to main; deployed to the poc 2026-06-20; adversarial review verdict SAFE): single-operator
RBAC + MFA CRUD over a declarative config store/API (`internal/config`, migration `000027`,
`PUT/GET /admin/v1/config/{kind}`), the propose/approve UI removed, and the **privileged subset** (any
reserved-group or `auto_issue=true` grant) kept on a two-person `dualcontrol` commit. **Phase 2**
(config-as-code via export/import + optional GitOps-as-control) is PLANNED; the **Terraform provider**
(future) is not committed. Amends
[[ADR 0004 - SSO-Driven User Enrollment]] (usertrust publish) and the dual-control decisions in the
cloudtrust/policy paths; relates to [[ADR 0009 - Control-Plane Trust-Zone Separation]] and
[[ADR 0010 - IPAM]].
**Date:** 2026-06-19
**Decision owners:** Chris Hyde

> **Honesty note.** The headline decision here is a **phased migration**, not "build a Terraform
> provider." The first draft proposed the full provider + GitOps as the headline and overclaimed in
> two places that this revision corrects: (1) it called branch protection "the dual-control" and "a
> stronger two-person control" while that move actually *removes* harbor's server-side distinct-actor
> enforcement for these kinds and lets an apply-token holder bypass the PR gate entirely; and (2) it
> invented `*:manage` permissions and a config-storage model that **do not exist today**. Both
> overclaims are corrected inline. The phasing also resolves the earlier "smaller vs larger surface"
> tension honestly: **Phase 1 genuinely IS a smaller product** — the propose/approve UI is deleted and
> replaced with simple, tested CRUD — and the *larger* config-as-code surface (export/import, drift,
> a provider) is an **explicit later-phase choice**, added deliberately for the config-as-code value,
> not sold as a smaller product. Several hard problems remain explicit Open Questions with the tradeoff
> named rather than solved — intentional for a *proposed* ADR.

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

1. **The in-app dual-control UI is complex and under-tested — this is the actual trigger.**
   Propose/approve screens, a pending-change inbox, self-approval / duplicate-actor guards, and
   step-up MFA add significant console surface for a workflow that is only partially implemented and
   not well exercised. It reimplements — inside the product — a review-and-approve workflow that
   operators already run **far more maturely in their DevOps tooling**.

2. **This config is exactly "infrastructure as code."** Firewall rules, trust grants, and netblock
   carve-ups are declarative, low-churn, diff-reviewable artifacts. Editing them imperatively
   (even with two-operator approval) forgoes what teams expect for infra: version history,
   peer-reviewed diffs, CI validation, environment promotion, reproducibility, and rollback. This
   is the value the *later* phases unlock — it is not needed to fix the trigger (problem 1).

**Stated precondition (applies from Phase 2 on).** The GitOps phases assume the mesh operators run
standard Git/PR/CI processes and administer their own branch protection. That precondition is
load-bearing — see *Who this serves / who it burdens* in Consequences — and is **not** universally
true of every operator profile this product targets. **Phase 1 deliberately does not require it.**

## Decision

The decision is a **3-phase path**, not "build a Terraform provider." The committed near-term step is
Phase 1; Phase 2 is a planned follow-on; the full Terraform provider is **demoted to a future,
optional phase** justified only by demands Phase 2 cannot meet.

The two NEW alternatives the prior draft listed under *Alternatives* — "delete the dual-control UI,
keep single-operator RBAC + MFA CRUD, no provider" and "keep in-app CRUD + export/import to Git, no
provider" — are **ADOPTED here as Phases 1 and 2 respectively**, so they are no longer "alternatives";
they are the spine of the decision (see *Alternatives considered* for what that move leaves rejected).

Every phase shares **one declarative set/get config primitive** (`PUT/GET /admin/v1/config/{kind}`).
That is deliberate: Phase 1 builds it, Phase 2 layers config-as-code on it, and the future provider
wraps the *same* API. Phase 1 is the foundation, not a throwaway.

### Phase 1 (✅ SHIPPED 2026-06-20, commit `5106646`) — Console CRUD + a declarative config API; delete the propose/approve UI

> **Shipped 2026-06-20** (`5106646`): built, adversarially reviewed (verdict SAFE — 0 blockers on
> validate-on-every-write / privileged-two-person / reader-writer-convergence), merged, and deployed to
> the poc. Adds `internal/config` store + migration `000027`; boot-seeds the live config from the legacy
> dual-control ledger. On the poc only cloudtrust is store-backed-enforced (collect `-cloudtrust-db`);
> the non-privileged single-operator regression noted below is moot there (single operator).

Delete the in-app propose/approve UI + handlers for policy/cloudtrust/usertrust (the complex,
under-tested surface — the actual trigger). Replace them with **single-operator RBAC + MFA CRUD** over
a **declarative set/get config API**. This is genuinely a **smaller product**: a large, under-tested
UI/flow is removed and replaced with simple, tested CRUD over a single primitive.

#### P1.0 — config store (Decision 0, a Phase-1 prerequisite)

Phase 1 rests on a storage primitive **that does not exist yet**. Today the "active config" of each
kind is *derived*, not stored: `dualcontrol.LatestCommitted(kind)` selects the most recent
`state=committed` row of `policy.publish`/`cloudtrust.publish`/`usertrust.publish` from the shared
`approvals` ledger; the payload column carries the data. There is **no standalone config table**.

Phase 1 MUST therefore build a **first-class set/get config store** for the three singletons (and use
the existing `netblock` rows), with at least `version`/`updated_at`. **Provenance/hash columns
(`source`, `last_applied_by`, `last_applied_hash`) are DEFERRED to Phase 2** — there is **no drift in
Phase 1**, so they are not yet needed. Sequenced first within Phase 1 deliberately.

#### P1.1 — the declarative set/get API

- `PUT /admin/v1/config/{policy|cloudtrust|usertrust}` — set the *entire* config for that type
  (validates, replaces, idempotent). `GET` returns the current config (plus a content hash once Phase 2
  adds it). `netblock` uses the existing `/admin/v1/ipam/netblocks` CRUD. This API is **the same
  primitive Phase 2 and the future provider build on.**

**Invariant — the PUT MUST re-run the commit-time validators on EVERY write path, including
break-glass.** This is the single most load-bearing carry-over. Today `usertrust.Validate` (incl.
`ErrAutoIssuePrivileged`), `policy.CheckInvariants` (+ `policy.Validate`), and `cloudtrust.Validate`
fire from the *dualcontrol commit path* (registered via `RegisterCommitter`) that this ADR removes
for these kinds. The PUT handler MUST therefore call the same `Parse`/`Validate`/`CheckInvariants`
chain inline for CLI, UI, **and** break-glass writes alike. If this wiring is not moved to the PUT,
the S8 guarantee — *one operator cannot mint a privileged auto-issue trust* — is silently dropped.
There is no acceptable variant of this item: it is folded into Phase 1, not deferred.

**Permission model (corrected — `*:manage` does not exist today).** There is **no**
`policy:manage` / `cloudtrust:manage` / `usertrust:manage`. The RBAC permissions that exist are
`policy:propose`, `cloudtrust:propose`, `usertrust:propose`, `ipam:manage`, and `approval:decide`
(`PermApprovalDecide`); `admin` (`RoleAdmin`) is an **unconditional superuser** (`roleHasPerm`
returns true for `admin` without consulting the matrix). Phase 1 must therefore define new
permission(s) explicitly. The chosen model:

- Define **config-manage** permissions `policy:manage`, `cloudtrust:manage`, `usertrust:manage` (new)
  that authorize the declarative PUT. (Reusing `:propose` is rejected: `:propose` is half of a
  maker-checker pair and collapsing both halves onto it muddies audit semantics.)
- An operator role holds these three config-manage perms (plus `ipam:manage` for netblocks) — and,
  for Phase 1, the human operator writes config directly via this API.
- Collapsing propose+approve into a single manage permission **removes the RBAC maker-checker split**
  for these kinds — except for the privileged subset, which retains a server-side second control
  (below).

**Keep step-up MFA on console writes; state the MFA gap on any machine-token path.** The console PUT
path retains `requireStepUp`, so human operator writes keep the MFA gate they have today. A
machine/API token can never satisfy `requireStepUp` (`MFAAt` is always nil for tokens), so **any
machine-token write path cannot carry step-up** — in Phase 1 routine writes are human console writes,
so this is stated rather than load-bearing yet; it becomes material when Phase 2 introduces a CI token.

#### P1.2 — keep the privileged-subset two-person control and break-glass guards

The `internal/dualcontrol` engine is **kept**. Only the *non-privileged* propose/approve wiring for
`policy`/`cloudtrust`/`usertrust` is removed.

- **Distinct-actor two-person control for the PRIVILEGED subset is RETAINED.** A privileged grant —
  any reserved-group grant (`policy.IsReservedGroup` — control-plane/lighthouse) or any
  `auto_issue=true` entry — MUST still require a **distinct second harbor sign-off recorded
  server-side**. The PUT detects (via the same validators) that an incoming config introduces or
  modifies a privileged grant and routes that change through a `dualcontrol` distinct-actor commit
  (`ErrSelfApproval` / `ErrDuplicateActor`) rather than applying it under one operator. (Trade: a
  slice of the propose/approve machinery and its console affordance survives — the product is *less*
  "smaller" than a naive UI-delete would be, but it is still markedly smaller.)
- **`bulk-revoke` keeps its two-person control.** `dualcontrol` still backs `bulk-revoke`
  (`revocation.BulkRevokeKind`), an emergency operation that must stay imperative
  (`REVOCATION-GUARDS-DECISIONS.md`).

#### P1 — honest framing & acknowledged regression

- **Honest framing.** Phase 1 IS a smaller product: the under-tested UI is deleted and replaced with
  simple, tested CRUD. This is the resolution of the earlier "smaller vs larger surface" tension —
  **P1 shrinks**; the larger config-as-code surface is added *deliberately* in later phases for the
  config-as-code value, not as creep.
- **Acknowledged regression.** Phase 1 makes **non-privileged** config single-operator (no second
  person) until Phase 2's GitOps gate. This is **moot for the near-term single-operator profile**, but
  a **bounded regression for multi-operator shops**. The privileged subset stays two-person (P1.2).
- **"Phase-1-only" risk.** Phase 1 can quietly become the permanent stopping point. That is **fine as
  a deliberate stop** for a single-operator shop — but if it stops there, the config-as-code goal
  (problem 2 in Context) is **not met**. This is a decision to make explicitly, not by drift (Open
  Question 9).

### Phase 2 (PLANNED follow-on) — Config-as-code via export/import + optional GitOps-as-control

Phase 2 turns the Phase-1 store into a config-as-code source of record and, optionally, makes Git the
routine two-person control — **without a Terraform provider.**

#### P2.1 — canonical serialization (PREREQUISITE — was Open Q4)

Promoted from an open question to a **Phase-2 prerequisite**, because the failure modes are
security-relevant, not cosmetic:

- A **false-negative** is the dangerous direction: a malicious or unintended change that happens to
  hash *equal* would never trip drift and would ride live undetected.
- A **spurious import→plan diff** invites operators to "apply to silence it" — silently reordering
  first-match `usertrust` entries (changing who matches) or bumping `policy.version`.

Therefore define **one canonical, ORDER-PRESERVING serialization** shared by the `harbor config export`
helper and the `last_applied_hash` computation. The hash MUST span exactly:

- **usertrust:** entry **order** (first-match-wins), and per entry `realm`, `directory_group`,
  `mesh_groups` (set semantics decided explicitly), `auto_issue`, `netblock`; plus `default_groups`.
- **cloudtrust:** per `aws` entry `account`, `arn_patterns`, `groups`, `auto_issue`, `netblock`; plus
  `default_groups`.
- **policy:** every firewall rule tuple `{from, to, proto, port}` **and its order**; and a decision on
  whether `policy.version` is **operator-owned** (part of the hash, operator bumps it) or
  **provider-computed** (excluded from the semantic hash) — pick one and document it.
- **netblock:** `name`, `kind`, `description`, and a CIDR representation that **excludes server-grown
  bits** (see the auto-grow caveat in the future-phase resource table).

Acceptance test (required): a fresh `export/import → diff` is **byte-clean** (no spurious diff), AND
**any** semantic change flips the hash (no false-negative).

#### P2.2 — export / import + provenance + drift detection

- Add `harbor config export` / `harbor config import`. The `export` helper MUST surface the invariant
  baseline that `policy.CompileHost` injects (control-plane/lighthouse reachability + ICMP) as a
  **non-editable note** — it is not part of `policy.Policy` and not representable in the exported
  config, so a diff is the *editable* config, not the full compiled-host firewall, and reviewers must
  not be misled.
- Add the **provenance columns** deferred from Phase 1: `source` (`terraform | cli | ui | break-glass`),
  `last_applied_by`, `last_applied_hash`.
- **Harbor-side drift detection.** Harbor computes `drifted = current content hash ≠ last_applied_hash`.
  **Baseline-advance rule (critical):** `last_applied_hash` MUST be advanceable **only** by writes
  whose authenticated `source` is the terraform/CI principal. A non-pipeline write (CLI / UI /
  break-glass) updates content + `source` + `last_applied_by` but **MUST NOT** advance
  `last_applied_hash`. Otherwise a CLI or break-glass writer would suppress its *own* drift badge —
  defeating the sole out-of-band-write control.
- **Drift signalling (mandatory).** Any transition to `drifted=true` MUST emit (a) a row in harbor's
  **hash-chained audit log** (`store.Audit`, `prev_hash`/`hash` chain, verified by `VerifyAudit`) and
  (b) an alertable Prometheus signal `ncp_config_drifted{kind}` (note: harbor metrics use the `ncp_`
  prefix — e.g. `ncp_ipam_autogrow_total`, `ncp_auditverify_tampered_total` — *not* `harbor_`).
- **Console drift badge** on any config type changed outside the pipeline ("modified outside
  Terraform — the next apply will revert"), so operators see drift without running a plan.
- **Optimistic concurrency.** The PUT takes an `If-Match` on `last_applied_hash` (or a monotonic
  `version`) and returns **412 Precondition Failed** on mismatch — needed once a pipeline and direct
  writes can race. Harbor has no such conflict primitive today; without it, two near-simultaneous
  applies, or an apply of stale state, silently clobber or revert each other.

#### P2.3 — GitOps-as-control (optional, no provider)

Run Phase 2 as **`harbor config import`-from-Git-in-CI + branch protection = GitOps-as-control**: the
PR review becomes the two-person rule for **non-privileged** config — **WITHOUT a Terraform provider.**

- **Branch protection** on the config repo: ≥1 required reviewer, no self-merge, PR-only. CI runs
  `harbor config import` of merged `main` with a CI-held token; the token lives **only in the CI
  secret store**, never in human hands.
- **Honest statement of the regression (corrects the earlier "this is the dual-control" / "stronger
  two-person control" overclaim).** This **removes** harbor's server-side distinct-actor enforcement
  (`ErrSelfApproval` / `ErrDuplicateActor`) for these kinds, and the **import-token holder can write
  config directly, bypassing the PR gate entirely.** For *non-privileged* changes that is an
  acceptable trade for the GitOps benefits. It is **not** a "stronger" control while a single token
  bypasses it.
- **Branch-protection caveats.**
  - **Reviewer population ≠ harbor approver population.** A GitHub reviewer is whoever holds repo
    review access — governed by the *forge* (CODEOWNERS / branch protection), not by harbor RBAC, the
    IdP, or MFA. The config-repo CODEOWNERS / required-reviewer set MUST be **constrained to, and kept
    in sync with, the harbor operators who would hold `approval:decide`**, and that synchronization
    MUST be audited.
  - The design MUST name **who administers branch protection** — that administrator is *inside the
    trust boundary* (they can weaken the only routine two-person control) and must be treated as such.
  - **Record the merge commit SHA + reviewer identity into harbor's audit chain.** Otherwise the only
    "second approver" record lives in mutable GitHub PR history, outside harbor's tamper-evident chain,
    and is not admissible evidence that the two-person rule held.

#### P2.4 — soft drift default + hard caveat for the privileged subset

Soft drift (allow + flag, don't reject) is the Phase-2 default — **except** for the privileged subset.

**Soft drift is the wrong default for the root of trust — and contradicts what we already ship.**
Trust config is read **live per enrollment**, so an out-of-band privileged write *actively mints certs*
until reverted, and an apply-revert does **NOT un-issue** the interim certs. There is a direct internal
contradiction: `internal/drift/drift.go` already ships **continuous (1-minute) detect-and-AUTO-REVERT**
for *per-host* config, yet a soft badge would give the far-more-sensitive *root of trust* a **weaker**
guarantee. Resolution for the **privileged subset** (one of):

- **Hard-reject** out-of-band privileged writes (they must go through the privileged-subset control,
  P1.2) — preferred; or
- **Bounded auto-revert / quarantine SLA** with a stated maximum drift window; or
- **Open Question** (Open Question 8) naming the **maximum drift TTL** and the **no-un-issue caveat**
  (revert does not retract certs already minted during the window).

At a **minimum** Phase 2 requires a **scheduled CI apply** (not only on-merge) with a stated maximum
drift window, so even non-privileged drift cannot persist indefinitely. And a **security-relevant
drift — especially a trust removal — GATES the next apply** until an operator reconciles it, rather
than being silently reverted: a routine apply MUST refuse to re-add a trust that a break-glass removal
cut, until the removal is reflected in `main`.

#### P2.5 — apply/import token scoping

The import token is a trust anchor: **one leaked CI secret = a full mesh trust rewrite, unattended.**
It MUST be scoped to contain that blast radius:

- Holds **only** the minimal config-write perms (the new config-manage perms + `ipam:manage`).
- MUST **NOT** be `RoleAdmin` — admin is an unconditional RBAC superuser and would grant the token the
  entire control plane, not just config.
- MUST **NOT** carry `approval:decide` (`PermApprovalDecide`) or any break-glass authority — so a
  leaked config token cannot self-approve the privileged-subset second control (P1.2) or perform
  bulk-revoke.
- **Compensating controls:** short-TTL CI-minted token (per-run, not a long-lived secret); bind the
  token to the **CI OIDC identity** (issued only to the CI workload, not exportable); and
  **audit-alert** on any pipeline write that grants a reserved group or sets `auto_issue`.

#### P2.6 — cross-resource references & ordering (applies once netblocks are declaratively managed)

`cloudtrust.Config` and `usertrust.Config` reference a netblock by **free-string name**, and harbor
**silently falls back to `default`** on an unknown name (`netblock.Resolve` / `ResolveFull`, IPAM
decision D20). Once netblocks are declaratively managed alongside trust config, a hardcoded netblock
*name* in a trust resource gives **no dependency edge** — config could be applied that references a
netblock that does not (yet) exist, silently re-homing hosts into the broad `default` block, while the
diff and the drift badge both report **clean**. This is a quiet security downgrade (broad default
scope instead of the intended narrow block).

Required mitigations:

- Model netblock refs as **references** (in the future provider, e.g.
  `netblock = harbor_netblock.x.name`) so create-before-reference / delete-after-dereference ordering
  is enforced; in the export/import flow, validate the same ordering.
- The trust PUT **validates referenced netblock names** (reject, or at minimum loud-warn + audit)
  instead of silently falling back to `default`.
- **Netblock deletion MUST be blocked while ANY referencer names it.** Today `netblock.Remove` guards
  only `Protected` blocks + live allocations — **not** references. The reference scan MUST span **both**
  the declarative referencers (cloudtrust/usertrust entries) **and** the imperative ones (join-key
  bindings).

### Future phase (OPTION, NOT a commitment) — a Terraform provider (`terraform-provider-harbor`)

A real provider (on `terraform-plugin-framework`), **not** a `null_resource`+CLI "module" (which has no
real state, drift, or import). It **wraps the SAME declarative API** Phase 1 built and Phase 2 hardened,
adding `terraform plan`/state/import and optimistic concurrency (`If-Match`/412 on the PUT). One resource
per declarative config type, mapped to the existing harbor models:

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

Provider auth is a harbor **admin API token** (RBAC-scoped to the minimal config-write permissions per
P2.5) from provider config / env. The genesis-managed **protected** netblocks (`central`, `default` —
`Protected=true`; note "protected" is a *flag*, not a `kind`, since `kind` is
`reserved`/`default`/`named`) are **not** TF-managed: the provider may `import`/read them but refuses
to manage protected blocks (they belong to genesis), and exports them read-only/unmanaged so a later
out-of-band protected seed is expected, never drift.

**`harbor_netblock.cidr` vs server-side auto-grow.** `netblock.Grow` mutates a named block's CIDR
`/P → /P-1` **automatically during allocation** (`ipam` allocator calls `Grow` on `ErrPoolExhausted`),
out of band and unattended. A naively TF-managed `cidr` would therefore spuriously *drift* the moment
the pool grows, and the next apply would *shrink it back* — corrupting live allocations. So
`harbor_netblock.cidr` MUST be **Computed/server-authoritative** (the provider reads it and ignores
server growth), or operators declare only a **floor/envelope** while the server owns the live size.
Either way, the drift hash for netblocks MUST exclude server-grown bits of the CIDR (P2.1).

**Cutover gate + Rollback (only relevant if this phase is built).** Removing any remaining in-app path
for a mesh MUST NOT proceed until: (a) every TF-managed object is **imported**; (b) `terraform plan` is
verified **empty** in CI (using the canonical serialization); (c) `source=terraform` is the recorded
**last writer** for all three config kinds **and** every non-protected netblock. Expose a **per-kind
readiness signal** (e.g. `managed_by_terraform{kind}`) so the gate is machine-checkable. Keep any
fallback **feature-flagged OFF (not deleted)** for **≥1 release** with a documented revert procedure;
cutover is **not safe** until the PUT path is confirmed (by test) to re-run the commit-time validators
(P1.1 invariant) and to enforce the privileged-subset second control (P1.2).

**Justification — why this is a future option, not the first step.** The provider is justified **only**
if **multi-mesh**, **true GitOps-as-control-with-enforced-state**, or **environment promotion** demand
`plan`/state. Otherwise Phase 2's export/import + CI is sufficient, and a full provider is over-built
for the near-term profile. Whether this phase is ever built is Open Question 9.

## Scope / non-goals

**Declaratively managed (config-as-code, from Phase 2):** firewall policy, cloud trusts, user trusts,
IPAM netblock definitions.

**Stays imperative (never declarative):**
- **Revocation / bulk-revoke** — emergency; can't wait for PR→import→apply. Keeps `dualcontrol` (P1.2).
- **Enrollment approvals** — per-host operational decisions.
- **IPAM allocations** — assigned dynamically at enroll; only netblock *definitions* are declarative.
- **Join keys** — ephemeral/operational secrets; awkward as long-lived declarative state. (A future
  `harbor_standing_join_key` for long-lived host-class keys is an open question; ephemeral minting
  stays imperative.)

**Urgent trust REMOVAL is distinct from low-churn addition — and must not be silently undone.** Cutting
a compromised AWS account or disabling an AD-group `auto_issue` is **time-critical** and read **live**;
forcing it through PR→CI→apply is a regression on response time. Worse, because the trust configs are
**full-replace singletons** and drift is soft, a break-glass trust **removal** can be **silently UNDONE**
by the next routine apply of stale `main` — re-admitting the attacker. Therefore (from Phase 2): provide
a **fast disable path** for trust cuts (or runbook break-glass as the emergency removal path), AND a
**security-relevant drift — especially a removal — GATES the next apply** until reconciled (P2.4).

## Alternatives considered

**Adopted as phases (no longer alternatives).** Two options the prior draft listed as alternatives are
now the spine of the Decision:

- *"Delete the dual-control UI; keep single-operator RBAC + MFA CRUD; NO provider"* → **adopted as
  Phase 1.** It captures the "smaller product" win with little added surface (deletes the propose/approve
  screens and non-privileged distinct-actor machinery; adds no provider, no pipeline, no provenance
  store). What it *lacks* — `plan` diffs, Git history, state-backed drift, reproducibility, environment
  promotion — is exactly what Phases 2 and the future provider add by choice.
- *"Keep in-app CRUD + an optional `harbor config export` / import to Git, no provider"* → **adopted as
  Phase 2.** Edits go through the API (with the kept RBAC/MFA + privileged controls), and export/import +
  branch protection make Git a config-as-code source and an optional two-person control without a
  stateful provider.

**Rejected:**

- **Keep in-app dual-control, just polish the UI.** Rejected: reimplements a review workflow operators
  already run better in Git; keeps a complex, under-tested surface — the trigger for this whole ADR.
- **A `null_resource`+CLI Terraform module (no provider).** Rejected: no real state, drift, or import;
  brittle; can't show meaningful `plan` diffs.
- **Per-entry resources** (`harbor_cloud_trust_account`, `harbor_user_trust_entry`). Rejected as the
  default: loses atomic apply + deterministic first-match ordering. (Revisit if ordering is made explicit
  via an index.)
- **Hard drift enforcement as the global default** (API rejects all non-pipeline writes). Adopted *for
  the privileged subset* (P2.4); rejected as the global default — blocks break-glass, heavier; soft drift
  + badge + scheduled apply first.
- **A full Terraform provider AS THE FIRST STEP.** Rejected: over-built for the near-term single-operator
  profile and a much larger surface than the trigger requires. The trigger is the under-tested UI, which
  Phase 1 fixes with a *smaller* product; provider value (`plan`/state/promotion) is real but only for
  multi-mesh / enforced-state / promotion needs, so it is **deferred to the future phase** and built only
  if those needs materialize.

> The honest tie-breaker: **a single-operator / CLI-first shop is well served by Phase 1 alone; a
> GitOps-mature, multi-operator shop progresses through Phase 2; only multi-mesh / enforced-state /
> promotion needs justify the future provider.** The phasing lets the ADR serve all three without
> forcing the heaviest option on the lightest profile.

## Consequences

- **Phase 1 has standalone value and is genuinely smaller.** It deletes a large, under-tested
  propose/approve UI and replaces it with simple, tested CRUD over one primitive. It does **not**
  require Git/CI/branch protection and serves the single-operator profile fully on its own.
- **Phase 1 opens a non-privileged single-operator window.** Non-privileged config becomes
  single-operator (no second person) until Phase 2's GitOps gate. Moot for single-operator shops; a
  **bounded regression** for multi-operator shops. The privileged subset stays two-person throughout.
- **"A-only" risk.** Phase 1 can become the permanent stop. Fine as a deliberate choice for a
  single-operator shop, but then the config-as-code goal is **not met** — a decision to make explicitly,
  not by drift (Open Question 9).
- **Controls move and change shape — not wholesale "stronger."** Phase 2's PR review + CI apply gives
  diff review, history, rollback, and CI validation, and operators already run it. But for these kinds it
  **removes** harbor's server-side distinct-actor enforcement and lets the import-token holder bypass the
  PR gate. The two-person rule is therefore *equivalent-or-weaker* for non-privileged changes (depends on
  forge config) and is **explicitly preserved server-side for the privileged subset** (P1.2). It is not
  honest to call this "a stronger two-person control" wholesale.
- **Surface grows only in later phases, by choice.** Phase 1 shrinks surface. Phase 2 and the future
  provider *add* surface deliberately — provenance/hash store, drift detection + badge + metric + audit
  rows, `harbor config export`/import, canonical serialization, an external GitOps pipeline, and (future)
  a whole `terraform-provider-harbor` codebase. That growth buys the config-as-code value (history,
  reproducibility, GitOps-as-control); it is **not** sold as a smaller product.
- **Who this serves / who it burdens.** *Phase 1 serves* single-operator / CLI-first shops directly.
  *Phase 2 serves* GitOps-mature, multi-operator shops that already live in PR/CI; it **burdens** anyone
  who must stand up Git/CI/branch protection — which is precisely why those phases are optional and gated.
- **Step-up MFA: kept on Phase-1 console writes; dropped on machine/CI paths.** Phase 1 human writes keep
  step-up. The Phase-2 CI/import token cannot satisfy step-up (`MFAAt` nil for tokens); the named
  compensating control is the non-privileged restriction + the privileged-subset server-side second
  control + token scoping (P2.5).
- **Trust shifts to the pipeline + a single token — only at Phase 2+.** The security boundary becomes
  branch protection + the CI-only import token + the forge's reviewer administration, not harbor's
  server-side approval. The token's blast radius (full mesh trust rewrite) is scoped per P2.5; the
  second-approver *record* must be written into harbor's audit chain (P2.3), not left in mutable PR
  history. In Phase 1 this shift has not happened.
- **Two write paths during any cutover**, and a flag-off-not-deleted fallback for ≥1 release (future
  phase only).

## Open questions

1. **Standing join keys as declarative config?** Add `harbor_standing_join_key` for long-lived
   host-class keys, or keep all join-key minting imperative? (Leaning: imperative for now.)
2. **Provider distribution (future-phase question)** — private registry vs in-repo; provider versioning
   vs harbor API versioning. Only relevant if the future provider phase is built.
3. **One config repo per mesh, or a module with per-mesh workspaces** for multi-mesh operators (Phase 2+).
4. **Break-glass UX** — exactly how a direct emergency write is flagged, audited, and reconciled; does the
   console offer a "copy current config" to ease reconciliation? (Mechanics matter from Phase 1 for the
   privileged-subset path and from Phase 2 for drift reconciliation.)
5. **Pre-PR local preview** — keep a thin `harbor policy diff` CLI, or rely solely on a `terraform plan` /
   export diff? (Phase 2+.)
6. **`policy.version` ownership** — operator-owned (in the hash) vs provider-computed (excluded). Tied to
   the canonical-serialization prerequisite; pick one before Phase 2.
7. **Privileged-subset hard-vs-soft drift, and the accepted-risk fallback.** Phase 1 keeps `dualcontrol`
   on the privileged direct-write path (P1.2). If that proves too heavy at Phase 2, the named fallback is:
   privileged grants ride GitOps two-person control only, accepting that *a leaked/misused config token
   can mint a privileged trust unattended* and the second-person record lives only in mutable PR history.
   Decide explicitly before Phase 2 ships GitOps-as-control.
8. **Maximum drift TTL for the privileged subset (Phase 2).** If neither hard-reject nor bounded
   auto-revert is adopted (P2.4), name the **maximum drift window** a privileged out-of-band write may
   persist, and restate the **no-un-issue caveat** (apply-revert does not retract certs already minted
   during the window).
9. **Does Phase 2 / the provider ever get built? — the A-only decision point.** Commit to progressing to
   config-as-code (Phase 2), and is the future Terraform provider ever justified (multi-mesh /
   enforced-state / promotion), or does this stop at Phase 1 for a single-operator shop — accepting that
   the config-as-code goal is then not met? Decide explicitly rather than by drift.
