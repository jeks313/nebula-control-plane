---
title: "ADR 0001 — Firewall Policy Scoping"
created: 2026-06-13
status: accepted
tags: [nebula, adr, policy, architecture, dual-control]
---

# ADR 0001 — Firewall Policy Scoping

**Status:** Accepted (Phase 0/1 are the direction; Phase 2 deferred behind a trust-model gate)
**Date:** 2026-06-13
**Decision owners:** Chris Hyde (+ a future second approver, per dual-control)

## Context

Today Harbor has **one global firewall policy**: a flat allow-list of `group → group`
rules (`internal/policy`, `{FromGroup, ToGroup, Proto, Port}`), implicit default-deny,
published via two-person dual-control (`policy.publish`; active = latest committed).
`CompileHost(policy, hostGroups)` compiles that single document down to each host's
Nebula firewall section, emitting only the rules touching that host's groups, plus a
non-removable baseline (every host reaches the control plane; ICMP both ways). A host's
groups come from its **join method** — join-key groups (token enroll) or the
cloud-trust per-account groups (attestation, M5.3). **Bare group names are global**, so
account A's `web` and account B's `web` are the *same* group.

The question raised: must policy be a single global document? It feels limiting and gets
unwieldy as the mesh grows, and a smaller-scoped policy would make blast-radius easier to
see. The proposal under discussion: **scope policy by join method** (like group
assignment) — a host joining via AWS account 1111 is governed by *that account's* policy,
with a thin separately-governed "interconnect" policy for cross-scope flows, composed
per-host, and groups namespaced by scope (`aws:1111:web`).

We adversarially pressure-tested it (7-agent: three red-team critiques, three alternative
architectures, an adversarial synthesis that cross-read the real code).

## Decision

**Adopt namespaced-single-policy + per-rule owner tag + scope-scoped propose authz**
(the minimal-change alternative), executed in phases. **Reject** the
document-split-plus-interconnect model as the default. Treat a true per-scope **document
split** as an opt-in **Phase 2**, gated on a *confirmed* untrusted-multi-tenant or
parallel-publish requirement — neither of which exists in today's single-operator posture.

This delivers the three goals — **manageability** as the mesh grows, **bounded/obvious
blast-radius**, **delegated ownership** — at roughly a tenth of the code and with **zero
change to the enforcement/analysis core** (`CompileHost`, `Reachable`/`Matrix`,
`CheckInvariants`, the baseline, the signed-bundle path, dual-control).

## Why the proposed document-split was rejected

1. **Keystone — "both-sides-consent for free" is false against the code.** A single
   `policy.Rule{From,To,Proto,Port}` *atomically* compiles to **both** the sender's
   outbound and the receiver's inbound (`policy.go:143-150`). There is no "each side
   authors only its half." So a split forces *either* an interconnect document that names
   both scopes' groups — **re-centralizing the cross-cutting document you set out to
   delete** — *or* a net-new **directional half-rule** representation + compiler change.
   The consent the proposal claimed comes free is, in fact, new machinery.
2. **Consent can't be subtractive.** The model is pure-allow + default-deny with no deny
   or priority rules, so composing scope-policy ∪ interconnect can only **widen**, never
   constrain. A scope cannot veto an interconnect rule that names its group → an
   interconnect admin could unilaterally expose a scope's inbound with zero consent.
3. **`any` is scope-blind.** `allow any → aws:1111:logs udp 514` punches across *every*
   scope regardless of namespacing (`CompileHost`'s host-membership gate is bypassed by
   `any`; `selector()` renders it `Host:"any"`). Bounded blast-radius is void for any
   rule touching bare `any` — under *any* scoping scheme.
4. **The analysis engine is single-policy.** `Reachable`/`Matrix` take one `Policy`; a
   naïve cross-document union makes the reachability matrix **lie** (reports reachable
   when no host's compiled firewall actually permits it) — exactly the false-allow class
   the A1.1 adversarial review already caught.
5. **No atomic cross-scope authoring primitive.** `dualcontrol` commits one change at a
   time, keyed on `Kind` (not `Target`). A cross-scope flow spanning N documents is
   half-open between commits (egress allowed, ingress still default-deny) → silent
   outages, and a worse TOCTOU surface than today.

## Considered options

| Option | Verdict | One-line |
|---|---|---|
| **A. Proposed: per-scope documents + interconnect** | Rejected | Its consent-for-free + thin-interconnect framing is contradicted by the compiler; the interconnect becomes the new centrally-owned, monotonically-growing bottleneck. |
| **B. Namespaced single policy + owner tag + scope RBAC** | **Chosen** | Same goals, ~10% of the code, enforcement/analysis core untouched. |
| **C. Selector/label-based policy (k8s NetworkPolicy / Cilium)** | Future evolution | Cross-scope spans scopes natively and is the natural home for the 5.5 immutable-fact group map — but "who can reach me?" becomes set-satisfiability and membership is dynamic (TOCTOU/auditability cost). Rewrites every analysis primitive. |
| **D. Intent/capability (exposes + consumed-by handshake)** | Future evolution | Makes both-sides-consent + blast-radius first-class and ownership local — but a bigger conceptual leap (Service/Exposure/Claim + a `Derive` layer) and more net-new security-critical code. |

C and D are credible *long-term* directions (especially C as the landing spot for the
5.5 group map), but both are larger, security-critical rewrites; neither is justified
ahead of B's cheaper, additive win.

## The decision driver (the fork)

Everything hinges on the **threat model for scope admins**:

- **Trusted-but-fallible** → server-enforced ownership over one document (B) is
  sufficient and far cheaper.
- **Untrusted / hostile multi-tenant** → only physically-separate documents give the
  *structural* guarantee that scope A cannot author scope B's rules. That, and only that,
  justifies the document split (Phase 2).

Today's posture is a single operator (one git identity, sole proposer). **Until genuine
multi-tenant delegation is a real requirement, B is correct and the split stays an
opt-in last resort.**

## Phased plan

- **Phase 0 — namespacing (do first; valuable standalone, and the unavoidable cost paid
  under every option).** Introduce `scope:name` groups (`aws:<account>:<g>` from
  cloud-trust; `key:<name>:<g>` from join keys). Groups are already opaque strings to
  `CompileHost`/`Reachable`/`Matrix`, so this is **zero compiler/analysis change**. Forbid
  bare `any`; add scope-qualified wildcards (`aws:1111:*`, privileged `mesh:*`). **Migration
  caveat:** group names live in ~5 stores *and are baked into issued certs*, so cutover
  needs a dual-name alias epoch (`matchGroup`/parse accept both forms) + a fleet-wide cert
  renewal via the M6.6 canary machinery before retiring bare names. Keep
  `control-plane`/`lighthouse` reserved so the baseline invariant holds. *This alone kills
  the cross-account name collision.*
- **Phase 1 — owner tag + delegated authorship (additive to the one document).** Add an
  `Owner` field to `policy.Rule`, **inert to the compiler** (bundles + reachability stay
  byte-identical). It powers: (a) filtered per-scope matrix/diff **views**; (b) exact,
  cheap **blast-radius** in the §4.4 approval snapshot; (c) **delegated edit** via a new
  scope-scoped permission (`policy:propose:<scope>`) checked at `handlePolicyPropose` by
  diffing the proposal and asserting every changed rule's owner ∈ the proposer's scope set
  (full-fleet `policy:propose` still allowed for the platform team). Cross-scope flows are
  rules tagged `owner=interconnect` in the *one* atomically-published document — so the
  half-open-flow failure cannot occur. `dualcontrol`, step-up, audit, `CheckInvariants`,
  baseline all unchanged.
- **Phase 2 — commit-isolation (opt-in; only if the trust-model fork flips).** Do **not**
  mint N change-kinds (the dynamic-registration no-op-commit footgun). Keep one
  `policy.publish` kind and key the active config on the existing `Change.Target` column
  (a one-line `WHERE` + a single dispatching committer). Only here take on the multi-doc
  compose + a **scope-aware** analysis-rail rewrite — and re-run the adversarial review
  that already caught a false-allow.

## Consequences

- **+** Manageability, bounded/obvious blast-radius, and delegated ownership, with the
  fail-closed enforcement/analysis core untouched through Phases 0–1.
- **+** Fixes the cross-account group-name collision (a latent correctness bug today).
- **+** Phase 1's owner tag directly de-risks A1.2 blast-radius (compute per-owner scope).
- **−** Phase 1 isolation is a **soft** boundary (server-enforced RBAC over one document),
  not a structural one; an untrusted scope admin who passed the scope check could still
  name another scope's group. Acceptable under the trusted-but-fallible model; the fix is
  Phase 2.
- **−** The namespacing migration is real, security-sensitive work (dual-name epoch +
  fleet-wide cert renewal). It is, however, owed under *every* option.
- **−** RBAC must grow a **resource dimension** (`authorize`/`requirePerm` are flat today).
  Required under every option that delegates.

## Open questions to resolve before building

1. **Trust model** for scope admins (the fork above) — decides whether Phase 2 ever happens.
2. **Is parallel publishing / per-scope commit-isolation a near-term need**, or speculative?
3. **How is rule ownership determined** — derived from the rule's namespaces (needs a
   cross-namespace tie-break) or intrinsic? A mis-tag mis-attributes blast-radius and
   mis-gates delegation; needs a validation invariant (owner must match the group prefixes).
4. **`cloudtrust.DefaultGroups`** (granted fleet-wide, flat) under namespacing — namespace
   per scope, or bless it as the one intentional cross-scope group and forbid it in
   scope-attributed rules?
5. **Shared/dual-scope hosts** (a bastion serving two scopes) and **offboarding** — a host
   attests once into one scope; dual membership needs a privileged second group source, and
   decommissioning a scope must clean up dangling cross-scope references (no
   referential-integrity check exists today).
6. **Matrix scaling** — all-pairs is O(groups²) and already DoS-capped (A1.1); summing
   groups across scopes squares a larger n. Needs a scope-filtered matrix mode.

## Relationship to other work

- **5.5 immutable-fact group map** — Option C (selectors/labels) is its natural long-term
  home; Phase 0 namespacing is forward-compatible with it.
- **A1.2 blast-radius** — Phase 1's owner tag is the cheap source for "affects N hosts."
- **Cross-account collision fix** — Phase 0 is independently valuable regardless of the rest.
