---
title: "ADR 0004 — SSO-Driven User Enrollment"
created: 2026-06-13
status: accepted
tags: [nebula, adr, enrollment, sso, oidc, saml, identity, approval, architecture]
---

# ADR 0004 — SSO-Driven User Enrollment

**Status:** Accepted (Phases 1–3 are the direction; auto-issue and device-code are deferred opt-ins)
**Status (2026-06-18):** CODE-COMPLETE, NOT ROLLED OUT. Phases 1–2 are built, merged, and
deploy-threaded but **OFF BY DEFAULT** — `internal/ssoassert` (dedicated-ECDSA signed
assertion), Core `processSSO` (re-verifies the pinned key + nonce/pubkey binding +
first-match `internal/usertrust`, default pending), the gateway portal (`internal/gateway/ssoportal.go`,
`cmd/gateway/sso.go`), `harbor usertrust publish` (dual-control), the admin-API user-trust
config + UI, SSO provenance, and genesis/bootstrap/terraform threading all exist. SSO stays
**fail-closed-disabled** until an operator registers the second AD/Entra SAML app, publishes
a user-trust config, and sets `-sso-acs-url` (empty ⇒ disabled). Phase 3 (lifecycle) and
Phase 4 (device-code, auto-issue) remain PLANNED. Decision log: `docs/SSO-DECISIONS.md`.
**Date:** 2026-06-13
**Decision owners:** Chris Hyde (+ a future second approver, per dual-control)

## Context

Harbor has two ways for a host to join the mesh: a **join key** (token, a scoped bearer
secret) and **cloud attestation** (aws-sigv4, a presigned STS identity). Both are
*machine*-oriented. What's missing is **user-initiated join**: an end-user or admin laptop
that needs to join the mesh to administer the other devices on it. The desired UX is
SSO-driven — no join key to distribute: the user is given a web redirect to an SSO sign-in,
and the result is an enrollment that **must be approved**.

The encouraging finding (as with the prior ADRs): the hard parts already exist.

- **The IdP integration is built.** `internal/adminauth` already authenticates humans for
  the admin console via a provider interface — `AuthURL(state, nonce, verifier,
  forceReauth)` → `Exchange(code, …)` → `Subject{ID, Email, Groups, MFAAt}` — across **OIDC,
  SAML, and GitHub**, with group-claim extraction, PKCE/state/nonce, and an MFA-freshness
  timestamp. SSO-join reuses this wholesale.
- **The enroll → queue → approval pipeline exists.** The public gateway vets and queues a
  candidate; Core re-verifies and either auto-issues or queues **pending manual approval**;
  the admin console has the approval queue. "An enrollment that must be approved" is the
  *existing* pending path.
- **There is a precedent for a signed identity proof bound to the enrollment.** aws-sigv4
  already binds a signed identity (STS) to the enrollment's nonce + host pubkey. SSO-join is
  the same shape with the human IdP as the identity source.
- **The config + provenance patterns exist.** cloud-trust is a dual-control-published
  `account → groups + auto_issue` map; the enrollment evidence columns
  (`attest_provider/account/principal/region`) are deliberately provider-agnostic.

So SSO-join is largely *wiring existing pieces together*, plus two genuinely new things: a
**public SSO surface** (the laptop is pre-mesh, so it cannot reach the mesh-only console),
and the **binding of the human's SSO to the device's enrollment key**.

## Decision

Add a third enrollment method, **`sso`**, symmetric with the existing two: a **portal-signed
SSO assertion bound to the enrollment's nonce + host pubkey**, which Core verifies and
**queues for approval by default**. The flow reuses `adminauth` (the IdP integration), the
enroll/queue/approval pipeline, the cloud-trust-style dual-control config pattern, and the
provider-agnostic evidence.

Concretely:

- A new **public enrollment portal** tier authenticates the human via the existing IdP and
  emits a short-lived **signed SSO assertion** (`subject, IdP groups, bound to pubkey+nonce,
  exp`). It holds the IdP secret + session state + an assertion-signing key, but **no CA/KMS
  — it never issues certs**. Authority stays in Core (mirroring the gateway's "public front,
  authority in Core" design).
- **Pilot** runs a browser SSO flow (loopback authorization-code for laptops; device-code
  for headless), then submits a normal enroll request with `method=sso` and the assertion as
  the credential.
- **Core** re-verifies the host JWS + the assertion (signature + nonce/pubkey binding) + a
  dual-control **user-trust** policy (which IdP group/domain may join, what mesh groups,
  what admission posture), then **records it pending** for a human to approve.
- **Default to pending approval** for SSO; auto-issue is a later per-group opt-in and should
  never apply to admin-group laptops.

## The flow, end to end

1. `pilot enroll --sso` generates the host key (P1), fetches a nonce bound to its pubkey,
   and opens an SSO-enroll session at the portal (pubkey_hash + nonce + a JWS
   proof-of-possession).
2. Pilot opens the browser to the portal's verification URL — **loopback
   authorization-code** flow on a laptop, **device-code** fallback when headless.
3. The human authenticates at the IdP (MFA enforced there). The **consent screen shows the
   device name + key fingerprint + requested groups** — the anti-relay defense.
4. On callback the portal extracts the `Subject`, **binds it to the session's pubkey+nonce
   via `state`**, and signs a short-lived assertion. No cert is minted.
5. Pilot submits the enroll request (`method=sso`, credential = the assertion) through the
   gateway → queue, exactly as the other methods do.
6. Core re-verifies the host JWS (it holds the key) + the assertion (signature + binding) +
   the user-trust policy, then records the enrollment **pending**.
7. An admin **approves in the existing queue**, seeing the SSO identity as provenance
   (`alice@corp` via Okta, IdP groups […] → mesh group `admin`). Approval issues the cert +
   bundle; Pilot polls and installs.

## Considered options / the design decisions

### Where the SSO surface lives

| Option | Verdict |
|---|---|
| **Extend the public gateway** | Rejected — the gateway is deliberately credential-less/no-DB; adding the IdP secret + session state breaks that property. |
| **Reuse the admin console's SSO** | Impossible for join — the console is mesh-only, and a brand-new laptop is pre-mesh. |
| **A new public enrollment portal (no CA)** | **Chosen.** IdP-connected + stateful, but holds no signing authority; vouches "human → key," Core issues. Mirrors the gateway pattern. It is a *richer* public surface than the gateway and is its own scrutiny target. |

### The binding (the security keystone)

The assertion MUST be cryptographically tied to the specific pubkey + nonce (via the OAuth
`state`), or an attacker relays a victim's SSO onto the attacker's key. Two layers:
state-binding (machine) + the **fingerprint on the consent screen** (human rejects an
unexpected device). This is the one part that must be exactly right.

### Browser flow

Loopback authorization-code (browser opens, redirects back to a localhost listener Pilot
ran — the `tsh`/`gcloud auth login` pattern) for laptops; **device-code** (user_code +
verification_uri) for headless admin servers. Loopback is the default; device-code is a
deferred opt-in (Phase 4).

### Group derivation + admission

A dual-control **user-trust** config maps `IdP group/domain → mesh groups + admission
posture`, exactly mirroring cloud-trust's `account → groups + auto_issue`. **Default
admission is pending approval.** Auto-issue is a later opt-in for specific low-privilege
groups and is never appropriate for admin-group laptops.

### Two authority layers — kept distinct

The mesh **group** (network reachability — lets the laptop *reach* devices/the console) is
separate from the console **RBAC role** (what the human may *do* in the console, derived
from their live SSO session). Both are SSO-derivable but governed independently. A laptop in
mesh group `admin` can *reach* the mesh-only console; its console powers still come from its
session + RBAC at use time.

### Lifecycle — the method-specific twist

Machine certs (token/attestation) renew freely. A **user cert ties to a revocable human**,
so user-method certs should be **shorter-lived and re-require SSO at renewal** (re-prove the
human is still valid), unlike machine renewal which just re-keys. Offboarding a user in the
IdP must cost them the mesh — via renewal denial and, for an active laptop, revocation (M7).

### Provenance — reuse the evidence shape

The M5.3 evidence columns are provider-agnostic, so SSO reuses them:
`attest_provider=oidc|saml`, `account=issuer`, `principal=email/sub`, plus the IdP groups.
The "Joined via" cell becomes "SSO · alice@corp (Okta)"; the approval queue shows it as the
decision context. Zero new columns.

## The decision driver (the fork)

The central trade is **a new public, IdP-connected, stateful surface** vs. the feature it
enables. We accept the surface because it is contained the same way the gateway is: it holds
**no signing authority** (Core issues), it defaults to **pending approval** (so even a
compromised portal or IdP account cannot auto-join), and its assertion is **bound to a
specific device key**. The richer surface is the price of human-initiated join; the
containment keeps the price acceptable — but the portal must be threat-modelled as a second
internet-facing entry point (it belongs in the enroll security-posture doc).

The secondary driver is **human revocability**: a user's authorization is not permanent the
way a machine's is, so the SSO method needs a lifecycle (short TTL + re-SSO at renewal +
M7) that the machine methods don't. This is the same M7 thread that ADR 0002 and the enroll
posture already depend on, sharpened by offboarding.

## Phased plan

- **Phase 1 — the core flow. ✅ DONE (code-complete, off by default).** The enrollment portal
  (IdP redirect/callback reusing `adminauth`, SAML ACS, assertion signing — no CA) lives on
  the off-mesh gateway (`internal/gateway/ssoportal.go`, `cmd/gateway/sso.go`); the `sso`
  method (`internal/enrollment` `processSSO`), the nonce/pubkey binding (`internal/ssoassert`),
  Core verification (pinned assertion key + binding + user-trust), **default pending**, and
  the SSO identity surfaced in the existing approval queue are all built.
- **Phase 2 — user-trust config + provenance UI. ✅ DONE.** Dual-control `IdP group/domain →
  mesh groups + admission` (`internal/usertrust`, `harbor usertrust publish` mirroring
  cloud-trust, admin-API `/usertrust/*` + the console editor), and the SSO provenance
  ("Joined via: SSO") reusing the provider-agnostic evidence columns.
- **Phase 3 — lifecycle.** *(PLANNED — not built.)* Shorter user-cert TTL + re-SSO at
  renewal; tie IdP offboarding to renewal denial; pair with M7 for active-laptop revocation.
  (The first ephemeral-TTL slice exists for the join-key method, but the SSO re-SSO-at-renewal
  / offboarding path is not yet implemented.)
- **Phase 4 — opt-ins.** *(PLANNED — not built.)* Device-code flow for headless admin hosts;
  optional per-group auto-issue for low-privilege groups (never admin).

## Consequences

- **+** Humans join with no shared secret to distribute — SSO + approval, reusing the IdP
  we already integrate and the queue we already have.
- **+** Symmetric with the existing methods (a signed identity proof bound to nonce+pubkey),
  so Core's verify/derive/queue path generalises cleanly.
- **+** Reuses adminauth, the enroll/queue/approval pipeline, the cloud-trust config
  pattern, and the provenance evidence — small net-new surface area in the core.
- **−** A new **public, IdP-connected, stateful** tier — a second internet-facing entry
  point to threat-model; contained by no-signing-authority + default-pending + key-binding.
- **−** SSO-join needs a **method-specific lifecycle** (short TTL, re-SSO at renewal) and
  leans on **M7 revocation** for lost/compromised admin laptops — the highest-value certs in
  the fleet.
- **−** The portal holds an IdP client secret + an assertion-signing key (new secrets to
  custody), though no CA.

## Open questions to resolve before building

*(Resolved-status annotations added 2026-06-18; decisions captured in `docs/SSO-DECISIONS.md`.)*

1. **Portal assertion-signing key custody** — a dedicated key Core pins, or reuse an
   existing root? Reuse is zero-new-trust-root; a dedicated key narrows blast radius (cf.
   the same fork in ADR 0003). **RESOLVED (S6): a dedicated ECDSA P-256 keypair, distinct
   from the CA; genesis mints it, the gateway holds the private half, Core pins the public
   half (`-sso-assert-pub`). See `internal/ssoassert`.**
2. **Portal deployment** — a standalone public service, or a narrowly-scoped public mode of
   an existing tier? It must be public (pre-mesh) yet must not drag the mesh-only console
   onto the public internet. **RESOLVED (ADR 0009): HTTP routes (`/v1/sso/start`,
   `/v1/sso/acs`) on the existing off-mesh gateway, enabled iff `-sso-acs-url` is set — no
   new tier. Splitting into its own Fargate service later is a pure deploy change.**
3. **Re-SSO-at-renewal mechanics** — how a user-method renewal re-triggers a browser SSO
   without a poor UX; what grace window applies; how this interacts with the
   Core-issued-renew command path. *(OPEN — Phase 3, not built.)*
4. **Mesh-group vs console-RBAC mapping** — one IdP-group→both mapping, or two independent
   maps? Keep them separate (reachability vs authority) but decide the config ergonomics.
   **RESOLVED: two independent maps — the portal maps groups → mesh groups via the published
   `user-trust` config; the console maps groups → admin RBAC roles separately.**
5. **Auto-issue policy** — which (if any) IdP groups ever warrant skipping human approval;
   admin groups never. *(OPEN — Phase 4; SSO defaults to pending today, no auto-issue path.)*
6. **Anti-relay UX** — exactly what the consent screen shows (device name, fingerprint,
   requested groups) and how a user is taught to reject an unexpected device. **RESOLVED in
   mechanism: the assertion is bound to pubkey-hash + nonce and Core enforces the binding
   (`ErrSSOBinding`); the consent-screen wording/teaching is still an operator-UX refinement.**

## Operator setup (live rollout)

SSO enrollment needs a **second SAML app registration in the IdP (AD/Entra/ADFS), distinct
from the admin-console app** — same tenant, same users, same directory groups, but its own
registration. Two reasons:

1. **Different ACS / Reply URL.** The IdP only POSTs the SAML response to a *registered* ACS.
   The console's ACS is the **mesh-only** admin-api URL (reached via tunnel); the enrollment
   portal's ACS is the **public** gateway: `https://<gateway-public-host>/v1/sso/acs`. One app
   cannot serve both.
2. **Trust-zone separation is load-bearing (ADR 0009).** The two surfaces are deliberately
   **different audiences** (SP entity IDs). The SAML library enforces `audience == this SP`, so
   a console-login assertion can never be replayed at the public portal (or vice-versa).
   Sharing one app would collapse that boundary — a real security regression.

**Deployment topology — combined with the gateway, not a separate tier (ADR 0009).** The
portal is HTTP routes (`/v1/sso/start`, `/v1/sso/acs`) on the **existing off-mesh gateway**
(`cmd/gateway`, Fargate), enabled iff `-sso-acs-url` is set — **no new container, task, or load
balancer**. It shares the gateway's public HTTPS surface, so the gateway must run with
**autotls + a public DNS name**: the browser/IdP POST the SAML response to
`https://<gateway-domain>/v1/sso/acs`, which needs a publicly-valid cert (the gateway's existing
Let's-Encrypt / ACME-DNS-01 cert). The gateway task simply gains the `-sso-*` env + the two SSO
secrets (SAML SP cert/key + the assertion-signing private key) — still **no CA** on the edge.
Splitting the portal into its own Fargate service later is a pure deploy-topology change (the
portal is optional gateway config, not a rewrite), and the no-issuance invariant holds either way.

**The new (enrollment-portal) app:**
- **Identifier (Entity ID)** = the gateway portal's `-sso-entity-id` (distinct from the console's
  `-saml-entity-id`).
- **Reply URL (ACS)** = `https://<gateway-public-host>/v1/sso/acs`.
- Emit the **group claim** (the same AD groups already surfaced to the console). The *claim* is
  identical; only the **mapping** differs — the console maps groups → admin RBAC roles; the
  portal maps groups → mesh groups via the published `user-trust` config (first-match-wins).
- The assertion **issuer/realm** (the gateway's `-sso-issuer`, fed to `usertrust.Match`) is the
  IdP's issuer — the same IdP backs both apps.

**Other live-rollout prerequisites (deploy-threaded 2026-06-18 — wired but off by default):**
- **Distribute the genesis-minted assertion keypair**: the **private** half → the gateway's
  config/secret (`-sso-assert-key` / `$NCP_GW_SSO_ASSERT_KEY_PEM`); the **public** half is pinned
  on Core (`-sso-assert-pub`). Genesis emits `sso-assert.key` / `sso-assert.pub` and records only
  the public half in the key registry.
- **Feed the gateway the portal SP**: `-sso-acs-url` (enables SSO), `-sso-idp-metadata-*` (the new
  app's IdP metadata), `-sso-sp-cert`/`-sso-sp-key`, `-sso-entity-id`, `-sso-issuer`.
- **Enable Core**: `-sso-assert-pub` (pin) + `-usertrust-db`, and **publish a user-trust config**
  (`harbor usertrust publish`, or the dual-control UI) mapping the AD groups → mesh groups + CIDR.
- **DONE — `deploy/prod/bootstrap-genesis.sh` now threads all of the above (commit `d3ea2ff`),
  off by default.** When `SSO_ACS_URL` is empty NONE of the SSO threading fires (genesis/recover/
  gateway/Core are byte-for-behavior unchanged); when set, bootstrap distributes the genesis
  assertion keypair, mints + snapshots a STABLE RSA SAML SP keypair (the IdP app pins the SP
  cert), and wires the gateway secret (`deploy/prod/terraform/app/harbor_config.tf` carries the
  `sso_*` fields, empty by default). The remaining operator steps — register the second SAML app,
  publish a user-trust config, set `SSO_ACS_URL` — are the only thing gating live SSO.

## Relationship to other work

- **`adminauth` (2.11)** — the IdP integration (`Authenticator`/`Subject`) reused directly;
  same OIDC/SAML/GitHub providers, group claims, MFA-freshness.
- **Enroll gateway + queue + approval** — the same vet→queue→Core→approve pipeline; SSO adds
  a method and a sibling public front.
- **cloud-trust + its editor** — the dual-control `→ groups + admission` config pattern and
  UI are the template for user-trust.
- **Enroll security posture** — the portal is a second public entry point and should be
  folded into that document (deferred for now per scope).
- **M7 revocation** — the dependency for revoking a lost/compromised admin laptop; shared
  with ADR 0002 and the enroll posture.
- **ADR 0002 (group reassignment) + ADR 0003 (self-update)** — the desired-vs-issued +
  generation + rollout patterns and the renewal machinery this lifecycle builds on.
