---
title: "ADR 0009 — Control-Plane Trust-Zone Separation"
created: 2026-06-15
status: proposed
tags: [nebula, adr, security, sso, enrollment, trust-zones, dmz, architecture]
---

# ADR 0009 — Control-Plane Trust-Zone Separation

**Status:** Proposed (the invariant + asymmetric model is the direction; Phase 0 guard is the only immediate build)
**Date:** 2026-06-15
**Decision owners:** Chris Hyde (+ a future second approver, per dual-control)

## Context

Harbor has, historically, kept the crown jewels off the internet by convention: the
**Core API** (`core-api`, `cmd/harbor/serve.go` `cmdCoreAPI`) binds to Core's overlay
IP and is the only holder of the **CA signer** — it is reached *through* the nebula
tunnel, never from the internet. ADR 0005 then took the one deliberately
internet-facing surface — the enrollment **gateway** — *off* the mesh entirely and
made it **credential-less and pull-only**: it holds no CA, initiates nothing, and
Harbor pulls candidates from it over leaf-pinned mTLS (`internal/collect`), re-verifying
every candidate. The trust direction is right: the protected side decides whom it talks
to; the exposed side is a sink it drains.

Two things now stress that picture:

1. **SSO is real (ADR 0004).** Operator console login terminates **OIDC/SAML/GitHub**
   in `internal/adminauth`, and SSO-driven **user enrollment** is on the roadmap. SSO
   flows are *inherently* internet-facing — a browser does an IdP redirect; a user
   self-enrolls from a laptop *before* it has a mesh cert.
2. **The admin-api blurs the boundary.** Today `admin-api` (`cmdAdminAPI`) **terminates
   SSO** (the unauthenticated `/admin/v1/auth/*` login/callback + SAML ACS routes,
   `internal/adminauth/auth.go`, `saml.go`) **and**, when started with `-ca-cert`
   (issuance mode, `serve.go:147-151`), **holds issuance authority** — its
   `/admin/v1/approvals/{id}/approve` calls `enrollment.Consumer.Approve` →
   `signer.Issue`. Both live in **one process, one trust zone**. "Mesh-only" is a
   deployment *comment* and a runtime `-addr` choice (`:8445` defaults to all
   interfaces) — **not** an enforced boundary. A single mis-bind or SG gap, plus one
   compromise, would hand an attacker *both* the IdP callback surface *and* cert
   issuance.

ADR 0005 itself flagged this: *"the SSO portal is another public front; whether it
follows the same pull/off-mesh posture is worth aligning (likely yes)."* This ADR is
that alignment.

### Current trust-boundary map (as built)

| Component | Exposure | Holds CA/KMS | Terminates SSO | Can issue | Into Core? |
|---|---|---|---|---|---|
| `core-api` + CA signer | mesh-only | **yes** | no | yes (renew) | inbound-only from mesh |
| `admin-api` (issuance mode) | mesh-only *by convention* | no (uses Consumer's signer) | **yes** | **yes** (approve) | n/a (same box) |
| `enrollment.Consumer` | mesh-only | **yes** (signer) | no | **yes** | n/a |
| Enrollment **gateway** (ADR 0005) | internet-facing | no | no (today) | no | **nothing** (Harbor pulls) |
| ADR 0004 SSO portal (planned) | internet-facing | no (design) | **yes** | no (design) | TBD — *this ADR* |

The sharp boundary already exists for **machine** enrollment (gateway = keyless,
off-mesh, pull-only). It is **blurred** exactly where SSO terminates: the admin-api
process, and the not-yet-built SSO user-enrollment portal.

## Decision

**Ratify one invariant and apply it asymmetrically to the two SSO planes, because they
have different exposure today.**

> **Invariant.** Any process that terminates an internet-facing SSO/IdP flow holds
> **no CA/KMS and no issuance authority**. It validates the IdP assertion, records a
> **signed, key-bound intent**, and the **mesh-only** plane **pulls** the intent and
> issues. Authority stays in Core, which re-verifies everything it pulls.

This is the ADR 0005 model — *protected side pulls from an untrusted sink; Core
re-verifies* — generalised from machine enrollment to **all** internet-facing SSO.
Applied to the two planes:

1. **User-enrollment plane (genuinely internet-facing — the live risk).** Build ADR
   0004's SSO enrollment **on the existing ADR 0005 off-mesh gateway**, not as a new
   public tier. The gateway gains a `wire.MethodSSO` path and a **no-CA assertion
   signer** (reusing the `adminauth` OIDC/SAML/GitHub authenticators); Core grows
   `enrollment.Consumer.processSSO` (mirroring `processAttested`/`processToken`) that
   re-verifies the assertion + the single-use, key-bound nonce, maps IdP group → mesh
   group via a user-trust config, and defaults to **pending**. This reuses
   `internal/collect`'s leaf-pinned mTLS pull **verbatim** — zero new transport, zero
   new public tier — with a **dedicated assertion-signing key** (not the genesis CA) to
   narrow blast radius.

2. **Admin-console plane (mesh-only today — latent risk).** Keep the console
   **mesh-only as the production default** (operators reach it through the tunnel), and
   close the latent gap *cheaply and structurally* with a **startup guard**: when
   `admin-api` runs in issuance mode (`-ca-cert`), it must **fail fast** unless bound to
   loopback/overlay — or an explicit `-allow-public-issuance` override is set. The full
   edge/core *process* split is made **available as an opt-in deploy mode** for any
   future deployment that chooses to expose the console, but is **not forced** on every
   deployment.

**Rejected:** a centralized internet-facing **identity-broker/DMZ** that fronts all
human auth with browser-held bearer tokens — it trades the console's `httpOnly` +
CSRF session model for **XSS-exfiltratable** tokens and rewrites the entire auth
surface to solve an exposure the mesh-only posture does not have.

## The decision driver (the fork): what is *actually* exposed

The instinct is "separate the admin plane from the mesh plane." But the precise fork is
**which SSO surface is internet-facing today**:

- **User enrollment is internet-facing by nature** — a host with no mesh cert must reach
  it from the public internet. This is the real, live risk, and it is exactly the shape
  ADR 0005 already solved (keyless, off-mesh, pull). So: **put SSO enrollment on that
  edge**, don't invent a new one.
- **The operator console is mesh-only today** — and the cheapest correct fix is to make
  that *enforced* (a startup guard) rather than conventional, and to keep a real split
  *available* for the day someone wants the console on the internet. Forcing a
  multi-process split on every deployment now would be cost without a matching exposure.

So the boundary is drawn by *exposure*, not by *role*: the pull edge becomes the single
trust seam for all internet-facing SSO; issuance authority stays exclusively in
mesh-only Core.

## Why pull (and why the edge can stay untrusted)

Same argument as ADR 0005, extended to SSO: an SSO enrollment candidate is a JWS-signed,
nonce-bound request carrying an **IdP assertion**. Core re-verifies the assertion
signature, the single-use replay-protected nonce, and the key binding, then defaults to
**pending** for a human approve. A compromised edge cannot manufacture a valid IdP
assertion (it lacks the IdP's signing relationship) nor a live victim nonce — it can
only serve garbage Core rejects, or withhold/replay (absorbed by the nonce + Core's
idempotency). The assertion-signing key the edge holds is **non-load-bearing for
issuance**: it attests "an IdP said this," not "issue a cert." So the edge needs no
privileged connectivity — which the off-mesh pull model already denies it.

## Considered options

| Option | Verdict | One-line |
|---|---|---|
| **Status quo — SSO + issuance in one admin-api process** | Rejected | The invariant is unmet; "mesh-only" is a comment, not a boundary — one mis-bind couples IdP callback + cert issuance. |
| **Portal-edge reuse — SSO enrollment on the ADR 0005 off-mesh pull gateway** | **Chosen (core)** | Reuses the keyless, initiates-nothing edge + the `collect` mTLS pull verbatim; Core re-verifies + defaults pending. Zero new public tier. |
| **Split-process admin — edge (auth/session, no CA) + mesh-only core (Consumer)** | **Chosen (opt-in)** | Cleanly separates console SSO from issuance; grafted as a deploy-mode for an exposed console, behind a flag — not forced. |
| **Identity-broker / DMZ with browser bearer tokens** | Rejected | Meets the invariant but replaces `httpOnly`+CSRF sessions with XSS-exfiltratable tokens and rewrites the whole auth surface to fix an exposure the mesh-only posture lacks. |

## The model in detail

- **Invariant, enforced not just documented.** A startup guard in `admin-api`: issuance
  mode (`-ca-cert`) + a non-loopback/non-overlay bind ⇒ refuse to start unless
  `-allow-public-issuance` is explicitly passed. Near-zero code; makes the boundary
  structural for the binary that exists today.
- **SSO enrollment on the gateway.** The gateway keeps its public face (`/v1/nonce`,
  `/v1/enroll`, `/v1/enroll/{id}`) and gains an SSO method: it runs the `adminauth`
  authenticator, validates the IdP assertion, and emits a `MethodSSO` candidate signed
  with a **dedicated assertion key** (pinned by Core at `Consumer` build time, rotatable
  without touching the CA ceremony). It still holds **no CA**.
- **Core grows `processSSO`.** Mirrors `processAttested`/`processToken`: re-verify the
  assertion + nonce + pubkey binding, map IdP identity → mesh group via a **user-trust
  config** (a dual-control published store, mirroring `cloudtrust`), and default to
  **pending** (per-group auto-issue an explicit opt-in). IdP provenance (email, groups,
  issuer) lands in the enrollment evidence columns + the console approval queue.
- **Transport: unchanged.** `internal/collect` leaf-pinned mTLS pull, verbatim. The
  edge initiates nothing; Harbor pulls.
- **Console split: available, not mandatory.** Two `adminapi.New()` instantiations
  selectable by flag/subcommand — **edge** (`CanIssue=false`, no `Consumer`, serving
  only `/admin/v1/auth/*` + session minting) and **core** (the `Consumer` + approvals +
  fleet, mesh-only). Ships disabled by default.
- **Session model: unchanged.** Keep `httpOnly` session cookies + CSRF + step-up MFA
  freshness (`mfa-freshness`, default 15m) on privileged actions, enforced **on the
  core side** after any split. No bearer tokens.

## Phased plan

- **Phase 0 — ratify + the startup guard (days; cheapest, highest-value).** Land the
  invariant in this ADR and the `admin-api` guard (refuse `-ca-cert` + public bind
  without `-allow-public-issuance`). Document the console as mesh-only in production.
  This makes "internet-facing SSO terminator holds no issuance authority" *structurally
  enforced* for the existing binary, with near-zero code.
- **Phase 1 — SSO enrollment on the off-mesh edge (~2–3 weeks).** `wire.MethodSSO` + a
  no-CA assertion signer at the gateway (reusing `adminauth`); `enrollment.Consumer.processSSO`
  in mesh-only Core (verify assertion + nonce/pubkey binding, default pending, surface
  IdP evidence). Reuse `internal/collect` pull verbatim. Dedicated assertion-signing key.
- **Phase 2 — user-trust config (~1–2 weeks).** IdP group/domain → mesh group mapping +
  per-group admission posture (pending-by-default; auto-issue opt-in), dual-control
  published (mirror `cloudtrust` table/CRUD). SSO provenance in the approval queue.
- **Phase 3 — optional console split (deploy-mode, ~6–9 days).** Extract `EdgeRoutes`
  (auth/session only) from `CoreRoutes` (Signer + approval, mesh-only) as two
  instantiations selectable by flag. Disabled by default; deployments keep the console
  mesh-only unless they explicitly opt into a public edge.
- **Phase 4 — SSO lifecycle (~2 weeks).** Re-SSO at renewal tied to nonce + cert-id;
  subject (email) re-binding to block lateral-move certs; IdP offboarding via
  heartbeat/renew denial + revocation. Adopt ADR 0005 Phase 4 long-poll if SSO-enrollment
  latency becomes a UX problem.

## Consequences

- **+** One invariant covers **all** internet-facing SSO; the proven pull edge is the
  single trust seam. Issuance authority lives **only** in mesh-only Core.
- **+** Phase 0 converts a documented convention into an **enforced** boundary for
  near-zero cost — the highest-leverage step.
- **+** No new public tier and no new transport for SSO enrollment — it rides the
  existing keyless, initiates-nothing gateway + `collect` mTLS.
- **+** Console keeps its `httpOnly`+CSRF session model; no XSS-exfiltratable tokens.
- **−** SSO enrollment inherits the gateway's **pull-loop latency** (fixed interval
  until ADR 0005 Phase 4 long-poll) — acceptable for a human-approved flow; explicitly
  **not** low-latency self-service.
- **−** The gateway now co-locates the nonce-HMAC (machine) path and the
  assertion-signing (human) path — **one blast zone**. Acceptable (Core re-verifies +
  defaults pending), but a future portal/gateway separation is deferred, not eliminated.
- **−** The console's human anti-relay consent (device + groups) can only be fully
  rendered at **Core approval time** (the off-mesh edge lacks mesh-group knowledge),
  lengthening the feedback loop versus a Core-side portal.
- **−** New key custody: the dedicated assertion-signing key on an internet-facing host
  (rotatable independent of the CA).

## Open questions to resolve before building

1. **Permanent console posture** — is mesh-only (reach-through-tunnel) the *permanent*
   production stance, or must the console ever be internet-facing? This decides whether
   Phase 3's edge/core split is ever deployed or stays latent-defense-only. Ratify or
   revise the Security Posture doc's "admin happens over the mesh."
2. **Assertion-signing key** — dedicated key (recommended) vs. reuse the genesis CA
   (ADR 0004 open Q#1, still open). Confirm the rotation story on an off-mesh host.
3. **Consent anti-relay fingerprint** — where does the device/groups consent screen
   render when the gateway (no mesh-group knowledge) terminates SSO? Device-name at the
   edge + group/admission at Core approval, or push minimal group hints to the edge?
4. **Guard enforcement mechanism** — refuse `-ca-cert` on a public bind vs. require an
   explicit `-allow-public-issuance`; what counts as "public" (non-loopback?
   non-overlay?). The current code has no such guard.
5. **Session model under a future split** — confirm `httpOnly`+CSRF is retained and the
   bearer-token/broker model is *explicitly* rejected, so it isn't reintroduced.
6. **SSO renewal & offboarding** — does user-cert renewal require re-SSO (re-asserting
   IdP identity), and how is subject (email) re-bound at renewal to prevent lateral-move
   certs? Out of scope for Phase 1, but the Core renewal path needs the hook designed now.

## Relationship to other work

- **ADR 0004 (SSO-driven user enrollment)** — this ADR *places* it: the SSO portal is the
  off-mesh gateway's SSO method, not a new public tier; `processSSO` is the Core seam.
- **ADR 0005 (pull-based gateways)** — the load-bearing precedent. SSO enrollment reuses
  the off-mesh gateway, the registry, and `internal/collect`'s leaf-pinned mTLS pull
  verbatim. This ADR answers ADR 0005's own "align the SSO portal to the pull posture."
- **`internal/adminauth`** — the OIDC/SAML/GitHub authenticators move (or are reused) at
  the edge for assertion validation; the session model + step-up MFA stay Core-side.
- **`enrollment.Consumer` (`processAttested`/`processToken`)** — the template for
  `processSSO`; the Consumer remains the *only* component wrapping the signer.
- **Security Posture doc** — currently asserts "admin happens over the mesh"; Phase 0
  makes that enforced for issuance mode, and open question #1 asks whether to keep it.
- **Non-removable control-plane baseline (policy §6.3)** — same reason as ADR 0005 that
  the edge stays *off* the mesh: an in-mesh edge could never enforce "initiates nothing."
