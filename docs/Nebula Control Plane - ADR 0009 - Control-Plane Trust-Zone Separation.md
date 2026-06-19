---
title: "ADR 0009 — Control-Plane Trust-Zone Separation"
created: 2026-06-15
status: accepted
tags: [nebula, adr, security, sso, enrollment, trust-zones, dmz, architecture]
---

# ADR 0009 — Control-Plane Trust-Zone Separation

**Status (2026-06-18):** Accepted & implemented — Phases 0–2 are CODE-COMPLETE + DEPLOY-THREADED but OFF BY DEFAULT (the SSO enrollment plane stays fail-closed-disabled until an operator publishes a user-trust config and sets `sso_acs_url`). The Phase 0 issuance-bind guard is SHIPPED & LIVE on the poc (it guards both `core-api` and `admin-api`). Phase 3 (opt-in console edge/core split) and Phase 4 (SSO lifecycle) remain deferred/PLANNED.
**Date:** 2026-06-15 (accepted & built 2026-06-18)
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
   in `internal/adminauth`, and SSO-driven **user enrollment** is on the roadmap *(now
   built per this ADR — code-complete, off by default; see Status above)*. SSO
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

### Current trust-boundary map (updated 2026-06-18)

| Component | Exposure | Holds CA/KMS | Terminates SSO | Can issue | Into Core? |
|---|---|---|---|---|---|
| `core-api` + CA signer | mesh-only (issuance-bind guard now enforced) | **yes** | no | yes (renew) | inbound-only from mesh |
| `admin-api` (issuance mode) | mesh-only — now **structurally enforced** (Phase 0 guard) | no (uses Consumer's signer) | **yes** | **yes** (approve) | n/a (same box) |
| `enrollment.Consumer` | mesh-only | **yes** (signer) | no | **yes** (incl. `processSSO`) | n/a |
| Enrollment **gateway** (ADR 0005) | internet-facing | no | **yes (SSO portal built; disabled until configured)** | no | **nothing** (Harbor pulls) |
| ADR 0004 SSO portal | internet-facing — **on the gateway** (this ADR's resolution; built, off by default) | no (dedicated assertion key, not the CA) | **yes** | no — Core's `processSSO` decides | none (Harbor pulls via `collect`) |

The sharp boundary already exists for **machine** enrollment (gateway = keyless,
off-mesh, pull-only). It was **blurred** exactly where SSO terminates: the admin-api
process, and the SSO user-enrollment portal. **(Resolved 2026-06-18:** the Phase 0 guard
now structurally enforces "issuance-mode binds loopback/overlay only," and the SSO
enrollment portal was built on the off-mesh gateway per this ADR — keyless, signing only
a dedicated assertion — rather than as a new public tier. Both ship disabled-by-default.)

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
   public tier. The gateway gains an SSO enrollment path (built as `wire.MethodOIDC`,
   not a separate `MethodSSO` constant) and a **no-CA assertion
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
- **SSO enrollment on the gateway.** *(Built 2026-06-18 — `internal/gateway/ssoportal.go`;
  disabled until `SSOConfig.SAML` + `SigningKey` are present, i.e. until `sso_acs_url` is set.)*
  The gateway keeps its public face (`/v1/nonce`,
  `/v1/enroll`, `/v1/enroll/{id}`) and gains an SSO method (the `wire.MethodOIDC` path; no
  separate `MethodSSO` constant was added): it runs the `adminauth`
  authenticator, validates the IdP assertion, and emits a candidate signed
  with a **dedicated assertion key** (`internal/ssoassert`, ECDSA P-256, minted at genesis;
  pinned by Core as `enrollment.Config.AssertionVerifyKey`, rotatable
  without touching the CA ceremony). It still holds **no CA**.
- **Core grows `processSSO`.** *(Built — `internal/enrollment/enrollment.go` `processSSO`,
  dispatched from the `wire.MethodOIDC` branch.)* Mirrors `processAttested`/`processToken`:
  re-verify the
  assertion + nonce + pubkey binding, map IdP identity → mesh group via a **user-trust
  config** (`internal/usertrust`, a dual-control published store, `usertrust.Match`
  first-match-wins, mirroring `cloudtrust`), and default to
  **pending** (per-group auto-issue an explicit opt-in). IdP provenance (email, groups,
  issuer) lands in the enrollment evidence columns + the console approval queue. Fails
  closed when no pinned key or no published user-trust config (`ErrSSONotConfigured`).
- **Transport: unchanged.** `internal/collect` leaf-pinned mTLS pull, verbatim. The
  edge initiates nothing; Harbor pulls.
- **Console split: deferred (Phase 3, not built).** The design is two `adminapi.New()`
  instantiations selectable by flag/subcommand — **edge** (`CanIssue=false`, no `Consumer`,
  serving only `/admin/v1/auth/*` + session minting) and **core** (the `Consumer` +
  approvals + fleet, mesh-only). *(Status 2026-06-18: NOT built — the Phase 0 issuance-bind
  guard already closes the latent gap, so the split was deferred per SSO-DECISIONS S11.
  `adminapi.Config.CanIssue` exists today and gates the approve endpoint, but the edge/core
  process split itself is unimplemented.)*
- **Session model: unchanged.** Keep `httpOnly` session cookies + CSRF + step-up MFA
  freshness (`mfa-freshness`, default 15m) on privileged actions, enforced **on the
  core side** after any split. No bearer tokens.

## Phased plan

- **Phase 0 — ratify + the startup guard (days; cheapest, highest-value). ✅ SHIPPED & LIVE.**
  Landed the
  invariant in this ADR and the issuance-bind guard (`cmd/harbor/serve.go`
  `checkIssuanceBind`: refuse `-ca-cert` + non-loopback/non-overlay bind
  without `-allow-public-issuance`) — applied to **both** `core-api` and `admin-api`.
  Console documented mesh-only in production.
  This makes "internet-facing SSO terminator holds no issuance authority" *structurally
  enforced* for the existing binaries.
- **Phase 1 — SSO enrollment on the off-mesh edge. ✅ CODE-COMPLETE, NOT ROLLED OUT.**
  Built as the `wire.MethodOIDC` path (no separate `MethodSSO` constant) + a
  no-CA assertion signer at the gateway (`internal/gateway/ssoportal.go`, reusing `adminauth` SAML);
  `enrollment.Consumer.processSSO` in mesh-only Core (verify assertion + nonce/pubkey binding,
  default pending, surface IdP evidence). Reuses `internal/collect` pull verbatim. Dedicated
  assertion-signing key minted at genesis (`internal/ssoassert`). Off by default
  (fail-closed-disabled until `sso_acs_url` is set + a user-trust config is published).
- **Phase 2 — user-trust config. ✅ CODE-COMPLETE, NOT ROLLED OUT.** IdP group/domain → mesh
  group mapping +
  per-group admission posture (pending-by-default; auto-issue opt-in), dual-control
  published (`internal/usertrust` + `/admin/v1/usertrust/*` propose/approve/active, mirroring
  `cloudtrust`). SSO provenance in the approval queue + UI.
- **Phase 3 — optional console split (deploy-mode, ~6–9 days). ⏸ DEFERRED / NOT BUILT.**
  Would extract `EdgeRoutes`
  (auth/session only) from `CoreRoutes` (Signer + approval, mesh-only) as two
  instantiations selectable by flag. Deferred per SSO-DECISIONS S11 — the Phase 0 guard
  already closes the latent gap; revisit only if the console is ever exposed.
- **Phase 4 — SSO lifecycle (~2 weeks). ⏸ DEFERRED / NOT BUILT.** Re-SSO at renewal tied to
  nonce + cert-id;
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

## Open questions (status as of 2026-06-18)

1. **Permanent console posture** — is mesh-only (reach-through-tunnel) the *permanent*
   production stance, or must the console ever be internet-facing? This decides whether
   Phase 3's edge/core split is ever deployed or stays latent-defense-only. Ratify or
   revise the Security Posture doc's "admin happens over the mesh." *(Still open. Console
   remains mesh-only on the poc; Phase 3 not built.)*
2. **Assertion-signing key** — ~~dedicated key (recommended) vs. reuse the genesis CA~~
   **RESOLVED (2026-06-18): dedicated key** (SSO-DECISIONS S6) — a P-256 key in
   `internal/ssoassert`, minted at genesis (only the public half recorded in the DB key
   registry), distinct from the CA. Rotatable independent of the CA ceremony.
3. **Consent anti-relay fingerprint** — where does the device/groups consent screen
   render when the gateway (no mesh-group knowledge) terminates SSO? Device-name at the
   edge + group/admission at Core approval, or push minimal group hints to the edge?
   *(Largely open; current build lands PENDING and surfaces IdP evidence + resolved
   groups in the Core approval queue.)*
4. **Guard enforcement mechanism** — ~~refuse `-ca-cert` on a public bind vs. require an
   explicit `-allow-public-issuance`; what counts as "public"~~ **RESOLVED (2026-06-18):
   built** as `checkIssuanceBind` (`cmd/harbor/serve.go`) — issuance mode (`-ca-cert`) is
   allowed only on loopback (127.0.0.0/8, ::1) or within the overlay pool; the unspecified
   address and any other non-loopback/non-overlay bind are refused unless
   `-allow-public-issuance` is passed.
5. **Session model under a future split** — confirm `httpOnly`+CSRF is retained and the
   bearer-token/broker model is *explicitly* rejected, so it isn't reintroduced. *(Settled
   in this ADR's Decision/rejected-options; the split itself is deferred so this is moot
   until Phase 3 is revisited.)*
6. **SSO renewal & offboarding** — does user-cert renewal require re-SSO (re-asserting
   IdP identity), and how is subject (email) re-bound at renewal to prevent lateral-move
   certs? *(Still open — this is Phase 4, deferred/not built; the Core renewal path still
   needs the hook designed.)*

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
