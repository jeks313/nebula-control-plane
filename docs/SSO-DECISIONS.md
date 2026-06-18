# SSO enrollment build — decisions log (for Chris's review)

Autonomous build of SSO-driven user enrollment (ADR 0004) under the ADR 0009 trust-zone
invariant. Settled decisions (confirmed with Chris) are **S#**; defaults taken during the
build are **B#** (appended as phases land). Review at the end.

## Settled (confirmed)

- **S1 — New first-class construct: `user-trust` (SSO entries).** A peer to join-keys and
  cloud-trusts, dual-control published. The core issuing-identity config for the SSO method.
- **S2 — Keyed by SAML AD-group membership.** Each entry: `directory_group → default mesh
  (nebula) groups + CIDR (netblock) + auto_issue`. Drives the generic `issue(…, netblock,
  method)` hook (IPAM D1) for `method=sso`.
- **S3 — AD-group uniqueness.** A given AD group appears in at most one entry; enforced in
  **both** the UI (can't add a duplicate) and the **server-side validator** at dual-control
  commit (UI is bypassable; the published config must be self-consistent).
- **S4 — Multi-group resolution: ordered entries, FIRST-MATCH WINS** for *both* mesh groups
  and CIDR (a user in several matched AD groups gets the first matching entry's groups+CIDR;
  no union). The UI shows + lets you reorder priority.
- **S5 — Trust-zone (ADR 0009).** SSO rides the **existing off-mesh gateway** (ADR 0005), not
  a new public tier. The gateway holds **no CA** and signs a short-lived **assertion**; mesh-only
  Core **pulls** the candidate (collect loop) and **re-verifies** everything before issuing.
  Internet-facing surface holds no issuance authority — the invariant.
- **S6 — Dedicated assertion-signing key** (ECDSA P-256), distinct from the CA; the gateway
  signs, Core pins the public key. Narrows blast radius vs reusing the CA.
- **S7 — SAML first.** Phase 1 targets the SAML path (reuse `internal/adminauth` SAML +
  `samlmock`); OIDC is a near-free follow-on (one `Authenticator` interface).
- **S8 — Admission defaults to PENDING.** Phase 1 issues nothing automatically; an admin
  approves in the existing queue. The per-entry `auto_issue` flag is honored but defaults off;
  admin/privileged groups never auto-issue.
- **S9 — Browser flow: loopback authorization-code** (laptop) for Phase 1; device-code
  (headless) deferred to lifecycle.
- **S10 — Phase 0 guard.** admin-api in issuance mode (`-ca-cert`) refuses a non-loopback/
  non-overlay bind unless `-allow-public-issuance` — structurally enforces "no internet-facing
  issuance" before any SSO is added.
- **S11 — Scope = Phase 0 + 1 + 2** (working SSO enrollment end-to-end). **Deferred (recorded):**
  Phase 3 (opt-in console edge/core split — the Phase 0 guard already closes the gap) and Phase 4
  lifecycle (re-SSO at renewal, IdP-offboarding→revocation, device-code). Offered as follow-ups.

## Defaults taken during the build

<!-- appended as phases land: B# — <title>. <what + why> -->

- **B1 — Phase 0 guard: what counts as allowed vs refused (loopback ∪ overlay).** The
  issuance-mode startup guard (`checkIssuanceBind`, `cmd/harbor/serve.go`) treats an
  **issuance-mode** server as one started with `-ca-cert` (core-api always — `-ca-cert`
  is required; admin-api when `-ca-cert` is set, i.e. the enroll-approve / signer path,
  `canIssue=true`). For such a server the `-addr` host is **allowed** iff it is a
  **loopback** address (127.0.0.0/8 or `::1`) **OR** lies **within `-pool`** (the overlay
  CIDR). It is **refused** if the host is the **unspecified address** (`0.0.0.0`, `::`, or
  an empty host like `:443` — all bind every interface and are internet-reachable) **OR**
  any other non-loopback, non-overlay address (e.g. a public or out-of-pool private IP).
  An unparseable host is also refused (fail closed). The refusal is fatal (`fatalf`) and
  names the addr, cites ADR 0009, and points at the `-allow-public-issuance` override.
  The guard is applied to **both** core-api and admin-api (both hold the CA and bind the
  overlay). **Live deploy verified to pass:** core-api `10.44.0.2:8444` and admin-api
  `10.44.0.2:443` under `-pool 10.44.0.0/16` are within the overlay → allowed.
  `-allow-public-issuance` (default false) is the explicit escape hatch for a deliberately
  exposed issuance surface. Non-issuance-mode servers (no `-ca-cert`) are never guarded.
