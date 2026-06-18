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

- **B2 — Assertion field set + signing scheme (`internal/ssoassert`).** The gateway-signed
  enrollment assertion (S5) carries exactly the facts Core needs to re-verify and act:
  **who** — `Subject` (`sub`, IdP NameID), `Email` (`email`), `Issuer` (`iss`, the realm),
  `IdPGroups` (`groups`, the directory groups the IdP asserted, fed to `usertrust.Match`);
  **which device** — `PubkeyHash` (`pkh`) + `Nonce` (`nonce`, the enrollment nonce it
  answers, anti-replay); **when** — `IssuedAt`/`ExpiresAt` (`iat`/`exp`, unix seconds, a
  short window). It is signed as a **compact ES256 JWS** (`protected.payload.signature`)
  with a typed protected header (`typ=ncp-sso-assertion-v1`, `ver=1`) so a token minted
  for another purpose can't be replayed here. **Reused `internal/jws`** (`SignES256` /
  `Verify`) rather than hand-rolling ECDSA, so there is one signature scheme across the
  control plane; `ssoassert` only adds the compact (de)serialization and the
  validity-window check. The key is a **dedicated ECDSA P-256 keypair (S6)**, distinct
  from the CA — gateway holds the private half, Core pins the public half. Keys move as
  **PKCS#8 `PRIVATE KEY` / PKIX `PUBLIC KEY` PEM** (matching `collect.GenerateSelfSigned`),
  with `GenerateKey`/`Marshal*PEM`/`Parse*PEM` helpers for genesis to mint + distribute.
  `Verify` rejects a forged or wrong-key signature (`ErrSignature`), a malformed token or
  wrong `typ` (`ErrMalformed`), and a token outside its window (`ErrExpired`); Core must
  still independently re-run nonce single-use + `usertrust.Match` — the assertion only
  proves the gateway vouched for these facts, never authorizes issuance.

- **B3 — `usertrust.Match` semantics: first-match entry, DefaultGroups always merged.**
  Resolution (S4) walks `IDPEntries` **in declared order** and returns the **FIRST** entry
  whose `DirectoryGroup` is in the user's asserted groups — that single entry supplies the
  mesh groups, the `Netblock`, AND the `AutoIssue` posture (no union across entries, no
  mixing one entry's netblock with another's groups). A user in several matched groups gets
  the highest-priority entry only; the UI's reorder controls the priority. `DefaultGroups`
  (the cloudtrust-style fleet baseline) is **always merged** into the matched entry's
  `MeshGroups` (deduped + sorted); the netblock and auto-issue come solely from the matched
  entry. No matching entry → DENY (`ok=false`, nil groups) — an identity in no trusted group
  may not enroll (fail closed). Server-side `Validate` enforces S3 **(realm, directory_group)
  uniqueness** (the same AD group in a *different* realm is allowed) and rejects an entry that
  would grant nothing (no `mesh_groups` and no config `default_groups`), since the UI guard
  is bypassable. Published via the `usertrust.publish` dual-control kind, re-parsed at commit.

- **B4 — Realm-wildcard rule.** An entry's `Realm` is matched **exactly** against the
  assertion issuer/realm, with one exception: an **empty `Realm` is a wildcard** that matches
  any realm. Combined with first-match-wins (B3) this lets a config place realm-specific
  entries ahead of a catch-all wildcard entry (e.g. `realm=corp → corp-eng`, then
  `realm="" → any-eng`): a `corp` user takes the specific entry, a `partner` user falls
  through to the wildcard. `Validate` still requires a non-empty `DirectoryGroup` on every
  entry (the wildcard is on realm only, never on the group), so a wildcard entry never grants
  blanket access — it still keys on AD-group membership.
