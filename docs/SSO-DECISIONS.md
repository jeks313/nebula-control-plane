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

- **B4 — Realm-wildcard rule.** *(SUPERSEDED by B16 — the empty-realm wildcard was removed;
  realm matching is now strictly exact.)* This originally allowed an **empty `Realm` to act
  as a wildcard** matching any realm, so a config could place realm-specific entries ahead of
  a catch-all. That branch was dead in any published config — `Validate` rejects an empty
  realm (`ErrNoRealm`) — and a wildcard ordered first would have shadowed specific-realm
  entries, so it was dropped. See B16.

- **B5 — SSO credential envelope: `{"assertion":"<compact-jws>"}`.** The wire
  `EnrollRequest.Credential` for `method=oidc` is a typed JSON wrapper carrying the
  gateway-signed assertion (the compact ES256 JWS from `internal/ssoassert`) under an
  `assertion` field, rather than the bare token. The wrapper keeps the SSO credential
  self-describing and symmetric with the other methods' JSON credentials
  (`{"token":...}`, the marshalled `awsattest.PresignedRequest`), and leaves room for
  future SSO-only fields (e.g. an IdP-attestation blob) without overloading a bare
  string. `processSSO` unmarshals the envelope; an empty/missing `assertion` or a
  non-JSON credential is a terminal `ErrSSOAssertion` deny.

- **B6 — SSO verification + device binding (fail-closed, all terminal).** Core, trusting
  the gateway for nothing beyond "the IdP said this", re-verifies in order: **(1)**
  `ssoassert.Verify(pinnedKey, token, now)` against the **pinned** gateway
  assertion-signing public key (S6) + the validity window — a forged/wrong-key signature,
  malformed/wrong-`typ` token, or an out-of-window token is a terminal `ErrSSOAssertion`;
  **(2) binding (anti-relay):** the assertion's `PubkeyHash` MUST equal the enrolling
  host's pubkey hash (`wire.PubkeyHash(pubBytes)`), the assertion's `Nonce` MUST equal the
  request's `Nonce`, AND that nonce MUST pass the **SAME** keyring check the other paths
  use (`c.cfg.Nonces.Verify(nonce, pubkeyHash)`) — reusing the existing single-use nonce
  mechanism rather than a parallel one (the outer JWS `verify()` already consumed the
  request nonce via the replay observer; this re-proves the *assertion's embedded* nonce
  is that same nonce, authentic for this device, so a gateway assertion minted for a
  different device or enrollment cannot be relayed). Any binding failure is a terminal
  `ErrSSOBinding`. **(3) policy:** `usertrust.Match(active, assertion.Issuer,
  assertion.IdPGroups)` (first-match-wins, B3) — no match is a terminal `ErrSSONotAllowed`.
  Evidence is recorded on the provider-agnostic columns (M5): `provider="sso"`,
  `account=`issuer/realm, `principal=`email (else subject), and the IdP groups stored
  comma-joined in the region column (so a pending row shows the membership that drove the
  match, and approve can re-resolve the netblock). All four SSO sentinels
  (`ErrSSONotConfigured`, `ErrSSOAssertion`, `ErrSSOBinding`, `ErrSSONotAllowed`) are in
  `Terminal()`, so a denied SSO enrollment is **acked, never redelivered** — recovery is a
  fresh re-enroll with a new nonce (the consumed nonce would otherwise loop on `ErrReplay`,
  mirroring the aws-sigv4 reasoning).

- **B7 — Admission default PENDING + provenance mapping (wire `oidc` → IPAM `sso`).**
  Admission defaults to **pending** (S8): `processSSO` records the pending result and
  issues nothing, honoring the matched entry's `auto_issue` ONLY when set — Phase 1's
  common path is pending → admin approves in the existing queue. The **wire** enrollment
  method is `oidc` (`wire.MethodOIDC`, recorded on the row's `method` column), but the
  **IPAM provenance** enum is `token|aws-sigv4|sso|genesis` (ADR 0010), so the allocation
  is recorded as `"sso"` — both the auto-issue path and the approve path map it via a
  single `provenanceMethod(oidc)→sso` helper, so a pending SSO enrollment re-issued on
  approve carries the same provenance its auto-issue sibling would have. `Approve`'s
  `approveNetblock` likewise re-resolves the SSO entry's netblock from the active
  user-trust config + the stored evidence (issuer + the comma-joined groups), mirroring
  the aws-sigv4 re-resolution, so a pending SSO host lands in the same block.

- **B8 — Config seam (pinned key + live user-trust getter); harbor wiring deferred.**
  `enrollment.Config` gains **(a)** `AssertionVerifyKey *ecdsa.PublicKey` — the pinned
  gateway assertion-signing public key (S6); and **(b)** `UserTrustActive func()
  *usertrust.Config` — the active user-trust source. Unlike `CloudTrust` (a snapshot
  pointer read once at consumer build), the user-trust source is a **getter** so the
  dual-control-published config is read **live per enrollment** (changing who may enroll
  needs no Core restart). If `AssertionVerifyKey == nil` OR `UserTrustActive == nil` OR
  the getter returns nil (no config published yet), `processSSO` returns a terminal
  `ErrSSONotConfigured` deny — fail closed. Wiring the real published-config reader (a
  `usertrust.publish` `LatestCommitted` reader, peer to `activeCloudTrust`) and the
  genesis key distribution (gateway gets the PKCS#8 private half, Core pins the PKIX
  public half via `ssoassert.Parse*KeyPEM`) into `cmd/harbor` is a **LATER integration
  step**; this change provides only the seam + tests that inject it.

- **B9 — Portal routes on the off-mesh gateway (two new, OPTIONAL).** The SSO enrollment
  portal (S7/S9, SAML loopback authorization-code) is **two** routes added to the
  existing gateway HTTP surface (`internal/gateway`), alongside the unchanged
  nonce/enroll/poll routes: **`GET /v1/sso/start`** (pilot begins an SSO session) and
  **`POST /v1/sso/acs`** (the IdP HTTP-POST SAML callback). They are **always mounted**
  but **gated on config**: when SSO is not fully configured they return **404
  `not_found` "SSO not enabled"** (uniform surface — a probe can't tell "off" from
  "missing route"), and the rest of the gateway is unaffected. **The actual enroll
  submission is UNCHANGED**: pilot still POSTs `EnrollRequest{method:oidc,
  credential:{"assertion":"<jws>"}}` to the existing `/v1/enroll` (B5), which queues it
  for Harbor's pull — `wire.MethodOIDC` was already accepted by `knownMethod`, so no
  change there. Per ADR 0009 the gateway holds **no CA**: the portal only runs the IdP
  flow and signs the short-lived assertion; all issuance authority stays mesh-only in
  Core, which pulls + re-verifies (B6).

- **B10 — Server-side session binding + loopback hand-off (the device cannot be
  substituted).** `/v1/sso/start` takes `pubkey_hash`, the pubkey-bound `nonce` pilot
  minted at `/v1/nonce`, and a `redirect` (pilot's loopback URL). It re-verifies the
  nonce with the **same `nonces.Verify(nonce, pubkey_hash)` keyring check** `/v1/enroll`
  uses (fail fast before a SAML round trip; Core still re-checks single-use, B6), mints
  an **unguessable 256-bit `state` token**, stores a **short-TTL, single-use server-side
  session** `{pubkey_hash, nonce, loopback_redirect, SAML requestID}` keyed by that
  state, and redirects to the IdP AuthnRequest with **`RelayState = state`**. The
  browser/user **never sees** pubkey_hash, nonce, or requestID — RelayState is only an
  opaque lookup key — so a user **cannot substitute a different device's** pubkey/nonce
  into the flow (the binding is fixed server-side at start, not carried in any
  user-controllable field). At `/v1/sso/acs` the session is **recovered and consumed
  (single-use) by RelayState FIRST**; an unknown/forged/replayed RelayState has no
  session and is rejected before any SAML work. **Hand-off:** after validation the
  gateway **302s the browser to the loopback `redirect` with
  `?assertion=<compact-jws>&state=<state>`** (the simpler safe option vs a retrieval
  handle) — the assertion is already integrity-protected (ES256), short-lived, and
  bound to {pubkey_hash, nonce}, so a different device can't use it even if the redirect
  query leaks; `state` is echoed so pilot can match the response to its own session. The
  session store is **in-memory with TTL GC** (loses everything on gateway restart;
  in-flight enrolls just retry — fine, mirrors the nonce/cookie ephemerality elsewhere).

- **B11 — Loopback-redirect validation (open-redirect / assertion-exfil guard).** The
  `redirect` is accepted **only** when it is an `http`/`https` URL with **no userinfo**
  whose host is a **loopback target** — the literal `localhost`, or an IP that
  `net.IP.IsLoopback()` accepts (`127.0.0.0/8`, `::1`). Everything else is refused at
  `/v1/sso/start` with `invalid_request` (and capped at 512 bytes): a public host, a
  private non-loopback IP, a non-http scheme, a `user:pass@` form, a bare path, a
  look-alike host like `127.0.0.1.evil.com` (rejected — its *host* is not loopback), or
  an unparseable URL. This is the key exfil guard: the signed assertion is only ever
  handed to a process **on pilot's own machine**, never to an attacker-chosen host. Host
  parsing uses `url.Hostname()` so a `:port` and IPv6 brackets are handled correctly.

- **B12 — Assertion TTL: short, configurable, default 3 min.** The signed
  `ssoassert.Assertion` carries `iat = now` and `exp = now + AssertionTTL`, with
  `AssertionTTL` configurable on the portal and **defaulting to 3 minutes** (within the
  S5 "2–5 min" band) — long enough for pilot to receive the loopback redirect and POST
  to `/v1/enroll`, short enough that a captured assertion is near-useless. Core
  independently re-checks the window in `ssoassert.Verify(pinnedKey, token, now)` (B6),
  so a too-long TTL on the gateway can never widen Core's acceptance beyond the embedded
  `exp`. The session TTL (how long a started flow may sit awaiting the ACS POST) is a
  **separate** knob, default 5 min.

- **B13 — SAML protections RELIED ON from adminauth (no hand-rolled SAML).** Per the
  ADR-0004 directive, the portal **reuses `internal/adminauth`'s SAML
  `SAMLAuthenticator`** for every SAML operation rather than parsing SAML itself. Two
  thin exported seams were added there: **`AuthnRedirect(relayState)`** (builds + signs
  the SP-initiated AuthnRequest, returns the IdP redirect URL + the AuthnRequest ID the
  portal stores as the only accepted InResponseTo — sets **no cookie**, mints **no
  RelayState**, because the portal owns that state server-side), and
  **`ValidateACS(r, requestID)`** (runs crewjam's `sp.ParseResponse(r, [requestID])` and
  returns the extracted `Subject`). Through crewjam, adminauth handles: **XML-dsig
  signature** verification against the trusted IdP signing cert; **signature-wrapping
  (XSW)** defenses; **audience** restriction (`== SP entity id`); the
  **NotBefore/NotOnOrAfter conditions**; and **InResponseTo / replay** (the assertion
  must answer the portal's stored `requestID`; `AllowIDPInitiated=false` means an
  empty/unsolicited assertion is refused, and `ValidateACS` additionally rejects an empty
  requestID). The **`Destination`/`Recipient`** checks line up because a new optional
  **`ACSPath`/`MetadataPath`** on `adminauth.SAMLOptions` lets the portal declare its own
  `/v1/sso/acs` as the SP's ACS (so the IdP auto-POSTs there and crewjam's URL checks
  match). On top of crewjam's SAML layer the portal adds **RelayState↔server-side-session
  binding** (single-use, unguessable) — defeating cross-flow / device-substitution
  injection that SAML alone does not cover.

- **B14 — Pilot client `pilot enroll --sso` (loopback authorization-code, S9).** The
  client side rides the EXISTING enroll machinery (`internal/enrollclient`) — only how
  the *credential* is obtained changes. **CLI:** `--sso` is a third, mutually-exclusive
  credential source on `pilot enroll` alongside `-join-key` and `-aws-sigv4` (exactly
  one required); it reuses the same `-gateway -config-pub [-dir] [-name] [-groups]`
  flags and adds `-sso-wait` (default 3 min) for the browser round-trip. **Flow
  (`enrollclient.EnrollSSO`):** mint/load the host key (the shared `loadOrGenerate`) →
  fetch a pubkey-bound nonce from the existing `/v1/nonce` → bind an **ephemeral
  loopback listener** on `127.0.0.1:0` with a one-shot `/callback` → call
  `GET /v1/sso/start?pubkey_hash=&nonce=&redirect=http://127.0.0.1:PORT/callback` with
  redirects DISABLED and read the **302 `Location`** (the IdP authorize URL) without
  following into the IdP → **open the user's browser** to it → wait for the browser to
  hit `/callback?assertion=<jws>` → submit the standard `EnrollRequest{method:oidc,
  credential:{"assertion":"<jws>"}}` (B5) via the shared `submitEnroll` → poll via the
  shared `finishEnroll`. The submit/poll path is factored out of `Enroll` into
  `submitEnroll`/`finishEnroll` so both methods share it and the SSO flow is testable
  against a fake gateway with no real browser/IdP. **Loopback callback + timeout:** the
  one-shot `/callback` captures `assertion` (a missing one → 400, shows a "you can close
  this tab" page), delivers it over a buffered channel, and the listener is shut down on
  return; `EnrollSSO` waits on the channel with a timer (`-sso-wait`, default 3 min) and
  ctx (SIGINT/SIGTERM), so it never hangs and never submits on timeout. **Browser-open:**
  a thin, **injectable** `OpenBrowser func(string) error` (default = cross-platform
  `open`/`xdg-open`/`cmd /c start`, missing launcher → non-fatal error); the authorize
  URL is **ALWAYS printed** too, and printed again if the open fails, so a headless or
  GUI-less host can still complete the flow by hand. **Pending-poll UX (S8):** SSO
  admission defaults to PENDING, so a `pending` poll outcome is **not an error** —
  `EnrollSSO` persists the resumable enroll ticket and returns `Status:"pending"`; the
  CLI prints "submitted — awaiting admin approval … re-run `pilot enroll --sso` later to
  fetch the bundle (no second sign-in needed)" and **exits 0**. A re-run with a live
  ticket short-circuits straight to the poll: no second browser round-trip and no second
  nonce (the ticket is removed only on `issued`/`denied`).

- **B15 — End-to-end binary wiring of the SSO config seams (the B8 seam, now fed).**
  The pieces from B1–B14 are joined to real flags/env across the two binaries; the
  control-plane invariant (ADR 0009) is unchanged — the gateway gains no CA, Core still
  re-verifies everything. **Gateway (`cmd/gateway`, new `sso.go`):** an OPTIONAL SSO
  flag group builds `gateway.Config.SSO`. The trigger is **`-sso-acs-url`** (the PUBLIC
  ACS URL, e.g. `https://<gateway>/v1/sso/acs`); when it is unset `Config.SSO` stays
  **nil** (portal disabled, gateway unaffected). When it IS set the rest become
  required and the builder **fails closed** with a clear error on any missing piece:
  the SAML SP keypair (`-sso-sp-cert`/`-sso-sp-key` or `$NCP_GW_SSO_SP_CERT_PEM` /
  `$NCP_GW_SSO_SP_KEY_PEM`), the IdP metadata (`-sso-idp-metadata-url` /
  `-sso-idp-metadata-file` / `$NCP_GW_SSO_IDP_METADATA`), and the gateway's
  **assertion-signing private key** (`-sso-assert-key` or `$NCP_GW_SSO_ASSERT_KEY_PEM`,
  loaded via `ssoassert.ParsePrivateKeyPEM`). `-sso-issuer` sets the assertion realm
  (`iss`); `-sso-assertion-ttl` / `-sso-session-ttl` tune the windows (B12 defaults). The
  SP is built by **reusing `adminauth.NewSAML`** (decision B13 — no hand-rolled SAML),
  deriving the SP BaseURL + `ACSPath` from `-sso-acs-url` so the IdP auto-POSTs to the
  portal's own `/v1/sso/acs`. The env-first material precedence and the small IdP-metadata
  parser mirror `cmd/harbor/adminauth_wire.go` (duplicated, not shared — two separate
  `main` packages). Unlike admin-api, the gateway does **not** mint an ephemeral SP
  keypair: a public, restartable surface needs a stable SP identity the IdP trusts, so a
  missing keypair is an error, not a warning. **Core (`cmd/harbor`):** two new core-flags
  feed the B8 seam on BOTH consumers (the `cmdCollect` consumer where `processSSO` runs
  AND the `cmdAdminAPI` approve-path consumer — both go through `buildConsumer`):
  **(a)** `-sso-assert-pub` (PEM → `ssoassert.ParsePublicKeyPEM` →
  `enrollment.Config.AssertionVerifyKey`), the **pinned** gateway public key, read once at
  startup like the CA cert (a deploy-time trust anchor, not live-rotated); unset →
  `AssertionVerifyKey` nil → the existing terminal `ErrSSONotConfigured`. **(b)**
  `-usertrust-db` wires `enrollment.Config.UserTrustActive` to a **getter closure** over a
  new `activeUserTrust` reader — the exact peer of `activeCloudTrust` (same
  `newPolicyController().LatestCommitted(usertrust.PublishKind)` + `usertrust.Parse`
  pattern, and `usertrust.RegisterCommitter` is now installed in `newPolicyController`
  alongside policy/cloudtrust). The ONE deliberate difference from cloud-trust: cloud-trust
  is read **once** at consumer build (`cf.cloudTrust(s)` → a snapshot `*Config`), whereas
  user-trust is passed as a **getter** (`cf.userTrustActive(s)` → `func() *usertrust.Config`
  reading `activeUserTrust` per call) — so the dual-control-published config is read **live
  per enrollment** and changing who may enroll needs no Core restart (the seam's whole
  point, B8); a getter returning nil (nothing published yet) is treated as not-configured
  (fail closed). **Key generation — chose GENESIS over a new subcommand.** Genesis now
  mints the dedicated ECDSA P-256 assertion keypair (S6) via `ssoassert.GenerateKey`,
  surfaces both PEMs in `genesis.Result` (`SSOAssertPrivPEM`/`SSOAssertPubPEM`), and
  `cmdGenesis` writes `sso-assert.key` (0600, O_EXCL — the gateway's private half) +
  `sso-assert.pub` (0644 — Core pins). Only the PUBLIC half is recorded in the DB key
  registry (kind `sso-assertion`, audited `genesis-sso-assertion-key`); the gateway's
  private half never touches the DB (the gateway holds no CA). This mirrors exactly how
  genesis already mints + distributes the CA / config-signing / lighthouse / Core
  material, so it added two `[]byte` Result fields and ~25 lines — strictly less coupling
  than a standalone `harbor sso-keygen` subcommand, which would also have needed a new
  entry in the CLI-surface fixture (`cli_surface_test.go`). The integration test's genesis
  key-set assertion was updated to expect the third (`sso-assertion`) key. **Tests:**
  gateway `cmd/gateway/sso_test.go` proves `Config.SSO` is nil when the flags are absent,
  is fully built (SAML + signing key) when present, and **fails closed** on each partial
  config (missing assert key / SP keypair / IdP metadata / non-absolute ACS URL); Core
  `cmd/harbor/usertrust_test.go` proves the `-usertrust-db` getter reads the published
  config LIVE (nil before publish → the committed config after, same getter, no rebuild),
  is nil without the flag, enforces two-person control on the publish, and that
  `-sso-assert-pub` pins the matching public key (nil when unset). **DEFERRED to deploy
  (live rollout, NOT done here):** wiring `deploy/prod/bootstrap-genesis.sh` to thread the
  new files; the operator-provided **IdP SAML metadata** + SP registration; and the
  **key distribution** itself — `sso-assert.key` to the gateway's Fargate config secret
  and `sso-assert.pub` pinned on Core. No live SAML IdP was set up. The binaries now
  COMPILE and are fully configurable to run SSO, and a fresh genesis produces the
  assertion keypair; turning it on is deploy plumbing.

- **B16 — Phase-1 review hardening: mandatory assertion expiry + exact-realm matching.**
  Two review findings tightened, both fail-closed corrections to earlier decisions.
  **(1) Mandatory expiry + bounded lifetime (revises B2/B12).** `ssoassert.Verify` no
  longer treats a zero/absent `exp` as "valid forever" — it had been `if exp != 0 && now >
  exp`, so an assertion with `exp == 0` slipped past the window check and was accepted
  indefinitely, violating the package's own validity-window contract. Verify now REQUIRES a
  positive window: `exp == 0` OR `iat <= 0` → `ErrExpired`; `now > exp` → `ErrExpired`;
  `now < iat` → `ErrExpired` (not yet valid); and `exp - iat` greater than a generous
  `maxLifetime` cap (**1h**, well above the B12 default 3 min / S5 2–5 min band) →
  `ErrExpired` (an implausibly long window is treated as malformed). This is belt-and-
  suspenders behind the signature (a forger past the pinned key is already inside the trust
  boundary), but it closes the never-expires gap and bounds a misconfigured/over-broad
  gateway TTL. **(2) Exact-realm matching, wildcard removed (supersedes B4).**
  `usertrust.Match` no longer treats an empty `IDPEntry.Realm` as "match any realm" — an
  entry now matches only when `e.Realm == realm`. The wildcard branch was already dead
  (`Validate` rejects an empty realm with `ErrNoRealm`, so no published config could carry
  one), the docs advertised a feature that couldn't exist, and a wildcard ordered first
  would have shadowed every specific-realm entry — a quiet trust-widening. The package /
  field / `Match` docs dropped the wildcard language; `TestMatchRealm` now builds its config
  via `Parse` so it can only assert behavior `Validate` permits. No config-format change
  (an empty realm was always invalid).
