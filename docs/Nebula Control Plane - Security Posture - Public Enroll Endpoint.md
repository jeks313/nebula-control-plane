---
title: "Security Posture — The Public Enrollment Endpoint"
created: 2026-06-13
status: living
tags: [nebula, security, enrollment, gateway, attestation, threat-model, risk]
---

# Security Posture — The Public Enrollment Endpoint

**Audience:** anyone scrutinising the one deliberately internet-facing surface of Harbor —
the enrollment gateway (`/v1/enroll`). This is where a host that is not yet on the mesh
asks to join, so it is, by design, reachable from the public internet. That is the point:
the mesh exists to **stitch together disparate networks**, and a host in a network we do
not control must have a way to present a credential and be admitted. This document states
what that endpoint actually exposes, the controls already in place, why the residual risk
is acceptable, and the measures that would harden it further.

## TL;DR

The public endpoint accepts *requests* but grants *nothing* without a valid, scoped,
bounded credential — it is **default-deny**. The public surface itself holds **no
authority**: the gateway is credential-less and has no access to the database, the CA, or
the signing keys, so compromising it yields no ability to mint an identity or read fleet
data. Every check the public edge performs is **re-performed by Core** behind the mesh,
which makes the authoritative decision. A successful enrollment grants only the groups the
credential authorises, and the firewall is default-deny group→group, so even an admitted
host can reach nothing it is not explicitly permitted. The risk is acceptable because the
*attack surface* (the public gateway) and the *authority* (Core + CA) are separated, the
credential model is least-privilege and revocable-by-expiry, and abuse is rate-limited and
audited at every layer. The one structural gap is **revocation (M7) is not yet built**, so
short certificate lifetimes are currently the only way to bound a mis-issuance.

## What the endpoint is, and why it is public

The enrollment gateway (`internal/gateway`) is a small, stateless HTTP service exposing
three routes:

- `GET /v1/nonce` — mint a short-lived, single-use nonce bound to the caller's public key.
- `POST /v1/enroll` — submit a signed enrollment request (token or cloud attestation).
- `GET /v1/enroll/{id}` — poll for the result with a one-time retrieval secret.

It must be public because the joining host is, by definition, **not yet on the overlay** —
it has no mesh address to be reached at. Once admitted, every other control-plane
interaction (renewal, heartbeat, admin) happens *over the mesh* and is authenticated by the
tunnel's overlay IP; the gateway is the only door that opens from the outside.

## The architecture that makes this safe: a credential-less edge

The single most important property (design §P3): **the gateway depends on no DB, no KMS,
and no CA.** Its package doc says it plainly — it "mints nonces, structurally validates
enroll requests, edge-rate-limits, and publishes vetted candidates to a queue… All
authoritative decisions (token/attestation, group resolution, issuance) live in Core,
which re-verifies everything."

Consequence: **a fully compromised gateway cannot issue a certificate, cannot read the
fleet database, and cannot reach the signing key.** The internet-facing process is an
untrusted edge filter, not a trust boundary. The trust boundary is Core, which sits behind
the mesh and pulls vetted candidates off a queue. This is deliberate blast-radius
reduction: the most-exposed component holds the least authority.

## Defense in depth — the controls already in place

### At the public edge (gateway, `handleEnroll`)

Applied in order, cheapest shed first:

1. **Source-IP rate limit before any parsing or crypto** (`ratelimit.Limiter`) — a flood is
   dropped before it can cost CPU.
2. **Hard body cap (16 KiB) pre-parse** (`http.MaxBytesReader`) — no unbounded reads.
3. **Structural validation** — JWS envelope shape, protocol version, request type, P-256
   curve, a 65-byte public-key point that must parse as a valid point.
4. **Per-identity rate limit** keyed on the public-key hash, once the identity is known.
5. **Proof of possession** — the request JWS must verify against the public key *inside*
   the request, and the JWS `kid` must equal that key's hash. You cannot enroll a key you
   do not hold the private half of.
6. **Nonce check** — the nonce must be unexpired and **bound to this public key**
   (`nonces.Verify(nonce, pubkeyHash)`), so a nonce minted for one key cannot be replayed
   with another.
7. Only then is a **vetted candidate published to a durable queue**, and the caller gets a
   retrieval ticket. **No authorization decision is made at the edge.**
8. **Result retrieval is capability-gated** — the issued bundle is released only to the
   holder of the one-time retrieval secret (`handlePoll`, bearer secret), as a one-time
   read.

### At the authoritative core (`enrollment.Consumer`)

Core pulls each candidate off the queue and **re-verifies everything the edge claimed** —
it never trusts the gateway's word:

1. **Re-verify the JWS and the binding** (`verify()`): re-parse, re-verify the signature,
   and require `kid == pubkeyHash == candidate.PubkeyHash` — the edge's claimed identity is
   independently re-checked.
2. **Re-verify the nonce** (freshness + key binding), then **single-use replay protection**
   (`Replay.Observe`): a nonce can be consumed exactly once; a queue redelivery or a
   replayed request hits `ErrReplay` and is denied.
3. **Token method** (`internal/joinkey`):
   - The join-key secret is a **bearer secret stored only as a SHA-256 hash** — the
     database never holds the secret.
   - `Lookup` admits only an **active, unexpired** key with **uses remaining**.
   - A **per-key rate quota** (`QuotaPerHour`) is checked *before* consuming a use, so a
     leaked or reusable key **cannot mint a fleet** in a burst.
   - The use is **atomically consumed** (`max_uses`).
   - **Bearer secrets default to PENDING manual approval** — a human approves before a cert
     is issued. `auto_issue` (mint immediately, no human) is **opt-in per key**.
4. **Attestation method** (`internal/awsattest`): the host presents a **presigned STS
   `GetCallerIdentity`** request, and Core enforces, in order:
   - **Binding**: the `x-harbor-nonce` and `x-harbor-pubkey-hash` headers must equal this
     enrollment's nonce + key, AND **must be inside the SigV4 SignedHeaders** — so an
     attacker cannot strip or swap the binding (`ErrUnsignedBinding`). The attestation is
     cryptographically bound to *this* host's key and *this* single-use nonce.
   - **SSRF discipline**: the signed URL must be `https` and an **allowlisted AWS STS host**
     (`^sts(\.[a-z0-9-]+)?\.amazonaws\.com$`) before Core forwards it.
   - **Account/role allowlist**: the verified caller identity must match the **dual-control
     cloud-trust config** (account + ARN globs); groups come from the matched account ∪
     defaults. An unconfigured/disabled/untrusted attestation **fails closed**.
5. **Group authority is server-side** — the host never selects its own groups; Core derives
   them from the credential. A host cannot self-elevate during enrollment.
6. **Fail-closed throughout** — `terminal()` classifies business denials as final (no
   retry); even an STS outage is a clean denial (the host re-enrolls with a fresh nonce),
   never a fallback to "allow."
7. **Everything is audited** into the hash-chained, tamper-evident audit log; pending
   enrollments wait for a human and are visible in the console queue.

### After admission — containment

Joining the mesh is not joining a flat network. The issued cert carries only the
authorised groups, and the firewall is **default-deny group→group** (`internal/policy`,
`CompileHost`): a freshly-admitted host can reach **only** what an explicit, dual-control-
published policy rule permits, plus the non-removable baseline (reach the control plane;
ICMP). A compromised or rogue enrollee is boxed in by the same policy as everything else.

## Why the residual risk is acceptable

1. **Default-deny, credential-gated.** The endpoint admits no one without proving
   possession of a scoped, revocable, bounded credential (a hashed join-key secret) or a
   cloud identity in an explicitly allowlisted account. "Public" means "reachable," not
   "open."
2. **Least-privilege, bounded credentials.** Join keys are scoped (groups), capped
   (`max_uses`), expiring (TTL), rate-limited (`quota/hour`), revocable, and default to
   manual approval. Auto-issue is opt-in. Attestation requires a live, signed AWS identity
   in an allowlisted account/role — not a static secret at all.
3. **Authority is not on the public surface.** The exposed component (gateway) cannot
   issue, cannot read the DB, cannot sign. Compromising the front door yields no keys to
   the house.
4. **Independent re-verification.** Core re-checks signature, identity binding, nonce, and
   replay — the edge is treated as untrusted. There is no single check that, if bypassed at
   the edge, admits a host.
5. **Layered anti-abuse.** Per-IP and per-identity rate limits, a per-key quota, body
   caps, single-use nonces, replay protection, and an SSRF allowlist on the one outbound
   callout.
6. **Post-admission containment.** Even a successful enrollment grants only the
   credential's groups, and the default-deny firewall limits reachability — admission is
   not lateral movement.
7. **Auditable and human-gated by default.** Bearer enrollments are PENDING (a human
   approves) unless explicitly set to auto-issue, and every decision is in a tamper-evident
   log.

In short: the blast radius of the public surface is small by construction, the credential
model is least-privilege, and admission is contained downstream.

## Residual risks (honest list)

1. **Auto-issue bearer keys are the highest-value target.** A leaked join key with
   `auto_issue=true` mints certs with no human in the loop. The bounds (hash-at-rest,
   `max_uses`, TTL, quota, revoke) limit the damage, but auto-issue is the dangerous mode.
2. **Revocation does not exist yet (M7).** A mis-issued or leaked-credential cert **cannot
   currently be revoked** — its only bound is its lifetime. This is the single biggest gap:
   the front door has strong locks, but we cannot yet recall a key that got through.
3. **Volumetric DoS.** A public endpoint invites floods. Rate limits + body caps + the
   credential-less edge blunt it, but a large distributed flood could still pressure the
   queue or the STS callout. No proof-of-work / CAPTCHA today.
4. **The STS callout is an attacker-influenced outbound.** Attestation makes Core call an
   external STS host. SSRF is allowlisted (https + STS-host regex) and STS-unavailable is a
   clean denial, but it is still outbound traffic shaped by an untrusted request.
5. **Single-use guarantee depends on the replay/nonce store.** If that store is not durable
   and consistent across Core instances, a nonce could in principle be accepted twice.
6. **Attestation trust = cloud account hygiene.** Trusting an AWS account trusts whoever
   can assume a matching role in it. Broad ARN globs widen that trust.
7. **Bearer-secret distribution.** Join keys are only as safe as how they are delivered to
   hosts; a key pasted into a world-readable place is a real-world failure mode the protocol
   cannot prevent.

## Additional measures to make it safer

Prioritised, roughly highest-leverage first:

1. **Build M7 (revocation / blocklist).** The one structural gap. Until then, **keep
   certificate TTLs short** — a short TTL is currently the only bound on a mis-issuance,
   and it also shrinks the window for the ADR-0002 group-removal caveat.
2. **Prefer attestation over bearer keys for auto-issue.** A live, signed cloud identity is
   far stronger than a static shared secret. Consider making auto-issue *require*
   attestation, and keep bearer keys at manual-approval by default (as they are).
3. **Put a CDN/WAF in front** (the infra plan already contemplates Cloudflare): volumetric
   DoS absorption, IP reputation, and basic L7 filtering before traffic reaches the gateway.
4. **Network-layer egress allowlist for the STS callout** — defense in depth beyond the
   in-process regex, so a regex slip cannot become an SSRF.
5. **Durable, shared nonce + replay stores** with bounded nonce TTLs; monitor the
   replay-rejection rate as an attack signal.
6. **Scope credentials tightly** — narrow ARN globs (specific roles, not account-wide),
   small `max_uses`, low quotas, short key TTLs; the cloud-trust config is already
   dual-control, which is the right gate for widening trust.
7. **Queue backpressure + an STS circuit breaker** (the unavailable-state classification
   already exists) so a flood or an STS brownout degrades gracefully rather than cascading.
8. **Observability + alerting on the enroll funnel** — attempt rate, denial reasons, quota
   exhaustion, attestation failures, and pending-queue growth are the early-warning signals
   for both abuse and misconfiguration.
9. **Optional, deployment-specific:** source-CIDR allowlists or geo-fencing where the
   joining population is known; a "first-contact" sampling-to-review mode even for
   auto-issue; proof-of-work for anonymous nonce minting under attack.

## Bottom line

The public enrollment endpoint is the right thing to expose — it is what lets the mesh
span networks we do not own — and it is exposed safely: the front door holds no keys, every
claim is re-verified behind it, admission requires a least-privilege credential, and the
firewall contains whatever gets in. The honest caveat to put in front of any reviewer is
**revocation (M7)**: today we admit carefully and bound mis-issuance with short lifetimes,
but we cannot yet recall an issued identity. Prioritising M7 and keeping TTLs short closes
the most important remaining gap.
