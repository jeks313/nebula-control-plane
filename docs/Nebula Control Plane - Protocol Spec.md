---
created: 2026-06-12
source: claude-chat
status: v1-draft
project: nebula-control-plane
tags: [networking, nebula, security, protocol, spec, enrollment, attestation]
---

# Nebula Control Plane — Wire Protocol Specification (v1)

Companion to [[Nebula Control Plane - Design Plan]] (v3) and [[Nebula Control Plane - Implementation Plan]]. This is implementation-plan step **3.0**: the enrollment / attestation / bundle wire protocol, written **before** M3 code so M3–M5 implement *against this document*, and so it is the artifact externally reviewed in **9.7**. Section references like *(§4.3)* point at the design doc; step references like *(3.4)* point at the implementation plan.

> **Status.** v1-draft. Normative keywords **MUST / SHOULD / MAY** per RFC 2119. Anything marked *(reserved)* is named here for forward-compatibility but not implemented in v1.

---

## 1. Scope and principles

This spec defines the **on-the-wire** contract between **Pilot** (host agent) and **Harbor** (control plane): how a host obtains an identity (cert + config), renews it, and reports state. It does **not** define Harbor's internal APIs, the queue, or the data plane (that is Nebula itself).

Binding principles (from design §2.1, §P11):

- **No bespoke crypto.** Signatures use **JWS (ES256)**; cloud attestation uses **AWS SigV4** / **Azure attested data**; HMAC is **HMAC-SHA256**. No hand-rolled constructions.
- **Control plane off the data path (P3).** The public surface is a thin, credential-less **Enrollment Gateway**; the authoritative **Core** is mesh-only.
- **Async by construction.** Enrollment is **submit → poll → receive**; the gateway never holds DB/KMS credentials.
- **Fail closed on identity (P8).** Bad/expired/forged freshness, skewed clocks, or unverifiable signatures **MUST** be rejected, never best-effort accepted.
- **Everything time-bound and bound to a key.** Every request carries a nonce and is tied to the host public key that will appear in the issued certificate.

---

## 2. Transport, endpoints, versioning

### 2.1 Endpoints

| Method & path | Surface | Auth | Step |
|---|---|---|---|
| `GET /v1/nonce` | Gateway (public) | none | 3.2 |
| `POST /v1/enroll` | Gateway (public) | request JWS + method credential | 3.3 |
| `GET /v1/enroll/{id}` | Gateway (public) | retrieval ticket | 3.6a |
| `POST /v1/certs/renew` | Core (**mesh-only**) | calling tunnel cert (§4.5) | 4.3 |
| `POST /v1/heartbeat` | Core (**mesh-only**) | calling tunnel cert | 4.6 |

The Gateway is reachable from the public internet (and via PrivateLink/Private Endpoint, 5.7). Core endpoints are bound to Core's overlay IP and **MUST NOT** be reachable off-mesh (4.1).

### 2.2 Versioning and negotiation (4.8)

- **Major** version is pinned in the URL (`/v1`). A breaking change ships under `/v2`; `/v1` keeps working through the deprecation window.
- Every envelope payload carries an integer `protocol_version`. v1 documents use `1`.
- The client **MUST** send `client.supported_protocol_versions`. The server picks the highest mutually supported version and echoes it in the response (`protocol_version`). If none overlaps, the server returns `unsupported_version` (§7).
- Servers **MUST** support the current major and the immediately previous minor behavior (N and N-1) so a fleet is never required to upgrade atomically.

### 2.3 Encoding

- Bodies are `application/json; charset=utf-8`.
- Binary fields are **base64url without padding** unless stated.
- Timestamps are **RFC 3339 / UTC** (e.g. `2026-06-12T05:49:13Z`).
- Signed objects use **JWS Flattened JSON Serialization** (§3).

---

## 3. Signature envelopes (JWS)

All signed objects use JWS Flattened JSON Serialization with `alg: ES256` (ECDSA P256 / SHA-256 — the curve the whole system already mandates, M0):

```json
{
  "protected": "<base64url(header)>",
  "payload":   "<base64url(json)>",
  "signature": "<base64url(ES256 sig over ASCII(protected) || '.' || ASCII(payload))>"
}
```

Two distinct signing roles, never interchanged:

1. **Host request signature** — the Pilot signs enrollment/renewal requests with the **host key** (the same P256 key that goes into the cert; see §4.1 note). This is the proof-of-possession (CSR self-signature).
   - protected header: `{"alg":"ES256","typ":"ncp-request+jws","ver":1,"kid":"<pubkey_hash>"}`
   - `kid` = `pubkey_hash` (§4.2), so the verifier knows which key to check **from the payload's own `csr.public_key`** (the request is self-describing; `kid` is a cross-check, not a trust anchor).

2. **Bundle signature** — Harbor signs the issued config/cert bundle with the **config-signing key** (distinct from the CA key, design §2.1). Pilot verifies it against the **pinned config-signing public key(s)** baked into Pilot's trust store.
   - protected header: `{"alg":"ES256","typ":"ncp-bundle+jws","ver":1,"kid":"<config_key_id>"}`
   - During config-key rotation (8.5) Pilot pins `[K1, K2]` and accepts either.

> COSE/CBOR is *(reserved)* for constrained transports; v1 is JSON+JWS only.

---

## 4. Identity, nonces, freshness

### 4.1 Keys

- The host **key-agreement key** is **P256** (Nebula cert v2 requirement, M0). Pilot generates it locally and never exports the private part (design P1, impl 1.4).
- **Proof of possession.** The enrollment request JWS is signed by this key using **ES256**. P256 permits both ECDH (Nebula handshake) and ECDSA (this PoP) over the same scalar; v1 reuses the key with strict **algorithm + `typ` domain separation**. *(A separate enrollment key is reserved as a future option; it would not add PoP of the cert key, which is what matters.)* Ultimate PoP is also enforced implicitly: a cert issued over a swapped public key is useless to anyone who lacks the matching private key, because Nebula's Noise handshake requires it.

### 4.2 Identifiers

- `pubkey_hash` = base64url( SHA-256( raw 65-byte uncompressed P256 point ) ). Stable identifier for the host key across nonce, request, and result binding.
- `enrollment_id` = server-issued opaque, unguessable (≥128 bits), single enrollment attempt.

### 4.3 Nonce (3.2)

`GET /v1/nonce?binding=<pubkey_hash>` → 

```json
{ "nonce": "<base64url>", "expires_at": "2026-06-12T05:50:13Z", "protocol_version": 1 }
```

The nonce is **stateless** at the gateway:

```
nonce      = base64url( ts_be8 || mac )
mac        = HMAC-SHA256( k_gw, "ncp-nonce-v1" || ts_be8 || binding )   // first 16 bytes
ts_be8     = big-endian uint64 unix-seconds of issuance
binding    = the pubkey_hash bytes (decoded)
```

- `k_gw` is the gateway nonce key, rotated with overlap (2.10/4.8); verification tries current then previous key.
- **Freshness:** a nonce is valid only while `now - ts ∈ [-MAX_SKEW, NONCE_TTL]`. v1 defaults: `NONCE_TTL = 60s`, `MAX_SKEW = 30s`.
- **Binding:** the nonce embeds the requester's `pubkey_hash`; a nonce minted for one key **MUST NOT** validate for another.
- **Single use:** statelessness means the gateway cannot enforce single-use. **Core MUST keep a replay cache** of accepted `(nonce)` values for at least `NONCE_TTL + MAX_SKEW` and reject repeats (defends the token/attestation flows against replay within the window).
- **Clock:** Pilot **MUST** pass a clock-sanity gate (1.13) before requesting a nonce; a host beyond hard skew fails closed locally rather than emitting future/expired material.

---

## 5. Enrollment

End-to-end: `nonce → submit (POST /enroll) → ticket → poll (GET /enroll/{id}) → bundle`. Submit and poll are separate because the gateway is credential-less and Core is mesh-only and asynchronous (3.3a/3.6a).

### 5.1 Submit — `POST /v1/enroll`

Body is a **host-request JWS** (§3, role 1). Decoded `payload`:

```json
{
  "protocol_version": 1,
  "type": "enroll",
  "issued_at": "2026-06-12T05:49:20Z",
  "nonce": "<base64url nonce>",
  "csr": {
    "curve": "P256",
    "public_key": "<base64url 65-byte point>",
    "requested_name": "web-1",
    "requested_groups": ["web"]          // advisory only; Harbor is authoritative (§4.3a)
  },
  "method": "token",                      // token | aws-sigv4 | azure-imds | oidc
  "credential": { "...": "method-specific (§5.4)" },
  "client": {
    "pilot_version": "1.2.3",
    "supported_protocol_versions": [1]
  }
}
```

**Gateway responsibilities (3.3), before any heavy work:**
1. Enforce a hard **max body size** and **request timeout**; reject oversized/slow bodies **pre-parse**.
2. Validate JSON schema and required fields; reject unknown `method`.
3. Verify the **request JWS** against `csr.public_key`; confirm `kid == pubkey_hash(csr.public_key)`.
4. Verify the **nonce** (HMAC, TTL, `binding == pubkey_hash`).
5. Edge **rate-limit** by source and by `pubkey_hash`.
6. Publish a *vetted candidate* to the internal queue (3.3a) and return a ticket. The gateway holds **no DB/KMS credentials** and makes **no authz decision** beyond the above structural checks.

`requested_groups` is advisory; the host can never grant itself privilege — groups are derived by Harbor from the token class (3.5) or immutable attestation facts (5.5).

**Success — `202 Accepted`:**

```json
{
  "protocol_version": 1,
  "enrollment_id": "<opaque>",
  "retrieval_secret": "<base64url ≥128-bit>",
  "poll_after_ms": 500,
  "expires_at": "2026-06-12T05:54:20Z"
}
```

`retrieval_secret` is returned **once**; it is the capability to fetch the result (§5.3). Stakes are modest (a certificate is not secret without its private key) but the result is still bound to this secret to prevent cross-tenant fetch and enumeration.

### 5.2 Core processing (3.4 / 3.9 / 3.10)

Core consumes the queued candidate and, idempotently:
1. Re-verifies request JWS + nonce; checks the **replay cache** (§4.3).
2. Authenticates the `method` credential (§5.4).
3. Enforces **enrollment quotas** (3.10): per-cloud-account, per-instance, and **per-join-key** caps, distinct from the signing circuit-breaker (2.5).
4. Resolves **groups** from the **join key** (token method, 3.5) or immutable facts (attestation, 5.5) — never from `requested_groups` or mutable tags.
5. **Approval decision (default-deny for bearer secrets):** a **join-key** (token-method) join goes to **PENDING manual approval (3.9)** unless that key explicitly sets `auto_issue` (a heavily-warned per-key opt-out). **Attestation methods** (aws-sigv4/azure-imds/oidc, and future TPM) may auto-issue. A conflicting existing active enrollment for the same instance/identity always routes to PENDING, never silent re-issue.
6. Drives device state `pending → active` (2.12); on auto-issue or after approval: allocates an overlay IP (2.6), assembles + signs the **leaf cert** (CA key, 2.3) and the **bundle** (config-signing key, §6), writes the bundle to the **result store** (3.6a).

Auto-issue vs. **pending approval**: a request may complete immediately (`issued`) or wait for a human (`pending` → later `issued`/`denied`). Both are delivered via the same poll endpoint. **The default for join keys is `pending`** — a host joining on a bearer secret is only admitted to the network after a human approves it in the UI.

### 5.3 Poll — `GET /v1/enroll/{id}`

Authorization: header `Authorization: Bearer <retrieval_secret>`. The result is released only to a request whose `enrollment_id` + `retrieval_secret` match; mismatches return `not_found` (no oracle). Reads are TTL-bound; the bundle read is one-time.

Responses:

```json
{ "status": "pending",  "poll_after_ms": 1000 }
```
```json
{ "status": "issued",   "bundle": { /* bundle JWS, §6 */ } }
```
```json
{ "status": "denied",   "reason": "conflict_existing_enrollment" }
```
- `202` for `pending`, `200` for `issued`/`denied`, `410 Gone` once consumed or expired, `404` on bad/again-used ticket.

### 5.4 Method credentials

| `method` | `credential` payload | Verified by | Step |
|---|---|---|---|
| `token` | `{ "token": "<join-key secret>" }` | matched (by hash) to an active **join key** (§4.1c): not expired, `used_count < max_uses`, within quota. **Defaults to PENDING approval** unless the key sets `auto_issue`. Groups come from the key. | 3.4 |
| `aws-sigv4` | `{ "presigned": { "method":"POST", "url":"https://sts.<region>.amazonaws.com/", "headers":{...}, "body":"Action=GetCallerIdentity&Version=2011-06-15" } }` — the SigV4 signature **MUST** cover headers `X-Harbor-Nonce: <nonce>` and `X-Harbor-Pubkey-Hash: <pubkey_hash>` | Core replays `GetCallerIdentity`; checks account/role-path allowlist + nonce/pubkey binding; secondary IID/DescribeInstances cross-check (5.3) | 5.1–5.3 |
| `azure-imds` | `{ "attested_document": "<base64 PKCS7>" }` — IMDS attested data with the nonce embedded natively | chain to Azure CA, subscription/vmId allowlist | 5.6 |
| `oidc` *(reserved, M9)* | `{ "id_token": "<JWT>" }` device-code flow | IdP JWKS, device↔human binding | 9.1 |

The **token** method is M3's path; cloud attestation lands in M5. The credential is inside the signed payload, so it is covered by the request JWS and bound to the nonce + pubkey.

---

## 6. Issued bundle (3.6, §P8/§P11)

The bundle is a **bundle JWS** (§3, role 2) signed by the **config-signing key**. Decoded `payload`:

```json
{
  "protocol_version": 1,
  "type": "config-bundle",
  "bundle_version": 12,                  // monotonic per device; drives drift/rollback (6.6/6.7)
  "issued_at": "2026-06-12T05:49:25Z",
  "device": { "name": "web-1", "overlay_ip": "100.64.0.5", "groups": ["web"] },
  "certificate": "<NEBULA CERTIFICATE V2 PEM>",   // leaf, signed by the CA key
  "ca_bundle": ["<NEBULA CERTIFICATE V2 PEM>"],    // trust bundle; may carry [CA1,CA2] mid-rotation (8.1)
  "config": { /* rendered Nebula policy: lighthouse, static_host_map, firewall, listen, tun */ },
  "lighthouses": [ { "overlay_ip": "100.64.0.1", "public_addrs": ["198.51.100.1:4242"] } ],
  "not_after": "2026-07-12T05:49:25Z",
  "next_renew_after": "2026-06-29T00:00:00Z"       // proactive-renewal hint (4.4), jittered
}
```

**Pilot verification order (MUST, fail-closed):**
1. Verify the **bundle JWS** against a **pinned** config-signing key (`kid` ∈ pinned set).
2. Verify `certificate` against `ca_bundle`, and confirm the cert's public key equals the host's own key (`pubkey_hash`).
3. Confirm `device.overlay_ip` ∈ the cert's networks; confirm `not_after` matches the cert.
4. Only then render config + (re)start Nebula (1.7/1.8). Reject and alert on any failure.

The split is deliberate: the **CA key** vouches for *identity* (the cert), the **config-signing key** vouches for *policy + delivery* (the bundle). Compromise of one is not compromise of the other.

---

## 7. Error model

Uniform error body on any non-2xx:

```json
{ "error": { "code": "invalid_nonce", "message": "human-readable", "retryable": false } }
```

`code` is a stable enum; clients branch on `code`, not `message`. `retryable` tells Pilot whether to back off and retry the same request unchanged.

| code | HTTP | retryable | meaning |
|---|---|---|---|
| `invalid_request` | 400 | no | malformed/oversized/schema failure |
| `unsupported_version` | 400 | no | no mutual protocol version |
| `invalid_signature` | 401 | no | request JWS failed |
| `invalid_nonce` | 401 | no | bad/forged nonce or wrong binding |
| `nonce_expired` | 401 | yes | fetch a fresh nonce and retry |
| `invalid_token` | 401 | no | unknown token |
| `token_used` | 409 | no | one-time token already consumed |
| `attestation_failed` | 401 | no | SigV4/IMDS/OIDC verification failed |
| `account_not_allowed` | 403 | no | account/subscription/role not allow-listed |
| `quota_exceeded` | 429 | yes | enrollment quota hit (3.10) |
| `rate_limited` | 429 | yes | edge rate limit; honor `Retry-After` |
| `signing_unavailable` | 503 | yes | signing circuit breaker open (2.5) |
| `pending_approval` | 202 | yes | not an error; keep polling |
| `conflict` | 409 | no | conflicting active enrollment → review (5.4) |
| `not_found` | 404 | no | unknown/!matching ticket (also the no-oracle response) |
| `gone` | 410 | no | result expired or already consumed |
| `internal` | 500 | yes | server fault |

Servers **MUST NOT** leak which of several checks failed in a way that builds an oracle (e.g., wrong-ticket and unknown-id both return `not_found`).

---

## 8. Lifecycle over the mesh (M4)

These run on Core, **mesh-only**, authenticated by the **calling tunnel's certificate** matched to the device record (§4.5, 4.2). No nonce/attestation — the live tunnel is the credential.

### 8.1 Renew — `POST /v1/certs/renew` (4.3)

Request JWS (signed by the host's *current* key, or a fresh key being rotated in) payload:

```json
{ "protocol_version": 1, "type": "renew",
  "csr": { "curve": "P256", "public_key": "<base64url 65-byte>" },
  "issued_at": "..." }
```

Core re-signs for the **already-enrolled** identity (no re-attestation), keeping the same overlay IP and groups unless policy changed; responds with a fresh **bundle** (§6). Renewal is **proactive at ~⅔ life with jitter** (4.4); IP/curve changes are *not* a renewal (they force re-enroll, see 1.8 reload matrix).

### 8.2 Heartbeat — `POST /v1/heartbeat` (4.6)

```json
{ "protocol_version": 1, "type": "heartbeat",
  "applied_bundle_version": 12, "cert_not_after": "...",
  "pilot_version": "1.2.3", "nebula_version": "1.10.3",
  "clock_offset_ms": 12, "health": "ok" }
```

Response carries a **narrow, typed command channel** — never arbitrary execution:

```json
{ "commands": [ { "type": "apply_bundle", "bundle_version": 13 },
                { "type": "renew" },
                { "type": "restart" } ] }
```

Pilot **MUST** reject any command `type` it does not recognize (closed enum).

---

## 9. Security properties (summary → design)

- **Freshness & anti-replay:** nonce TTL + Core replay cache (§4.3); one-time tokens (5.4); clock-sanity gate (1.13).
- **Key binding:** nonce ⇄ `pubkey_hash` ⇄ request JWS ⇄ issued cert; result ⇄ retrieval secret.
- **Least authority on the edge:** gateway is credential-less and makes no authz decision (P3); Core is mesh-only.
- **Two independent trust roots on delivery:** CA key (cert) + config-signing key (bundle), each pinned/rotatable independently (§6, M8).
- **Fail closed (P8):** any signature/freshness/clock/quota failure rejects; no partial trust.
- **No self-granted privilege:** `requested_*` fields are advisory; groups derive from token class or immutable facts (§4.3a).
- **Auditable:** every accept/deny/issue is an audited, hash-chained event (2.2) with a stable error `code`.

---

## 10. Open items for review (9.7)

- Confirm acceptability of **P256 key reuse** for ECDH + ES256 PoP, or switch to a dedicated enrollment-auth key.
- `NONCE_TTL`/`MAX_SKEW`/quota defaults under real clock-skew and fleet-launch storms (9.8).
- Retrieval-secret strength vs. enumeration; whether to additionally bind poll to a request JWS.
- Canonicalization is delegated to JWS (signs exact bytes); confirm no place relies on JSON canonicalization.
- Replay-cache sizing/HA semantics for multi-Core (9.5).
