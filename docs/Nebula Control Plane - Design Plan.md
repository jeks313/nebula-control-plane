---
created: 2026-06-11
source: claude-chat
status: draft-v3
project: nebula-control-plane
tags: [networking, nebula, security, pki, aws, azure, zero-trust, design]
---

# Nebula Control Plane — Design Plan (v3)

Working codenames: **Harbor** (central control plane) and **Pilot** (the per-host wrapper/agent that supervises Nebula). A harbor pilot guides ships safely past the lighthouse into port — fits Nebula's metaphor. Rename later.

Background on Nebula itself: [[Nebula - Open Source Overlay Mesh Network]].

> **Revision history**
> - **v1** — initial design (Harbor + Pilot, KMS CA, cloud attestation, central firewall).
> - **v2** — security review pass: AWS attestation moved to sigv4 (IID can't carry a nonce); post-enrollment auth moved over the mesh (Nebula certs aren't X.509); public Enrollment Gateway split from mesh-only Harbor Core; added supply-chain controls, hash-chained audit, threat model, runbooks.
> - **v3 (2026-06-11)** — second review pass. Closed four architecture holes — **genesis/self-renewal bootstrap (§3.1)**, **peer-side blocklist enforcement (§4.7)**, **groups bound to immutable attestation facts (§4.3a)**, **out-of-band admin break-glass (§10)** — and added: signing **circuit-breaker (§4.3)**, **AWS account isolation (§6.3)**, revocation-as-DoS invariants (§4.7), **no-bespoke-crypto** principle (P11), explicit **default-deny** baseline (§4.4), a concrete **detection catalog (§7.1)**, an explicit **TCB statement (§2.1)**, a **security-assurance section (§13)**, and notes on containers/autoscaling, IdP-in-TCB, lighthouse availability, and Nebula reload semantics.

## 1. Problem & goals

Stock Nebula leaves four operational gaps that we want to close, securely and at fleet scale:

1. **IP assignment** — Nebula IPs are hand-allocated and baked into certs; collisions and bookkeeping are manual.
2. **Certificates & joining** — issuing a host cert, getting it approved, and getting the key onto the host is a manual, error-prone, out-of-band dance.
3. **Cert rotation** — machine certs and the CA cert expire; rolling them across a live fleet with no downtime is painful and easy to get wrong.
4. **Firewall management** — the per-host firewall lives in each `config.yml`; there's no central, auditable source of truth.

**Design objective:** a central system (**Harbor**) + a host agent (**Pilot**, a parent process that launches `nebula` as a subprocess) that automates enrollment, approval, IP assignment, key issuance, firewall policy, and rotation — **with security as the paramount constraint**, and with AWS/Azure infrastructure woven into the trust model via cloud-native attestation and KMS-backed signing. The control plane is internet-reachable and therefore assumed to be **under constant attack**; the design minimizes and hardens that public surface rather than merely shielding it.

### Locked design decisions

| Decision | Choice |
|---|---|
| Enrollment trust | **Cloud attestation + fallback** — AWS sigv4/STS + IID cross-check, Azure IMDS attested data; one-time tokens / OIDC device flow / manual approval for laptops & on-prem |
| CA custody | **Single AWS KMS CA** — P256, Nebula cert **v2**, key non-exportable, signing via KMS API ([`nebula-cert-kms`](https://github.com/NebulaOSS/nebula-cert-kms) pattern), in an **isolated PKI account** |
| Firewall policy | **Harbor is the source of truth** — Pilot renders `config.yml` firewall section and reverts local drift |
| Management plane | **Over the mesh** — only enrollment is public; renew/config/heartbeat/admin run inside Nebula (with an out-of-band admin break-glass, §10) |

## 2. Security principles (paramount — read first)

These constraints shape every flow below. If a feature conflicts with one of these, the principle wins.

- **P1 — Private keys never move.** Each host generates its own Nebula keypair locally; the private key never leaves the host and is never seen by Harbor. Pilot sends only the **public key** + attestation; Harbor returns a **signed certificate**. (Nebula explicitly supports [signing certs from a public key](https://nebula.defined.net/docs/guides/sign-certificates-with-public-keys/).)
- **P2 — The CA key is non-exportable.** The CA private key lives in **AWS KMS** (P256), in an isolated PKI account. Harbor can call `KMS:Sign` but cannot export the key, edit its policy, or delete it. Every signature is logged in CloudTrail.
- **P3 — Control plane is on the management path, not the data path.** Nebula's data plane is fully peer-to-peer. **Harbor being down must never drop existing tunnels.** Pilot operates from cached cert/config and only *needs* Harbor to enroll, renew, or change policy.
- **P4 — Short-lived everything.** Host certs are short-lived (default ~30 days, renewed at ~⅔ life; lighthouses/servers can be longer). Short lifetimes make revocation mostly unnecessary and shrink the blast radius of any leaked key.
- **P5 — Attestation is challenge-bound where the platform allows, compensated where it doesn't.** Azure attested data and AWS sigv4 requests carry a Harbor nonce directly. The AWS IID **cannot** carry a nonce (static document) — it is only ever a *secondary* check, never sufficient alone (§6.1).
- **P6 — Least privilege & separation.** The only component with `KMS:Sign` is a minimal **Signer**, not the whole API. Privileged group grants, policy publishes, bulk revocations, and release signing all require **dual control** (two approvers).
- **P7 — Everything is audited, append-only, tamper-evident.** Every enrollment, approval, signature, policy change, and revocation → **hash-chained** append-only log shipped to SIEM + object-lock storage. KMS use → CloudTrail.
- **P8 — Fail closed on identity, fail open on availability.** Refuse to issue/renew on any attestation or signature failure (closed). Never tear down a working data plane because Harbor is unreachable (open).
- **P9 — Minimize the public surface.** Exactly two pre-auth endpoints exist (`/nonce`, `/enroll`) on an isolated, stateless gateway; everything else — Harbor Core and the admin plane — is reachable **only over the mesh**. Cloud VMs enroll over private endpoints, taking even the gateway off their path.
- **P10 — The fleet must not be able to sever itself.** Policy compilation, blocklist, and revocation all enforce invariants (control-plane and lighthouse reachability can never be removed) and roll out staged with automatic rollback.
- **P11 — No bespoke crypto.** Use standard constructs only — sigv4 as-is, **JWS/COSE** for every signed envelope (config bundles, policy, commands), HKDF/HMAC for nonces. No hand-rolled signature schemes or envelope formats. The enrollment protocol gets an external review before it carries production trust (§13).

### 2.1 Trusted Computing Base (the irreducible trust roots)

Everything else is derived. A reader should see the whole trust surface here:

| Root of trust | What it protects | Custody |
|---|---|---|
| **AWS KMS — host CA key** | every host identity | non-exportable KMS, isolated PKI account, deletion-protected, dual-control governance |
| **AWS KMS — config/policy signing key** | what every Pilot will *apply* | same custody as CA; **co-equal in importance** |
| **Pilot/nebula release-signing key** | the code itself (worst-case = fleet RCE) | KMS/HSM-backed, **dual-control signing**, treated identically to the CA |
| **Gateway identity pin** | bootstrap trust of first contact | baked into Pilot image; rotation path via update channel |
| **AWS/Azure attestation roots** | who may auto-enroll | vendor PKI; pinned + refreshed out-of-band |
| **IdP (OIDC)** | human/laptop enrollment only | external; scoped to lower-trust device class (§4.1b) |

Compromise of any single root above is a top-severity event with a dedicated runbook (§10). The release-signing key is **co-equal with the CA** and must not be treated as a mere CI secret.

## 3. Architecture

```
        INTERNET                                 │            MESH-ONLY (Nebula overlay)
                                                 │
  ┌──────────────────────────┐                   │   ┌─────────────────────────────────────────┐
  │  ENROLLMENT GATEWAY      │                   │   │  HARBOR CORE  (runs Pilot+nebula itself, │
  │  /v1/nonce  /v1/enroll   │── vetted, queued ─┼──►│  group: control-plane)                   │
  │  stateless, no DB creds, │   requests only   │   │  IPAM · policy compiler · approvals ·    │
  │  no KMS access, sandboxed│                   │   │  renew/config/heartbeat APIs · admin API │
  │  parsers, rate-limited   │                   │   │  Postgres · Signer* ─┐                   │
  └──────────▲───────────────┘                   │   └──────────────────────┼──────────────────┘
             │ public TLS (laptops/on-prem)      │            mesh tunnels   │ cross-acct assume-role
             │ PrivateLink / Private Endpoint    │                   │       ▼
             │ (cloud VMs never touch internet)  │         ┌─────────┴──┐  ┌────────────────────────┐
  ┌──────────┴────────┐         out-of-band      │         │ PILOT      │  │ ISOLATED PKI ACCOUNT   │
  │  new, un-enrolled │         admin break-glass │        │  └ nebula   │◄►│ KMS: CA key,           │
  │  host (bootstrap) │         (SSM, §10) ──────────────► │            │  │ config-signing key     │
  └───────────────────┘                          │         └────────────┘  │ SCP: no delete/policy  │
                                                 │         ... fleet ...    └────────────────────────┘
```

- **Enrollment Gateway (public)** — the *only* internet-facing component. Stateless, minimal, hardened (§4.0). Holds no DB credentials and no KMS permissions; its only outbound capability is publishing shape-checked candidates to an internal queue. Full gateway compromise yields the ability to *submit* enrollment requests into the same vetted pipeline — nothing more. (It does hold a queue-publish credential and the nonce HMAC key; neither lets it mint identity, since Core re-validates all attestation. Stated plainly so "privilege-free" isn't overclaimed.)
- **Harbor Core (mesh-only)** — API tier + Postgres + minimal **Signer** (sole holder of `KMS:Sign`, via cross-account role into the PKI account). Itself a Nebula node in group `control-plane`. Renewals, config distribution, heartbeats, and admin are reachable **only over the mesh** — for an enrolled host the Nebula tunnel *is* the authentication (cert identity bound to the tunnel), backed by an out-of-band admin path for break-glass (§10).
- **Pilot** — parent process on each host: generates keypair, enrolls once (gateway or private endpoint), then conducts all management over the mesh. Supervises `nebula`, renders config, reverts drift, heartbeats.
- **Lighthouses** — ordinary Nebula nodes (stable, public UDP) with group `lighthouse`, longer cert life. *Discovery only*: a compromised lighthouse observes connection metadata and can disrupt discovery, but cannot decrypt traffic or mint identities. Availability matters (§4.9).
- **State store** — Postgres (ties to [[PgDog - Horizontal Scaling for PostgreSQL]] / [[Postgres by Example]] if it ever needs to scale).

### 3.1 Genesis & self-bootstrap (the chicken-and-egg)

Mesh-only management is circular at t=0 and whenever Core's own cert must renew. Resolve both explicitly:

- **Genesis ceremony (one-time, out-of-band):** two operators in the isolated PKI account create the CA + config-signing keys in KMS, then mint the **first lighthouse** and **first Harbor Core** certs directly with `nebula-cert-kms` (no Harbor yet exists). These bootstrap certs are short-lived and recorded in the audit log retroactively. The mesh stands up; Harbor begins issuing.
- **Harbor self-renewal (steady state):** Core cannot depend on reaching "the mesh" to renew the node that *runs* the mesh. Pilot-on-Core uses a **local self-renewal path** — it calls the Signer directly over localhost/loopback (or a dedicated in-account channel), not over a Nebula tunnel — so Core can always re-cert itself even if the overlay is degraded. This path is tightly scoped (only the `control-plane` group, only Core's own IP) and dual-logged.
- **Lighthouse renewal:** lighthouses renew over the mesh like any host, but because they're discovery-critical, Harbor force-renews them well ahead of expiry and alerts hard if any lighthouse is within 2× the renewal window of expiring.

## 4. Core flows

### 4.0 Public gateway hardening (pre-auth surface)

- **Stateless nonces:** nonce = `HMAC(k_gw, timestamp ‖ client-binding)` (HKDF-derived key), short TTL — verifiable without server state, so nonce issuance can't be a state-exhaustion DoS.
- **Strict input discipline:** hard request-size caps, aggressive timeouts, schema validation before any parsing. Attestation parsers (PKCS7/ASN.1, JWT) are the classic pre-auth vuln zone — **fuzz them in CI (§13)**, run them in a sandboxed least-privilege worker, memory-safe (Go).
- **Rate limiting & quotas:** per-IP/ASN at the edge; per-cloud-account and per-instance-id enrollment quotas at Core.
- **No information leakage:** uniform error responses; externally indistinguishable "unknown account" vs "bad signature."
- **Optional shielding:** WAF/CDN for volumetric DoS, but never let a middlebox terminate attestation-body validation.
- **Private enrollment for cloud VMs:** expose the gateway via **AWS PrivateLink** / **Azure Private Endpoint** — cloud workloads enroll without touching the internet; the public gateway then serves only the (small) laptop/on-prem population, which can additionally require OIDC (§4.1b).
- **SSRF discipline:** Core's cross-checks (STS, DescribeInstances, ARM) hit allowlisted, pinned endpoints only; attestation content never influences a URL.

### 4.1 Enrollment & attestation

```
Pilot (new host)                          Gateway → Harbor Core
  │  generate Nebula keypair (P256), keep priv local (P1)
  │  GET /v1/nonce ────────────────────────►  stateless HMAC nonce (P5)
  │  build attestation bound to nonce + pubkey hash:
  │    AWS  → sigv4-signed STS GetCallerIdentity request with
  │           X-Harbor-Nonce + X-Harbor-Pubkey-Hash inside the signature
  │    Azure→ IMDS attested data with nonce param (native support)
  │    else → one-time token  /  OIDC device-code flow (4.1b)
  │  POST /v1/enroll {pubkey, nonce, attestation, name(cosmetic), hints} ─►
  │                                         gateway: shape/size/rate checks → queue
  │                                         core verifies attestation (§6), then:
  │                                           derive GROUPS from IMMUTABLE facts only (4.3a)
  │                                           IPAM allocates IP (4.2)
  │                                           Signer validates template + circuit-breaker → KMS:Sign
  │                                         decision: cloud-attested + allow-policy → AUTO
  │                                                   else → PENDING (admin queue, over-mesh)
  │  ◄──────── {signed cert, CA bundle, JWS-signed config bundle} ─────────
  │  write cert+config (0600), start nebula, switch to mesh management (P9)
```

Key properties: identity proven by the cloud's own signature or an out-of-band human grant, never a shared secret; the **public key is bound into the attestation**, so a stolen attestation can't be replayed with the attacker's key; re-enrollment of an instance-id with an active cert is a **conflict requiring review** (legitimate rebuild vs. compromised host minting a second identity — Harbor must not guess silently). The `name` field is **cosmetic only** — IP and groups are the sole authz inputs, so a host self-selecting a name cannot matter.

### 4.1b Laptop / human-device enrollment (OIDC device flow)

Laptops use an **OIDC device-code flow** against the IdP (Pilot shows a code, human authenticates with MFA, Harbor binds device→human). Closes Nebula's "no SSO" gap and gives offboarding a hook (disable user → stop renewing their devices). One-time tokens remain only for headless on-prem boxes. **Note:** this puts the IdP in the TCB for the laptop device-class (see §2.1, §7).

### 4.2 IP address management (IPAM)

- Harbor is the **authoritative allocator**; allocation recorded in Postgres and **bound into the signed cert** (the IP *is* the L3 identity in Nebula).
- Pool-based per network/region; deterministic reservations for infra (lighthouses, gateways, Core). Release on decommission with a **quarantine window** before reuse (avoids stale-cert confusion).
- Cross-cloud: carve sub-ranges per cloud/region for readability (AWS `100.64.0.0/17`, Azure `100.64.128.0/17`); routing stays flat in the overlay. **Pick the overlay block to avoid collisions** with k3s defaults (`10.42.0.0/16` pods, `10.43.0.0/16` services) and typical LAN ranges — hence the CGNAT (`100.64.0.0/10`) example; a `10.42.x` overlay would break a local k3s cluster's routing.
- **Ephemeral/autoscaling:** short certs + quarantine handle churn, but high-churn fleets exhaust pools and accumulate stale records fast — size pools generously and auto-reap on instance-terminated events from the cloud (§12 has the container-granularity stance).

### 4.3 Certificate issuance

- Cert profile (v2/P256): subject name (cosmetic), **single IP**, **groups**, `NotBefore`/`NotAfter`, CA = current active KMS CA.
- Signing is always `KMS:Sign` via the Signer (P2/P6). The Signer is a **policy-enforcing chokepoint, not a dumb proxy**: it validates the template (groups allowed for this device class, IP within the device's allocation, sane lifetime) before signing.
- **Signing circuit-breaker (new):** the Signer enforces a **fleet-wide issuance-rate ceiling** (certs/hour). Breach → halt-and-alarm requiring human acknowledgement. This bounds a minting-oracle Core to a small, loud burst rather than thousands of silent rogue certs — proactive, not just CloudTrail-after-the-fact.
- **Clock skew:** issue with `NotBefore = now − 5min`; Pilot monitors NTP sanity and alerts on drift (skewed clocks are the classic short-lived-cert outage).
- Issued certs recorded (fingerprint, serial, IP, groups, CA id, expiry) for rotation/revocation accounting and reconciliation (§7.1).

### 4.3a Group assignment — bind to immutable facts only (new, critical)

Groups *are* the privilege (they drive firewall reach), so deriving them safely is as important as the firewall rules themselves.

- **Never derive groups from mutable cloud metadata** — especially **EC2 tags**, which an instance role with `ec2:CreateTags` can set on *itself* → self-promotion into `group:db`/`group:admin` → lateral movement.
- Derive groups only from facts the workload **cannot self-modify**: AWS account id + IAM role ARN/path, Azure subscription + resource group + managed-identity, or **explicit Harbor-side records** keyed to the verified identity.
- Treat the attestation→group mapping with the **same dual-control rigor as firewall policy** (it's the same authority). Changes are versioned, signed, and audited.

### 4.4 Firewall policy — central source of truth

- **Baseline is default-deny** (Nebula default): no traffic is permitted except by explicit group-based allow. State this so no one ships a permissive base.
- Policy authored as **data** against **groups** (`allow group:web → group:db proto tcp port 5432`), never per-IP. Harbor compiles to the per-host firewall section (each host gets only rules relevant to its groups).
- **Compile-time invariants (P10):** compiler statically guarantees (a) every host keeps reachability to `group:control-plane`, and (b) lighthouse discovery is never blocked. Violating policy can't be published, regardless of approvals.
- **Dual-control publishes:** a policy version needs a second admin before it's signed and distributed. Blunts DB compromise — rows aren't policy until signed; Pilots verify the **JWS signature**, not the database.
- **Staged rollout with auto-rollback:** canary wave (≈5% + one host per group) → watch heartbeats → missing-heartbeat threshold auto-reverts to the previous signed version and freezes → then widen in waves.
- **Signed bundle (JWS/COSE, §P11)** verified by Pilot before apply (P8); render `config.yml`; reload Nebula. **Reload semantics caveat:** confirm in the target Nebula version which changes hot-reload via SIGHUP (firewall rules do) vs. require a brief supervised restart (cert/CA-bundle changes may) — see §12. Windows has no SIGHUP → fast supervised restart.
- **Drift control:** Pilot owns the firewall section; local edits are detected each sync and reverted; tamper attempts logged.

### 4.5 Machine cert rotation (routine)

- Pilot tracks `NotAfter`; at ~⅔ life it **renews proactively** over the mesh (the existing tunnel authenticates the request; Core checks the tunnel cert matches the device record), stages the new cert, atomically swaps + reloads.
- No re-attestation while a valid cert exists; a host whose cert has **fully expired** must re-enroll via the gateway with fresh attestation — it can no longer reach the mesh-only API (self-enforcing). Harbor-Core itself uses the local self-renewal path (§3.1), not the mesh.
- Overlapping validity = zero-downtime. If Harbor is unreachable, Pilot keeps retrying (P3); alert on "fleet % within N days of expiry."

### 4.6 CA rotation (the hard case)

Nebula hosts trust a **bundle** of CA certs, which is what makes online rotation possible:

1. **Mint CA2** in KMS (new key/ARN), status `staged`.
2. **Distribute trust first:** push `[CA1, CA2]` to **every** host; confirm 100% via heartbeat. (Trust before you sign.)
3. **Cut over signing:** active CA → CA2. New enrollments/renewals sign with CA2; CA1 certs keep working.
4. **Drain:** certs migrate to CA2 as they renew; Harbor tracks active certs per CA; force-renew stragglers.
5. **Retire CA1:** once no active cert is CA1-signed **and** CA1 certs have expired, push `[CA2]` and schedule CA1 deletion (waiting period; deletion alarms).

Invariant: overlap window > **max host-cert lifetime**. CA lifecycle is a state machine (`staged → active → draining → retired`); a CA with live dependents cannot be retired. The same machinery covers **emergency rotation** (suspected CA compromise) — step 4 becomes a forced mass re-issue and CA1 is distrusted immediately, accepting tunnel churn. The **config-signing key** rotates by the identical dual-key-overlap method.

### 4.7 Revocation & offboarding — and why it actually works

- Primary mechanism is **short lifetimes** (P4): deprovision = stop renewing; the cert ages out. For human-bound devices, IdP disablement halts renewals.
- **Immediate kill uses Nebula's blocklist (by fingerprint) — enforced peer-side.** This is the key correctness point: a *compromised* host won't honor an order to block itself (Pilot is the attacker's now). The control works because **every other node refuses to handshake with a blocklisted fingerprint**. So the SLO that matters is **propagation latency to the healthy fleet**, not to the target. (Verify your Nebula version enforces blocklist at handshake time.)
- **Revocation/blocklist is itself a fleet-DoS vector (P10):** a malicious or fat-fingered mass-blocklist/mass-revoke can take the fleet down. Therefore: you **cannot blocklist `group:control-plane` or lighthouses** (invariant), and **bulk revocation requires dual-control + rate limiting**.
- Decommission also revokes the device's enrollment so a wiped/rebuilt host must re-attest from scratch. Freed IP returns to IPAM after quarantine.

### 4.8 Harbor's own keys (custody & rotation)

- **Config/policy signing key** — KMS-backed, non-exportable, distinct from the CA, **co-equal in importance (§2.1)**. Pilots pin the public key; rotate by dual-key overlap (`[K1pub, K2pub]` → cut over → retire).
- **Gateway nonce HMAC key** — short-lived, auto-rotated (overlapping), held only by gateway + Core.
- **Gateway TLS cert** — public PKI (ACME); Pilot pins gateway identity for bootstrap, with a rotation path baked into the update channel.
- **Release-signing key** — see §2.1/§5; KMS/HSM + dual control.

### 4.9 Lighthouse availability

Lighthouses are public UDP and thus DDoS/reflection targets; degraded discovery hurts the whole mesh. Mitigations: **multiple lighthouses** (ideally anycast / multi-region), edge rate limiting, minimal dedicated hosts. Crucially, **established tunnels survive lighthouse loss** (P3-adjacent) — lighthouses are needed to *form new* connections and recover paths, not to sustain existing ones.

## 5. The Pilot agent (wrapper) design

- **Process model:** Pilot is the parent/supervisor; `nebula` is the child (start, liveness, exponential-backoff restart, signal forwarding). Pilot is what systemd/Windows-Service supervises.
- **Binary integrity & supply chain:** Pilot verifies the `nebula` binary **digest** before every exec. Pilot + nebula ship as **signed releases** (sigstore/cosign); the **self-update channel verifies signatures and rolls out in waves**. The update channel + release-signing key are the single highest-value supply-chain target (§2.1, §7) → dual-control release signing, KMS/HSM custody.
- **Files it owns:** host private key (`0600`), host cert, CA trust bundle, pinned Harbor public keys, `config.yml`.
- **Reload vs restart:** firewall/policy → SIGHUP (Unix) / fast restart (Windows); cert/IP/interface → coordinated staged restart (verify reload semantics, §12).
- **Heartbeat (over mesh):** versions, cert fingerprint+expiry, applied policy version, drift, clock-sanity, optional posture facts, health. Drives expiry dashboards, canary decisions, detections (§7.1). The **command channel back to Pilot is narrow and typed** (renew / apply config N / restart) — never arbitrary execution.
- **Offline resilience (P3):** fully functional from cache when Harbor is down; never tears down the data plane.
- **Least privilege:** `CAP_NET_ADMIN` only; dedicated service account; no long-lived secrets (auth = attestation at bootstrap, then the mesh tunnel).
- **Container note:** IMDSv2's default hop limit of 1 breaks metadata access from containers — containerized Pilots need hop limit 2 or host-network mode; see §12 for identity granularity.
- **Posture hooks (future):** Harbor can gate *renewal* on posture (disk encryption, patch level), turning cert lifetime into a compliance lever.

## 6. AWS / Azure integration specifics

### 6.1 AWS attestation (IID alone is insufficient)

The IID is **static**: no nonce, and `pendingTime` is launch — not request — time, so an exfiltrated IID+PKCS7 replays for the instance's life. Therefore:

- **Primary:** Vault-pattern **sigv4-signed `sts:GetCallerIdentity`** with `X-Harbor-Nonce` + `X-Harbor-Pubkey-Hash` folded into the signature using the instance role's credentials; Core executes/validates it (AWS vouches for the signer). Nonce+pubkey binding defeats replay and key-substitution. Requires each instance to carry *an* IAM role; allowlist on account + role path.
- **Secondary:** IID/PKCS7 vs AWS regional certs to bind the specific instance-id, plus `ec2:DescribeInstances` (running state, expected account/region — **not** mutable tags for authz, §4.3a).
- **Hard rule:** one active enrollment per instance-id; conflicts alert, never auto-issue.

### 6.2 Azure attestation

IMDS attested data **natively supports a client nonce** — Pilot passes the Harbor nonce; Core validates the signature chain to the Azure intermediate CA (handle Azure's documented cert-chain rotations), checks `subscriptionId`/`vmId` allowlist, optional ARM cross-check. Pin and refresh Azure signing roots out-of-band.

### 6.3 KMS-backed CA + account isolation (new)

- CA + config-signing P256 keys live in an **isolated PKI AWS account**. The Signer (in the Core account) assumes a tightly-scoped cross-account role limited to `KMS:Sign` + `KMS:GetPublicKey` on those ARNs. The PKI account's **SCPs forbid key deletion and key-policy edits** to everyone, so even a Core compromise can request signatures (bounded by the circuit-breaker) but cannot alter the key's governance.
- Cert v2 required (KMS can't do Ed25519 — P256 only). Reuse [`nebula-cert-kms`](https://github.com/NebulaOSS/nebula-cert-kms) / [PKCS#11 support](https://github.com/slackhq/nebula/pull/1153).
- **DR:** multi-region KMS keys (or a warm-standby CA staged in every trust bundle); a regional KMS outage shorter than cert lifetime is tolerable (P3), but the CA must survive region loss. Deletion-protection on; alarm on any `ScheduleKeyDeletion`.
- **Cloud-agnostic by design:** the same trust model spans Azure and AWS, fitting a "private networking + authenticate all client-to-server calls" goal without per-host manual cert ops.

## 7. Threat model (summary)

| Attacker / event | Vector | Controls |
|---|---|---|
| Internet attacker | Public gateway (pre-auth parsers, DoS) | P9 split; stateless nonces; size/rate caps; fuzzed sandboxed parsers; WAF; quotas (§4.0) |
| Stolen AWS IID | Replay to enroll rogue node | sigv4 primary w/ nonce+pubkey binding; one-enrollment-per-instance-id; quotas (§6.1) |
| Self-promoting instance | Set own EC2 tags → escalate groups | groups bound to immutable facts only, never tags (§4.3a) |
| Compromised enrolled host | Lateral movement; second identity; won't self-block | default-deny group-scoped firewall; re-enroll conflict alerts; short certs; **peer-side** blocklist; binary digest checks (§4.7) |
| Compromised Gateway | — | no DB/KMS creds; only submits vetted enrollment requests; Core re-validates everything |
| Compromised Harbor Core | Minting oracle; bad policy; mass-revoke DoS | Signer template validation + **circuit-breaker**; dual-control on groups/policy/bulk-revoke; PKI-account SCPs; CloudTrail + detection catalog; P10 invariants |
| Compromised DB | Forge devices/policy | nothing trusted unsigned — Pilots verify JWS/KMS signatures, not rows; dual-control publish; audit hash-chain breaks on tamper |
| Compromised lighthouse | Metadata; discovery disruption/DoS | discovery-only (no decrypt/mint); multiple/anycast; established tunnels survive (§4.9) |
| Compromised update channel | **Fleet-wide RCE (worst case)** | signed releases, dual-control release signing, waved rollout w/ health gates (§5) |
| CA / config-key compromise | Total identity / arbitrary config | non-exportable KMS in isolated account; emergency rotation (§4.6); deletion alarms |
| Compromised IdP | Rogue laptop enrollment | scoped to low-trust laptop class; MFA; device→human binding revocable (§4.1b) |
| Insider admin | Quiet escalation | dual control; tamper-evident audit; admin mesh-only + IdP MFA + out-of-band break-glass (§10) |

### 7.1 Detection catalog (concrete — replaces "anomaly detection")

Build these specific detections, each wired to an alert:

- Cert issued for a **group a device-class has never held**.
- Enrollment from a **never-before-seen account/subscription**.
- **Signing rate** over rolling baseline (and the circuit-breaker trip itself).
- **Audit hash-chain break** (tamper).
- Same **instance-id enrolling twice** (active-cert conflict).
- **Policy/blocklist/group-map change outside a change window** or without two approvers.
- **Issued-cert reconciliation:** periodic diff of issued certs vs. live cloud inventory (AWS/Azure APIs) → flag certs with no matching running instance.
- Any **`ScheduleKeyDeletion`** or KMS key-policy change in the PKI account.
- Lighthouse heartbeat loss / cert nearing expiry.

## 8. Data model (Postgres, sketch)

- `devices` — id, type (ec2/azurevm/laptop/server/lighthouse/core), cloud, account/subscription, instance/vm id, owner (human id for 4.1b), status, created.
- `enrollments` — id, device_id, method (sigv4/azure/token/oidc), nonce, attestation_blob (encrypted, retention-limited), result, approver(s), ts.
- `certificates` — id, device_id, nebula_ip, groups[], ca_id, not_before, not_after, fingerprint, serial, status.
- `ip_allocations` — ip, network, device_id, allocated_at, released_at, quarantine_until.
- `group_map` — version, immutable-fact-selector → groups[], approvers[2], signature, ts (the §4.3a authority, versioned like policy).
- `policies` — version, content, invariant_check_hash, approvers[2], jws_signature, ts; `policy_versions_applied` per host.
- `revocations` — fingerprint, reason, approver(s), bulk?, ts.
- `keys` — id, kms_key_arn, purpose (host-ca/config-signing/release-signing), curve, state, not_before, not_after.
- `audit_log` — append-only, **hash-chained** (prev-hash per row); actor, action, target, before/after hash, ts; → SIEM + object-lock.

## 9. API surface

**Public (Enrollment Gateway only):**
- `GET  /v1/nonce` → stateless HMAC challenge.
- `POST /v1/enroll` {pubkey, nonce, attestation, name, hints} → `{cert, ca_bundle, config}` or `{status: pending, id}` (pollable).

**Mesh-only (Harbor Core; authn = Nebula tunnel identity vs device record):**
- `POST /v1/certs/renew` {new_pubkey} → new cert.
- `GET  /v1/config` → JWS-signed bundle (CA bundle, firewall policy, lighthouses, settings, blocklist).
- `POST /v1/heartbeat` {versions, cert expiry, policy version, drift, clock, posture} → ack / typed commands.
- **Admin API/UI** (mesh-only + IdP SSO + MFA; RBAC; dual-control on privileged ops; reachable out-of-band for break-glass, §10): approve/deny enrollment, set group-map, author/publish policy (two-person), CA/key rotation, revoke device (bulk = dual-control), break-glass ops.

## 10. Runbooks (must exist before production)

- **Genesis** — the §3.1 ceremony; two operators, isolated PKI account, retroactive audit entry.
- **Out-of-band admin break-glass (new):** admin is normally mesh-only, so a dedicated non-Nebula path into Harbor Core must exist — **SSM Session Manager / a bastion in the Core account** — for when the mesh itself is degraded (bad push, lighthouse outage, Core cert lapse). You cannot rely on fixing the network over the network it provides. Every use alarms and is dual-operator.
- **Break-glass enrollment** — Harbor down, host must join now: manual `nebula-cert-kms` signing, two operators with separate IAM roles, loud alarm, reconciled afterward.
- **Host compromise** — blocklist fingerprint → push signed bundle to the **healthy fleet** → quarantine IP → revoke enrollment → forensics on heartbeat/audit.
- **Harbor Core compromise** — freeze the Signer (revoke its cross-account session), audit CloudTrail for all signatures in window, reconcile issued certs vs. inventory, mass-renew if needed; gateway + data plane unaffected (P3/P9).
- **CA / config-key compromise** — emergency rotation (§4.6 immediate-distrust variant); communicate tunnel churn.
- **Policy incident** — auto-rollback already triggered (§4.4); manual republish of last-known-good signed version; invariants kept control-plane reachable.

## 11. Build roadmap

- **Phase 0 — Foundations.** Isolated PKI account + KMS CA + config-signing key; **genesis ceremony**; cert v2 profile; Signer (with circuit-breaker) proven via `nebula-cert-kms`; lighthouses; CIDR plan; **gateway/core split designed in from day one**.
- **Phase 1 — Pilot + token enrollment (MVP).** Wrapper supervises nebula (binary digest checks from day one); local keypair; token enroll via gateway; KMS signing; IPAM; mesh-based proactive renewal + Core self-renewal path. *Kills pains #1–3.*
- **Phase 2 — Cloud attestation.** AWS sigv4 + IID cross-check, then Azure attested data; PrivateLink/Private Endpoint; group-map from immutable facts.
- **Phase 3 — Central firewall policy.** Policy-as-data; default-deny; invariants; dual-control publish; JWS bundles; canary + auto-rollback; drift revert. *Kills pain #4.*
- **Phase 4 — CA & key rotation.** Multi-CA trust bundles; CA/config/release-key lifecycle state machines; **rotation drill actually run in staging**.
- **Phase 5 — Hardening & scale.** OIDC device flow; posture-gated renewal; detection catalog (§7.1) wired to SIEM; HA Harbor; signed waved self-update; parser fuzzing; gateway pentest; protocol review (§13).

## 12. Open questions / risks

- **Endpoint trust limits.** Local root can tamper with Pilot or read the host key; attestation + short certs + binary digest checks mitigate, not eliminate. Consider TPM-backed key storage when Nebula supports it.
- **Platform coverage.** Pilot targets **Linux + Windows first-class** (Windows-heavy fleet) and **macOS** for laptops; each needs its own service model, key-at-rest protection (POSIX modes / Windows DACL+DPAPI / macOS Keychain), and code-signing (sigstore + **Authenticode** + **notarization**) — see implementation plan M1.10–1.12. **Mobile (iOS/Android) is out of scope for Pilot**: use Nebula's own apps with an MDM-driven enrollment story — open question how that ties into Harbor attestation/groups.
- **Container / autoscaling granularity.** The model is VM-centric. Per-container Nebula identity is likely the wrong granularity — prefer **per-host Pilot with containers sharing the overlay**, unless per-workload isolation is truly required. High-churn fleets stress IPAM/quarantine; auto-reap on terminate events.
- **Nebula reload semantics — RESOLVED (Nebula v1.10.3, M1.8, 2026-06-12).** Read from `pki.go`/`firewall.go`/conn/tun reload paths and confirmed live (SIGHUP to a running node hot-reloaded a firewall change with **no process restart**, verified by stable PID + "Caught HUP, reloading config" + the new rule appearing). **Hot-reloads via SIGHUP:** firewall rules, lighthouse/static_host_map, punchy, logging, **and the PKI cert + CA bundle** — so a normal renewal (same overlay networks, same curve) reloads with **zero restart**. **Requires a restart:** `listen.host`/`listen.port`, `tun.dev`, a cert whose overlay networks or curve changed, or a cipher change (reload silently keeps the old cipher). Windows has no SIGHUP → all changes go through a fast supervised restart. This is implemented as `internal/reconcile.Classify`/`Apply` over the supervisor's `Reload`/`Restart` primitives; the zero-downtime claims in 4.4/4.5 hold for the reload-eligible set above.
- **Residual minting-oracle risk.** Even with template validation + circuit-breaker, a compromised Core can issue *plausible* certs within the rate ceiling. Reconciliation (§7.1) is the realistic backstop; accept and monitor.
- **sigv4 dependency.** Requires every AWS instance to have *an* IAM role (even permission-less). Confirm fleet-wide; some spot/legacy launch paths lack one.
- **Stack:** **Go** for Harbor and Pilot (matches Nebula; can import `github.com/slackhq/nebula/cert`; static binaries). Postgres for state.
- **Build vs buy:** overlaps **Defined Networking's** managed plane. The mesh-only management plane + KMS custody + account isolation are the deciding lens — verify whether their product can meet them before building.
- **Cert v2 / PKCS#11 — VALIDATED (M0, 2026-06-11).** A SoftHSM-held **P256** CA signs working Nebula certs via `nebula-cert` built `-tags pkcs11` (build pinned to the runtime nebula version; nebula 1.10.3 already defaults to cert v2). The AWS KMS path is the same shape, different backend. Flow: host `keygen` locally → CA `sign -pkcs11 -in-pub` (host key never leaves the host). Any legacy Ed25519/v1 nodes must move to v2 before KMS/HSM signing.

## 13. Security assurance (how we gain confidence)

Net-new + security-paramount ⇒ make assurance explicit and tracked, not scattered:

- **Threat-model-driven tests** — a test case per row of §7 / detection in §7.1.
- **Parser fuzzing in CI** — PKCS7/ASN.1/JWT attestation parsers, continuously.
- **External protocol review (P11)** — independent review of the enrollment/attestation/signed-envelope protocol *before* it carries production trust; no hand-rolled crypto (use sigv4, JWS/COSE).
- **Rotation drills in staging** — CA, config-key, and release-key rotations executed for real, including the emergency-distrust path.
- **Runbook tabletops** — walk every §10 runbook, especially genesis and the two break-glass paths.
- **Gateway pentest** — the public surface, before exposure.
- **CloudTrail/SIEM validation** — prove each §7.1 detection actually fires in a drill.

## Sources

- [Nebula docs — PKI](https://nebula.defined.net/docs/config/pki/) · [Sign certificates with public keys](https://nebula.defined.net/docs/guides/sign-certificates-with-public-keys/) · [Upgrade to cert v2](https://nebula.defined.net/docs/guides/upgrade-to-cert-v2-and-ipv6/)
- [nebula-cert-kms (AWS KMS signing)](https://github.com/NebulaOSS/nebula-cert-kms) · [PKCS#11 support PR](https://github.com/slackhq/nebula/pull/1153)
- [AWS — verify instance identity document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-pkcs7.html) · [Azure IMDS attested data](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [Vault AWS auth method (sigv4 GetCallerIdentity pattern)](https://developer.hashicorp.com/vault/docs/auth/aws)
