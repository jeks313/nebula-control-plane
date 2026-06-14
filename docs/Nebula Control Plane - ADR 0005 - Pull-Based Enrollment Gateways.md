---
title: "ADR 0005 — Pull-Based Enrollment Gateways"
created: 2026-06-13
status: accepted
tags: [nebula, adr, gateway, enrollment, queue, security, dmz, architecture]
---

# ADR 0005 — Pull-Based Enrollment Gateways

**Status:** Accepted (the B / out-of-mesh model is the direction; supersedes the shared-queue/Postgres split for multi-gateway)
**Date:** 2026-06-13
**Decision owners:** Chris Hyde (+ a future second approver, per dual-control)

## Context

The enrollment **gateway** is Harbor's one deliberately internet-facing surface
(ADR/posture: `internal/gateway`). It is credential-less by design — no CA, no
fleet DB — and today it hands work to Core through a **shared durable queue**
(`internal/queue/durable.go`): the gateway `Publish`es HMAC-authenticated candidates,
the Core **worker** `Claim`s/`Ack`s them and `PutResult`s the issued bundle, and the
gateway serves the host's poll via `GetResult`. There is **no direct gateway↔Core
RPC** — the queue is the only seam.

That queue is **SQLite-only** (`OpenDurable` hardcodes `sqlite.Open(dsn)`), i.e. a
local file. So the gateway and worker can only share it by living on the **same
host** (the current demo co-locates them). The moment you want a **separate**, or
**multiple**, gateway node(s), the shared queue has to become network-reachable —
which under the existing design means a shared **Postgres** both tiers connect to.
That has the public gateway open an **outbound connection *into* the protected data
tier** — the wrong trust direction for the most-exposed component, and a new
stateful dependency.

The better framing: the gateway should be a thing the protected side **pulls from**,
not a thing that **reaches in**. And because **Core already re-verifies every
candidate** (`enrollment.verify`: JWS signature, nonce, replay; then the
credential), a candidate is a self-authenticating signed object a malicious gateway
cannot forge — so the gateway can be treated as **fully untrusted** and therefore
needs **no privileged connectivity at all**.

## Decision

**Invert the transport to pull: Harbor polls a registry of gateways over mTLS; each
gateway keeps a *local* SQLite queue and initiates nothing; gateways are NOT mesh
members.**

- A **gateway registry** (mirroring `internal/lighthouse`): an admin-managed list of
  gateways — address + a pinned cert. Harbor knows whom to poll.
- A Harbor **collector loop**, Harbor-initiated only: for each registered gateway,
  *pull pending candidates → verify + issue with the CA → push results back → ack
  consumed* — over a dedicated **mTLS** channel (not the overlay). The gateway's
  Harbor-facing API accepts **only Harbor's client cert**; Harbor **pins the
  gateway's cert**. (This is defense in depth on top of per-candidate
  re-verification, which is what actually protects integrity.)
- **Per-gateway local SQLite** queue. No shared DB, no Postgres, no cross-host queue.
- The enrolling **host still polls its gateway** (public `/v1/enroll/{id}`) for the
  result, which Harbor pushed back during the collect cycle.
- **Gateways are not on the mesh.** A gateway's network posture is **inbound only**:
  `:8443` from the internet (enroll/nonce/poll) + the Harbor-poll port from **Harbor's
  source only**; **no outbound to anything.** It is a sink Harbor drains.

This **supersedes the shared-queue / Postgres-for-split-gateway direction** discussed
earlier: pull + local-SQLite removes the network-DB requirement entirely.

## The decision driver (the fork): in-mesh (A) vs out-of-mesh (B)

The goal is "the gateway initiates nothing toward the mesh." The clincher is our own
**non-removable firewall baseline**: `CompileHost` injects, for every mesh host, an
un-removable `outbound → group:control-plane` + ICMP both ways (so policy can never
sever the control plane, §6.3). Therefore:

- **A — gateway is a locked-down mesh member.** Even with a `gateway` group that has
  no user outbound rules, the **baseline still permits gateway → control-plane**. You
  cannot enforce "initiates nothing" at the firewall; you'd be relying on the gateway
  *choosing* not to use a permitted path — a "permitted-but-unused" gap. The gateway
  also holds a valid mesh cert and an overlay presence.
- **B — gateway is NOT a mesh member.** No overlay cert, no overlay reachability, the
  baseline does not apply. A compromised gateway has **zero** mesh identity and
  **zero** pivot. Harbor reaches it at its registered address over mTLS; the gateway
  reaches nothing.

**B is chosen.** The mesh's value (any-to-any encrypted reachability) isn't needed
for a gateway Harbor pulls from at a fixed address — and mesh membership *forces* the
baseline outbound that B avoids. Off-mesh + mTLS is both simpler and strictly more
contained.

## Why the gateway can be fully untrusted

A candidate is a JWS-signed enroll request bound to a single-use, key-bound nonce; a
join-key token or an attestation/SSO credential rides inside it. **Core re-verifies
all of it** (`verify` → `processToken`/`processAttested`), and a nonce is single-use
+ replay-protected. A malicious gateway therefore cannot manufacture a valid
candidate (it lacks a victim's key and a live nonce) — it can only serve garbage that
Core rejects, or withhold/replay (which the nonce + Core's idempotency absorb). The
nonce HMAC key the gateway holds is **non-load-bearing**: a nonce without a credential
enrolls nothing. So the gateway needs no trust, hence no privileged connectivity —
which is exactly what the pull/off-mesh model grants it.

## Considered options

| Option | Verdict | One-line |
|---|---|---|
| **Co-located gateway + worker, shared SQLite** | Current / single-node only | Fine for one box; can't scale to a separate or multiple gateways (SQLite is local-file). |
| **Shared Postgres queue, gateway connects in** | Rejected | Makes the most-exposed node open an outbound into the protected data tier; new stateful dependency; wrong trust direction. |
| **A — in-mesh, locked-down gateway** | Rejected | The non-removable control-plane baseline permits gateway→Core outbound — can't enforce "initiates nothing"; gateway still holds a mesh identity. |
| **B — out-of-mesh gateways, Harbor pulls a registry over mTLS, local SQLite** | **Chosen** | Protected Core pulls from an untrusted sink that initiates nothing; no shared DB; gateway has zero mesh presence. |

## The model in detail

- **Gateway (unchanged public face + new Harbor-facing API):** keeps the existing
  `GET /v1/nonce`, `POST /v1/enroll`, `GET /v1/enroll/{id}`; the durable queue stays
  but is **local** (per gateway). Adds a mutual-TLS internal API Harbor calls:
  list-pending-candidates, put-results, ack-consumed. Binds the public port to the
  internet and the internal port to Harbor's source only.
- **Harbor collector:** a loop (interval or long-poll) over the gateway registry that
  reuses the existing `enrollment.Consumer` to verify + issue, then returns results to
  the originating gateway. No worker draining a shared queue anymore — Harbor pulls.
- **Gateway registry:** an admin-managed store table + CRUD, modeled on
  `internal/lighthouse` (address, pinned cert, state), surfaced in the console and the
  CLI. Adding/removing a gateway is an audited admin action.
- **Keys:** the nonce HMAC key stays shared gateway↔Core (so Core can verify nonces
  the gateway minted). The mTLS identities (Harbor client cert + each gateway's server
  cert) are the new material; the gateway's cert is pinned in the registry.

## Phased plan

- ✅ **Phase 1 — the pull transport.** Local-per-gateway queue (drop the shared-queue
  assumption); the gateway's mTLS internal API (list/put/ack); the Harbor collector
  loop wrapping the existing `Consumer`. Single registered gateway, end to end.
  **Implemented (2026-06-14):** `internal/collect` — leaf-pinned mTLS (self-signed
  certs, no CA: `ServerTLS`/`ClientTLS` pin the peer's leaf by SHA-256, per open
  question #1's chosen answer), the gateway-side `Server` (`claim`/`results`/`ack`
  over its local `*queue.Durable`), and the Harbor-side `Collector` (claim →
  `Consumer.Process` via a `CaptureSink` → ship results back → ack; ship-before-ack
  for at-least-once). `enrollment.Config.Results` is now a `ResultSink` interface
  (`*queue.Durable` still satisfies it, so co-located mode is unchanged). Wired:
  `gateway -collect-addr/-collect-cert/-collect-key/-harbor-client-cert` (+
  `gateway collect-keygen` to mint the pinned identities) and `harbor collect`
  (replaces `enroll worker` for the split topology). *Proven:* unit
  `TestPullTransportEndToEnd` (pull → issue → ship-back → ack) + both wrong-pin
  refusals, and a real-binary check (the gateway's collect listener refuses no/
  unpinned client certs and serves the pinned Harbor client). Open questions #2–#5
  took their minimal answers (fixed-interval poll; admin-paste pin bootstrap; reuse
  the existing result-TTL; pinned-cert-is-sufficient since Core re-verifies).
- **Phase 2 — the registry.** Gateway registry store + admin CRUD (mirror lighthouse)
  + console/CLI surfaces; Harbor polls all registered gateways.
- **Phase 3 — the demo node.** A standalone public gateway EC2 (own SG: `:8443`
  public + the poll port restricted to Harbor; **not** on the mesh), registered with
  Harbor — the real public-edge/Core split, with no Postgres.
- **Phase 4 — hardening.** Long-poll for low-latency enrollment; per-gateway rate/
  depth caps + alerting; gateway health in the fleet view.

## Consequences

- **+** The internet-facing component initiates **nothing** and has **no mesh
  identity** — a gateway compromise yields no pivot, no reach into Core, only the
  ability to serve candidates Core already re-verifies. Smallest possible blast radius.
- **+** **No shared DB / no Postgres** — each gateway is self-contained (local SQLite);
  the earlier network-DB requirement disappears.
- **+** Natural **multi-gateway / horizontal scale** and geo-distribution: register N
  gateways; Harbor pulls them all. Mirrors the lighthouse-registry pattern.
- **+** The trust direction is right: the **protected** side decides when and whom it
  talks to, to allowlisted/pinned endpoints, re-verifying everything it pulls.
- **−** A real **transport change**: a new Harbor↔gateway collect protocol + mTLS + a
  registry, and reworking the queue from "shared, worker-drained" to "per-gateway,
  Harbor-pulled." (The queue ops themselves are reused; the transport changes.)
- **−** **Poll latency** on enrollment (mitigated by a short interval / long-poll).
- **−** Harbor now makes an **outbound** to each gateway's public address (the good
  direction, but a new egress path to manage + pin).
- **−** New key material to custody: the mTLS client/server certs (Harbor's + each
  gateway's pinned cert).

## Open questions to resolve before building

1. **mTLS identity source** — reuse the genesis CA for the Harbor client + gateway
   server certs (zero new root) or a dedicated gateway-PKI? (Same fork as ADRs 0003/0004.)
2. **Poll cadence vs. long-poll** — fixed interval (simple) vs. long-poll (low-latency
   enrollment); the host's own poll interval interacts with this.
3. **Registry trust bootstrap** — how a gateway's pinned cert first enters the registry
   (admin paste vs. a TOFU-with-confirm enrollment of the gateway itself).
4. **Result retention / cleanup** on the gateway (a host may never return to poll) —
   TTL on local results, and Harbor's ack semantics for at-least-once delivery.
5. **Gateway authenticity to Harbor** — pinned cert is enough given Core re-verifies
   candidates; confirm no scenario needs more (it shouldn't — candidates are
   self-authenticating).

## Relationship to other work

- **Enroll security posture doc** — this strengthens it: the public surface moves from
  "credential-less but co-located" to "credential-less, off-mesh, initiates nothing."
  Fold this model in when revising that doc.
- **`internal/queue/durable.go`** — stays the queue engine, but **local per gateway**;
  the SQLite-only limitation becomes a non-issue (no cross-host sharing needed).
- **`internal/lighthouse` registry** — the template for the gateway registry (admin
  CRUD, address + pinned material, audited).
- **`internal/gateway` + `enrollment.Consumer`** — the gateway keeps its public face;
  the Consumer is reused by the Harbor collector instead of a queue-draining worker.
- **ADR 0004 (SSO enrollment)** — the SSO portal is another public front; whether it
  follows the same pull/off-mesh posture is worth aligning (likely yes).
- **Non-removable control-plane baseline (policy §6.3)** — the reason A (in-mesh) can't
  enforce "initiates nothing," and thus the reason B wins.
