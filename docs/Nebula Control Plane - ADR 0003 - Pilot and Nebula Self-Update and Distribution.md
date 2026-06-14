---
title: "ADR 0003 — Pilot + Nebula Self-Update & Distribution"
created: 2026-06-13
status: accepted
tags: [nebula, adr, pilot, supervisor, distribution, self-update, rollout, supply-chain, architecture]
---

# ADR 0003 — Pilot + Nebula Self-Update & Distribution

**Status:** Accepted (Phases 1–3 are the direction; in-process nebula deferred behind an isolation-vs-simplicity gate)
**Date:** 2026-06-13
**Decision owners:** Chris Hyde (+ a future second approver, per dual-control)

## Context

Pilot is the host agent: it supervises the nebula data-plane process and runs the
renew/heartbeat/drift loops. Today the nebula binary is an operator-supplied path with an
operator-supplied digest — `pilot supervise -nebula <path> -sha256 <hex>` — and the
**supervisor verifies that SHA-256 before every exec** (`internal/binverify`, M1.5). The
nebula version on a host is therefore whatever a system package or manual install put
there; Harbor neither chooses nor distributes it.

The goal of this ADR: make the **pilot+nebula duo self-managing via Harbor** —

1. **Harbor distributes the nebula version** we want to run, rather than relying on a
   system package.
2. **Ship a single binary (pilot)** that bootstraps nebula (both are single Go binaries).
3. **Pilot self-updates** — the hard part, because pilot is the process *supervising* the
   nebula child, so replacing pilot must not strand a host reachable only over the mesh
   pilot maintains.

The encouraging finding (as with ADRs 0001/0002): most of the machinery already exists.

- **Integrity-before-exec is built in.** The supervisor already refuses to exec a nebula
  binary whose SHA-256 doesn't match (`binverify`). The only change is *who supplies the
  expected digest* — a CLI flag today, a Harbor-signed bundle tomorrow.
- **Signed distribution + staged rollout exist.** Bundles are config-signed (the
  config-signing key is pinned in Pilot); the **rollout engine** does per-host versioning,
  **canary**, and **auto-rollback**, driven by heartbeats; `commandsFor` is the typed
  command channel (`apply_bundle`, `renew`).
- **The fleet's versions are already reported.** Each heartbeat carries `pilot_version` +
  `nebula_version`; Harbor renders the version landscape and the rollout state machine
  converges / rolls back on them.
- **Reload-vs-restart is classified** (`reconcile.Classify`, M1.8): a binary swap is not
  hot-reloadable, so it is a supervised `Restart`.

So problem 1 is a small extension of the signed-bundle + rollout machinery; problem 2 is a
packaging choice; problem 3 is the genuinely hard, high-stakes one. They are **separable**
and decided independently below.

## Decision

Treat the three as separate problems and reuse the existing **signed-bundle + rollout
(canary + auto-rollback)** machinery as the distribution/staging vehicle for all of them.
The integrity anchor is free: the bundle is config-signed, so a **`nebula_version` +
`nebula_sha256` carried in the signed bundle is authenticated without a new trust root**.

- **Distribute nebula** by putting the desired version + sha in the signed bundle and
  fetching the bytes from a signed-sha-anchored source; apply via supervised `Restart`,
  staged through the rollout engine (canary + auto-rollback).
- **Bootstrap from one binary** by **embedding a known-good nebula** in pilot (`go:embed`)
  for offline first-boot, with Harbor distributing newer versions thereafter.
- **Self-update pilot** via **re-exec + re-adopt of the running nebula** (zero data-plane
  drop), backed by a last-good auto-revert and staged through the rollout engine.

Hold the **in-process nebula** alternative (import the library, one process) as a credible
long-term simplification, **deferred** behind the isolation-vs-simplicity gate below.

Non-negotiable invariants for every distributed/updated binary: **signed-sha integrity
before exec** (have it), **staged canary + auto-rollback** (have it), **keep the last-good
binary**, **atomic swap**, and **never let a self-update strand a host reachable only over
the mesh.**

## Problem 1 — distributing the nebula version

The integrity anchor (signed sha in the bundle) is fixed; the only choice is where the
bytes come from.

| Option | How | Verdict |
|---|---|---|
| **A. Harbor/gateway serves the artifact** (content-addressed by sha) | Pilot GETs `/v1/artifact/nebula/<sha>` over the mesh (or the public gateway for first boot) | Air-gapped fallback — self-contained but puts artifact bandwidth on the control plane (better on the gateway/a sidecar than off-data-path Core). |
| **B. External object store / CDN** (S3 / infra-plan Cloudflare) | Bundle carries a URL; Pilot fetches + verifies the **signed** sha | **Chosen.** Scales, offloads bandwidth, and the source need not be trusted — the signed sha is the integrity anchor. |
| **C. Inline in the bundle** | bytes ride the bundle | Rejected — ~10–20 MB per push is far too heavy for the bundle/heartbeat channel. |

**Apply path:** a binary swap is a `Restart` (write to a versioned dir → `binverify` SHA →
atomic flip → supervisor restart), and the **desired nebula version becomes a per-host
rollout target exactly like `bundle_version`** — so canary staging and auto-rollback come
for free, and a bad nebula version reverts automatically. Keep the previous binary on disk
for instant revert.

## Problem 2 — one pilot binary that bootstraps nebula

| Option | How | Verdict |
|---|---|---|
| **A. `go:embed` a known-good nebula in pilot** | First run writes the embedded nebula (verify embedded sha) → supervise it; Harbor (Problem 1) distributes newer ones after | **Chosen.** One artifact, **offline first-boot**; pilot ~2× size; the embedded version is just the bootstrap default. |
| **B. Download on first run** | Pilot fetches nebula during enrollment over the **public** path (the mesh isn't up yet — the enroll bundle carries version+sha+url) | Viable but adds a network dependency + a bootstrap chicken-and-egg the embed avoids. |
| **C. In-process nebula** | No separate nebula binary at all | The bold alternative — see the fork. |

## Problem 3 — pilot self-update (the child-process problem)

The insight that makes this tractable: **once nebula is running it holds its tunnels
independently of pilot.** Pilot can be replaced without dropping the data plane *iff* the
update does not kill the nebula child.

| Option | Mechanic | Data-plane impact | Verdict |
|---|---|---|---|
| **A. Re-exec + re-adopt** | Pilot writes nebula's PID to a file, then `syscall.Exec`s the new pilot binary. `exec` keeps the same PID and its children, so nebula survives; the new pilot **re-adopts** it from the pidfile (monitors via signal-0 liveness; signals by PID) instead of forking a new one | **Zero** | **Chosen**, with a last-good auto-revert if the new pilot doesn't come up. Most elegant, single-binary; the supervisor gains an "adopt existing PID" mode (can't `Wait()` a non-child → poll). |
| **B. Tiny launcher/watchdog** | A minimal, ~never-changing `pilot launch` mode supervises `pilot supervise`; swaps + restarts pilot; pilot re-adopts/restarts nebula | Zero (re-adopt) / brief (restart) | **Optional belt-and-suspenders.** The launcher is an immutable recovery anchor — if a new pilot won't start, revert to last-good. Same binary, two modes. |
| **C. Hand off to systemd/SCM** | Pilot swaps the binary, asks the service manager to restart the unit | Brief blip (nebula is pilot's child → dies + relaunches) | Simplest, but a system-service dependency, a data-plane drop, and Windows needs SCM. Rejected as the default. |

Self-update is the **highest-stakes** operation — a bad pilot can brick a host that is only
reachable over the very mesh pilot maintains. So regardless of mechanic it must be:
canary-staged + auto-rolled-back (rollout engine), keep a known-good binary, atomic swap,
and time-boxed health-gated ("if the new pilot hasn't re-established heartbeat within N
seconds, revert"). The **desired pilot/nebula version + generation** mirrors the ADR-0002
**desired-vs-issued + generation** pattern almost exactly, and rides the same rollout
vehicle.

## The decision driver (the fork)

Everything long-term hinges on **child-process (isolation) vs. in-process (single
binary).**

- **Child-process model (chosen for Phases 1–3):** keeps the data plane isolated from the
  agent (a nebula crash doesn't take pilot, and vice-versa), preserves the existing
  M1.5–1.8 machinery, and lets nebula and pilot version independently. The cost is the
  self-update complexity (Problem 3) and shipping/superintending a second binary.
- **In-process nebula (deferred):** `slackhq/nebula` is importable (we already depend on
  its `cert` package) and exposes a programmatic entry returning a `*nebula.Control`. Pilot
  could run nebula in a goroutine — collapsing all three problems into "update one
  process": one binary, no digest distribution, no child-process self-update problem, and
  Harbor chooses the nebula version by choosing the pilot version. **But** it couples
  nebula↔pilot release cadence, **loses process isolation** (a nebula panic can take pilot
  down — the deliberate isolation the current design bought), needs tun/CAP_NET_ADMIN for
  the whole pilot process, and rewrites the supervise/binverify/reconcile path.

The gate: in-process is the most elegant *end state* for "single self-updating binary," but
the loss of data-plane/agent isolation is a real security and resilience regression. Adopt
it only if (a) Phases 1–3 prove the coupling is acceptable, and (b) the isolation loss is
judged worth the single-process win — neither of which is established today.

## Phased plan (lowest-risk first)

- **Phase 1 — Harbor-distributed nebula.** `nebula_version` + `nebula_sha256` in the signed
  bundle; Pilot fetches from a signed-sha-anchored source (CDN; gateway fallback), verifies,
  atomic-swaps, and `Restart`s; staged through the rollout engine (canary + auto-rollback).
  Kills the system-package dependency. Small, additive, reuses canary/rollback.
- **Phase 2 — single-binary bootstrap.** `go:embed` a known-good nebula in pilot; first run
  materialises + verifies + supervises it; Phase 1 distributes newer versions thereafter.
- **Phase 3 — pilot self-update.** Re-exec + nebula-pidfile re-adopt (zero drop) + last-good
  auto-revert, with the desired-pilot-version generation driven by the rollout engine.
  Optionally add the `pilot launch` watchdog as a recovery anchor.
- **Phase 4 — evaluate in-process nebula.** Only after 1–3 are proven; weigh the isolation
  loss against the single-process simplification (the fork above).

## Consequences

- **+** Harbor owns the nebula version fleet-wide, integrity-verified, canary-staged, and
  auto-rolled-back — no system packages, no version drift the dashboard can't see.
- **+** A single pilot artifact that works offline on first boot.
- **+** Zero-drop pilot self-update (re-exec + re-adopt), so the agent can be patched
  without touching the data plane.
- **+** Almost entirely reuses existing machinery (binverify, signed bundles, rollout
  canary/auto-rollback, heartbeat versions, the ADR-0002 generation pattern).
- **−** Self-update is the highest-stakes path in the system; it demands the full safety
  envelope (staged, health-gated, last-good revert) or it can brick mesh-only hosts.
- **−** Pilot binary grows (~2×) with an embedded nebula.
- **−** The supervisor gains an "adopt an existing PID" mode (liveness-poll instead of
  `Wait`), a new code path to test on every platform.
- **−** Distributing executables is a new supply-chain surface; the signed-sha anchor and
  last-good revert are load-bearing.

## Open questions to resolve before building

1. **Artifact source + format** — CDN vs gateway-served; content-addressed object naming;
   how the enroll (pre-mesh) bootstrap fetch is authenticated (the embed sidesteps this).
2. **A dedicated release-signing key, or reuse config-signing?** Reusing config-signing is
   zero-new-trust-root; a separate release key narrows blast radius if it leaks. Decide per
   the threat model (cf. ADR-0001's trust-model fork).
3. **Re-adopt mechanics across platforms** — pidfile + signal-0 liveness on Unix; the
   Windows path (no SIGHUP, different process model) likely degrades to a restart.
4. **Health gate for self-update** — what signal proves "the new pilot is healthy" (heartbeat
   re-established within N seconds?) and how the auto-revert is triggered without a working
   new pilot.
5. **Rollback floor** — how many last-good binaries to retain; disk budget on small hosts.
6. **In-process privilege** — running nebula in-process needs tun/CAP_NET_ADMIN for all of
   pilot; acceptable, or a disqualifier for Phase 4?

## Relationship to other work

- **Rollout engine (M6.6)** — the staging/auto-rollback vehicle for nebula *and* pilot
  versions; this ADR extends its "version" notion from bundles to binaries.
- **`binverify` (M1.5) + supervisor (M1.6/M1.8)** — the integrity-before-exec and
  reload/restart primitives this builds on directly.
- **Signed bundles (M6)** — authenticate the desired version+sha with no new trust root.
- **ADR 0002 (group reassignment)** — the desired-vs-issued + generation + rollout pattern
  is the same shape reused here for desired-version reconciliation.
- **CA/key rotation (M8)** — release-signing key custody/rotation belongs with the broader
  key-rotation story if a dedicated release key is adopted (open question 2).
