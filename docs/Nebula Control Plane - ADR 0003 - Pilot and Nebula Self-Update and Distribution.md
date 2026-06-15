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
  - ✅ **1a** — bundle carries `nebula_version`/`nebula_sha256`/`nebula_url`, threaded through
    Harbor (coreapi + enrollment + flags); the sha rides inside the signed payload (no new
    trust root).
  - ✅ **1b** — `internal/nebulaupdate`: reads the desired version from the current bundle and,
    when the on-disk binary's sha differs, fetches the url, verifies the sha, atomically
    installs (keeping `<path>.last-good`), and triggers a supervised `Restart`; wired into
    `pilot supervise` as a loop alongside renew/drift/heartbeat. No-ops when the bundle pins
    no version (back-compat) and on Windows (deferred to Phase 3). Tested: install / idempotent
    no-op / keep-last-good / sha-mismatch-refused.
  - ✅ **1c** — the desired nebula version is a per-host **rollout target** on a dedicated
    `nebula` lane (its own track, parallel to policy/blocklist), not applied immediately. A
    `nebula_versions` **registry** (gen → version/sha256/url) is the catalog (`harbor nebula
    add`/`list`); `harbor nebula release -gen N` stages gen N over the prior gen across the
    fleet (canary → widen → auto-rollback). `coreapi.assembleBundle` stamps each host the tuple
    for **its** staged gen (in-wave → target, else prev; gen 0 → unpinned), so the canary is
    real; the pilot reports its **running** nebula version each heartbeat (`nebula -version`),
    The pilot reports its running binary's **sha256** (the convergence key — the artifact's
    own identity, which the pilot already verifies) plus the version string (fleet display);
    Harbor maps the sha back to a gen (`applied_nebula_version`) to drive convergence + auto-
    rollback. Keying on the sha — not the version string — is deliberate: it's unambiguous
    across rebuilds that share a semver, and it reflects what the host is *actually* running,
    so a failed swap that reverted to last-good reports the prev gen and the lane correctly
    rolls back instead of false-converging (which a bundle-carried generation number would
    do). New hosts enroll on the current settled gen (`NebulaReleaseFor`). Falls back to the
    static `-nebula-version` config when no release/rollout is configured (1a/1b back-compat).
    Tested: per-host staging (in/out-of-wave/non-member), unpinned + static fallback, engine
    stage→converge→revert, sha↔gen mapping, running-binary reporting. **Note:** a host that
    enrolls *mid-rollout* (not in the wave set) holds on the prev gen and converges to the
    completed target at its next renewal (same as any host offline during the rollout); it is
    never permanently stranded (the completed state stamps the target for all hosts).
  - ✅ **pilot-local rollback (1c safety layer)** — after a swap + `Restart` the pilot verifies
    the new nebula actually came up and **held** (`supervisor.WaitHealthy`, sustained uptime of
    a child started *after* the restart — guarding the async-restart race); if not, it reverts
    to `<path>.last-good` and **quarantines** the bad sha so it can't crash-loop. This recovers
    a host whose new binary would isolate it from the mesh — the failure Harbor's fleet
    rollback structurally **can't** reach (Core is mesh-only, so an off-mesh host can't be
    commanded). `install`/`revert` are crash-safe (copy + atomic swap; `<path>` is never left
    missing, even on a failed first install). Layered *under* Harbor's fleet rollback, which
    handles the reachable-but-unhealthy case + stops the rollout widening. Tested incl.
    first-install failure, ctx-cancel-skips-revert, and the restart-race freshness guard.
- ✅ **Phase 2 — single-binary bootstrap.** `go:embed` a known-good nebula in pilot; first
  run materialises + verifies + supervises it; Phase 1 distributes newer versions thereafter.
  **Implemented:** `internal/nebulaboot` materialises the embedded binary on `pilot supervise`
  start when no nebula exists at the path (atomic write + sha-verify; no-op once a binary is
  present, so Phase 1 owns updates from then on). The binary is gated behind the `embed_nebula`
  build tag (`embed_on.go`/`embed_off.go`) and fetched per-GOOS/GOARCH at build time (`make
  embed-nebula` → gzipped, gitignored asset; `make pilot-embedded` builds with the tag) — the
  default `go build ./...` embeds nothing and needs no asset. Offline first-boot, and it gives
  the Phase 1c local revert a guaranteed last-good (a host can never be left with no nebula).
  Tested: materialise-when-missing / no-op-when-present / no-embed-no-op; both build modes
  compile.
- **Phase 3 — pilot self-update.** Re-exec + nebula-pidfile re-adopt (zero drop) + last-good
  auto-revert, with the desired-pilot-version generation driven by the rollout engine.
  Optionally add the `pilot launch` watchdog as a recovery anchor.
  - ✅ **3a — supervisor adopt-PID mode** (the load-bearing primitive). Launched with
    `AdoptPID`, the supervisor monitors an already-running nebula it did NOT fork (signal-0
    liveness poll — it can't `Wait()` a non-child; stop/reload by PID), and falls through to
    normal fork supervision when that process exits or a restart is requested. So a
    re-exec'd pilot re-adopts the nebula the previous pilot left running — zero data-plane
    drop. Unix-only (Windows stubs → self-update there degrades to an SCM restart);
    `Health`/`Reload` are dual-mode. Tested: adopt→fork-on-death, restart-stops-adopted-
    then-forks, shutdown-stops-adopted (reparented-orphan stub so signal-0 reflects real
    death). Cross-compiles for windows.
  - ✅ **3b — the re-exec + last-good revert mechanism** (✅ **live-validated 2026-06-15** on a real macOS/launchd host — see the validation note below). The
    `pilotupdate` package: `Apply` re-reads the running nebula PID (defers if it's gone — no
    fork-fresh drop), **arms** the pidfile + a pending-revert marker (deadline = now + confirm
    window) *before* swapping the binary (so a pre-swap failure never leaves an unprotected
    swapped binary), keeps `<path>.last-good`, then `syscall.Exec`s the new pilot with
    `-adopt-nebula-pid <pid>`; the new pilot re-adopts nebula (3a) and `Confirm(version)`s
    after a 30s stable window (clearing only ITS marker). `CheckRevert` at startup reverts to
    last-good if a marker is past its deadline, with a loop-breaker (already-reverted → don't
    re-exit) and a corrupt-marker guard; an *impossible* revert runs the current binary + alerts
    loudly rather than crash-looping. Wired in `pilot supervise` (`-adopt-nebula-pid` flag +
    `-pilot-version/-sha/-url` manual trigger). The `syscall.Exec` seam is injectable so the
    swap/marker/revert/pidfile/PID-lifecycle logic is unit-tested; **the re-exec itself and the
    service-restart revert are NOT unit-testable and MUST be live-validated on a real host
    before production** (a bad pilot can brick a mesh-only host). Hardened against an adversarial
    review (13 findings: arm-before-swap, defer-if-no-nebula, validate-pidfile-before-delete,
    revert loop-breaker, corrupt-marker, version-matched Confirm). The "binary won't even start"
    case still needs the optional `pilot launch` watchdog (Option B) as the immutable anchor.
    - **Service-manager interaction (resolved + one open item).** The happy-path re-exec is
      transparent to the OS: `Type=exec`/launchd track pilot's main PID, and `syscall.Exec`
      keeps the same PID, so systemd never sees an exit and never spuriously restarts. To keep
      nebula alive across a pilot CRASH (the revert path), the units must not kill the data
      plane when pilot dies: **systemd `KillMode=process`** (was `mixed`) + **launchd
      `AbandonProcessGroup`** — the pilot owns nebula's lifecycle (clean stop: pilot stops
      nebula; crash: nebula survives for the auto-restarted pilot to re-adopt via the pidfile).
      Done. **Writable binary (resolved):** `ProtectSystem=strict` makes `/usr/local/bin/pilot`
      read-only, so the self-update swap would fail with EROFS. The service now runs a MANAGED
      copy at `/var/lib/pilot/bin/pilot` (under StateRoot, in `ReadWritePaths`); `pilot install`
      copies the running binary there and `ExecStart` points at it, keeping `ProtectSystem=strict`
      for everything else. (Linux-only; macOS `/usr/local` is writable.)
  - ✅ **3c — pilot-version distribution.** The trigger: the bundle carries
    `pilot_version`/`pilot_sha256`/`pilot_url`; the pilot reads its desired version from the
    verified bundle and self-updates (3b). It is **canary-staged**, not pushed fleet-wide — the
    rollout engine was generalized across lanes (`genForLane`/`currentCompletedGen`; nebula
    behavior unchanged, asserted by the existing tests) and a `pilot` lane added, the mechanical
    mirror of Phase 1c: a `pilot_versions` registry (migration 000017), `coreapi` stamps the
    per-host pilot tuple (`PilotGenFor` → in-wave target / else prev / static fallback), the
    pilot reports its **own** binary sha so Harbor maps it to a gen for convergence + auto-
    rollback, and `harbor pilot add/list/release/status/abort` drives it. New hosts enroll on
    the current settled gen. The manual `-pilot-version/-sha/-url` flags remain as an
    all-or-nothing live-test override. Reviewed (no nebula-lane regression; the loop's flag
    precedence + bundle read/verify visibility hardened). ✅ The 3b re-exec gate is now
    cleared (live-validated 2026-06-15), so a real fleet pilot rollout is unblocked.
  - ✅ **3b live validation (2026-06-15, macOS 26 / arm64 / launchd).** Drove the real
    `syscall.Exec` path standalone (no Harbor/mesh) via the `-pilot-*` override + a local HTTP
    server, adopting a stand-in process as the "nebula" (the supervisor's adopt-PID is signal-0
    liveness only, so any long-running PID proves zero-drop). Results:
    - **Happy path A→B:** the re-exec was fully transparent to launchd — same pilot PID, the job
      stayed `running` with `runs=1` / `never exited` (launchd saw no restart), the on-disk binary
      flipped to B, the adopted PID was unchanged (zero data-plane drop), and `Confirm` cleared
      the marker exactly 30s after the swap. ✅
    - **Failure path →bad:** a real-pilot binary that runs `CheckRevert` then exits non-zero
      before confirming (a test sentinel) crash-looped under launchd `KeepAlive`; at the 90s
      deadline `CheckRevert` restored `last-good`, relaunched the good binary, and it re-adopted
      the SAME stand-in — which survived the entire crash-loop + revert. ✅
    - **Recovered/settled:** with the bad version withdrawn (what Harbor's auto-rollback does),
      the pilot rested on the good binary with a stable PID and zero re-attempts. ✅
    - **Finding (open):** unlike `nebulaupdate` (which quarantines a failed sha so it won't
      retry), `pilotupdate` has **no quarantine** — so a canary pilot RE-ATTEMPTS a still-advertised
      bad version every ~confirm-window (update→crash→revert→update…) until Harbor's auto-rollback
      stops advertising it. The data plane survives every cycle (zero drop, observed), so it is
      bounded and non-fatal, but it is avoidable thrash and delays the "this host rejected the
      update" signal. Consider a pilot-side failed-sha quarantine mirroring `nebulaupdate`.
  - ✅ **Operability — Releases console (#39).** The Harbor admin UI gained a **Releases**
    page (`/releases`) listing both registries (gen / version / sha / status / added) and
    triggering a per-lane fleet upgrade to any registered gen, with canary/wave/observe
    overrides, live wave-convergence + auto-rollback state, and an abort. Backed by
    `GET /admin/v1/releases` + `POST /admin/v1/releases/{kind}/rollouts[/current/abort]`
    (`rollout:control`, read-only for viewers). **No upload UI** — binaries are still
    registered out-of-band via `harbor nebula/pilot add`; Harbor stays a pointer registry.
    The rollout host set is filtered to **live** hosts (stale ghosts can't become the
    canary and silently trip auto-rollback).
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
