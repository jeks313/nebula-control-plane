# CLAUDE.md — Nebula Control Plane

Context for any future Claude Code session picking up this project cold. Read this, then read
the planning docs in the vault (below) before doing design-level work.

## What this is

A control plane for [Nebula](https://github.com/slackhq/nebula) (the open-source overlay mesh
VPN). It automates the four things stock Nebula leaves manual:

1. **IP assignment** on the overlay
2. **Certificates & joining** (enrollment + approval + key delivery)
3. **Certificate & CA rotation** across a live fleet, zero-downtime
4. **Central firewall policy** (group-based, no per-host drift)

Two components, both Go:
- **Harbor** — the central control plane (enrollment, IPAM, signing, policy, rotation, admin UI/API).
- **Pilot** — the per-host agent: a parent process that **supervises `nebula` as a subprocess**,
  generates the host keypair locally, enrolls, renews, renders config, and reverts drift.

This is a **standalone project**. Typical deployment context: mixed Linux/Windows fleets across
AWS and/or Azure that want zero-trust private networking and authenticated host-to-host calls
without per-host manual certificate ops.

## The planning docs (read these first)

In-repo copies live in **`docs/`** (self-contained; no vault needed). Originals are in Chris's
Obsidian vault `~/Data/knowledge/Plans/` — keep the two in sync; treat **this repo as
canonical** going forward. See `docs/README.md`.

- **`docs/Nebula Control Plane - Design Plan.md`** (v3) — architecture, security model, flows.
  Uses `§`/`P` refs (e.g. §4.3, P2). **Source of truth for *what* and *why*.**
- **`docs/Nebula Control Plane - Implementation Plan.md`** (v2) — milestones **M0–M9**, PR-sized
  steps with "Done when" acceptance. **Source of truth for *order* and *scope*.**
- **`docs/Nebula Control Plane - Infrastructure Plan (AWS).md`** (v2) — local-first → minimal AWS
  harness → full production tiers (incl. k3s Tier 1+).
- **`docs/Nebula Control Plane - Admin UI Plan.md`** — the Harbor web console + site settings.
- Background (vault only): `~/Data/knowledge/Interesting/Nebula - Open Source Overlay Mesh Network.md`.

Re-read them rather than trusting this summary; they evolve. (Docs use Obsidian `[[wikilinks]]`
that only resolve in the vault — they read fine as plain text here.)

## Locked design decisions (don't relitigate without the user)

- **Enrollment trust:** cloud attestation + fallback — AWS **sigv4 `GetCallerIdentity`** (IID is a
  *secondary* check; it can't carry a nonce) + Azure IMDS attested data; one-time tokens / OIDC
  device-flow / manual approval for laptops & on-prem.
- **CA custody:** a single **AWS KMS** CA, **P256, Nebula cert v2**, key non-exportable, signed via
  the `nebula-cert-kms` / PKCS#11 path, in an **isolated PKI account**. (KMS can't do Ed25519 → P256.)
- **Firewall:** Harbor is the source of truth; Pilot renders `config.yml` and reverts drift.
- **Management plane runs over the mesh** (only enrollment is public); plus an out-of-band admin
  break-glass (SSM).

## Security stance (this is a security-paramount project)

Principles P1–P11 in design §2; the non-negotiables:
- **P1** private keys never leave the host (Pilot sends a pubkey; Harbor returns a signed cert).
- **P2** CA key non-exportable in KMS; only a minimal **Signer** holds `KMS:Sign`.
- **P3** control plane is off the data path — Harbor down must never drop tunnels.
- **P11** no bespoke crypto (sigv4, JWS/COSE, HKDF only).
- **TCB roots** (§2.1): KMS **CA key**, **config-signing key**, **release-signing key**
  (co-equal — fleet-RCE risk), the gateway **pin**, AWS/Azure attestation roots, the IdP.
- The admin UI is a **thin client, never a trust root** (UI plan §2).

## Local dev approach (and how to test almost everything offline)

Strategy = **local-first** (infra plan Tiers 1 / 1+). Separate *our logic* (100% local-testable)
from *their guarantees* (AWS IAM/SCP/Shield + real AWS/Azure attestation signatures — only those
need the cloud, verified once in the minimal Tier-2 harness).

- **Data plane locally:** `nebula` in **Linux network namespaces** (no containers needed for M0).
- **KMS stand-in:** **SoftHSM2 via PKCS#11** — faithful "key never leaves the module"; Nebula's
  PKCS#11 path needs **P256/cert v2** and a `nebula-cert` built with `-tags pkcs11`.
- **Tier 1+ (k3s):** production-shaped integration env — but use **k3d / a disposable k3s**, NOT
  the user's existing cluster.
- Pluggable backends from day one (testability + cloud-agnosticism): Signer `PKCS#11|KMS`,
  AttestationVerifier `test-CA|AWS|Azure`, metadata `fake-IMDS|real-IMDS`, inventory `fake|EC2/ARM`.

## This machine (CachyOS / Arch) — environment facts

- **Go 1.26** at `/usr/bin/go`; `GOPATH=~/go`.
- **k3s + kubectl** installed (`/usr/local/bin`). **No docker, no podman, no k3d, no helm** yet.
- **No** `nebula` / `nebula-cert` / `softhsm` / `opensc` yet → install on Arch:
  `paru -S nebula` and `sudo pacman -S --needed softhsm opensc`.
  (From the Claude Code prompt, the user can run these inline with the `!` prefix.)
- `/dev/net/tun` present. Package managers: `pacman`, `paru` (AUR). Installs need sudo (interactive)
  — Claude generally can't run them; ask the user to.
- **`~/Data/nebula` is the user's REAL, running Nebula network** (live `ca.key`, host certs,
  `nebula.service`). **Never touch it.**
- This repo lives at `~/Data/Devel/nebula-control-plane`. (`~/Data` may be sync-watched — keep build
  artifacts gitignored.)

## Critical gotchas

- **Overlay CIDR = `100.64.0.0/16`** (CGNAT). Do NOT use `10.42/10.43` — those are **k3s defaults**
  (pod/service CIDRs) and an overlay there breaks the user's cluster routing.
- **Nebula needs TUN + `NET_ADMIN`** → can't run in AWS **Fargate**; Core (once a mesh node) and
  lighthouses must be **EC2**. The public enrollment gateway (no nebula) can be Fargate.
- **PKCS#11/HSM signing requires P256 (cert v2)**, not Nebula's default Ed25519.
- Don't deploy the dev mesh into the live k3s; rootful Podman needed for TUN if/when containers
  are used; k3s Traefik holds host ports 80/443.

## Current status

> **Keep this section in sync — update it after each implementation-plan step** so a
> cold session can pick up with clean context. Source of truth for *order/scope* is the
> implementation plan (per-step `✅` + "Proven:" notes); for *what/why* the design plan.
> This is a fast summary — re-read those for exact state.

**M0–M6 complete; M7.1 done; mid-milestone DIVERGENCE to ADR 0005 (pull-based gateways) for a
real-topology live demo — ADR 0005 Phase 1 done, next is its Phase 2/3, then back to 7.2.** Schema
at migration **000014**. M0 feasibility PASSED (2026-06-11: SoftHSM P256 CA signs certs,
tunnel forms — design §M0 results; spike under `spike/m0/`, `make m0-*`). The trust
spine is built end-to-end **on Linux** (Windows/macOS parity deferred to M10):
- **M1 Pilot** — supervises `nebula`, host keygen, enroll, renew, render, drift-revert.
- **M2 Harbor Core** — GORM store (sqlite/postgres) + hash-chained audit, IPAM (quarantine
  built), Signer (SoftHSM/PKCS#11 + circuit-breaker), secrets, reusable dual-control/RBAC.
- **M3 enrollment** — public gateway, stateless nonce, durable queue + result store, token
  enroll, async poll, approval queue, genesis ceremony.
- **M4 lifecycle** — Core-as-mesh-node, renewal + jitter, heartbeat, drift, P3 chaos.
- **M5 attestation** — AWS sigv4 `GetCallerIdentity` enroll + dual-control cloud-trust.
- **M6 policy** — group DSL → compiler → JWS-signed firewall in the bundle, compile-time
  invariants, dual-control publish, canary rollout + auto-rollback, drift-revert, lighthouse
  registry.
- **Admin UI** — React console UI-0..UI-4 (auth shell, devices, approvals + join keys, fleet
  health, group/cloud-trust, policy designer + dual-control inbox) over a contract-tested
  OpenAPI; the CLI is a strict subset (see `cmd/harbor/cli_surface_test.go`).

### M7 — Revocation & offboarding (current milestone)

Steps: **7.1** blocklist distribution · **7.2** revoke-as-DoS guards (dual-control + rate
limit + can't-blocklist-control-plane/lighthouses) · **7.3** decommission (revoke enrollment
+ 2.12 device-state machine + IP→quarantine + cloud-terminate auto-reap) · **7.4** IdP
offboarding (depends on M9 OIDC — scaffolding until then). Decisions logged this milestone:
- **7.1 split** into 7.1a (data path) → 7.1b (fast propagation). Both done.
- **Persistence kept minimal:** `revocations` table + `enrollments.fingerprint` (NOT the full
  `certificates` table — revisit for M8 drain + §7.1 issued-vs-inventory reconciliation).
- **7.1b propagation = reuse the 6.6 rollout engine** (concurrent **blocklist lane**) with
  **freeze-the-spread** semantics: an unhealthy canary freezes (stops widening), no content
  revert — the blocklist set is always the latest active set, an operator lifts a bad entry.
  (No per-version snapshots.) `apply_bundle` now means "refetch the latest bundle" via `GET
  /v1/config`.
- **2.12 device-state machine is unbuilt** (the `devices` table is id/name/created_at only); it
  is a hard prerequisite for 7.3.

- ✅ **7.1a — blocklist in the signed bundle (data path).** `internal/revocation.Registry`
  (Add/Lift/List/ActiveFingerprints — normalized lowercase-hex, **sorted** for byte-stable
  bundles, audited; mirrors `internal/lighthouse`) + migration 000013. `bundle.Bundle.Blocklist`
  threads into `RenderNebulaConfig` → nebula `pki.blocklist` (the render sink pre-existed).
  Core sources it **live** at bundle-build time on both the enrollment consumer and the
  `core-api` renew path via a fail-open `BlocklistSource` (`-blocklist-db`). The issued cert
  **fingerprint is persisted** on the enrollment row at issue and **re-stamped on every renewal**
  (it rotates with the key), so a host can be blocklisted by overlay IP. `harbor blocklist
  add|remove|list` (`-fingerprint` or `-device`; break-glass CLI — the console blocklist view +
  dual-control bulk-revoke land in 7.2/UI-5). **Propagation here is renewal/drift-cadence (slow);
  fast push is 7.1b.** Peer-side handshake refusal itself is the M0.5 spike proof (nebula 1.10.3).
  *Tests:* `internal/revocation` unit, `internal/bundle` blocklist tamper-refused + render,
  integration `TestRenewBundleCarriesBlocklist`.
- ✅ **7.1b — fast staged propagation.** Rollout engine is now **lane-aware** (`rollouts.lane`,
  migration 000014): a **blocklist-lane** rollout runs concurrently with a policy rollout (one
  active *per lane*); its own version axis is `bundle.BlocklistVersion` + heartbeat
  `applied_blocklist_version`. New **`GET /v1/config`** (coreapi) returns the host's current bundle
  built from its **stored cert** — no key rotation/re-issue (`enrollclient.FetchConfig` +
  `writeConfigArtifacts` deliberately do NOT rewrite the cert, so a renewed host isn't clobbered by
  Core's enroll-time copy). Pilot wires `heartbeat.Handlers.ApplyBundle` → fetch+apply+reload and
  reports both applied versions from the verified stored bundle. `core-api` `commandsFor` emits one
  `apply_bundle` when **either** lane is behind. Blocklist lane **freezes** on an unhealthy canary
  (no revert command). `harbor blocklist add|remove` stage it; `harbor blocklist status` shows
  convergence. *Tests:* `internal/rollout` `TestConcurrentLanesAndBlocklistFreeze`; integration
  `TestConfigFetchNoReissueCarriesBlocklist`, `TestHeartbeatDrivesBlocklistConvergence`.

### ADR 0005 — pull-based enrollment gateways (current divergence)

Goal: an off-mesh, initiates-nothing public gateway that Harbor PULLS from over leaf-pinned mTLS —
so a real public-edge/Core split is safe to stand up for the live demo. Decision (2026-06-14):
**leaf-pinning, no CA** for the mTLS identities (each side self-signed; the peer pins the leaf by
SHA-256). Open questions #2–#5 took minimal answers (fixed-interval poll; admin-paste pin
bootstrap; reuse result-TTL; pinned-cert-sufficient).

- ✅ **Phase 1 — pull transport.** `internal/collect`: `ServerTLS`/`ClientTLS` (leaf-pin),
  gateway-side `Server` (`claim`/`results`/`ack` over its local `*queue.Durable`), Harbor-side
  `Collector` (claim → `Consumer.Process` via a `CaptureSink` → ship-back → ack; ship-before-ack).
  `enrollment.Config.Results` is now a `ResultSink` interface (`*queue.Durable` still satisfies it →
  co-located mode unchanged). `gateway -collect-addr…` + `gateway collect-keygen`; `harbor collect`
  (replaces `enroll worker` for the split topology). Proven by unit tests + a real-binary mTLS check.
- ⏭️ **Phase 2 — the gateway registry (NEXT).** `internal/gatewayreg` mirroring `internal/lighthouse`
  (address + pinned cert + state, audited) + `harbor gateway add|remove|list`; the collector polls
  all registered gateways (swap the single `-gateway-url` flag for the registry). Console surface
  deferred with the other UI work.
- ⏭️ **Phase 3 — the demo node (Terraform).** `deploy/terraform`: add a standalone OFF-mesh gateway
  EC2 with its own SG (`:8443` public + the collect port from Harbor's source only; **no** Nebula
  UDP); harbor STOPS exposing the gateway publicly and instead reaches out to the gateway's collect
  port; `user_data` bootstraps `cmd/gateway`; register it with `harbor gateway add`. Today's
  terraform co-locates the gateway on the harbor host (`deploy/terraform/main.tf`) — Phase 3 splits it.
- Phase 4 (deferred): long-poll, per-gateway rate/depth caps, gateway health in the fleet view.

**After ADR 0005: back to 7.2 — revoke-as-DoS guards.** Reuse `internal/dualcontrol` (register a
`revoke.bulk` Kind) for bulk-revoke (quorum ≥2) + a DB-backed rate limit (model on `signer` breaker,
NOT the in-memory `internal/ratelimit`); refuse blocklisting a `control-plane`/lighthouse fingerprint
— enforced server-side at BOTH propose and commit (resolve groups via `adminapi` `fleetGroupMap` +
`lighthouse.Registry` + `policy.GroupControlPlane`/`GroupLighthouse`). Add the admin API routes +
RBAC perm + step-up MFA, and the UI-5 blocklist/propagation-status console view.

## Conventions

- **Go module:** `github.com/jeks313/nebula-control-plane`. Binaries: `pilot`, `harbor`.
- **Git identity:** Christopher Hyde / chris@hyde.ca. **Never add `Co-Authored-By` lines.**
- **Commit/push only when the user explicitly asks.** Milestone steps commit directly to `main`
  (linear history, one commit per step); an `origin` remote exists — push only on request.
- `spike/m0/run/` and `spike/m0/tools/` are gitignored (generated certs/keys/SoftHSM token/built binaries).
- Stack (from design §12): Go for Harbor + Pilot (can import `github.com/slackhq/nebula/cert`),
  Postgres for state, JWS/COSE signed envelopes.
