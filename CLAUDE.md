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

## The planning docs live in the vault (read these first)

Path: `~/Data/knowledge/Plans/` (Chris's Obsidian vault — also a git repo
`github.com:jeks313/knowledge`, synced via OneDrive). The build follows them.

- **`Nebula Control Plane - Design Plan.md`** (v3) — architecture, security model, flows.
  Uses `§`/`P` refs (e.g. §4.3, P2). **This is the source of truth for *what* and *why*.**
- **`Nebula Control Plane - Implementation Plan.md`** (v2) — milestones **M0–M9**, PR-sized
  steps with "Done when" acceptance. **This is the source of truth for *order* and *scope*.**
- **`Nebula Control Plane - Infrastructure Plan (AWS).md`** (v2) — local-first → minimal AWS
  harness → full production tiers (incl. k3s Tier 1+).
- **`Nebula Control Plane - Admin UI Plan.md`** — the Harbor web console + site settings.
- Background: `~/Data/knowledge/Interesting/Nebula - Open Source Overlay Mesh Network.md`.

Re-read them rather than trusting this summary; they evolve.

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

**M0 — Spike (feasibility), scaffolded, not yet run end-to-end.** See `spike/m0/README.md`.
- Toolchain not installed yet; scripts pass `bash -n` but haven't been executed (no nebula/softhsm
  at authoring time). Expect first-run iteration, especially the **PKCS#11 URI** in
  `31-gen-certs-hsm.sh`.
- **The make-or-break test is M0.3**: a SoftHSM-held P256 CA key signs certs and a tunnel forms.
  Everything downstream assumes this works — prove it before building Harbor.

### Run M0
```bash
make m0-prereqs                 # checks tooling, prints install command
make m0-up && make m0-test      # [sudo] simple path (local CA): tunnel + blocklist + groups
make m0-build && make m0-hsm    # build pkcs11 nebula-cert + SoftHSM CA (the M0.3 proof)
make m0-down                    # [sudo] teardown
```

## Roadmap pointer

Follow implementation-plan milestones in order. **First slice:** M0.1 → M0.2 → **M0.3** → M0.7
(underlay/MTU). Then write the **protocol spec (M3.0)** before M3 code, and stand up the
**plumbing (M2.9–2.11: observability, secrets, reusable dual-control/RBAC)** before piling features
on Harbor. **Must-fix before M3 code:** async enrollment delivery (3.0a/3.6a), reusable
dual-control/RBAC (2.11), secrets + release-key custody (2.10/1.2a), renewal jitter (4.4).

## Conventions

- **Go module:** `github.com/jeks313/nebula-control-plane`. Binaries: `pilot`, `harbor`.
- **Git identity:** Christopher Hyde / chris@hyde.ca. **Never add `Co-Authored-By` lines.**
- **Commit/push only when the user explicitly asks.** No remote configured yet.
- `spike/m0/run/` and `spike/m0/tools/` are gitignored (generated certs/keys/SoftHSM token/built binaries).
- Stack (from design §12): Go for Harbor + Pilot (can import `github.com/slackhq/nebula/cert`),
  Postgres for state, JWS/COSE signed envelopes.
