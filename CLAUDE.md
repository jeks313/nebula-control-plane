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

## Deploying to the POC (live control plane, ca-central-1)

There is ONE live environment. To ship a harbor change, from the repo root run:

```bash
bash deploy/scripts/deploy-harbor.sh                # changelog regen -> build -tags ui -> stage -> hot-swap -> recreate units -> verify
bash deploy/scripts/deploy-harbor.sh --skip-build   # redeploy the existing bin/harbor as-is
```

The script is self-contained and idempotent. It: regenerates the embedded changelog
(`gen-changelog.sh`), builds `bin/harbor` with `make harbor-ui` (npm build + `-tags ui` so the
console stays embedded, version stamped from `git describe`), uploads the binary to the artifacts
S3 bucket, then over **one SSM RunShellScript** makes the box pull it, verify sha256, back up the
current binary (`/usr/local/bin/harbor.bak-<sha>-<ts>`), atomic-rename swap it in, and **recreate**
the three transient units capturing each one's argv live from `/proc`. It verifies all units are
`active`, no proc runs a `(deleted)` inode, ports `:443/:8444/:9445` listen, and `harbor fleet` runs.
Commit first for a clean version stamp (a dirty tree stamps `-dirty`).

Environment facts (overridable via `NCP_*` env vars):
- **Harbor box** `i-0123456789abcdef0` (`ncp-harbor`), reached only via **SSM** (no direct SSH needed —
  transfer goes through S3). Harbor runs as **transient `systemd-run --collect` units** owned by
  `ec2-user`, NOT plain unit files: `ncp-core` (core-api :8444), `ncp-collect` (collect), `ncp-admin`
  (admin-api/console :443 — needs `AmbientCapabilities=CAP_NET_BIND_SERVICE`). `pilot supervise`
  manages **nebula only**, never harbor. Never `systemctl restart` these — a binary swap doesn't
  update a running transient unit; you must stop + `systemd-run` again (the script does this).
- **Artifacts bucket** `ncp-artifacts-123456789012` (the box has GetObject; workstation creds have PutObject).
- **AWS creds**: gpg-decrypted from `~/aws-key-*.env.gpg` (auto-discovered; see the aws-creds-gpg note).
  A first `gpg -d` in the session may prompt once to cache the passphrase.
- **Rollback**: the previous binary is the `harbor.bak-*` file left on the box — `cp` it back over
  `/usr/local/bin/harbor` and re-run with `--skip-build`, or rebuild the prior commit. Don't prune the `.bak`s blindly.

NOT handled by the script — do these manually when the change needs them:
- **Migrations are manual.** `serve` never runs `migrate.Up`. A change that adds a migration needs
  `harbor migrate up` on the box (env-default DB flags from `/etc/profile.d/harbor-cli.sh`) — apply the
  additive migration BEFORE swapping the binary.
- **The gateway is a separate target** (Fargate distroless image): `deploy/prod/fargate/build-push.sh`
  + `aws ecs update-service --force-new-deployment`. Only needed if the change touches gateway-linked
  packages (`internal/enrollment` etc.). A harbor-only change does not require it.

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

**Milestone track: M0–M4 + M6 complete; M5 PARTIAL; M7 is the frontier (7.1 done · 7.2 engine+CLI
built, no console · 7.3 partial · 7.4 blocked on M9 OIDC); M8 (CA rotation) is the ACTIVE milestone
(slice 1 + 8.1 + 8.3a-c + 8.4 retirement-local built and **DEPLOYED to the POC 2026-07-23 @
`v0.1.3-62-g08ee74a`**; **8.5 config-key rotation BUILT + harness-drilled 2026-07-24, NOT yet deployed**;
8.4 KMS drill + the POC rotation drill + 8.6 emergency path next); M9/M10
PARTIAL. Development forked off the linear track into ADR-driven parallel streams — ADRs 0003–0011
have all shipped or are code-complete (per-ADR built-state below).** A live demo (terraform apply + bootstrap-genesis.sh) can
run now on the real off-mesh topology. Schema ceiling on disk is **000036** (next free: **000037**;
the older "000015" here was stale). M0 feasibility PASSED
(2026-06-11: SoftHSM P256 CA,
tunnel forms — design §M0 results; spike under `spike/m0/`, `make m0-*`). **The poc *is* the prod
stack** (Aurora + KMS CA/config-signing keys-never-on-disk + ACME edge TLS + distroless Fargate
gateway & lighthouse, SSM-only). The trust spine is built end-to-end **on Linux** (Windows/macOS =
M10, PARTIAL):
- **M1 Pilot** — supervises `nebula`, host keygen, enroll, renew, render, drift-revert.
- **M2 Harbor Core** — GORM store (sqlite/postgres) + hash-chained audit, IPAM (quarantine
  built), Signer (SoftHSM/PKCS#11 + circuit-breaker), secrets, reusable dual-control/RBAC.
- **M3 enrollment** — public gateway, stateless nonce, durable queue + result store, token
  enroll, async poll, approval queue, genesis ceremony.
- **M4 lifecycle** — Core-as-mesh-node, renewal + jitter, heartbeat, drift, P3 chaos.
- **M5 attestation** — ⚠ **PARTIAL:** AWS sigv4 `GetCallerIdentity` enroll (5.1/5.2) + immutable-fact
  group map (5.5, `internal/cloudtrust`, live) done; **open:** IID cross-check (5.3), one-enroll-per-
  instance (5.4), Azure attested data (5.6), PrivateLink (5.7).
- **M6 policy** — group DSL → compiler → JWS-signed firewall in the bundle, compile-time
  invariants, dual-control publish, canary rollout + auto-rollback, drift-revert, lighthouse
  registry.
- **Admin UI** — React console UI-0..UI-4 (auth shell, devices, approvals + join keys, fleet
  health, group/cloud-trust, policy designer + dual-control inbox) + a **CA Rotation** page (M8,
  read-only) over a contract-tested OpenAPI; the CLI is a strict subset (see
  `cmd/harbor/cli_surface_test.go`).

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
- **2.12 device lifecycle is now BUILT (partial):** the reaper (`internal/reaper`, migrations 000025
  `enrollments.ephemeral` + 000026 `devices.reaped_at`/`reap_reason`) soft-marks + reclaims cert-lapsed
  hosts; a reaped-but-live host self-heals on check-in (`coreapi` heartbeat-self-heal + IP reconcile).
  Still a soft-mark, not yet a full lifecycle state column.

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
- 🟢 **7.2 — revoke-as-DoS guards: engine + CLI + dual-control BUILT; admin-API/console PENDING.**
  `internal/revocation` has `BulkRevokeKind` (two-person quorum via `dualcontrol`), a DB-backed rate
  limit (`MaxBulkPerWindow=3`/`BulkWindow`, counts *operations* not rows), `ErrControlPlaneProtected`
  (can't blocklist a control-plane/lighthouse fingerprint), `ErrBulkTooLarge`. Wired to a break-glass
  CLI `harbor blocklist bulk-revoke -operator-a/-operator-b -fingerprints` (`cmd/harbor/bulkrevoke.go`,
  tested). **Still open:** the admin-API route + RBAC perm + step-up MFA + the **UI-5** blocklist /
  propagation-status console view (no Blocklist page in `Shell.tsx` nav yet — the last visible gap).
- 🟡 **7.3 — decommission: reaper slice BUILT, cloud-terminate hook NOT.** `internal/reaper`
  (default-on; `-reap-disable`/`-reap-dry-run`) reclaims a cert-lapsed host's overlay IP, prunes its
  heartbeat, soft-marks the device — **never** reaps a valid-cert / control-plane / central-block host,
  **never** blocklists; a reaped-but-live host **self-heals** on check-in (`coreapi` steps 6–8, audited).
  **Still open:** an explicit `harbor decommission`, a cloud-terminate/CloudTrail-driven auto-reap
  (today's trigger is cert-lapse/time, not cloud inventory), and hard-delete of reaped rows.
- 🔴 **7.4 — IdP offboarding: NOT STARTED** (needs the M9 laptop OIDC device-code flow, itself unbuilt).

### ADR-driven parallel streams (shipped/code-complete since 7.1b)

The linear track forked into ADR streams. Net state (✅ built · ◐ code-complete-but-off · 🟡 partial · ✎ design-only):
- ✅ **ADR 0003 — pilot + nebula self-update/distribution.** `internal/{nebularelease,nebulaupdate,
  pilotrelease,pilotupdate,pilotservice,binverify}`; migrations 000016/000017 (release registries),
  000020/000021 (per-arch + `host_arch`). Rollout engine now has **four lanes** (`LanePolicy`/
  `LaneBlocklist`/`LaneNebula`/`LanePilot`; nebula/pilot *revert* on rollback, unlike blocklist freeze).
  `harbor nebula|pilot` + release-ingest; console **Releases** page; publishing runbook.
- ◐ **ADR 0004 / 0009 — SSO user enrollment + control-plane trust-zone separation.** `internal/
  {usertrust,ssoassert,autotls}`; `harbor usertrust publish`; `pilot install/enroll --sso` (loopback
  auth-code); Entra MFA via the `amr` claim (`adminauth`); off-mesh SSO portal + `checkIssuanceBind`
  invariant. **Code-complete but OFF BY DEFAULT** on the poc (runs `-mock-idp`).
- ✅ **ADR 0005 — pull-based enrollment gateways** (own subsection below) + **gateway health**
  monitoring (migration 000031 `gateway_health`, `internal/gatewayhealth`, console Gateways pane).
- ✅ **ADR 0006 — distroless Fargate/lighthouse images** (Phases 1–2; Phase 3 digest-pin/supply-chain open).
- ✅ **ADR 0007 — production deploy + HA fixes.** `deploy/prod/` (terraform foundation+app; monitoring:
  prometheus/loki/alertmanager/grafana/alloy). HA substrate: shared nonce-replay guard (000018,
  `internal/replay`) + fleet-wide signer circuit breaker (000019, `signer/breaker_sql.go`). **Still
  single-AZ** (`desired_count=1`); durable enrollment queue still SQLite.
- ✅ **ADR 0008 — client install & bootstrap** (Phases 1/3/4: idempotent `pilot install`, per-OS
  service backends, multi-mesh, `uninstall -purge`). Phase 2 (org-signed meshinfo / org-root pin /
  console "Generate installer") unbuilt.
- ✅ **ADR 0010 — IPAM named netblocks** (SHIPPED, all phases): `internal/netblock`, migrations 000022/
  000023/000029, `harbor ipam`, console **IPAM** page, per-netblock metrics.
- 🟡 **ADR 0011 — declarative config store** (Phase 1 shipped): `internal/config` + migration 000027
  `config_store` (first-class set/get for policy/cloudtrust/usertrust; propose/approve handlers removed →
  `PUT/GET /config/{kind}` + `*:manage` perms). Phase 2 (export/import, GitOps, drift, TF provider) unbuilt.
- ✅ **ADR 0002 / 0013 — group reassignment.** Migration 000030 (`desired_groups`/`groups_generation`/
  `issued_generation`); single-device `PATCH /devices/{ip}/groups` (`device:manage`); **bulk
  name-pattern re-group** (`adminapi/device_regroup_bulk.go`: dry-run preview + guarded apply, cap 100,
  dual-control ≥25 but **opt-in/off by default**); console **Devices** bulk UI. *(Both ADRs read
  "proposed" but Phase A is shipped + tested; ADR 0013 Phase B enforceable-reductions is not.)*
- ✎ **ADR 0012 — pilot fleet metrics: DESIGN-ONLY.** Harbor-component + gateway-health metrics exist
  (those are ADR 0007/0005), but the ADR-0012 subject — pilots pushing nebula `:4280` metrics on the
  heartbeat → `ncp_fleet_*` — is **unbuilt** (three forks open). The pilot leaf tier is the obs gap.
- ✅ **Lighthouse HA + scheduled cert rotation + relay** (extends M4/M6): migration 000028
  `lighthouse_rotations`, `harbor lighthouse rotate` (in-place re-sign), multi-LH blip-free rotation,
  registry→fleet propagation, lighthouse-as-Nebula-relay (`use_relays` for symmetric-NAT off-cloud hosts).
- ✎ **ADR 0014 — overlay naming & split-horizon DNS: DESIGN-ONLY** (detail below).

### M8 · M9 · M10 status

- **M8 — CA & key rotation: STARTED (slice 1 + 8.1 + 8.3a built).** ✅ **CA registry + lifecycle state
  machine** (`internal/ca`, migration **000032** `ca_certs`): `staged→active→draining→retired` with
  DB-enforced single-active (partial unique index), `TrustBundle()` (non-retired CAs, sorted/byte-stable),
  `Active()` (the signing CA), `SeedActive()` boot-seed, plus Stage/Activate(atomic cut-over demotes prior
  active to draining)/Retire(refuses live dependents)/Abandon, all audited + unit-tested. ✅ **8.1 trust
  distribution**: `CABundleSource` seam on `enrollment.Config`+`coreapi.Config` (fail-open to the static
  `-ca-cert`) so every enroll/renew/`GET /v1/config` bundle's `ca_bundle` is sourced from `TrustBundle`
  live; core-api + enroll-worker **boot-seed the current CA as active** on start (race-tolerant);
  `harbor ca list|stage|activate|retire|abandon` break-glass CLI (classified in the CLI-surface guard).
  Proven by integration `TestEnrollBundleCarriesStagedCA`. ✅ **8.1 adoption tracking** (migration **000033**
  `heartbeats.trusted_cas`): each pilot reports, on its heartbeat, the CA fingerprints it trusts (from its
  VERIFIED applied `ca_bundle` — `wire.HeartbeatRequest.TrustedCAFingerprints`); coreapi stores it per host
  (in the upsert's `DoUpdates`, so it converges each beat); `ca.Registry.AdoptionStatus` computes 100%-of-LIVE
  adoption (stale hosts excluded + surfaced; empty/unreported = laggard, fail-closed; empty fleet = vacuously
  adopted); **`harbor ca activate` now REFUSES cut-over until 100%** (pure `adoptionGate`, `-force` break-glass
  override) + a `harbor ca adoption -id N` inspector. Reviewed adversarially (5-lens workflow, 0 defects).
  ⚠ **DEPLOY ORDER:** apply migration 000033 (`harbor migrate up`) BEFORE swapping the binary; old pilots
  omit the field and read as laggards until they re-beat under the new pilot, so the first post-ship
  `activate` is blocked until the fleet re-reports (or use `-force`). ✅ **8.3a drain tracking** (migration
  **000034** `enrollments.ca_fingerprint`): the CA that signed each host's CURRENT leaf (its `cert.Issuer()`,
  byte-identical to the active CA's registry fingerprint) is stamped at issue AND re-stamped on every renewal
  (`enrollment.issue/record`/Approve + `coreapi.handleRenew`, folded into the existing fail-closed updates).
  `ca.Registry.LiveDependents(fp)` counts issued, non-expired leaves per CA (by the stored fingerprint OR the
  leaf's own `Issuer()` when empty, so a **pre-8.3 fleet is never miscounted as 0** — the load-bearing fallback);
  **`Retire` now self-counts and refuses fail-closed** while any live leaf remains (dropped the manual
  `-dependents` flag). `harbor ca list` shows a **LIVE-DEPS** column; the boot-seed backfills empty rows to the
  genesis CA. Proven by `internal/ca` `TestLiveDependents`/`TestRetire` + integration `TestCAFingerprintStampedAndRestamped`.
  Reviewed adversarially (inline 5-lens pass, 0 defects). ⚠ **DEPLOY ORDER:** apply migration **000034**
  (`harbor migrate up`) BEFORE swapping the binary — the first post-swap core-api/enroll-worker boot backfills
  `ca_fingerprint` on existing issued rows, and the stamp/re-stamp writes need the column.
  ✅ **8.3b signing cut-over (HOT-SWAP, zero-downtime — user-chosen mechanism).** The `Signer` now holds its
  `{CA cert, backend}` behind an `atomic.Pointer` (`signingIdentity`); `Issue()` snapshots it once per call so an
  in-flight signature can never chain to one CA while signing with another's key. `Signer.SwapCA` re-points it,
  running the SAME validation as boot (parse/IsCA/P256/backend-pubkey==cert-pubkey) plus an expiry guard, and is
  **fail-safe**: any failure returns an error and the prior CA keeps signing (no torn state, no halt). The
  breaker/policy/audit/clock are process-level and deliberately NOT swapped, so the fleet-wide rate ceiling +
  audit trail survive a rotation. A per-process poll reconciler (`RunActiveCAReconciler`, `-ca-cutover-interval`
  default 30s, 0 disables) on **core-api + the enroll worker/collector** watches `ca.Active()` and hot-swaps when
  a new CA is activated — no restart. Cut-over latency is bounded + harmless (activate already gated on 100%
  trust adoption, 8.1). Backend rebuild uses an injected `BackendFactory` (KMS ARN / `pkcs11:<label>` id-based, so
  **NO CA private key is ever handled in-process**, P2); a *software* CA2 cut-over is refused with a clear
  "restart with -ca-key" (dev-only; the poc is KMS). `ncp_signer_active_ca_cutovers_total` + a `ca-signing-cutover`
  audit row per swap. Proven by `internal/signer` `TestSwapCAValidatesAndIsAtomic`/`TestIssueFollowsHotSwap`/
  `TestReconcileActiveCA` + integration `TestSigningCutsOverToActivatedCA` (enroll under CA1 -> activate+swap ->
  renew re-signs under CA2, drain moves CA1->CA2, no restart). ⚠ **runbook (8.4):** keep `-ca-cert` pointed at a
  still-trusted CA — booting with a *retired* CA in `-ca-cert` would briefly sign untrusted leaves until the
  first reconcile tick (a draining CA is fine — still trusted).
  ✅ **8.3c force-renew stragglers (operator-triggered, waved -- user-chosen).** `harbor ca force-renew -id N
  [-window 30m] [-stop]` (migration **000035** `ca_certs.force_renew_started_at`/`force_renew_window_ns`, only
  on a DRAINING CA). Core's heartbeat path (`coreapi.forceRenewStraggler` + the `CADrain` seam; `ca.Registry`
  implements it) answers a host still chaining to the force-drained CA (`dev.ca_fingerprint` != the active CA)
  with a `renew` command in **deterministic widening waves** (`inDrainWave`: an `fnv32a(overlay_ip)` bucket opens
  linearly over the window -- ~1% renew at t0 growing to 100% at window end, no storm) so the host re-keys onto
  the ACTIVE CA and the drain finishes in ~a window instead of a full cert lifetime. **Pauses widening while the
  signing breaker is open** (`signer.BreakerOpen`) so a force-drain never piles onto a halted signer; fail-safe
  (any read error -> no forced renew; natural renewal still drains). Self-terminating: a renewed straggler
  re-stamps to the active CA (8.3a) and drops out; when `LiveDependents` hits 0 the operator retires. Proven by
  `internal/ca` `TestForceRenewLifecycle`, `internal/coreapi` `TestInDrainWave`/`TestForceRenewStragglerGating`,
  integration `TestForceRenewDrainsStragglers`. Cost: one indexed active-CA lookup per non-renewing heartbeat
  (cheap; only for hosts carrying a fingerprint).
  🟡 **8.4 retirement + KMS deletion (LOCAL slice built; the KMS call + CloudWatch alarm are AWS-verified).**
  migration **000036** `ca_certs.key_deletion_scheduled_at`/`key_deletion_date`. `ca.Registry.ScheduleKeyDeletion`
  guardrails, fail-closed: ONLY a RETIRED CA (state check + CAS), NO live dependents (belt-and-suspenders over
  Retire, fail-closed on read error), a real key backend (`kms_key_id` set), a 7-30-day KMS window, no
  double-schedule. Calls the backend FIRST then persists; on a persist failure it rolls the backend schedule
  back (and surfaces a failed rollback) so a key is never silently pending-deletion-but-unrecorded.
  `CancelKeyDeletion` aborts within the window (cancel backend first). A `ca.KeyDeleter` seam keeps the package
  AWS-free + testable: `ca.NoopKeyDeleter` (dev/software) is fully local-tested; **cmd/harbor `kmsKeyDeleter`**
  drives real KMS `ScheduleKeyDeletion`/`CancelKeyDeletion` (wired, AWS-verified-later, never reads the key P2).
  `ncp_ca_key_deletion_pending` + `_seconds_remaining` (the `ca.Collector`, on Core /metrics) is the alarm
  signal; `harbor ca schedule-key-deletion|cancel-key-deletion` (break-glass) + a KEY-DEL column in `ca list`.
  Proven by `internal/ca` `TestScheduleKeyDeletionGuardrails`/`TestScheduleAndCancelKeyDeletion`/
  `TestScheduleKeyDeletionRejectsNoKeyAndLiveDeps`/`TestScheduleKeyDeletionBackendErrorNoPersist`/
  `TestKeyDeletionCollector`. **Still AWS-only:** the CloudWatch alarm on the pending gauge (Terraform) + a live
  KMS ScheduleKeyDeletion drill.
  ✅ **M8 console surface (read-only CA Rotation dashboard).** `GET /admin/v1/ca` (`listCAs`) + `GET
  /admin/v1/ca/{id}/adoption` (`getCAAdoption`) in `internal/adminapi/ca.go` (compose `ca.Registry`; authed,
  no special perm, like `/gateways`) surface the full lifecycle: state, active/trusted (trust-bundle
  membership), drain count, force-renew window, key-deletion countdown, and per-CA trust-adoption (the
  activate gate). New React **CA Rotation** page (`ui/src/pages/CARotation.tsx` + nav/route + `useCAs`/
  `useCAAdoption`): state-badged rows, the signing CA highlighted, drain + key-deletion signals, and an
  adoption progress bar for staged CAs. **Read-only by design** (user-chosen) — the lifecycle ACTIONS
  (stage/activate/retire/force-renew/schedule-key-deletion) remain break-glass CLI; console-driven guarded
  actions (dual-control + step-up MFA) are a deferred follow-up. OpenAPI schemas + contract test + handler
  tests (`ca_test.go`); UI typechecks + builds (`-tags ui`). *("key bundles" in the dashboard = the CA trust
  bundle every signed config bundle distributes = the non-retired CAs.)*
  ✅ **M8 adversarial review remediation (8-lens multi-agent + verify).** A deep review of the whole 8.3-8.4 +
  dashboard cluster found **4 real defects, all fixed**: (1) **CRITICAL ship-blocker** — `LiveDependents` filtered
  on the FROZEN `enrollments.cert_pem` (renewal re-stamps ca_fingerprint but never rewrites cert_pem), so a fleet
  older than one cert lifetime undercounted toward 0 and a still-depended-on CA could be retired / its key
  deleted (fleet-wide tunnel loss). Now derives liveness from the maintained `heartbeats.cert_not_after`
  (fallback to the frozen cert only for a never-checked-in host). (2) HIGH — **admin-api (issuance mode) never
  started the cut-over reconciler**, so console enroll-approvals kept signing under the old CA and a rotation
  could never drain; now `cmdAdminAPI` starts it on `consumer.Signer()`. (3) MEDIUM — `forceRenewStraggler` gated
  on the REGISTRY's active CA, not THIS process's signer, so in a fail-safe state (`-ca-cutover-interval=0` /
  refused software swap / stuck KMS) it re-signed a straggler under the same draining CA forever; now also
  requires `s.cfg.Signer.CurrentFingerprint() == activeFp`. (4) LOW — the reconciler's first poll was one interval
  late; `startCACutoverReconciler` now does one **eager synchronous reconcile before serving** so a restart with a
  stale `-ca-cert` argv doesn't sign under a since-retired CA for ~30s. Regression tests added
  (`TestLiveDependentsUsesHeartbeatExpiry` + updated `TestForceRenewStragglerGating`).
  ✅ **DEPLOYED to the live POC — 2026-07-23, `v0.1.3-62-g08ee74a`.** All of M8 (slice 1 → 8.4 local
  slice + dashboard + the remediation above) went live on `ncp-harbor`. The 2026-07-22 deploy was
  interrupted by a power loss before it reached the box; recovered next session. The box had been on
  `v0.1.3-37-ge95f963` (2026-07-09) — ~25 commits back, missing ALL of M8 — so this was a **5-migration
  jump (`000032`→`000036`)**, applied in the correct order: `migrate up` with the new binary FIRST (old
  units still serving), THEN `deploy-harbor.sh --skip-build` (swap + unit recreate). A straight
  `--skip-build` alone would have booted the new binary against a schema with no `ca_certs` table →
  outage; the migrate-before-swap rule matters most on a multi-migration jump. Verified live: `harbor ca
  list` shows the genesis CA `harbor-ca` `active` with `LIVE-DEPS=9`, the M8.3b cut-over reconciler
  logs "started", all three units active `NRestarts=0`. (Recovery also surfaced + fixed a
  `deploy-harbor.sh` bug where a trailing `rm -f` masked the remote exit code → false "deploy OK",
  now fixed to propagate the inner exit code.)
  ✅ **8.5 config-signing-key rotation — BUILT + reviewed + harness-drilled (2026-07-24, commits `297ff15`
  + `49a5aab`; NOT yet deployed).** Rotates the config-signing key (Pilot's PINNED bundle-trust ROOT, a
  co-equal TCB root — fails CLOSED, unlike `ca_bundle`) by the identical staged→active→draining→retired
  overlap. New `internal/configkey` (registry+lifecycle+adoption/drain gate+KMS key-deletion+collector,
  migrations **000037** `config_signing_keys` + **000038** `heartbeats.trusted_config_keys`); new
  `internal/configsign` (atomic hot-swap `ConfigSigner`, snapshot-per-Sign so a swap never tears a Kid
  across a signature; reconciler mirroring the CA cut-over, wired on ALL 4 signing procs: core-api, enroll
  worker, collector, admin-api-issuance); `bundle.ConfigSigningKeys`+`ConfigKeyVersion` (byte-stable,
  fail-open source) + **`bundle.TrustedSet`/trust-file** (`<base>/config-signing-trust.json` = pin UNION
  learned, RE-READ per verify so a running pilot adopts K2 mid-run; fail-safe monotonic anti-rollback;
  fsynced); `jws.VerifyAny` + set-based `bundle.Verify` across all 9 pilot verify sites; heartbeat
  `TrustedConfigKeyFingerprints` sourced from the trust file (the exact set Verify consults) + coreapi
  `trusted_config_keys` in the `OnConflict DoUpdates`; `harbor config-key {list,stage,adoption,activate,
  retire,abandon,schedule/cancel-key-deletion}` break-glass CLI + read-only console page + `ncp_configkey_*`
  metrics. Acceptance `TestConfigKeyOverlapVerifiesNoRejection` (enroll K1→stage→adopt→activate+hot-swap→
  renew K2→retire K1, zero rejections) + `TestFullRotationDrillBothRoots` (CA **and** config-key rotated in
  one host's life, zero data-plane discontinuity). **Adversarial 5-lens review fixed 2 defects:** the
  heartbeat now reports config-key trust from the trust FILE not the last bundle's advertised keys (which,
  written first, could over-report adoption and strand a host at cut-over — regression-tested); trust file
  fsynced. **Fingerprint invariant (load-bearing):** registry fp == JWS Kid == pilot-reported == stored ==
  `wire.PubkeyHash(65-byte P256 point)`, CASE-SENSITIVE base64url (never lowercased, unlike hex CA fps).
  ⚠ **DEPLOY ORDER:** apply **000037 + 000038** (`harbor migrate up`) BEFORE swapping the binary.
  **Still open:** DEPLOY 8.5 to the POC + a **controlled POC rotation drill** (needs a 2nd KMS config key —
  and a 2nd KMS CA key for the CA half), then 8.4 KMS deletion drill + CloudWatch alarm, 8.6 emergency path.
  *(The scheduled lighthouse-cert rotation above is 6.8-adjacent, NOT M8 CA rotation.)*
- **M9 — hardening & operations: PARTIAL (delivered via ADR 0007, not per-step ticks).** The poc IS the
  prod stack (above); ✅ 9.6 signed waved self-update (ADR 0003); 🟡 HA substrate present but single-AZ;
  🟡 SSM break-glass path live (no dual-operator drill). ❌ 9.1 laptop OIDC device-code flow (blocks 7.4),
  9.3/9.4/9.7/9.8/9.10 open.
- **M10 — Windows + macOS parity: PARTIAL (past stubs).** Real Windows **SCM** backend
  (`pilotservice/service_windows.go`, `svc.Run`), macOS launchd scaffold, **Wintun** self-staging
  (`nebulaboot/embed_wintun_windows.go`), opt-in SSM-only Windows client on prod. **Still open:**
  host-key DACL/DPAPI at-rest, least-priv service account (runs LocalSystem), MSI + Authenticode/
  notarization, Win/mac CI runners, macOS Keychain, laptop OIDC.

### ADR 0014 — overlay naming & split-horizon DNS (PROPOSED design; NO code yet)

Design-only decision record (committed 2026-07-16, `docs/Nebula Control Plane - ADR 0014 - Overlay
Naming and Split-Horizon DNS.md`, mirrored to the vault). A net-new, **un-milestoned** capability —
auto-DNS (every node a unique name matching its cert) + admin-defined split-horizon forward zones.
**Nothing is built**; this is the ADR a future milestone rides. Key decisions:
- **Resolver = a per-host EMBEDDED Go resolver in Pilot** (`miekg/dns`, already an indirect dep →
  **zero new release-signing TCB**), answering from the cached signed bundle. Chosen over Nebula's
  built-in `lighthouse.dns` (no forwarding/split-horizon) and a central `unbound` pair (a P3
  dependency, and per-group confidentiality would degrade to a source-IP-ACL second policy engine).
  `KillMode=process` + ADR 0003 re-adopt mean a resolver crash can't drop the tunnel.
- **Phase 0 = the linchpin: cert names are NOT unique today.** Host-asserted `RequestedName`, signer
  only rejects empty, and `ipam.ensureDevice`'s `FirstOrCreate` silently collapses same-named hosts
  onto one `devices` row. Must add normalize→DNS-label + `overlay_ip`-anchored uniqueness (a
  `dns_names` table) BEFORE any name is served. Standalone correctness win independent of DNS.
- **Delivery = the signed bundle** (new `bundle.DNS`, two fail-open build sites, sorted/byte-stable),
  a `dns` rollout lane, dual-control forward-zone publish. First migration would be **000032**.
- **Ask C (default-forward path):** non-mesh queries go to **per-netblock** default forwarders
  (resolved from `enrollments.sub_range`) → fleet default → the host's captured pre-existing
  upstreams (non-destructive) → SERVFAIL. Answers "where does everything else go" once Pilot is first-stop.
- **Scale posture:** **SCOPED is the fleet default** (OS split-DNS routes only mesh + forward zones to
  Pilot); **PRIMARY (Pilot as the host's default resolver) is never the fleet default.** The shared
  `unbound` forward-cache (co-located on lighthouses) flips **default-ON ≥ ~1k hosts / metered
  upstreams** with a mandatory direct-fallback; the resolver runs as a supervised child in its own
  cgroup at scale.
- **TLS:** name the mesh a **subdomain you own** (`mesh.<yourdomain>`) so the existing `autotls`
  DNS-01 flow issues public certs for names that resolve only on-mesh; `.internal` forces a private CA.
Phases: 0 name-hardening → 1 auto A/PTR (Linux) → 2 forward zones + governance + scale items →
3 cross-platform + console → 4 deferred. Open questions #1–#8 live in the ADR (mesh apex, posture, …).

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
- ✅ **Phase 2 — the gateway registry.** `internal/gatewayreg` (migration 000015 `gateways`;
  Add/Remove/List/Active, audited, validates the pinned cert, reactivates-in-place) + `harbor gateway
  add|remove|list`. `harbor collect` polls all active registered gateways by default (re-read each
  cycle), `-gateway-url` kept as a single-gateway override. Console surface deferred with the UI work.
- ✅ **Phase 3 — the demo node (Terraform).** `deploy/terraform`: 4th node `gateway` (off-mesh, EIP)
  + its own SG (`:8443` public; `collect_port` 9443 from harbor's SG only; no Nebula UDP); the gateway
  port removed from the harbor SG (harbor reaches OUT + pulls). `bootstrap-genesis.sh` step 7 mints
  leaf-pinned mTLS, runs the off-mesh gateway, `harbor gateway add`s it, and runs `harbor collect`
  (replaces `enroll worker`). `terraform validate` + `bash -n` clean; **not yet applied to live AWS**
  — `terraform apply` + the bootstrap runs the real demo (expect first-run iteration).
- Phase 4 (deferred): long-poll, per-gateway rate/depth caps, gateway health in the fleet view.

**Deploy patterns (two):**
- **`deploy/local/`** — single-instance PERSONAL deploy, maximally simplified: one box, localhost,
  SQLite, software CA, **co-located** enrollment (gateway + worker share one local queue — NOT the
  ADR-0005 pull split), admin **console via GitHub OAuth** (`NCP_GITHUB_CLIENT_ID/SECRET`, else a dev
  mock-IdP), console UI built with `-tags ui` when `npm` is present. `local-up.sh` / `local-down.sh`.
  GitHub-gated joins = mint a join key + approve the device in the GitHub-authed console. Console
  bound to 127.0.0.1 (default-roles admin, safe local-only). Verified end-to-end (enroll + SPA console).
- **`deploy/terraform/` + `deploy/scripts/bootstrap-genesis.sh`** — multi-host AWS. Default topology
  is now **3 EC2 (lighthouse + harbor + cloud client) + a serverless Fargate gateway**: `terraform apply`
  then `aws-vault exec nebula -- env SSH_KEY=~/.ssh/absolute bash ../scripts/bootstrap-genesis.sh`
  (the default needs AWS creds at bootstrap — it builds/pushes the gateway image + populates its secret).
  Dedicated VPC, tiered subnets; prints the enroll commands + config-signing pin. (Not applied to live AWS.)
  - **Runtime toggles** (what can avoid a VM = what needs no TUN):
    - **`gateway_runtime = "fargate"` (DEFAULT) | `"ec2"`** — the off-mesh gateway runs no `nebula`, so
      it's serverless: ECS service + NLB + Secrets Manager (`gateway_fargate.tf`, `deploy/fargate/`),
      ADR-0005 posture (enroll public, collect Harbor-only) enforced at the NLB SG. The bootstrap fully
      wires this (build-push.sh → secret → `aws ecs update-service`). `"ec2"` = the original VM path.
    - **`lighthouse_runtime = "ec2"` (DEFAULT) | `"fargate"` (SPIKE)** — a lighthouse does only
      control-plane work, so it can run `nebula` with **`tun.disabled`** (no TUN/privilege) as a Fargate
      container behind a **UDP NLB + pinned EIP** (`lighthouse_fargate.tf`, `nebula.Dockerfile`). Still a
      Nebula protocol member (cert + handshake) — VM-free, NOT off-mesh. ⚠ KEY UNKNOWN: the UDP NLB must
      preserve the client address (`preserve_client_ip=true`) or hole-punching breaks — unverified live.
      Health check via nebula's prometheus TCP port (UDP TGs can't UDP-health-check). Bootstrap aborts on
      this (manual procedure in `deploy/fargate/README.md`); host key is generated off-box + injected.
  - **harbor (Core) is always EC2** — it routes core-api over the overlay → needs a real TUN. Shared
    Fargate scaffolding (locals + ECS assume-role) is in `fargate.tf`. `terraform validate` clean in all
    runtime combinations; images build; `bash -n` clean; **not live-applied** (no AWS/docker in dev env).

Note: the durable queue (`internal/queue`) is now safe for concurrent first-open by several processes
(the co-located gateway+worker+admin) — AutoMigrate tolerates the benign create race.

**Genuinely-unbuilt frontier (what a next session could pick up):**
- **Finish 7.2** — the engine/CLI/dual-control/rate-limit/P10-guard are done; add the admin-API route +
  RBAC perm + step-up MFA + the **UI-5** blocklist/propagation-status console view (the last visible gap).
- **7.3** — an explicit `harbor decommission` + a cloud-terminate/CloudTrail-driven auto-reap (today's
  reaper triggers on cert-lapse, not cloud inventory) + hard-delete.
- **M8 — CA & key rotation** — the ACTIVE milestone. Registry + lifecycle (slice 1), 8.1 trust distribution +
  adoption gate, 8.3a drain tracking, **8.3b signing cut-over (zero-downtime hot-swap)**, **8.3c waved
  force-renew**, 8.4 retirement-local, and **8.5 config-key rotation (built + harness-drilled, NOT deployed)**
  are done; next is **deploy 8.5 + a controlled POC rotation drill** (needs 2nd KMS CA + config keys), the
  8.4 KMS-deletion drill + CloudWatch alarm, then 8.6 emergency path, 8.7 full staging drill.
- **7.4 / M9 9.1** — laptop OIDC device-code flow (unblocks IdP offboarding).
- **ADR 0012** (pilot fleet metrics) and **ADR 0014** (overlay DNS) are design-only.
- **M10** — the Windows/macOS hardening tail (DACL/DPAPI, Authenticode/notarization, CI runners, least-priv).

## Conventions

- **Go module:** `github.com/jeks313/nebula-control-plane`. Binaries: `pilot`, `harbor`.
- **Git identity:** use your configured git `user.name` / `user.email`. **Never add `Co-Authored-By` lines.**
- **Commit/push only when the user explicitly asks.** Milestone steps commit directly to `main`
  (linear history, one commit per step); an `origin` remote exists — push only on request.
- `spike/m0/run/` and `spike/m0/tools/` are gitignored (generated certs/keys/SoftHSM token/built binaries).
- Stack (from design §12): Go for Harbor + Pilot (can import `github.com/slackhq/nebula/cert`),
  Postgres for state, JWS/COSE signed envelopes.
