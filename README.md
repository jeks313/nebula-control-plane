# Nebula Control Plane (Harbor + Pilot)

A control plane for [Nebula](https://github.com/slackhq/nebula), the open-source overlay mesh
VPN. It automates the four things stock Nebula leaves manual:

1. **IP assignment** on the overlay (IPAM).
2. **Certificates & joining**: enrollment, approval, and signed-credential delivery.
3. **Certificate lifecycle**: zero-downtime renewal and revocation across a live fleet.
4. **Central firewall policy**: group-based, compiled and signed centrally (no per-host drift).

Two Go components:

- **Harbor** is the central control plane: enrollment, IPAM, a KMS-backed signing CA, group
  firewall policy, staged rollouts, revocation, and an admin API + web console.
- **Pilot** is the per-host agent: a privileged parent that **supervises `nebula` as a
  subprocess**, generates the host keypair locally, enrolls, renews, renders `config.yml`, reverts
  drift, and self-updates both binaries.

Typical target: mixed Linux/Windows fleets across AWS/Azure that want zero-trust private
networking without per-host manual certificate ops.

## Features

**Enrollment & trust**
- Public, credential-less **enrollment gateway** that makes no authorization decisions; Core
  re-verifies everything (proof-of-possession JWS + single-use HMAC nonce + rate limit).
- Join methods: one-time / reusable **join keys**, **AWS SigV4 `GetCallerIdentity`** cloud
  attestation, and **SSO** (OIDC/SAML) user enrollment. Groups are always control-plane
  authoritative; the client CSR is advisory.
- Manual **approval queue** with async polling; auto-issue is opt-in per join source.
- Pull-based **off-mesh gateways** (ADR 0005): Harbor initiates nothing public. It *pulls* vetted
  candidates over leaf-pinned mTLS, so the public edge holds no CA.

**Signing & config delivery**
- Signing CA in **AWS KMS** (prod) or **SoftHSM/PKCS#11** (local) behind one pluggable backend:
  Nebula **cert v2, P256**, private key never exportable.
- Every host gets a **JWS-signed config bundle** (leaf cert, CA bundle, compiled firewall,
  lighthouses, blocklist, binary versions) signed by a **separate config-signing key** that Pilot
  **pins**; nothing inside is trusted until the bundle verifies.

**Firewall policy & fleet ops**
- Group **firewall DSL** compiles to a signed firewall in the bundle, with compile-time invariants
  (a control-plane node can never lose its own API ports).
- **Staged canary rollouts** with auto-rollback, across four independent lanes: policy, blocklist,
  nebula binary, pilot binary.
- **Revocation blocklist** (peer-enforced) with a two-person **dual-control** bulk-revoke, plus
  guards that refuse to blocklist a control-plane/lighthouse host.
- **IPAM** with named netblocks and per-scope allocation; an auto-reaper reclaims lapsed hosts.
- **Lighthouse** registry with scheduled cert rotation and relay support.
- Signed, waved **self-update** of the `nebula` and `pilot` binaries (SHA-256 verified before exec,
  so the CDN/URL need not be trusted).

**Administration**
- Versioned **`/admin/v1` API** + embedded **React console** (devices, approvals, join keys, fleet
  health, policy designer, IPAM, releases, dual-control inbox).
- **RBAC** (admin/operator/viewer/break-glass), **dual-control** for privileged changes, and
  step-up MFA, over a bring-your-own-IdP session layer (OIDC / SAML / GitHub).
- Hash-chained **audit log** and Prometheus **metrics** throughout.

## Security model

A security-paramount project. The load-bearing invariants:

- **Private keys never leave the host:** Pilot sends a public key; Harbor returns a signed cert.
- **CA key is non-exportable** in KMS; only a minimal signer holds `KMS:Sign`.
- **The control plane is off the data path:** Harbor being down must never drop tunnels.
- **Signed, pinned bundles:** the config-signing, CA, and release-signing keys are the trust roots,
  and the admin UI is a thin client, never a trust root.
- **No bespoke crypto:** standard SigV4, JWS/COSE, HKDF only.

See `docs/Nebula Control Plane - Design Plan.md` (§2) for the full principle set (P1-P11).

## Repository layout

```
cmd/                 binaries (main packages)
  harbor/            control plane + admin CLI: serve (core-api / admin-api / collect),
                     migrate, genesis, ca, policy, cloudtrust, usertrust, blocklist,
                     rollout, lighthouse, gateway, nebula/pilot releases, joinkey, ...
  pilot/             per-host agent: install, enroll, supervise, renew, info, uninstall
  gateway/           off-mesh public enrollment gateway (ADR 0005; pulled over pinned mTLS)
  nebula-boot/       nebula self-staging helper (embeds Wintun on Windows)

internal/            ~60 implementation packages, by concern:
  enrollment/trust   gateway, enrollment, enrollclient, collect, awsattest, cloudtrust,
                     usertrust, ssoassert, joinkey, nonce, replay, jws, wire
  signing/config     signer (kms, pkcs11, software), bundle, policy, nebulaconfig
  mesh API/agent     coreapi, heartbeat, renew, supervisor, drift, hostkey, reconcile, paths
  fleet operations   rollout, revocation, reaper, lighthouse, ipam, netblock, fleet,
                     {nebula,pilot}release, {nebula,pilot}update, binverify
  admin/auth         adminapi, adminauth, adminui, dualcontrol, config
  platform           store, queue, dbsecret, ratelimit, obs, autotls, genesis, auditverify

ui/                  React admin console (embedded into harbor via `-tags ui`)
deploy/
  local/             single-box personal deploy (SQLite, software CA, GitHub-OAuth console)
  terraform/ + scripts/bootstrap-genesis.sh   multi-host AWS demo (EC2 core/lighthouse +
                     serverless Fargate gateway)
  prod/              production stack (Aurora, KMS CA, ACME edge TLS, monitoring)
  fargate/           distroless container images (gateway, lighthouse)
docs/                design & implementation plans, protocol spec, ADRs 0001-0014, runbooks
spike/m0/            throwaway feasibility harness (netns + SoftHSM), run via `make m0-*`
```

Module `github.com/jeks313/nebula-control-plane`, Go 1.26. The overlay CIDR defaults to
`100.64.0.0/16` (CGNAT, to avoid colliding with k3s' `10.42/10.43`).

## Build & run

```bash
make build        # bin/pilot, bin/harbor, bin/gateway
make harbor-ui    # harbor with the web console embedded (-tags ui)
make check        # fmt + vet + lint + test
make test

# single-box local mesh (enroll + console end-to-end):
bash deploy/local/local-up.sh
bash deploy/local/local-down.sh
```

The **M0 feasibility spike** (a Nebula overlay in Linux network namespaces with a SoftHSM-backed
CA, no cloud, no containers) still lives under [`spike/m0/`](spike/m0/README.md): `make m0-hsm`,
`make m0-up`, `make m0-test`.

## Status & documentation

The trust spine is built end-to-end on Linux (enrollment, renewal, signed bundles, group firewall,
staged rollouts, revocation, admin console). Host and lighthouse certificates already rotate with
zero downtime; the two main remaining milestones are rotation of the CA and config-signing keys
themselves (M8) and the Windows/macOS hardening tail (M10). The per-OS service backends (Windows SCM,
macOS launchd) are built and validated on real hosts, so what remains for M10 is at-rest host-key
protection, least-privilege service accounts, and signed installers. The planning docs in **`docs/`**
are canonical and evolve with the code: the Design Plan (*what* & *why*), the Implementation Plan
(*order* & *scope*), the Protocol Spec, and ADRs 0001-0014. `CLAUDE.md` carries a living,
code-verified status summary.
