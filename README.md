# Nebula Control Plane (Harbor + Pilot)

A control plane for [Nebula](https://github.com/slackhq/nebula): automated device enrollment,
IP assignment, certificate issuance/rotation, and central firewall policy — with a KMS-backed CA
and cloud attestation. Codenames: **Harbor** (control plane), **Pilot** (per-host agent that
supervises `nebula`).

> Design, implementation, infrastructure, and UI plans live in Chris's knowledge vault
> (`Plans/Nebula Control Plane - *`). This repo is the build.

## Status

**M0 — Spike (feasibility).** Proving the foundations *locally* before building Harbor:

1. A Nebula overlay between nodes (network namespaces, no cloud, no containers).
2. **A CA whose private key lives in a hardware module** (SoftHSM via PKCS#11) signs Nebula
   certs and a tunnel forms — the local stand-in for the AWS KMS CA, and the single biggest
   feasibility risk (impl plan M0.3).
3. Blocklist peer-enforcement (M0.5) and group→firewall semantics (M0.6).

See [`spike/m0/README.md`](spike/m0/README.md).

## Local dev approach

Local-first (this Linux box): the data plane runs as `nebula` processes in **Linux network
namespaces**; **SoftHSM2** stands in for AWS KMS faithfully (key never leaves the module).
Later tiers add a k3s integration environment and a minimal AWS harness. Overlay uses
`100.64.0.0/16` (CGNAT) to avoid colliding with k3s defaults (`10.42/10.43`).

## Quick start (M0)

```bash
make m0-prereqs        # check tooling, print install command
# install the toolchain it prints (needs sudo), then:
make m0-up             # bring up the netns overlay (local CA)   [sudo]
make m0-test           # ping across the overlay + blocklist + groups  [sudo]
make m0-down           # tear it all down  [sudo]

# the feasibility test (HSM-backed CA):
make m0-hsm            # SoftHSM CA + pkcs11 nebula-cert + tunnel
```

## Layout

```
spike/m0/      throwaway M0 feasibility harness (netns + SoftHSM)
Makefile       top-level targets
```
