---
created: 2026-06-12
source: claude-chat
status: v1
project: nebula-control-plane
tags: [networking, nebula, security, runbook, genesis, ceremony, pki]
---

# Nebula Control Plane — Genesis Ceremony Runbook

Implementation-plan **3.1**. Genesis bootstraps the control plane's two trust roots and the first lighthouse. It is a **two-operator ceremony** and the single most security-critical procedure in the system — everything else inherits trust from it. See [[Nebula Control Plane - Design Plan]] §3.1 and [[Nebula Control Plane - Protocol Spec]] §6.

## What genesis creates

1. **CA key** — signs all host/lighthouse/Core certificates. (design §2.1 TCB root)
2. **Config-signing key** — signs the JWS config/cert **bundles** Pilot consumes (protocol §3/§6). **Distinct** from the CA key, so compromise of one is not compromise of the other.
3. **First lighthouse certificate** — issued from the lighthouse's *own* public key (P1: the lighthouse generates its key locally; genesis never holds it), in group `lighthouse`.
4. **First Core (control-plane) certificate** *(recommended; `-core-pub`)* — issued from Core's own public key (P1), in group **`control-plane`**. The firewall baseline (policy §6.3) routes *every* host's renew/heartbeat to `group:control-plane`, so a Core node **must** hold that group or it is silently unreachable. Issuing it here keeps the bootstrap self-consistent with the baseline. If you skip `-core-pub`, you **must** mint Core's cert out-of-band before bring-up (`harbor issue-cert -groups control-plane …`) — genesis prints a warning in that case.
5. **Recorded keys + audit** — both roots land in the `keys` table; every step is an entry in the hash-chained audit log (2.2) under both operator identities.

## Trust-root custody

| Environment | CA + config-signing keys | Ceremony |
|---|---|---|
| **Local / dev** | `-backend software` — keys written to `ca.key` / `config-signing.key` (0600). Convenient, **not** for production. | one machine |
| **Production** | `-backend pkcs11` (HSM) or KMS (lands with 2.7) — keys generated **inside** the module, non-exportable. | offline, two operators, air-gapped if possible |

> The current tooling represents two-person control by **recording two distinct operator identities** in the audit log. True cryptographic dual-control (no single identity can act) is implementation-plan **2.11**; wire genesis to it before any production run.

## Prerequisites

- `harbor` and `pilot` binaries built (`make build`).
- For `pkcs11`: a token initialized with a **CA key** and a **config-signing key** (two labels), e.g. via `softhsm2-util` + `pkcs11-tool` (see `spike/m0/20-softhsm-ca.sh` for the pattern); `harbor` built with `-tags pkcs11`.
- The lighthouse's public underlay address (`host:port`, default UDP 4242) reachable by future members.

## Procedure (local / software)

```bash
# 1. The lighthouse AND Core each generate THEIR OWN key (P1). Run on each host, or
#    locally and ship only host.key to each afterwards.
pilot init -dir /tmp/lh            # writes host.key (0600) + host.pub
pilot init -dir /tmp/core          # Core's own key (the control-plane node)

# 2. The two operators run the ceremony. Operators must be distinct.
harbor genesis \
  -out ./genesis \
  -operator-a alice -operator-b bob \
  -lighthouse-pub /tmp/lh/host.pub \
  -lighthouse-ip 100.64.0.1 \
  -lighthouse-addr 198.51.100.1:4242 \
  -core-pub /tmp/core/host.pub \
  -core-ip 100.64.0.2 \
  -pool 100.64.0.0/16
# -> ./genesis/{ca.crt, config-signing.pub, lighthouse-1.crt, harbor-core.crt,
#               genesis.json, ca.key, config-signing.key}
```

Production variant: replace the backend flags —

```bash
harbor genesis -out ./genesis -operator-a alice -operator-b bob \
  -lighthouse-pub host.pub -lighthouse-addr <addr> \
  -backend pkcs11 -pkcs11-token harbor-ca -pkcs11-pin "$PIN" \
  -pkcs11-ca-key-label harbor-ca-key -pkcs11-config-key-label harbor-config-key
```

## Distribute the artifacts

- `ca.crt` → every member's trust bundle (`pki.ca`).
- `config-signing.pub` → **pinned into Pilot** (the bundle-verification root, protocol §6). Treat the pin as code: changing it is a trust event.
- `lighthouse-1.crt` + the lighthouse's `host.key` → the lighthouse host.
- `harbor-core.crt` + Core's `host.key` → the Core host (its control-plane identity).
- `genesis.json` → archive (records CA fingerprint, config-signing key id, lighthouse + core fingerprints, operators, timestamp).
- `ca.key` / `config-signing.key` (software only) → **secure offline storage**; these are the crown jewels.

## Bring up the lighthouse

Render a Nebula config with `am_lighthouse: true`, `pki.ca = ca.crt`,
`pki.cert = lighthouse-1.crt`, `pki.key = host.key`, then run it under Pilot
(`pilot supervise`, M1.6). Validate first with `nebula -test -config <cfg>`.

## Bring up Core

Run Core's Nebula node with `pki.cert = harbor-core.crt` + Core's `host.key`, then start
`harbor core-api` with **`-host-cert ./genesis/harbor-core.crt`**. At boot, core-api
verifies that cert carries `group:control-plane` and **fails fast** if it does not — so a
mis-issued or wrong-group Core identity is caught at bring-up rather than silently
breaking fleet-wide renew/heartbeat. It logs `control-plane identity verified` on success;
omitting `-host-cert` logs a warning that the invariant is unverified.

## Verification (the 3.1 "done when")

```bash
nebula-cert verify -ca genesis/ca.crt -crt genesis/lighthouse-1.crt   # cert chains to CA
nebula -test -config <lighthouse.yml>                                  # config is valid
harbor audit verify                                                    # chain intact:
#   genesis-ca, genesis-config-key, issue-cert (lighthouse), genesis-core, genesis-complete
nebula-cert verify -ca genesis/ca.crt -crt genesis/harbor-core.crt     # Core cert chains to CA
```

The automated equivalent is `internal/integration` `TestGenesisRun`.

## After genesis

- Stand up enrollment (3.2 `GET /v1/nonce` → …) so members join without manual cert issuance.
- Plan **CA / config-signing rotation** (M8) — genesis is also where the *first* multi-CA bundle and key-id pinning set begin.
- If a trust root is ever suspected compromised: emergency rotation (8.6) + re-genesis of the affected root.
