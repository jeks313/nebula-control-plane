---
title: "Runbook — Stand up the Nebula Control Plane on AWS (genesis bootstrap)"
created: 2026-06-12
source: claude-chat
status: active
project: nebula-control-plane
tags: [nebula, runbook, genesis, bootstrap, aws, production, pki, kms, standup]
---

# Runbook — Stand up the Nebula Control Plane on AWS (genesis bootstrap)

**Status (2026-06-18):** LIVE. This exact flow built the `poc` stack — which *is* the production control plane today (`deploy/prod/`, S3 remote state in `ca-central-1`, `poc-harbor`/`poc-gateway.mesh.failsafe.net`). KMS-backed trust roots, Aurora, ACME edge TLS, Fargate gateway **and** Fargate lighthouse, SSM-only node access, and the full React console on :443 are all running.

This is the **start-to-finish** guide for bringing a fresh Nebula control plane online on AWS. It
assumes **no prior knowledge** of the system — every term is explained — and it matches what the
orchestration script `deploy/prod/bootstrap-genesis.sh` actually does today (KMS-backed trust root,
Entra SSO, the console on HTTPS/443, ACME TLS). At its heart is the **genesis ceremony** — the
one-time creation of the cryptographic trust roots everything else depends on.

You run two things, in order: **`terraform apply`** (creates the cloud infrastructure), then **one
bootstrap script** (wires the software on top). The bootstrap runs **from your laptop** and drives
the cloud nodes over SSH — you never log into them by hand.

> ✅ **Battle-tested (2026-06-18).** This flow has been run against real AWS — it stood up the live
> `poc`/prod stack. Earlier this said "nothing here has been run against real AWS"; that is no longer
> true. The checklist at the end is still the right thing to walk for a fresh standup.

Conceptual background: **Design Plan §3.1** (the ceremony) + **Protocol Spec §6** (the bundle
signature); the KMS / SAML / TLS / HA decisions are in **ADR 0007**.

---

## Plain-English glossary (read this once)

- **Nebula:** the open-source overlay-mesh VPN this whole system manages. Hosts get a private "mesh" identity and talk directly to each other over encrypted tunnels.
- **Overlay vs underlay:** the **overlay** is the mesh network (private addresses like `10.44.0.2`). The **underlay** is the real network underneath (a host's actual AWS/public IP). Nebula runs the overlay on top of the underlay.
- **Lighthouse:** a Nebula node that helps the others find each other (peer discovery + hole-punching). The mesh needs at least one.
- **pilot:** the agent that runs on every host — it enrolls the host, supervises the local `nebula` process, and self-updates.
- **Harbor / Core:** the control plane. "Core" is Harbor's mesh-facing API (issues/renews certs, takes heartbeats). Harbor also runs the **admin console** (the web UI). Both are **mesh-only** — reachable only from inside the mesh, never the public internet.
- **Gateway:** the **only** public-facing piece — an off-mesh node that accepts enrollment requests from new hosts and hands them to Harbor. Hosts join *through* the gateway; Harbor itself stays private.
- **Enrollment:** how a new host gets its first mesh certificate (proves who it is → gets issued an identity).
- **CA (certificate authority):** the signing key that issues every host's mesh certificate. **Trust root #1.**
- **Config-signing key:** a *separate* key that signs the **config bundles** Harbor sends to hosts (firewall policy, the lighthouse list, revocations). **Trust root #2.** Kept distinct from the CA so compromising one doesn't compromise the other.
- **Trust root:** a key that must never leak — everything's security depends on it. There are exactly two here (CA + config-signing).
- **The pin (`config-signing.pub`):** the *public* half of the config-signing key. Every host is given this one value and refuses any config bundle not signed by its private counterpart. It is the single anchor of trust on the client side.
- **Genesis ceremony:** the one-time act of creating those two trust roots and issuing the first certificates. Done under **two operators** (below).
- **KMS (AWS Key Management Service):** a service that holds private keys **non-exportably** — the key never leaves AWS, you can only ask it to *sign*, and every signature is logged. We use it for the two trust roots by default, so the private keys never touch a disk.
- **ACME / Let's Encrypt / DNS-01:** the standard way to get a real HTTPS certificate automatically. "DNS-01" proves you own the domain by writing a DNS record (we use Cloudflare). Harbor uses this to serve real HTTPS for the console + Core.
- **SAML / Entra:** how the console does "log in with your Microsoft work account" (see the companion SAML runbook). Optional — there's a dev fallback (`mock-idp`).
- **Cloud-trust:** a rule that says "any host running under *this* AWS account + IAM role is allowed to auto-enroll." Lets cloud VMs join keyless (they prove identity with their AWS role).
- **Two-operator ceremony (`alice` / `bob`):** genesis records two operator names — one "signs" the CA, the other the config-signing key — into a tamper-evident audit log. It's *process discipline + an audit trail*, **not** cryptographically enforced dual-control (the names are just strings; one person can run it). It exists so the most security-critical act is deliberate and recorded.

## The big picture

```
        you (laptop)
           │  terraform apply  (foundation → app)         ← builds the cloud
           │  bash bootstrap-genesis.sh   (over SSH)      ← wires the software
           ▼
  ┌─────────────────── AWS VPC ───────────────────┐
  │  Gateway (PUBLIC)  ◄── new hosts enroll here    │
  │       ▲ pulled by Harbor (mTLS), initiates nothing
  │  Harbor / Core (MESH-ONLY) ── CA + console      │   trust roots in KMS
  │  Lighthouse (mesh)  ── peer discovery           │
  │  cloud client / iMac ── data-plane members      │
  └─────────────────────────────────────────────────┘
```

The bootstrap is **one script that performs 8 phases** end to end (build → init nodes → genesis →
start the mesh → cloud-trust → gateway → console). You run it once; it does the rest.

---

## Before you start

**1. Apply terraform first — foundation, then app.** The bootstrap reads its inputs from terraform
outputs; if you skip this it has nothing to read.
- **`deploy/prod/terraform/foundation/`** (apply first) — the **state bucket** + the two **KMS trust-root keys** (CA + config-signing). These keys must exist *before* genesis; genesis uses them, it does not create them.
- **`deploy/prod/terraform/app/`** (apply second) — the VPC, the Aurora database, the EC2 nodes (Harbor / client / monitoring), the gateway and the lighthouse (both **Fargate by default**; override `gateway_runtime`/`lighthouse_runtime` to `ec2` for a VM), and the Cloudflare-token secret. It reads the foundation's KMS ARNs via remote state.

**2. Decide the overlay pool.** `POOL` (default `10.44.0.0/16`) is the mesh's private address range.
⚠️ **Never use `100.64.0.0/10` if you also run Tailscale** — its anti-spoof rules silently drop that
range. The lighthouse is `10.44.0.1`, Harbor is `10.44.0.2` by default.

**3. For HTTPS + SSO (recommended): set the mesh domain + a Cloudflare token.**
- Set `mesh_name` + `mesh_domain` in the app stack (e.g. `poc` + `mesh.failsafe.net`) → Harbor gets a real Let's Encrypt cert and serves the console on **HTTPS**. Without this the console is plain HTTP and **SAML SSO cannot work** (its login cookie requires HTTPS).
- Create a **scoped Cloudflare API token** (Zone.DNS:Edit only) and put it in the secret terraform created: `aws secretsmanager put-secret-value --region <region> --secret-id <cloudflare_token_secret_arn> --secret-string <token>`. The bootstrap refuses to proceed on a placeholder token.

**4. Local tools:** `terraform`, `jq`, `go`, `ssh`, `scp`, `openssl` are required. `aws` is also
needed if you set the mesh domain (to fetch the Cloudflare token) **or** run a Fargate component. A
container engine (`podman` or `docker`) is needed **only** for a Fargate gateway/lighthouse (to
build + push the image).

**5. AWS credentials** in your shell — the *same* ones you ran terraform with. Use `aws-vault` (e.g.
`aws-vault exec nebula -- bash …`); never paste keys.

**6. An SSH key** that can reach the nodes (`SSH_KEY` → your public key path; the private half in
your agent). Nodes log in as `ec2-user` by default.

**7. (Optional, for real SSO)** the Entra SAML env vars + SP keypair — see *Wire real SSO* below and
the companion **Entra SAML runbook**. If you skip these, the console comes up with the **dev
mock-IdP** so you can still get in.

---

## The genesis ceremony — what's actually happening (the security-critical heart)

When the bootstrap reaches phase 3 it runs `harbor genesis`. This is the **one irreversible,
security-critical act** in the whole system — everything inherits trust from it. It:

1. **Creates two trust roots** (both P-256 elliptic-curve keys, kept **distinct** — genesis refuses if they're the same):
   - the **CA key** — signs every host's mesh certificate;
   - the **config-signing key** — signs every config bundle hosts receive.
2. **Issues the first two certificates** from the CA: the **lighthouse**'s cert and **Harbor's own control-plane cert**. Harbor's cert *must* carry `group:control-plane` — the firewall baseline routes every host's renew/heartbeat there, so without it Harbor is silently unreachable (genesis issues it when given `-core-pub`, which the bootstrap always does).
3. **Writes the public artifacts** to `~/ncp/genesis` on the Harbor node: `ca.crt`, `config-signing.pub`, `lighthouse-1.crt`, `harbor-core.crt`, and `genesis.json` (an immutable record of the ceremony — who, when, fingerprints).
4. **Records the ceremony in a tamper-evident audit log** under two operators — `-operator-a alice` signs the CA, `-operator-b bob` the config-signing key — hash-chained, so editing any entry breaks the chain. (The rows it writes: `genesis-ca`, `genesis-config-key`, two `issue-cert` rows — lighthouse + harbor-core, `genesis-core`, `genesis-complete`.)

**KMS by default — the private keys never touch disk.** Because the foundation stack provisioned the
two KMS keys, the bootstrap passes `-backend kms -kms-ca-key-id <arn> -kms-config-key-id <arn>`, and
genesis only ever asks KMS to *sign* — it writes the public `ca.crt` / `config-signing.pub`, but the
private keys stay locked in KMS (non-exportable, every use logged in CloudTrail). If the KMS ARNs are
absent (a non-prod foundation), it falls back to the **software backend**, which generates the keys
in memory and writes `ca.key` / `config-signing.key` to `~/ncp/genesis` (mode 0600, never
clobbering existing files) — *you* must then guard those files as the crown jewels.

**The pin.** After genesis, `config-signing.pub` is copied to
`deploy/prod/terraform/app/config-signing.pub` (gitignored) and handed to **every** client as
`-config-pub`. A host trusts a config bundle **only** if it's signed by the matching private key.
Guard this value: swap it and you could feed hosts forged policy.

**Honest note on "two operators":** today `alice`/`bob` are just names written to the audit log — it
proves the act was deliberate and gives you an audit trail, but it is **not** enforced dual-control
(one person can run the whole thing). True cryptographic dual-control is a future hardening item.

---

## Run it

From the repo root, with AWS creds + your SSH key:

```bash
SSH_KEY=~/.ssh/your-key.pub  aws-vault exec nebula -- bash deploy/prod/bootstrap-genesis.sh
```

Useful environment variables (all optional; sensible defaults shown):

| Var | Default | What |
|---|---|---|
| `SSH_KEY` | `~/.ssh/absolute.pub` | your public key; the private half must be in your ssh agent |
| `SSH_USER` | `ec2-user` | the node login user |
| `POOL` | `10.44.0.0/16` | overlay address range (⚠️ not `100.64/10` with Tailscale) |
| `CORE_PORT` / `ADMIN_PORT` | `8444` / `443` | Core API / admin console ports (both mesh-only) |
| `--skip-build` (arg) | off | skip rebuilding the Go binaries (reuse what's there) |
| `CONTAINER_ENGINE` | `podman`→`docker` | image build engine (only for Fargate) |
| `SAML_*` | unset → mock-IdP | real Entra SSO inputs (see *Wire real SSO*) |

It builds for `linux/amd64`. The console defaults to **443** (clean `https://<host>` URLs); core-api
stays on **8444**.

## What it does, phase by phase

| # | Phase | In plain terms |
|---|---|---|
| 0 | **Build + distribute** | compiles `harbor`/`pilot`/`gateway` and `scp`s them to the nodes (skip with `--skip-build`) |
| 1 | **Lighthouse init** | creates the lighthouse's own mesh key. EC2 lighthouse: on the node (key never leaves it). Fargate lighthouse (the default): the keypair is generated off-box and injected via the config secret (the task filesystem is ephemeral) |
| 2 | **Harbor init** | creates Harbor's own mesh key + points it at the lighthouse, then opens the Nebula firewall for Core's ports (8444 + 443) so the mesh can reach the console |
| 3 | **Migrate + genesis** | runs DB migrations, then **the genesis ceremony** above (CA + config-signing + the first certs), pulling the public artifacts back to your laptop |
| 4 | **Lighthouse start** | installs its cert and starts `nebula` — the mesh now has a discovery point |
| 5 | **Harbor joins the mesh** | installs Harbor's control-plane cert and starts `nebula` — Harbor is now reachable at `10.44.0.2` |
| 6 | **Cloud-trust** | publishes "hosts in *this* AWS account + role may auto-enroll" so cloud VMs join keyless |
| 7 | **Gateway + collector** | stands up the public enrollment gateway (EC2 or Fargate) and registers it with Harbor, which *pulls* from it over mTLS |
| 8 | **Core + console** | starts `core-api` (renew/heartbeat) and the admin console (with SAML or the mock-IdP), over HTTPS if the mesh domain is set |

---

## After it finishes

The script prints a summary. Key things in it:
- **The config-signing pin** (`deploy/prod/terraform/app/config-signing.pub`) — give this to every client you enroll.
- **The gateway enrollment URLs** — public (off-cloud hosts) and in-VPC (cloud hosts).
- **The admin console URL** — `https://<mesh_name>-harbor.<mesh_domain>/` (port-less, mesh-only). Reach it from a machine that's *on the mesh* and resolves that name to Harbor's overlay IP (`10.44.0.2`).
- **The iMac join key** and ready-to-paste enroll commands:
  - **cloud client** — keyless via `aws-sigv4` (it proves identity with its AWS role; cloud-trust auto-issues);
  - **off-cloud host (the iMac)** — uses the **join key** and needs **manual approval** in the console (or via `harbor enroll approve`).

## Wire real SSO (Entra SAML)

By default the console comes up with the **dev mock-IdP** so you can log in immediately. For real
Microsoft Entra SSO, set the `SAML_*` env vars (`SAML_METADATA_URL`, `SAML_SP_KEY_FILE`,
`SAML_SP_CERT_FILE`, `SAML_ROLE_MAP`, …) **before** running the bootstrap — it then wires real SAML
in production mode and prints the exact Entity-ID / ACS URLs to register in Entra. This **requires
HTTPS** (so `mesh_name` + `mesh_domain` must be set). Full step-by-step (the Entra app registration
and the SP keypair) is in the companion **Entra ID SAML SSO for the Console** runbook.

## Follow-on (separate scripts, run after genesis)

- **Binary hosting** — `deploy/prod/artifacts/publish.sh` publishes the pilot/nebula binaries to the S3 artifacts bucket for self-update (only if you set `artifacts_bucket_name`). See the artifacts README.
- **Monitoring** — `deploy/prod/monitoring/deploy.sh` enrolls a monitoring node and brings up Prometheus/Alertmanager/Grafana/Loki. Run it **after** genesis (it needs the pin) + set `GF_ADMIN_PASSWORD`. See the monitoring README.

---

## Verify (the 3.1 "done when")

1. **Lighthouse + Harbor are reachable on the mesh:** from any joined node, `ping 10.44.0.1` (lighthouse) and `ping 10.44.0.2` (Harbor).
2. **The certs chain + configs are valid** (on the Harbor node's `~/ncp/genesis`): `nebula-cert verify -ca ca.crt -crt lighthouse-1.crt` and `… -crt harbor-core.crt`; `nebula -test -config <lighthouse.yml>`.
3. **The audit chain is intact:** `harbor audit verify` walks the hash chain and prints `audit: chain verified, N rows intact` — an intact chain *is* the pass signal; it does **not** list the events. The rows the ceremony wrote are `genesis-ca`, `genesis-config-key`, two `issue-cert` (lighthouse + harbor-core), `genesis-core`, `genesis-complete` (inspect the audit table directly if you want to see them).
4. **A client appears in the fleet:** the cloud client shows up in the console's fleet dashboard (it's heartbeating).
5. **The console loads:** browse the console URL from an on-mesh machine; you get the login (SAML or mock-IdP).

(The automated equivalent of the genesis checks is `internal/integration` `TestGenesisRun`.)

## If it breaks — common causes

- **"no terraform outputs" / empty IPs:** you didn't `terraform apply` (foundation *and* app) first, or you're running from the wrong directory.
- **Genesis fails "must be distinct trust roots":** the same KMS key id was given for both CA and config-signing — they must be two different keys.
- **Genesis can't find the KMS keys:** the keys must already exist (foundation stack); genesis doesn't create them. Check the `ca_key_arn` / `config_signing_key_arn` outputs are non-empty.
- **Cloudflare token error:** the secret still holds the placeholder — populate it (command above) before re-running.
- **Nodes ping but the console/Core times out:** the Nebula firewall didn't open the service ports (phase 2) — re-run, or confirm `/etc/nebula/config.yml` has inbound TCP for 8444 + 443.
- **SAML won't log in:** you're on plain HTTP (set `mesh_name`/`mesh_domain`), or the Entra URLs don't match what the bootstrap printed — see the SAML runbook.
- **Re-running genesis fails (software backend):** `ca.key`/`config-signing.key` already exist (genesis won't clobber a trust root). This is a safety feature — don't delete them blindly; understand why you're re-running.

## Notes

- **Order is load-bearing:** foundation terraform → app terraform → populate the Cloudflare token → bootstrap → (monitoring/artifacts). Genesis depends on the KMS keys + the node IPs existing first.
- **Harbor stays mesh-only:** the console + Core bind the overlay IP, in no public security group. Only the gateway faces the internet (ADR 0005). Moving the console to 443 is for clean URLs over the mesh, not public exposure.
- **The two trust roots are forever:** the KMS keys (and the foundation state) are `prevent_destroy`. Losing them, or the pin, is a top-severity event — custody accordingly; suspected compromise means emergency rotation + re-genesis of the affected root.
