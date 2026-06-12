---
created: 2026-06-11
source: claude-chat
status: draft-v2
project: nebula-control-plane
tags: [networking, nebula, security, infrastructure, aws, devops, local-dev, terraform]
---

# Nebula Control Plane — Infrastructure Plan (Local-first → AWS)

Companion to [[Nebula Control Plane - Design Plan]] (v3), [[Nebula Control Plane - Implementation Plan]] (v2), and [[Nebula Control Plane - Admin UI Plan]]. Refs *(§…)* point at the design doc; *(M…)* at the implementation plan.

> **Revision (2026-06-11):** restructured to a **three-tier, local-first** strategy. Most of the system is application logic and a Linux data plane — both fully testable on a single workstation. AWS is introduced only for what genuinely *can't* be faked: real KMS+IAM+SCP, EC2 instance attestation, and internet NAT traversal.
> - **Tier 1 — Local** (this box): ~80–90% of milestones, full or near-full coverage.
> - **Tier 1+ — Near-100% local on k3s**: pluggable backends + test doubles + a k3s cluster push local coverage to ~100% of *our* logic/topology, incl. HA, failover, deploy/rollback, fleet-scale load, and NAT traversal.
> - **Tier 2 — Minimal AWS harness**: shrinks to a brief trust-anchor smoke test (≈2 EC2 + 1 KMS key).
> - **Tier 3 — Full production** (target state, last).

## Guiding idea: what actually needs a cloud?

Almost nothing, until late. Nebula runs in local containers (privileged for `/dev/net/tun`); Harbor is a Go service + Postgres; the queue/result-store/secrets all have faithful local stand-ins; and — crucially — **the CA-in-a-hardware-module property is reproducible locally with SoftHSM2 via Nebula's PKCS#11 path**. AWS KMS is just a *different backend for the same concept*, so the riskiest feasibility question (M0.3) is answerable on this laptop. The genuinely cloud-bound pieces are: **real KMS/IAM/SCP behavior**, **EC2 instance attestation** (sigv4 from an instance role, IID, `DescribeInstances`), **internet NAT traversal/underlay**, and later HA/DR/PrivateLink.

---

# Tier 1 — Local-first (this workstation)

Target: a single CachyOS/Arch box runs the **entire mesh + control plane** as containers, with local stand-ins for every AWS dependency. This is the daily dev + integration environment.

## 1.0 Local isolation & prerequisites (read first — avoid breaking your real k3s)

- **Overlay CIDR must not collide with k3s.** k3s defaults to pods `10.42.0.0/16` and services `10.43.0.0/16`. A Nebula overlay in `10.42.x` (as earlier examples used) will fight the cluster's routing/iptables. Use a block clear of both **and** your LAN — examples here use CGNAT space **`100.64.0.0/16`** (AWS `100.64.0.0/17`, Azure `100.64.128.0/17`).
- **Don't deploy the dev mesh into your production k3s.** Nebula nodes are privileged, create TUN devices, and touch routes — not something to run loose in your live cluster. For **Tier 1+**, use **k3d** or a **separate/disposable k3s** (own data-dir or VM); keep **Tier 1** on Podman compose. This gives *zero* interference with the existing cluster.
- **Podman ↔ k3s coexist fine** — different runtimes (Podman vs k3s containerd), they ignore each other. Use **rootful Podman for the nebula nodes** (rootless can't reliably create TUN / change routes); SoftHSM/Postgres/etc. can stay rootless. Nebula pods need `--cap-add=NET_ADMIN --device /dev/net/tun` (or privileged).
- **Host-port clashes:** k3s Traefik holds `80/443` — publish the dev gateway on other ports (or use the disposable cluster's own ingress).
- **Host networking blast radius:** Nebula's *firewall* is in-process (userspace) so it won't pollute host iptables, but **TUN routes and the NAT-traversal scenario** (netns/`nftables MASQUERADE`, §1+.3) *do* touch host networking — contain those in the disposable cluster / VMs, not the host.
- **Resources:** a scaled Pilot fleet + k3s on one box adds up — size CPU/RAM accordingly and tear down between runs.

## 1.1 Toolchain (install once)

- **Container runtime:** Docker or Podman (rootful or `--privileged`/`--cap-add NET_ADMIN --device /dev/net/tun` for nebula nodes).
- **Go** (Harbor + Pilot), `golangci-lint`.
- **Nebula** (pinned version) + `nebula-cert`.
- **SoftHSM2** + `opensc` (PKCS#11) — the **local CA-in-a-module stand-in**. Create a P256 key in a SoftHSM token; Nebula's PKCS#11 signing path uses it exactly as it would an HSM/KMS. Proves "private CA key never exported, signs valid certs."
- **Postgres** (container).
- **AWS API emulation:** **LocalStack** (KMS / SQS / STS / DynamoDB) and/or **DynamoDB Local**. Use LocalStack-KMS as an alternative way to exercise the `nebula-cert-kms` *code path* against an emulated KMS API; use SoftHSM as the faithful crypto stand-in.
- **OIDC:** a local **Keycloak** or **Dex** container for SSO + the laptop device-code flow (M9.1).
- **Observability:** Prometheus + Grafana + Jaeger via compose.
- **Queue (optional):** NATS or Redis as a lighter local alternative to SQS, or LocalStack-SQS for fidelity.

## 1.2 The local mesh (compose topology)

One `docker-compose`/`Podman` stack:

```
softhsm (CA, PKCS#11)        localstack (KMS·SQS·STS·DynamoDB)     keycloak (OIDC)
        │                              │                                  │
   ┌────▼──────────────────────────────▼──────────────────────────────────▼────┐
   │ HARBOR CORE (+ nebula sidecar, privileged)   GATEWAY    SIGNER→SoftHSM/KMS │
   │ Postgres   prometheus/grafana/jaeger                                       │
   └────┬───────────────────────────────────────────────────────────────────────┘
        │  Nebula overlay (all on the local bridge)
   ┌────▼────┐   ┌─────────┐   ┌─────────┐
   │LIGHTHOUSE│   │ PILOT A │   │ PILOT B │   ... add N pilot containers ...
   └─────────┘   └─────────┘   └─────────┘
```

- Each nebula-running container is privileged (TUN). The local bridge means **no real NAT traversal** — that's the one data-plane gap (covered in Tier 2).
- Scale Pilots up (tens, low hundreds) to exercise renewal jitter, canary rollout, blocklist propagation.

## 1.3 Local coverage by milestone

| Milestone | Local coverage | Gap → needs AWS |
|---|---|---|
| **M0** spike | Tunnel, blocklist peer-enforcement, groups→firewall (containers); **CA-sign via SoftHSM/PKCS#11** | Real KMS (T2); real NAT/underlay + MTU (T2, M0.7) |
| **M1** Pilot (Linux) | supervise, keypair, digest, reload, systemd — **full** | Windows service/DACL/Authenticode → local **Windows VM** (KVM) or CI; macOS → Mac/CI |
| **M2** Harbor Core | Postgres, audit+chain, IPAM, Signer (SoftHSM), template validation, circuit-breaker, observability, secrets — **full** | Cross-account KMS **SCP isolation** (T2) |
| **M3** enrollment | gateway, stateless nonce, queue (NATS/LocalStack-SQS), result store (DynamoDB Local), token enroll, async poll, genesis (SoftHSM), approval workflow — **full** | — |
| **M4** lifecycle | Core-as-mesh-node, renewal+jitter, heartbeat, self-renewal, version-skew, **P3 chaos** (kill Core) — **full** | — |
| **M5** attestation | **sigv4 verify logic** testable against **real STS using a local IAM user's creds** (no EC2) | **EC2 instance** attestation (IID, role, DescribeInstances), PrivateLink, Azure → T2/T3 |
| **M6** policy | DSL, compiler, invariants, JWS bundles, canary+auto-rollback, drift — **full** | — |
| **M7** revocation | blocklist propagation, bulk-revoke guards, decommission — **full** | EC2-terminate auto-reap (EventBridge) → T2/T3 |
| **M8** rotation | multi-CA trust bundle, state machine, drain, config-key rotation — **full** (two SoftHSM keys) | Multi-region KMS DR → T3 |
| **M9** hardening | OIDC device flow (Keycloak), SIEM stack, load test (many Pilot containers), policy/protocol fuzzing — **mostly** | SSM break-glass, real HA/DR, Shield/WAF, EC2-Mac, gateway pentest → T2/T3 |

**Bottom line:** every milestone's *application logic* and the *Linux data plane* are provable locally. Windows/macOS Pilots use local VMs or CI. Only the cloud-trust integrations and internet-scale concerns leave the box.

## 1.4 What basic local (compose) can't prove — and what closes it

- Real **NAT traversal / hole-punching** (flat bridge) → closed by **Tier 1+** (deliberate NAT topology).
- Real **KMS / IAM / SCP** semantics → crypto closed by SoftHSM; IAM/SCP *enforcement* stays cloud (Tier 2).
- **EC2/Azure instance attestation** end to end → *logic* closed by Tier 1+ test doubles; *signature authenticity* stays cloud (Tier 2).
- **HA, multi-AZ, DR, deploy/rollback** → closed by **Tier 1+** (k3s + CloudNativePG); PrivateLink/Shield stay cloud (Tier 3).

Tier 1+ below closes most of these on your k3s cluster.

---

# Tier 1+ — Near-100% local on k3s

**The reframe:** separate **our logic** from **their guarantees**. A local setup can exercise 100% of *our* code, topology, and failure modes. It cannot reproduce *other parties'* security enforcement — AWS IAM/SCP/Shield and the authenticity of AWS/Azure-signed attestations. Those aren't functional tests; they're trust-anchor integration checks (Tier 2). So **"100% local" = 100% functional/integration of our system**, with ~4 narrow third-party checks deferred.

## 1+.1 The enabler: pluggable backends + test doubles

Design these as interfaces from day one (cheap now, also good architecture — testability + cloud-agnosticism, not test-only scaffolding):

- **Signer backend:** `PKCS#11 (SoftHSM)` | `KMS`. Local = SoftHSM; KMS is a thin adapter checked once in Tier 2.
- **AttestationVerifier:** `test-CA` | `AWS-sigv4` | `AWS-IID` | `Azure`. Test mode trusts a local test CA.
- **Instance-metadata source:** `fake-IMDS` | `real-IMDS`. A local service serves test-CA-signed IID / attested-data; LocalStack provides STS for sigv4.
- **Cloud inventory:** `fake` | `EC2/ARM`. For `DescribeInstances` cross-checks + reconciliation (§7.1).

In test mode, swap in local doubles + test trust anchors; in prod, the real backends. Same code path either way.

## 1+.2 k3s component map (production-shaped)

- **Harbor Core** → Deployment (multi-replica, pod anti-affinity across **zone-labeled** nodes).
- **Postgres** → **CloudNativePG** (or Patroni) operator = real HA + failover — tests M9.5 locally; ties to [[PgDog - Horizontal Scaling for PostgreSQL]] / the Patroni notes.
- **Gateway** → Deployment behind **Traefik Ingress** (+ Coraza/ModSecurity to exercise WAF-rule logic).
- **Signer** → Deployment → SoftHSM (or LocalStack-KMS).
- **Queue / result store** → NATS/Redis or LocalStack SQS + DynamoDB.
- **OIDC** → Keycloak/Dex (admin SSO + laptop device flow, M9.1).
- **Observability** → kube-prometheus-stack + Grafana + Jaeger/Tempo.
- **Secrets** → Sealed Secrets / External Secrets / Vault-dev (secrets-mgmt analog, M2.10).
- **Pilot fleet** → a **scalable Deployment of privileged pods** (`NET_ADMIN` + `/dev/net/tun`), each a mesh node — scale to hundreds/low-thousands for **load, renewal-jitter, canary rollout, blocklist-propagation** tests (M9.8).
- **Lighthouse(s)** → Deployment(s); multi-node k3s gives real cross-node paths.

> TUN in pods works via `securityContext` privileged / `NET_ADMIN` + the tun device — k3s doesn't have Fargate's restriction.

## 1+.3 Closing the four "cloud-only" gaps locally

1. **NAT traversal / hole-punching** — build deliberate NAT: multi-node k3s across libvirt/multipass VMs on separate NATed subnets (hostNetwork pods), or a side `netns`+`nftables MASQUERADE` scenario = two NAT'd "sites" + a public lighthouse. Genuinely exercises hole-punching (better than a single flat CNI).
2. **KMS / IAM / SCP** — crypto via SoftHSM (faithful "key never exported"); API path via LocalStack-KMS. IAM/SCP *enforcement* is AWS's job → not a local functional test; verify once in Tier 2. Our Signer logic is 100% local.
3. **Instance attestation** — fake-IMDS + test-CA-signed IID/attested-data + LocalStack STS test **all** of Harbor's verification logic (parsing, nonce+pubkey binding, allowlists, conflict handling). Only the *authenticity of real AWS/Azure signatures* defers to Tier 2 (swap the trust anchor).
4. **HA / DR / deploy-rollback** — multi-node k3s + zone labels + CloudNativePG: kill a node/replica → enrollment/renewal survive (**M4.9, M9.5**); rolling Core upgrade + rollback (**M9.9**); backup→restore drill (**M9.10**) fully local. Two k3s clusters/node-pools simulate "regions" for DR.

## 1+.4 The irreducible residual (genuinely not local)

- Authenticity of **real AWS/Azure attestation signatures** (their private keys).
- **AWS IAM/SCP enforcement** of PKI isolation (their control plane).
- **PrivateLink** wiring and **Shield** volumetric DDoS (managed services).
- Real internet-scale **NAT diversity** (CGNAT, exotic firewalls).

These are ~4 trust-anchor/integration checks — done once in Tier 2, not part of the functional suite.

## 1+.5 Verdict

With pluggable backends + k3s, **dev and functional/integration testing are effectively 100% local** — including HA, failover, deploy/rollback, fleet-scale load, and NAT traversal. **Tier 2 shrinks from "the test environment" to a brief smoke test of 3–4 third-party guarantees.** Most milestones can reach "done" on k3s; AWS becomes a verification gate, not a development dependency.

---

# Tier 2 — Minimal AWS test harness

Target: the **smallest possible** AWS footprint that validates exactly the four things local can't — real KMS-signing + IAM, EC2 instance attestation, and real NAT traversal — then tears down. Deploy with Terraform; tag `lifecycle=harness`; destroy when idle.

## 2.1 Bill of materials (minimal)

- **1× KMS asymmetric key** (`ECC_NIST_P256`, `SIGN_VERIFY`) + an IAM role that can only `KMS:Sign`/`GetPublicKey`. Validates M0.3 against *real* KMS + `nebula-cert-kms`.
- **1× EC2 "harbor" instance** (`t3.small`, public subnet, **SSM-managed — no SSH key**) running the whole stack in containers: Harbor Core + gateway + Postgres + a **lighthouse**. Public IP/EIP; SG opens only the gateway TLS port + the Nebula UDP port.
- **1× EC2 "pilot" instance** (`t3.micro`, **with a minimal instance role**) that enrolls against harbor — this is what exercises **sigv4 GetCallerIdentity + IID/PKCS7 + DescribeInstances** (M5.1–5.3) and, because it sits behind real AWS networking, **real NAT traversal** to the lighthouse (M0.7).
- **1 tiny VPC**, 1 public subnet, IGW. **No** ALB/WAF/NAT-gateway/Aurora/PrivateLink/multi-AZ — deliberately omitted.
- IAM: a role for harbor to call `ec2:DescribeInstances` + assume the KMS-sign role.

That's **2 EC2 + 1 KMS key + 1 micro-VPC**. Everything else (Core/gateway/DB/lighthouse) is colocated on one box to stay minimal.

## 2.2 What it validates (and only this)

- Real **KMS P256 signing** path + IAM scoping (the LocalStack→real delta).
- **EC2 attestation** end to end: sigv4 from an instance role, IID cross-check, DescribeInstances.
- **Real NAT traversal / underlay / MTU** between two real network locations (M0.7).
- A real **public gateway** reachable from an enrolling host.

## 2.3 Optional "harness+" (one more account)

If validating the **PKI isolation** model (§6.3) early matters: add a **second AWS account** holding the KMS key with an **SCP denying delete/policy-edit**, and have harbor's role assume cross-account to sign. Adds one account, no new compute. Otherwise defer isolation to Tier 3.

## 2.4 Cost & hygiene

- ~2 small/micro EC2 + 1 KMS key + EIP. Pennies-to-low-dollars per day; **destroy when not in use** (`terraform destroy`). No NAT gateway (the silent cost sink) by design.
- Access via **SSM Session Manager** only — no SSH keys, no bastion.

---

# Tier 3 — Full production (target state, last)

Everything below is the production target; build it only after Tiers 1–2 prove the system. (This is the original infra design, retained as the destination.)

## 3.1 Account architecture (AWS Organizations)

| Account | Holds |
|---|---|
| **Management** | Org root, SCPs, Control Tower, billing |
| **PKI (isolated)** | KMS CA / config-signing / release-signing keys; SCP denies delete/policy-edit (§6.3); cross-account `KMS:Sign` only |
| **Log Archive / Security** | Org CloudTrail, audit **WORM** (S3 Object Lock), GuardDuty, Security Hub, Config, SIEM |
| **Shared Services / CI** | Build pipelines, artifact registry, release signing |
| **Workload: dev / staging / prod** | Harbor + mesh, one per environment — **each a separate trust domain** (own CA/keys/mesh) |

## 3.2 Environments

- **dev** — small, single-AZ; or fold into Tier-1 local most of the time.
- **staging** — prod-shaped, **multi-AZ**, isolated trust domain; where drills run (CA rotation M8.7, P3 chaos M4.9, load M9.8). First "real" cloud deploy of the prototype.
- **prod** — Multi-AZ + cross-region DR.

## 3.3 Key decisions (carry over from Tier-2 learnings)

- **EC2 vs Fargate — the TUN gotcha:** anything running `nebula` (Core mesh node M4.1, lighthouses) needs TUN + `CAP_NET_ADMIN` → **EC2**. The public **gateway runs no nebula → Fargate** is fine.
- **Aurora PostgreSQL** (Multi-AZ; Global Database for DR) for staging/prod; RDS `t4g` for dev.
- **Terraform** + per-account remote state.
- **VPC endpoints** (KMS/STS/SSM/Secrets/S3/ECR/Logs) keep AWS-API traffic private; Core never internet-reachable; only gateway ALB + lighthouses are public.
- **SSM Session Manager** for admin + break-glass (no SSH/bastion).

## 3.4 Production-only infrastructure (by milestone)

- **M2:** PKI KMS keys + cross-account Signer role + **SCP** isolation; Secrets Manager; CloudWatch/AMP/AMG + X-Ray; **WORM** audit in Log Archive.
- **M3:** public **ALB + WAF** → Fargate gateway; ACM cert; **SQS** + DLQ; **DynamoDB** result store (TTL).
- **M4:** Core EC2/ASG mesh node; lighthouses ≥2 across AZs.
- **M5:** instance IAM roles; cross-account `DescribeInstances`; **PrivateLink** (NLB + VPC Endpoint Service) for private cloud enrollment.
- **M7:** **EventBridge** / ASG lifecycle hooks → auto-reap on terminate.
- **M8:** **multi-region KMS**; deletion alarms.
- **M9:** HA (Multi-AZ Core ASG, Aurora Multi-AZ, ≥3 lighthouses); OIDC IdP (Identity Center or Entra); SIEM (Security Lake/OpenSearch/Splunk); **DR** (Aurora Global + multi-region KMS, tested restore); **Shield Advanced** + WAF; **EC2 Mac** for macOS build/test; spot-fleet load test; gateway pentest.

## 3.5 Network design (production VPC)

```
 Internet → [ALB+WAF | Lighthouse EC2 (EIP,UDP)]  (public subnets)
                     │
   private app:  Gateway(Fargate) · Harbor Core(EC2, mesh node) · Signer→PKI KMS
                     │  VPC endpoints: KMS·STS·SSM·Secrets·S3·ECR·Logs
   private data: Aurora PostgreSQL (no internet route)
```

## 3.6 Security guardrails

SCPs (deny KMS key deletion in PKI, deny disabling CloudTrail/GuardDuty, region allowlist for the deployment's approved regions); PKI account isolation; gateway as sole public compute (WAF+Shield); no long-lived secrets (Secrets Manager + IAM roles, auto-rotated nonce key); WORM audit in a separate account; per-environment CA isolation.

---

## Progression at a glance

1. **Build & integrate locally** (Tier 1) — everything except cloud-trust + internet networking, including the SoftHSM CA. Cheap, fast, offline.
2. **Validate the cloud-only deltas** (Tier 2) — 2 EC2 + 1 KMS key prove real KMS/IAM, EC2 attestation, and NAT traversal; tear down after.
3. **Stage the prototype, then productionize** (Tier 3) — multi-account, HA, DR, the public surface, and the drills.

## Open questions

- **Windows/macOS local testing:** local KVM Windows guest for the Pilot (M1.10) vs. lean on CI Windows runners? macOS almost certainly CI/EC2-Mac only.
- **LocalStack fidelity for KMS asymmetric sign** — confirm the emulated `Sign` matches real KMS closely enough, or rely on SoftHSM locally + the Tier-2 harness for the real KMS check.
- **Tier-2 PKI isolation:** include the second-account SCP test in the minimal harness, or defer to staging?
- **IdP:** local Keycloak/Dex for dev; AWS Identity Center vs corporate **Entra** for staging/prod.

## Sources / references

- [[Nebula Control Plane - Design Plan]] §2.1, §6.3, §P3.
- [[Nebula Control Plane - Implementation Plan]] — milestones M0–M9.
- Nebula PKCS#11 (SoftHSM-compatible) [support PR](https://github.com/slackhq/nebula/pull/1153) · [`nebula-cert-kms`](https://github.com/NebulaOSS/nebula-cert-kms).
