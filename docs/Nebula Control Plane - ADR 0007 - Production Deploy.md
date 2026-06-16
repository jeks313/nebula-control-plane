---
title: "ADR 0007 — Production Deploy"
created: 2026-06-14
status: accepted
tags: [nebula, adr, production, deploy, kms, aurora, postgres, saml, entra-id, ha, observability, terraform]
---

# ADR 0007 — Production Deploy

**Status:** Accepted (target architecture for `deploy/prod/`; phased)
**Date:** 2026-06-14
**Decision owners:** Chris Hyde

## Context

The cloud deploy proven live on 2026-06-14 (`deploy/terraform`, both-Fargate gateway +
lighthouse) is deliberately **lab-grade**: the CA + config-signing keys are `0600` files
on the harbor node; `harbor.db` and the enrollment queue are local **SQLite**; the console
uses the **dev mock-IdP**; public enroll is **plaintext HTTP** behind the NLB; everything
is **single-AZ**; images are **alpine**. That tree stays as-is for demo/iteration work.

`deploy/prod/` is a **separate, self-contained copy** of that baseline (repointed to its
own tree; the demo is untouched). **This ADR is the design to bring `deploy/prod/` to
production grade**, and it is grounded in a code assessment of what harbor already does.

### Key finding — harbor was built for production; the demo just runs the lab-mode options

This is the framing that should govern the work: the production primitives are **already
in the codebase**, so prod is overwhelmingly *provision the managed infra + flip lab→prod
flags + a handful of small, already-hooked code changes* — **not** a rebuild.

- **Datastore is already multi-dialect.** `store.Open` switches the GORM dialector on
  `-driver sqlite|postgres` (`internal/store/store.go:45`); pgx is vendored; all 15
  `gormigrate` migrations have hand-typed Postgres SQL; every subcommand carries
  `-driver/-dsn`. **Aurora is a DSN swap, not new persistence code.**
- **Signing is already backend-pluggable.** `signer.Backend` (PublicKey +
  SignDigest→ASN.1-DER, `internal/signer/signer.go:23`) is consumed by **both** the
  nebula-cert path and the ES256 JWS config-signing path, with a **working pkcs11/SoftHSM
  backend** proving the abstraction over real hardware, and `store.Key` already has
  `Backend`/`URI` columns documented `kms | softhsm | local`. **KMS = implement the
  already-designed backend (~100 lines), not design signing.**
- **Console auth is already production-complete.** `internal/adminauth` ships generic
  **OIDC** (Auth-Code+PKCE), a **SAML 2.0 SP** (signed assertions, RelayState/InResponseTo,
  ForceAuthn step-up, SP metadata), and **GitHub OAuth** — all fail-closed to RBAC roles,
  server-side sessions, CSRF. The demo only *looks* mock-only because genesis runs
  `-mock-idp -environment development`. **Entra ID SSO = configure the existing SAML SP.**
- **harbor already runs as N instances.** It is stateless-per-request against a shared DB;
  the correctness-critical concurrency paths (IPAM unique+retry, queue claim/ack, join-key
  max-uses) are multi-instance-safe. HA needs four small shared-state fixes, **not** a
  redesign and **no** leader election.

What is genuinely net-new is narrow and enumerated below.

## Decision

Target architecture for `deploy/prod/`:

1. **Keys → AWS KMS.** The CA signing key and the config-signing key become KMS
   `ECC_NIST_P256` `SIGN_VERIFY` keys; harbor signs via `kms:Sign`/`kms:GetPublicKey`. Keys
   never leave KMS; the genesis ceremony stops writing `ca.key`/`config-signing.key`.
2. **Database → Aurora PostgreSQL (Multi-AZ).** `harbor.db` moves to Aurora (DSN swap). The
   enrollment **queue** — the one SQLite-pinned component — moves to **SQS + DLQ** (or a
   Postgres-dialect queue) behind the existing `queue.Queue` seam.
3. **IdP → Azure AD / Entra ID via SAML** for the admin console (configure the existing
   SAML SP). Step-by-step in the companion runbook (below).
4. **HA / multi-AZ.** ≥2 harbor Cores across AZs (+ the four shared-state fixes), ≥2
   gateways, ≥3 lighthouses, Aurora Multi-AZ.
5. **Edge TLS → ACM on an ALB** for public enroll (+ WAF/Shield). Collect stays
   leaf-pinned mTLS; the lighthouse keeps the UDP NLB (`preserve_client_ip` proven live
   2026-06-14). Multi-AZ subnets.
6. **Distroless images** — per **ADR 0006**.
7. **Observability + backup/DR.** `/metrics` + `/healthz` + `/readyz`, CloudWatch for the
   harbor node(s), SNS alarms (wire the existing `signer.OnAlarm`), Aurora PITR, KMS
   multi-Region replica, audit export to S3 Object-Lock.

## What exists vs. net-new (the honest inventory)

| Area | Already in harbor | Net-new **code** (small, hooked) | Net-new **terraform/ops** |
|---|---|---|---|
| **Postgres/Aurora** | multi-dialect store, all 15 PG migrations, pgx | PG **connection-pool** tuning (`store.go:63` hook); **queue** PG-dialect or SQS backend; audit **advisory lock** | Aurora cluster (Multi-AZ), SG, subnet group, Secrets Manager DSN, migrate-as-init job |
| **KMS** | `signer.Backend` iface + working pkcs11 backend; `store.Key.Backend/URI` cols | `internal/signer/kms.go` (~100 LOC, aws-sdk-go-v2); `"kms"` case in 3 dispatch switches + `-kms-*-arn` flags | 2× `aws_kms_key` (ECC_P256) + least-priv IAM (`kms:Sign`/`GetPublicKey` only) + CloudTrail |
| **Entra SAML IdP** | full SAML 2.0 SP (`internal/adminauth/saml.go`), `-saml-*` flags, fail-closed RBAC | OIDC client-secret-from-file *(SAML already uses key files)*; schedule `SessionStore.GC` | register the Enterprise App; inject metadata + SP keypair; sessions ride Aurora |
| **HA** | N stateless instances; IPAM/queue/joinkey concurrency-safe | 4 fixes: audit advisory lock, **nonce replay** shared store, signer **breaker** shared, **rollout** `FOR UPDATE` | ≥2 Cores multi-AZ; ≥2 gw / ≥3 lh; pre-deploy migrate step |
| **Edge TLS** | in-gateway TLS wired; collect mTLS real | *(none if ACM/ALB path)* | ALB + ACM for enroll; WAF/Shield; multi-AZ subnets |
| **Obs / DR** | slog, hash-chained audit, `signer.OnAlarm` hook | `/metrics`+`/healthz`+`/readyz`; wire `OnAlarm`→SNS; optional `audit export` | CloudWatch (EC2 harbor), SNS alarms, Aurora PITR, KMS multi-Region, S3 WORM audit |

The recurring theme: the **terraform/ops** column is the bulk of the work; the **code**
column is a short list of small, localized changes against hooks that already exist.

## Phased plan

Ordered so each phase de-risks the next; KMS + Aurora are the foundation.

- **Phase 1 — Datastore (Aurora).** `aws_rds_cluster` (aurora-postgresql, Multi-AZ) +
  instances + subnet group + SG (5432 from the harbor SG only) + Secrets Manager DSN;
  add a `case "postgres"` pool-tuning block at `store.go:63`; **decide the queue backend**
  (SQS+DLQ recommended — the queue is ephemeral per-gateway today); run `harbor migrate up`
  as a one-shot init job against the Aurora **writer**; add Postgres CI integration tests.
- ✅ **Phase 2 — KMS backend (code done; AWS live-validation pending).** `internal/signer/kms.go`
  implements `signer.Backend` over `aws-sdk-go-v2` (pure-Go, no build tag): `SignDigest` →
  `kms:Sign` MessageType=DIGEST / ECDSA_SHA_256, returning KMS's ASN.1-DER unchanged;
  `PublicKey` → `kms:GetPublicKey`, validates `KeySpec==ECC_NIST_P256`, converts the DER SPKI
  to the 65-byte point, cached. `"kms"` is wired into all three selectors — `genesis` +
  `ca-init` (`cmd/harbor/ca.go`), `backendFlags.load` (`cmd/harbor/main.go`, `-kms-key-id`),
  and the runtime `coreFlags.loadBackend` used by `serve` + the enroll worker
  (`cmd/harbor/enroll.go`, `-kms-ca-key-id`/`-kms-config-key-id`/`-kms-region`). Keys
  pre-exist in KMS; genesis self-signs the CA cert from them and does NOT write
  `ca.key`/`config-signing.key` (only `software` does). `signer.New` already fails closed if a
  key id's pubkey ≠ the CA cert. Software + SoftHSM/PKCS#11 paths are unchanged (minimal
  self-hosted / debug). Unit-tested via an injected fake KMS backed by a real P256 key,
  including the full `SelfSignCA → New → Issue → verify` path. The terraform for the keys is
  the **foundation** stack below. **Still to do:** apply the foundation stack + validate
  against real AWS KMS (no creds in CI; the live gate, like the 3b host validation), and
  populate `store.Key.URI`.
- ✅ **Terraform structure — hybrid (foundation + app), greenfield.** `deploy/prod/terraform`
  is split into an isolated **`foundation/`** stack (its own state) and an **`app/`** stack
  that reads it via `terraform_remote_state` — so a routine app change can never destroy the
  trust root. **`foundation/` is written** (`deploy/prod/terraform/foundation/`): the
  versioned/encrypted/TLS-only/`prevent_destroy` S3 **state bucket** (for both stacks), the
  **two KMS keys** (ECC_NIST_P256 / SIGN_VERIFY — CA + config-signing, distinct,
  `prevent_destroy` + 30-day deletion window, key policy delegates to account IAM), and the
  least-priv **`core_kms_sign`** IAM policy (`kms:Sign`/`GetPublicKey` on exactly the two
  ARNs) the `app/` stack attaches to the Core role. `terraform fmt`/`validate` clean;
  adversarially reviewed (KMS admin-vs-use separation tightened — no `kms:PutKeyPolicy` for
  lifecycle admins). Bootstrap is local-state → `init -migrate-state` into the bucket.
  - ✅ **`app/` network layer** — the `app/` stack now exists (the lab root `.tf` relocated +
    a missing `user_data.sh.tftpl` restored so it validates), wired to `foundation` via
    `terraform_remote_state` (re-exports the KMS ARNs + `core_kms_sign` policy). Network
    hardened: VPC flow logs → CloudWatch, the VPC default SG emptied (deny-all), an S3 gateway
    endpoint, and a **private multi-AZ data tier** for Aurora — on top of the existing tiered
    subnets + per-role SGs + edge NACL. (The relocation also fixed the operator bootstrap's
    `TFDIR`/pin paths.) `fmt`/`validate` clean; reviewed.
  - ✅ **`app/` data layer (Phase 1)** — `data.tf`: Aurora PostgreSQL, Multi-AZ (a writer +
    reader, one per private data-tier AZ), in the private subnets; storage + the RDS-managed
    master secret (Secrets Manager — never in TF state) + Performance Insights all under a
    customer-managed KMS CMK; `rds.force_ssl=1`; a DB SG reachable on 5432 from the harbor SG
    only with explicit deny-all egress; PITR (14-day backups), `deletion_protection` +
    `prevent_destroy`, unique final-snapshot id. Harbor SG gained an explicit 5432 egress to
    the data tier so Core can actually reach it. `fmt`/`validate` clean; reviewed (the
    aws_security_group egress-is-Optional+Computed allow-all trap was caught + fixed). Code
    follow-up (not infra): point Core at the DSN + move the durable queue off SQLite.
  - ✅ **`app/` compute layer** — `compute.tf`: the Core (harbor) node gets a DEDICATED
    least-priv instance role — foundation's `core_kms_sign` (kms:Sign/GetPublicKey on the two
    trust-root keys) + read the Aurora master secret (secretsmanager:GetSecretValue/Describe on
    exactly that ARN, with kms:Decrypt on the RDS CMK scoped via `kms:ViaService` to Secrets
    Manager). Every other node keeps the minimal permission-less role; the instance-profile is
    selected per-node (`harbor` → core, else node). IMDSv2 enforced; the node root volumes
    (the only EBS — Core uses Aurora, no data volumes) are encrypted with a customer-managed
    CMK (not the aws/ebs default), matching the Aurora + trust-root key posture; Fargate
    ephemeral storage is encrypted by default.
    `fmt`/`validate` clean; reviewed (0 findings). Operational follow-up: the genesis bootstrap
    runs Core with `-backend kms … -dsn <from the secret>` (ARNs/endpoints are outputs).
  - Remaining `app/` layers: edge (ALB + ACM + WAF) → artifacts (S3 + CloudFront) → obs.
- **Phase 3 — IdP (Entra SAML).** Configure the existing SAML SP per the **runbook**;
  custody a **stable SP keypair**; add OIDC client-secret-from-file (SAML already uses key
  files); schedule `SessionStore.GC`; sessions persist via Aurora (Phase 1). Pin a
  `-role-map` from the Entra admin group to `admin` and verify before cutover.
- **Phase 4 — HA.** ✅ **The four shared-state code fixes are DONE** (Core-side; the
  credential-less gateway is untouched and gains no DB access):
  - **Audit advisory lock** — `store.AppendAudit` takes `pg_advisory_xact_lock` (Postgres)
    so the hash-chain read-head→write-link serializes across Cores; SQLite's single writer
    already does.
  - **Shared nonce replay** — `replay.Observer` interface + DB-backed `SQLStore`
    (`nonce_replays`, atomic `INSERT … ON CONFLICT`); a transient store error retries
    rather than false-rejecting. Wired Core-side in `buildConsumer`.
  - **Shared signer breaker** — `signer.Breaker` interface + DB-backed `SQLBreaker`
    (`signer_breaker` latch + `signer_issuance` events, advisory-locked count→latch) so the
    cert/hour ceiling is fleet-wide and a trip halts every Core; fails closed. Lane `ca`
    shared by core-api renewal + the enroll consumer.
  - **Rollout `Evaluate` row-lock** — `evaluateLane` runs in one tx with the rollout row
    `SELECT … FOR UPDATE` (Postgres), audits deferred past commit; `AbortLane`/`Start` take
    the same lock / a lane advisory lock so operator paths can't race a concurrent evaluate.
  - Postgres-only primitives are guarded by `db.Name()=="postgres"`; SQLite stays correct via
    its single-writer connection. Migrations `000018`/`000019` (up+down verified).
  **Remaining (terraform/deploy):** ≥2 Cores across AZs (ASG / Fargate `desired_count≥2`,
  each its own `group:control-plane` mesh node) + ≥3 lighthouses across AZs. ⚠ Scaling
  gateways to ≥2 behind the single internal NLB needs its own design — each task has its own
  local queue, so claim/ack could land on different tasks; register each gateway separately
  or front per-task, don't just bump `desired_count`.
- **Phase 5 — Edge/TLS (REVISED: end-to-end TLS, no ALB/ACM/AWS-WAF).** Encrypt every hop
  including load-balancer→application: each component **terminates its own TLS** with a
  **public Let's Encrypt cert it obtains via ACME DNS-01 (Cloudflare)** — no plaintext
  anywhere. So **no ALB and no ACM**: the NLBs stay **L4/TCP passthrough**, preserving the
  app's own TLS. **WAF is Cloudflare's** (the public edge proxies to the origin; AWS WAF
  walked back). ✅ **Code done** (`internal/autotls`, certmagic DNS-01/Cloudflare → an
  auto-renewing `*tls.Config`; wired into gateway + core-api + console via a shared
  `-acme-domain`/`-acme-cloudflare-token-file`/`$NCP_ACME_CLOUDFLARE_TOKEN`; `httpserve`
  serves a preconfigured ACME `TLSConfig`; `-insecure` kept only as an explicit
  behind-proxy opt-out). DNS-01 (not HTTP-01/ALPN) because origins sit behind Cloudflare
  and harbor is mesh-only. The mesh-only harbor APIs also get public LE certs by hostname
  (uniform mechanism). ✅ **Infra done** (`deploy/prod/terraform/app/acme.tf`): a Secrets
  Manager secret for the scoped Cloudflare token (placeholder + `ignore_changes`, injected as
  `$NCP_ACME_CLOUDFLARE_TOKEN`); a CMK-encrypted **EFS** cert cache for the ephemeral Fargate
  gateway (its ACME cache must survive restarts or LE rate-limits bite) behind a non-root EFS
  access point; least-priv `GetSecretValue` grants for the gateway exec role + Core; the
  gateway task now serves `-acme-domain` (with `health_check_grace_period` for the blocking
  first issuance) and harbor-side outputs. Component DNS names follow ONE convention:
  `mesh_name` + `mesh_domain` derive `<mesh_name>-gateway.<mesh_domain>` /
  `<mesh_name>-harbor.<mesh_domain>` (e.g. `poc` + `mesh.failsafe.net` →
  `poc-gateway.mesh.failsafe.net`); the `harbor_domain`/`gateway_url` outputs are derived from
  them. The genesis bootstrap (`bootstrap-genesis.sh`)
  now wires harbor too: when `harbor_domain` is set it fetches the scoped Cloudflare token
  (Secrets Manager), delivers it to the box as a `0600` file over ssh stdin, and passes
  `-acme-domain`/`-acme-cloudflare-token-file`/`-acme-cache` to core-api + admin-api (sharing a
  persistent cert cache), flipping the printed client `-core`/console URLs to `https://<harbor_domain>`.
  **Remaining (operator-owned):** Cloudflare DNS + WAF, and the DNS record resolving
  `harbor_domain` → Core's overlay IP for mesh members. Collect + the lighthouse UDP NLB are unchanged.
- **Phase 6 — Images.** ✅ **Done** — both prod Fargate images are **distroless, shell-less,
  nonroot** (`gcr.io/distroless/static-debian12:nonroot`, uid 65532) per **ADR 0006**: gateway
  reads its material from `$NCP_GW_*` env (no entrypoint shell); the lighthouse uses the new
  static `cmd/nebula-boot` shim (renders config + exec's nebula). The demo tree stays alpine.
  **Remaining:** ADR 0006 Phase 3 supply-chain hardening (digest-pin the base, `IMMUTABLE` ECR
  tags + lifecycle policy, pin `platform_version`).
- **Phase 7 — Obs/DR.** `/metrics`+`/healthz`+`/readyz` on core-api/admin/gateway; ship
  EC2-harbor logs to CloudWatch; SNS alarms (wire `signer.OnAlarm`, breaker trips,
  audit-verify failures); Aurora PITR + final-snapshot + deletion-protection; KMS
  multi-Region replica keys; export the hash-chained audit to S3 Object-Lock; raise log
  retention + customer-managed CMKs + non-zero secret recovery windows.

## Consequences

- **+** A genuinely production-grade posture — non-exportable CA in KMS, Multi-AZ managed
  DB with PITR, enterprise SSO, HA control plane, TLS+WAF at the edge — reached mostly via
  managed AWS services + a short, well-scoped code list, because the architecture
  anticipated it.
- **+** The demo (`deploy/terraform`) is untouched and stays fast to iterate on.
- **−** Real net-new code, even if small: the KMS backend, the queue backend, the four HA
  shared-state fixes, metrics/health endpoints, and a few secret-from-file hooks. None are
  architecture changes, but all need tests (the Postgres path currently has **zero**
  runtime test coverage).
- **−** More moving parts + cost: Aurora, KMS, ALB/WAF, multi-AZ, CloudWatch/SNS.
- **−** Operational ceremony grows: the genesis ceremony now creates KMS keys; key rotation
  (CA + config-signing) is designed (staged/active/draining/retired) but **unimplemented**
  and becomes a real prod need.

## Relationship to other work

- **ADR 0006 (Distroless images)** — Phase 6; the prod images are distroless.
- **ADR 0005 (Pull-based gateways)** — the off-mesh gateway + collect mTLS carried forward.
- **ADR 0004 (SSO-driven user enrollment)** — *reuses* this ADR's IdP (adminauth); it's a
  feature built on the same SAML/OIDC, not a prod-readiness blocker for the
  console+machine-enrollment scope.
- **ADR 0003 (self-update/distribution)** — the KMS/PKI fork here mirrors 0003/0004.
- **Implementation Plan M9 / M9.5** — already names the HA targets (shared nonce/audit,
  Aurora, SQS); this ADR is their deploy-shaped expression.
- **`deploy/prod/`** — the tree this ADR drives; **companion runbook:** `Nebula Control
  Plane - Runbook - Entra ID SAML SSO for the Console.md`.
