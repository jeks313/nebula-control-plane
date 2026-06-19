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

**Status (2026-06-18):** Largely SHIPPED & LIVE — the `poc` IS the prod stack now. Aurora
PostgreSQL (DSN-wired, rotating creds) + KMS-backed CA & config-signing (private keys never
on disk, live-validated) + per-component ACME/Let's-Encrypt edge TLS (`poc-harbor` /
`poc-gateway.mesh.failsafe.net`) + distroless Fargate gateway + Fargate lighthouse
(`tun.disabled`, `preserve_client_ip` proven, now the terraform DEFAULT) + EC2 harbor
(`-tags ui` React console on :443) + SSM-only node access are all deployed. REMAINING
prod-grade gaps: **HA/multi-AZ** (Phase 4 code done; ≥2 Cores / ≥3 lighthouses / gateway
scaling terraform not built — all still `desired_count=1`/single-AZ), **real Entra SAML for
the console** (Phase 3 code-complete + bootstrap-threaded but the live poc still runs the dev
mock-IdP), the **durable enrollment queue still on SQLite** (per-node `queue.db`, not yet
SQS/Postgres), backups/DR depth, and ADR 0006 Phase 3 supply-chain hardening.

## Context

The cloud deploy proven live on 2026-06-14 (`deploy/terraform`, both-Fargate gateway +
lighthouse) is deliberately **lab-grade**: the CA + config-signing keys are `0600` files
on the harbor node; `harbor.db` and the enrollment queue are local **SQLite**; the console
uses the **dev mock-IdP**; public enroll is **plaintext HTTP** behind the NLB; everything
is **single-AZ**; images are **alpine**. That tree stays as-is for demo/iteration work.

`deploy/prod/` is a **separate, self-contained copy** of that baseline (repointed to its
own tree; the demo is untouched). **This ADR is the design to bring `deploy/prod/` to
production grade**, and it is grounded in a code assessment of what harbor already does.

> **Update (2026-06-18):** this design is now overwhelmingly realized — `deploy/prod/` IS
> the live `poc` stack (S3 remote state, `ca-central-1`). The lab→prod flips below are mostly
> flipped: KMS keys, Aurora, ACME edge TLS, distroless Fargate (gateway + lighthouse) and
> SSM-only access are all deployed and validated. The per-phase ✅/Remaining markers below are
> the source of truth for what is still open (HA terraform, Entra SAML rollout, the durable
> queue still on SQLite).

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
5. **Edge TLS** — *(superseded 2026-06-18: the ALB+ACM+AWS-WAF path was walked back; each
   component now terminates its OWN TLS with a public Let's Encrypt cert via ACME DNS-01
   (Cloudflare), NLBs stay L4/TCP passthrough, WAF is Cloudflare's — see Phase 5, SHIPPED &
   LIVE)*. Originally: ACM on an ALB for public enroll (+ WAF/Shield). Collect stays
   leaf-pinned mTLS; the lighthouse keeps the UDP NLB (`preserve_client_ip` proven live
   2026-06-14, now the default). Multi-AZ subnets.
6. **Distroless images** — per **ADR 0006**.
7. **Observability + backup/DR.** `/metrics` + `/healthz` + `/readyz`, Aurora PITR, audit
   export to S3 Object-Lock. *(superseded 2026-06-18: alarming landed as a self-hosted
   Prometheus/Alertmanager/Grafana/Loki monitoring node rather than CloudWatch+SNS; and KMS
   multi-Region was NOT done — `multi_region` is fixed at key creation and the live keys are
   `prevent_destroy`, so DR for the trust root is cross-region snapshot/replica of the
   encrypted data, not key replication — see Phase 7.)*

## What exists vs. net-new (the honest inventory)

| Area | Already in harbor | Net-new **code** (small, hooked) | Net-new **terraform/ops** |
|---|---|---|---|
| **Postgres/Aurora** | multi-dialect store, all 15 PG migrations, pgx | PG **connection-pool** tuning (`store.go:63` hook); **queue** PG-dialect or SQS backend; audit **advisory lock** | Aurora cluster (Multi-AZ), SG, subnet group, Secrets Manager DSN, migrate-as-init job |
| **KMS** | `signer.Backend` iface + working pkcs11 backend; `store.Key.Backend/URI` cols | `internal/signer/kms.go` (~100 LOC, aws-sdk-go-v2); `"kms"` case in 3 dispatch switches + `-kms-*-arn` flags | 2× `aws_kms_key` (ECC_P256) + least-priv IAM (`kms:Sign`/`GetPublicKey` only) + CloudTrail |
| **Entra SAML IdP** | full SAML 2.0 SP (`internal/adminauth/saml.go`), `-saml-*` flags, fail-closed RBAC | OIDC client-secret-from-file *(SAML already uses key files)*; schedule `SessionStore.GC` | register the Enterprise App; inject metadata + SP keypair; sessions ride Aurora |
| **HA** | N stateless instances; IPAM/queue/joinkey concurrency-safe | 4 fixes: audit advisory lock, **nonce replay** shared store, signer **breaker** shared, **rollout** `FOR UPDATE` | ≥2 Cores multi-AZ; ≥2 gw / ≥3 lh; pre-deploy migrate step |
| **Edge TLS** | in-gateway TLS wired; collect mTLS real | `internal/autotls` (ACME DNS-01/Cloudflare) — *done; ALB/ACM path walked back, Phase 5* | NLBs stay L4 passthrough; Cloudflare-token secret + EFS cert cache; multi-AZ subnets *(was: ALB+ACM+AWS-WAF)* |
| **Obs / DR** | slog, hash-chained audit, `signer.OnAlarm` hook | `/metrics`+`/healthz`+`/readyz` (done); audit verifier metrics; `harbor audit export` writer (open) | self-hosted Prometheus/Alertmanager/Grafana/Loki node, Aurora PITR, S3 Object-Lock audit export *(CloudWatch+SNS+KMS-multi-Region walked back)* |

The recurring theme: the **terraform/ops** column is the bulk of the work; the **code**
column is a short list of small, localized changes against hooks that already exist.

## Phased plan

Ordered so each phase de-risks the next; KMS + Aurora are the foundation.

- ✅ **Phase 1 — Datastore (Aurora). SHIPPED & LIVE.** `aws_rds_cluster` (aurora-postgresql,
  Multi-AZ) + instances + subnet group + SG (5432 from the harbor SG only) + the RDS-managed
  rotating master secret are deployed (`app/data.tf`), and the genesis bootstrap wires Core at
  the Aurora DSN with `DB_BACKEND=aurora` (`-driver postgres -dsn … -db-secret-arn …`, rotating
  creds via the instance role — no static password on disk/argv). The `case "postgres"`
  pool-tuning block at `store.go:63` is wired; `harbor migrate up` runs against the Aurora
  writer. **Remaining:** the durable enrollment **queue is still SQLite** (a per-node
  `queue.db`, even on the Aurora backend) — the SQS+DLQ / Postgres-dialect queue behind
  `queue.Queue` is NOT yet built; and Postgres CI integration tests are still outstanding
  (the Postgres path has no runtime test coverage in CI).
- ✅ **Phase 2 — KMS backend. SHIPPED & LIVE (live-validated 2026-06-18).** `internal/signer/kms.go`
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
  the **foundation** stack below. ✅ **Live (2026-06-18):** the foundation stack is applied and
  the `poc` runs the KMS backend against real AWS KMS — the CA + config-signing private keys
  never touch disk (genesis self-signs the CA cert from the KMS keys; only `software` writes
  `ca.key`/`config-signing.key`). **Still to do:** populate `store.Key.URI`.
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
  - ✅ **`app/` artifacts layer** — `artifacts.tf`: an opt-in **public-read** S3 bucket
    (`artifacts_bucket_name`) hosting the **pilot + nebula** data-plane binaries the self-update
    lanes fetch (ADR 0003). Public-read (NOT CloudFront — operator's choice) is safe because the
    signed bundle's sha256 is the integrity anchor (the `-pilot-url`/`-nebula-url` flags are
    explicitly "sha-verified, so the source need not be trusted"), and no-creds reach lets the
    off-cloud iMac self-update. Objects are RAW executables (both updaters sha256 raw bytes +
    chmod 0755, no untar); `deploy/prod/artifacts/publish.sh` builds pilot + extracts nebula's raw
    binary from the GitHub tarball, uploads under `pilot|nebula/<ver>/<name>-<os>-<arch>`, and
    prints the `harbor … add`/`release` commands. `BucketOwnerEnforced`, versioned, AES256, TLS-
    only; the public-access-block deliberately allows the public-read policy (the lone public
    bucket in the stack). Outputs: `artifacts_bucket` + `{version}`-token URL templates.
    Per-arch: a release generation now carries a binary **per `(goos, goarch)`** (the pilot
    reports its `runtime.GOOS/GOARCH`; Core stamps each host its own arch's artifact), so one
    staged generation serves a mixed-arch fleet — `harbor nebula add` + `add-artifact -gen N`
    then `release -gen N`. **Arch affinity**: `release` (CLI + admin API) stages only hosts whose
    arch the generation ships (`ServableFleet`, resolving each host's arch like `coreapi.device()`
    — latest issued enrollment, id DESC) and reports the rest, so an unshipped-arch host can't
    strand the rollout into an observe-window auto-rollback. `fmt`/`validate` clean.
  - Other `app/` layers: **edge** pivoted to per-component ACME/Let's-Encrypt (Phase 5 `acme.tf`,
    no ALB/ACM/WAF); **obs** landed in Phase 7. So the originally-listed remaining layers are done.
- **Phase 3 — IdP (Entra SAML). CODE-COMPLETE + BOOTSTRAP-THREADED, NOT ROLLED OUT.** The
  genesis bootstrap wires the console to real Entra SAML in production posture when the operator
  supplies `SAML_METADATA_URL`/`_FILE` + `SAML_SP_KEY_FILE`/`_CERT_FILE` + `SAML_ROLE_MAP` (the
  STABLE SP keypair is delivered `0600`/`0644` over ssh stdin, fail-closed: SAML refuses to
  launch without HTTPS/ACME and without a role-map). But the **live poc still defaults to the
  dev mock-IdP** (`-mock-idp -environment development`) — no Entra Enterprise App is registered.
  **Remaining (operator rollout):** register the Entra Enterprise App per the **runbook**;
  custody a **stable SP keypair**; pin a `-role-map` from the Entra admin group to `admin`;
  verify before cutover; (and the still-open `SessionStore.GC` schedule + OIDC
  client-secret-from-file, since SAML already uses key files).
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
- **Phase 7 — Obs/DR.** Done incrementally; Aurora PITR + final-snapshot + deletion-protection
  and customer-managed CMKs already landed (Phases 1–2).
  - **7a — Observability endpoints ✅ DONE.** `/metrics` (Prometheus) + `/healthz` + `/readyz`
    on core-api + admin-api (their mesh-only muxes) and the gateway (a SEPARATE internal
    `-obs-addr` listener — never the public enroll port; smoke-confirmed enroll:`/metrics`→404).
    `internal/obs` (cached readiness probe → no `/readyz` connection-storm), `store.Ping`.
    Alarm-source metrics: `ncp_signer_breaker_open` (reconciled from the shared latch on a
    cadence so an idle Core stays fleet-truthful) + `ncp_signer_breaker_trips_total`; a periodic
    audit verifier (`internal/auditverify`) exporting `ncp_audit_verify_{runs,failures,tampered}_total`
    + `_rows`/`_last_success_seconds`, joined on shutdown.
  - **7b — Alarms: self-hosted Prometheus + Alertmanager + Grafana (operator's choice). ✅ DONE.**
    A dedicated **mesh-member** monitoring EC2 node scrapes the control plane's `/metrics`
    (mesh-only core-api/admin-api by overlay IP — HTTPS validated via SNI when auto-TLS is on;
    plus the lighthouse) and alerts on the 7a metrics. Config in `deploy/prod/monitoring/`
    (alerts.yml: breaker open/trips, audit tampered/fail/stale, target down; alertmanager.yml
    with a **placeholder** receiver; compose + Grafana datasource). The monitoring-node
    terraform (instance + `monitoring` SG, mesh member, UIs SSH-tunnel-only) + `deploy.sh`
    (enrolls it keyless via aws-sigv4, renders prometheus.yml for the real targets/scheme, runs
    the stack) complete it. A real Alertmanager receiver (Slack/email/PagerDuty) is wired
    out-of-band; the Grafana password lands in a `0600 .env`, not on a command line.
  - **7c — Log aggregation (Loki): ✅ DONE.** A **Loki** container alongside the Prometheus
    stack + a Grafana Loki datasource; **Grafana Alloy** (promtail's supported successor) on
    the harbor node tails journald and pushes to Loki over the VPC (SG-locked: monitoring
    ingress 3100 ← harbor; harbor egress 3100 → client tier). `deploy.sh` installs Alloy +
    renders its endpoint. The Fargate gateway/lighthouse already ship via awslogs. (Future
    hardening: ship over the overlay instead of the VPC — needs a nebula-policy inbound rule.)
  - **7d — DR terraform: ✅ DONE (with one documented caveat).** `secret_recovery_window_days`
    (default 7) on the gateway/lighthouse/cloudflare secrets (was 0 = immediate); raised
    `fargate_log_retention_days` (default 30, was 14); an **opt-in S3 Object-Lock** audit-export
    bucket (`audit_export_bucket_name`) — versioned, COMPLIANCE-mode retention, BPA, TLS-only,
    `prevent_destroy` — plus a Core `s3:PutObject`-only grant, so the hash-chained audit can be
    archived WORM (the `harbor audit export` writer is a tracked code follow-up). **Caveat —
    KMS multi-Region:** `multi_region` is fixed at key CREATION and the live CA/config-signing/
    RDS/EBS/EFS keys are `prevent_destroy`, so it can't be retrofitted without destroying
    encrypted data; it must be chosen at first apply (a fresh-deploy setting), so the existing
    keys are deliberately left single-Region. DR for them is cross-region snapshot/replica of the
    encrypted data, not key replication.

## Consequences

- **+** A genuinely production-grade posture — non-exportable CA in KMS, managed DB with
  PITR, end-to-end Let's-Encrypt TLS at the edge with Cloudflare WAF — reached mostly via
  managed AWS services + a short, well-scoped code list, because the architecture
  anticipated it. *(2026-06-18: mostly LIVE on the `poc`; enterprise SSO for the console and
  a true HA / Multi-AZ control plane are the main not-yet-rolled-out pieces.)*
- **+** The demo (`deploy/terraform`) is untouched and stays fast to iterate on.
- **−** Real net-new code, even if small: the KMS backend, the queue backend, the four HA
  shared-state fixes, metrics/health endpoints, and a few secret-from-file hooks. None are
  architecture changes, but all need tests (the Postgres path currently has **zero**
  runtime test coverage).
- **−** More moving parts + cost: Aurora, KMS, ACME/Cloudflare edge, multi-AZ, the
  self-hosted Prometheus/Loki/Grafana monitoring node. *(ALB/AWS-WAF/SNS were walked back —
  see Phase 5 / 7b.)*
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
