# Minimal AWS EC2 lab (Terraform)

Four small EC2 nodes for trying the Nebula control plane end to end:

- **lighthouse** — `nebula` with `am_lighthouse`; discovery + NAT hole-punch. Elastic IP.
- **harbor** — control plane: **Core/core-api** (renew, heartbeat) + **admin console** + the **pull collector** (`harbor collect`) + DB + CA/config-signing keys. Itself a mesh node in group `control-plane`. Elastic IP (core-api + console are overlay-only; harbor reaches OUT to the gateway).
- **gateway** — the public **enrollment gateway** (ADR 0005), on its **own** node and **off the mesh**: serves public enroll + a Harbor-only mTLS collect port over a local queue; Harbor PULLS it. It holds no CA/DB and no overlay identity — a compromise yields no mesh pivot. Elastic IP.
- **client** — a `pilot` mesh member that joins **keyless via `aws-sigv4` attestation** (its instance IAM role), then renews/heartbeats to core-api.

Plus your **off-cloud iMac** (not managed here) which enrolls via a **join key
with manual approval** — the off-cloud path. All nodes run Amazon Linux 2023, use
**your personal SSH key**, get an **instance IAM role** (ready for M5 sigv4
attestation), are **IMDSv2-only**, and have **encrypted EBS**.

### Network isolation

The nodes live in a **dedicated VPC** (`vpc_cidr`, default `10.99.0.0/16`) with a
**per-tier subnet** each — `control` (harbor), `edge` (gateway), `mesh` (lighthouse),
`client` — so the untrusted, internet-facing gateway has its **own network**, fenced
from the control tier at two layers:

- **Security groups (stateful, the authoritative control).** Egress is locked per
  role. The **gateway** may egress **only** bootstrap (TCP 443/80) + DNS — **no
  Nebula UDP, no SSH-out, nothing toward harbor/mesh**; because SGs are stateful, it
  still answers the public enroll *and* Harbor's pull (both inbound) with zero
  egress. So a compromised gateway **cannot initiate** any connection into harbor or
  the mesh. Harbor egress is limited to the gateway's collect port + mesh UDP +
  bootstrap; lighthouse/client to mesh UDP + bootstrap. Harbor reaches the gateway
  (it **pulls**); the gateway never reaches harbor.
- **NACLs (stateless, defense-in-depth).** The `edge` subnet carries a restrictive
  NACL that, in particular, permits **no UDP egress except DNS** — an L3 backstop to
  the SG so the off-mesh gateway can't send Nebula UDP into the control/mesh tiers
  even if an SG rule were loosened. The trusted mesh tiers keep the default NACL (their
  data plane uses arbitrary UDP ports that are unsafe to NACL; their egress is locked
  at the SG).

Only the **lighthouse's UDP discovery** and the **gateway's TCP enroll port** face the
internet; the gateway's collect port is reachable **only from harbor's SG**; core-api
(8444) + console (8445) are overlay-only (in no SG). SSH is locked to your IP. The
**lighthouse** stays a mesh member, so it must keep Nebula UDP to/from harbor — it
can't be fully fenced from harbor without leaving the mesh; its SG egress is still
tightened to mesh UDP + bootstrap.

---

## ⚠️ First: rotate any credentials you've shared in plaintext

If an access key/secret has ever been pasted into a chat, a ticket, a file, or a
shell history, treat it as **compromised**. In the AWS console go to **IAM →
Users → Security credentials**, deactivate/delete that access key, and create a
fresh one. The steps below assume you have a key you have *not* exposed.

## Credentials: never stored unencrypted

These configs contain **no** credentials — the AWS provider reads them from the
environment. Pick one of the following so secrets never sit unencrypted on disk:

### Option A — aws-vault (recommended)
Stores the keys in your OS keychain / an encrypted file backend and only injects
them into the Terraform subprocess.
```bash
brew install aws-vault            # or your distro's package
aws-vault add nebula              # prompts for the key + secret (not echoed, not on disk)
aws-vault exec nebula -- terraform plan
aws-vault exec nebula -- terraform apply
```

### Option B — encrypted env file with SOPS + age
```bash
age-keygen -o ~/.config/age/keys.txt          # one-time
# create env.sops.yaml with AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, then:
sops --encrypt --age <your-age-pubkey> env.yaml > env.sops.yaml && rm env.yaml
# per session:
export $(sops --decrypt env.sops.yaml | xargs)   # decrypts to env only, never to disk
terraform apply
```

### Option C — ephemeral shell export (simplest; not stored at all)
Nothing is written to disk; the values live only in the current shell.
```bash
read -rs AWS_ACCESS_KEY_ID;     export AWS_ACCESS_KEY_ID
read -rs AWS_SECRET_ACCESS_KEY; export AWS_SECRET_ACCESS_KEY
export AWS_REGION=ca-central-1
terraform apply
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY   # when done
```
> Do **not** use `~/.aws/credentials` for this — that file is plaintext at rest,
> which is exactly what you asked to avoid. Avoid `export VAR=value` inline too
> (it lands in shell history); the `read -rs` form above does not echo or persist.

**Never** put keys in `*.tf`, `*.tfvars`, or commit `*.tfstate` (state can hold
sensitive values — it's gitignored here; use the **encrypted S3 backend** in
`versions.tf` for anything shared).

---

## Use

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: set allowed_ssh_cidr to "<your-ip>/32" and the key path

terraform init
aws-vault exec nebula -- terraform apply     # (or Option B/C, then plain terraform apply)

terraform output                              # public_ips, ssh, lighthouse_addr, gateway_url
```

`terraform destroy` tears it all down (these are billable resources — region
`ca-central-1`).

## Bootstrap the mesh (genesis)
After `apply`, run the helper from your machine — it builds + uploads the binaries
and stands up the **full control plane + data plane**:
```bash
SSH_KEY=~/.ssh/absolute bash ../scripts/bootstrap-genesis.sh
```
Steps: lighthouse init → harbor init (its own mesh key) → genesis (CA + config-signing
+ lighthouse cert + **Harbor's `control-plane` cert**, so Harbor is a real mesh node) →
lighthouse + harbor online → **publish a cloud-trust config** (this AWS account → groups,
auto-issue) → **off-mesh gateway** (ADR 0005: leaf-pinned mTLS minted on each side; the
gateway serves public enroll + a Harbor-only collect port over a local queue) +
**`harbor gateway add`** + **`harbor collect`** (Harbor pulls + issues + pushes results
back) + imac join key → **core-api** (renew/heartbeat, boot-verifies its control-plane
cert) + **admin console** (mock-IdP), both bound to Harbor's overlay IP (mesh-only).

It prints the gateway URL, the **config-signing pin** (`config-signing.pub`), the imac
join secret, and the exact enroll commands: the **cloud client joins keyless via
`aws-sigv4` attestation** (its IAM role; auto-issued), and the **off-cloud iMac** joins
via a join key with **manual approval** (approve it in the console or by CLI). The
**admin console** is mesh-only — reach it from an enrolled member at
`http://<harbor-overlay>:8445`, or SSH-tunnel ports 8445+8446 to Harbor (the out-of-band
admin path). (Re-run with `--skip-build` to skip rebuilding.)

**Overlay range (important):** the bootstrap defaults the overlay to `10.44.0.0/16`
(`POOL` / `LH_OVERLAY` env vars). Do **not** use `100.64.0.0/10` (CGNAT) if any
host also runs **Tailscale** — Tailscale installs an nftables rule that drops
`100.64.0.0/10` traffic on non-`tailscale0` interfaces, which silently kills the
nebula data plane (handshakes succeed, pings don't). This was hit and fixed live.

## What it creates
- A **dedicated VPC** (`vpc_cidr`, default `10.99.0.0/16`) + Internet Gateway + a public route table, with **four per-tier /24 subnets** (control/edge/mesh/client). *(This replaces the earlier single-default-subnet layout — `terraform apply` over an old deployment recreates the topology: it destroys the default-VPC nodes and builds the new VPC.)*
- 4× `t3.micro` EC2 (Amazon Linux 2023), encrypted root volume, IMDSv2-only, one per tier subnet; Elastic IPs on lighthouse, harbor + gateway.
- Four role-split security groups with **locked egress** (the gateway may egress only bootstrap + DNS — no path into harbor/mesh; harbor/lighthouse/client to mesh UDP + bootstrap), plus a restrictive **NACL on the edge (gateway) subnet** (defense-in-depth: no UDP egress except DNS). Only the lighthouse UDP + the gateway's enroll TCP face the internet; the gateway's collect port is reachable only from harbor's SG; core-api (8444), console (8445), mock-IdP (8446) are overlay-only, in no SG.
- An EC2 key pair from your `~/.ssh/absolute.pub`.
- A permission-less IAM role + instance profile (enough for `sts:GetCallerIdentity`).

## Binaries
The bootstrap script builds harbor/pilot/gateway for linux/amd64 and `scp`s them
up for you (no public signed-release pipeline yet — impl-plan 1.2). Each box's
`/root/NEXT-STEPS.txt` has the manual fallback. See also
`docs/Nebula Control Plane - Genesis Runbook.md`.
