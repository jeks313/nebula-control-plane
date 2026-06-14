# Minimal AWS EC2 lab (Terraform)

Three small EC2 nodes for trying the Nebula control plane end to end:

- **lighthouse** — `nebula` with `am_lighthouse`; discovery + NAT hole-punch. Elastic IP.
- **harbor** — control plane: enrollment **gateway** (public) + **Core/core-api** (renew, heartbeat) + enroll **worker** + **admin console**, DB, CA + config-signing keys. Itself a mesh node in group `control-plane`. Elastic IP (gateway is public; core-api + console are overlay-only).
- **client** — a `pilot` mesh member that joins **keyless via `aws-sigv4` attestation** (its instance IAM role), then renews/heartbeats to core-api.

Plus your **off-cloud iMac** (not managed here) which enrolls via a **join key
with manual approval** — the off-cloud path. All nodes run Amazon Linux 2023, use
**your personal SSH key**, get an **instance IAM role** (ready for M5 sigv4
attestation), are **IMDSv2-only**, and have **encrypted EBS**. Security groups are
**split by role**: only the lighthouse's UDP discovery and harbor's TCP gateway
face the internet; Core's API (8444) is overlay-only. SSH is locked to your IP.

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
auto-issue) → enrollment plane (gateway + attestation-enabled worker) + imac join key →
**core-api** (renew/heartbeat, boot-verifies its control-plane cert) + **admin console**
(mock-IdP), both bound to Harbor's overlay IP (mesh-only).

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
- 3× `t3.micro` EC2 (Amazon Linux 2023), encrypted root volume, IMDSv2-only; Elastic IPs on lighthouse + harbor.
- Three role-split security groups (lighthouse UDP, harbor gateway+UDP, client UDP; SSH locked to your IP). Only the lighthouse UDP + harbor's gateway TCP face the internet — core-api (8444), the admin console (8445) and the mock-IdP (8446) are overlay-only, in no security group by design.
- An EC2 key pair from your `~/.ssh/absolute.pub`.
- A permission-less IAM role + instance profile (enough for `sts:GetCallerIdentity`).

## Binaries
The bootstrap script builds harbor/pilot/gateway for linux/amd64 and `scp`s them
up for you (no public signed-release pipeline yet — impl-plan 1.2). Each box's
`/root/NEXT-STEPS.txt` has the manual fallback. See also
`docs/Nebula Control Plane - Genesis Runbook.md`.
