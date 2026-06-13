# Minimal AWS EC2 lab (Terraform)

Two small EC2 nodes for trying the Nebula control plane: a **harbor** box
(control plane + lighthouse) and a **pilot** box (mesh member). Both run Amazon
Linux 2023, use **your personal SSH key**, get an **instance IAM role** (so
they're ready for the M5 sigv4 attestation), are **IMDSv2-only**, and have
**encrypted EBS**. SSH is locked to your IP.

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

terraform output ssh                          # -> ssh ec2-user@<ip> per node
```

`terraform destroy` tears it all down (these are billable resources — region
`ca-central-1`).

## What it creates
- 2× `t3.micro` EC2 (Amazon Linux 2023), public IP, encrypted root volume, IMDSv2-only.
- A security group: SSH + optional gateway port from your IP only; Nebula UDP/4242 open; all egress.
- An EC2 key pair from your `~/.ssh/absolute.pub`.
- A permission-less IAM role + instance profile (enough for `sts:GetCallerIdentity`).

## Installing the harbor/pilot/gateway binaries
Not auto-installed (no public signed-release pipeline yet — impl-plan 1.2). After
`apply`, SSH in and read `/root/NEXT-STEPS.txt`: build the binaries locally
(`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/...`), `scp` them up, or
bake an AMI. Then follow `docs/Nebula Control Plane - Genesis Runbook.md`.
