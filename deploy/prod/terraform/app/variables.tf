variable "region" {
  description = "AWS region."
  type        = string
  default     = "ca-central-1"
}

variable "project" {
  description = "Project tag applied to all resources."
  type        = string
  default     = "nebula-control-plane"
}

variable "name_prefix" {
  description = "Name prefix for created resources."
  type        = string
  default     = "ncp"
}

variable "instance_type" {
  description = "EC2 instance type (t3.micro is the small/cheap default)."
  type        = string
  default     = "t3.micro"
}

variable "vpc_cidr" {
  description = "CIDR for the dedicated lab VPC. Tiered /24 subnets are carved from it (control/edge/mesh/client). Pick a range that won't collide with your other networks."
  type        = string
  default     = "10.99.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR, e.g. 10.99.0.0/16."
  }
}

variable "ssh_public_key_path" {
  description = "Path to YOUR personal SSH *public* key; the matching private key is how you log in."
  type        = string
  default     = "~/.ssh/absolute.pub"
}

variable "allowed_ssh_cidr" {
  description = <<-EOT
    CIDR allowed to reach SSH (and the optional gateway port). Set this to your
    own address — e.g. "$(curl -s https://checkip.amazonaws.com)/32". There is no
    default on purpose: opening SSH to the world should be a conscious choice.
  EOT
  type        = string

  validation {
    condition     = can(cidrhost(var.allowed_ssh_cidr, 0))
    error_message = "allowed_ssh_cidr must be a valid CIDR, e.g. 203.0.113.10/32."
  }
}

variable "nebula_version" {
  description = "slackhq/nebula release to install on the data plane (matches the module's pinned version)."
  type        = string
  default     = "1.10.3"
}

variable "nebula_sha256" {
  description = "sha256 of nebula-linux-amd64.tar.gz for nebula_version (verified in user_data before install). Empty skips verification (a supply-chain gap). Update this whenever nebula_version changes."
  type        = string
  default     = "99ac335caeb69d02a6b6b00a3d4b5d0a36ec3971df480a1cc50e6db378342955" # v1.10.3 linux-amd64
}

variable "nebula_port" {
  description = "UDP port the Nebula data plane / lighthouse listens on."
  type        = number
  default     = 4242
}

variable "gateway_port" {
  description = "Public TCP port for the enrollment gateway (nonce/enroll/poll)."
  type        = number
  default     = 8443
}

variable "collect_port" {
  description = "TCP port for the gateway's Harbor-facing collect API (mTLS). Reachable ONLY from Harbor's security group (ADR 0005 — the protected side pulls)."
  type        = number
  default     = 9443
}

variable "gateway_runtime" {
  description = "How to host the off-mesh gateway: 'fargate' (a serverless container — no VM, the DEFAULT, since the gateway runs no nebula/TUN) or 'ec2' (a VM). Fargate needs gateway_image pushed (deploy/fargate/build-push.sh gateway) and the config secret populated — the genesis bootstrap does both."
  type        = string
  default     = "fargate"

  validation {
    condition     = contains(["ec2", "fargate"], var.gateway_runtime)
    error_message = "gateway_runtime must be \"ec2\" or \"fargate\"."
  }
}

variable "gateway_image" {
  description = "Container image URI for the Fargate gateway (gateway_runtime=fargate). Empty defaults to the ECR repo created here, tag 'latest' — push it with deploy/fargate/build-push.sh gateway."
  type        = string
  default     = ""
}

variable "gateway_fargate_cpu" {
  description = "Fargate task CPU units for the gateway (256 = 0.25 vCPU)."
  type        = number
  default     = 256
}

variable "gateway_fargate_memory" {
  description = "Fargate task memory (MiB) for the gateway."
  type        = number
  default     = 512
}

# ── Lighthouse runtime (SPIKE) ────────────────────────────────────────────────
# A dedicated lighthouse does only control-plane work (discovery + hole-punch
# coordination over UDP) and passes no data-plane traffic to/from itself, so it can
# run nebula with `tun.disabled` — no TUN, no CAP_NET_ADMIN, no privilege — which
# makes it Fargate-eligible (unlike Core, which routes core-api over the overlay and
# needs a real TUN). Default 'ec2' because the Fargate path is an unproven spike: it
# needs a UDP NLB that PRESERVES the client address (the lighthouse learns each
# host's post-NAT underlay address from the packet source) — see deploy/fargate/README.
variable "lighthouse_runtime" {
  description = "How to host the lighthouse: 'ec2' (a VM, the default) or 'fargate' (a serverless tun.disabled nebula container behind a UDP NLB — SPIKE, see deploy/fargate/README.md)."
  type        = string
  default     = "ec2"

  validation {
    condition     = contains(["ec2", "fargate"], var.lighthouse_runtime)
    error_message = "lighthouse_runtime must be \"ec2\" or \"fargate\"."
  }
}

variable "lighthouse_image" {
  description = "Container image URI for the Fargate lighthouse (lighthouse_runtime=fargate). Empty defaults to the ECR repo created here, tag 'latest' — push it with deploy/fargate/build-push.sh lighthouse."
  type        = string
  default     = ""
}

variable "lighthouse_fargate_cpu" {
  description = "Fargate task CPU units for the lighthouse (256 = 0.25 vCPU)."
  type        = number
  default     = 256
}

variable "lighthouse_fargate_memory" {
  description = "Fargate task memory (MiB) for the lighthouse."
  type        = number
  default     = 512
}

variable "lighthouse_stats_port" {
  description = "TCP port the Fargate lighthouse exposes nebula's prometheus stats on, used ONLY as the UDP target group's health check (NLB UDP target groups require a TCP/HTTP health check). Internal — reachable from the NLB only, never public."
  type        = number
  default     = 8080
}

variable "gateway_cidr" {
  description = <<-EOT
    CIDR allowed to reach the enrollment gateway. The off-cloud iMac enrolls over
    this, so it must cover your home IP. Default is open (the gateway is
    credential-less and rate-limited by design); tighten to your IP for less
    exposure.
  EOT
  type        = string
  default     = "0.0.0.0/0"
}

# ── Edge TLS: per-component Let's Encrypt via ACME DNS-01 (Cloudflare) ────────
# The scoped Cloudflare DNS token itself is NOT a variable — it lives in the Secrets
# Manager secret created here (operator/bootstrap populates it), injected as
# $NCP_ACME_CLOUDFLARE_TOKEN. Cloudflare DNS records + WAF are operator-owned.
variable "gateway_domain" {
  description = "Public DNS name the enrollment gateway serves (e.g. enroll.example.com). When set (+ gateway_runtime=fargate), the gateway obtains a Let's Encrypt cert via ACME DNS-01 and serves HTTPS; empty keeps the -insecure plaintext-behind-proxy spike."
  type        = string
  default     = ""

  validation {
    # ACME wiring (EFS cache, token grant, -acme-domain flag, https outputs) is Fargate-only.
    # gateway_domain on the EC2 runtime would create an orphaned token secret no gateway
    # principal can read AND advertise an https:// enroll URL the EC2 gateway never serves.
    condition     = var.gateway_domain == "" || var.gateway_runtime == "fargate"
    error_message = "gateway_domain requires gateway_runtime=fargate — auto-TLS is wired only on the Fargate gateway. For the EC2 gateway, terminate TLS upstream or use -tls-cert."
  }
}

variable "harbor_domain" {
  description = "DNS name harbor's core-api + console serve (e.g. harbor.mesh.example.com, an A record to Core's overlay IP). When set, Core's role is granted read on the Cloudflare DNS token so it can obtain LE certs via ACME DNS-01 (the bootstrap passes -acme-domain)."
  type        = string
  default     = ""
}

variable "acme_email" {
  description = "ACME account email for Let's Encrypt. Empty = an anonymous LE account (valid, but you get NO cert-expiry warnings or account-recovery mail) — SET THIS for a production auto-renewing cert."
  type        = string
  default     = ""
}

variable "acme_staging" {
  description = "Use the Let's Encrypt STAGING CA (untrusted, no rate limits) while testing the ACME wiring."
  type        = bool
  default     = false
}

variable "state_bucket_name" {
  description = "The foundation stack's Terraform state bucket (its `state_bucket` output) — this stack reads foundation's remote state from it for the KMS key ARNs + IAM policy. Same value you set in the backend block (versions.tf)."
  type        = string
}

variable "flow_log_retention_days" {
  description = "CloudWatch retention for VPC flow logs."
  type        = number
  default     = 90
}

# ── Data layer (Aurora PostgreSQL) ───────────────────────────────────────────
variable "aurora_engine_version" {
  description = "Aurora PostgreSQL engine version. VERIFY it exists in your region: `aws rds describe-db-engine-versions --engine aurora-postgresql --query 'DBEngineVersions[].EngineVersion'`."
  type        = string
  default     = "16.6"
}

variable "db_instance_class" {
  description = "Aurora instance class (one writer + one reader are created). db.t4g.medium suits a control plane; bump to db.r6g.* for heavier fleets."
  type        = string
  default     = "db.t4g.medium"
}

variable "db_name" {
  description = "Initial database name created in the cluster (Harbor's schema; the Postgres path has 15 migrations under internal/store/migrate)."
  type        = string
  default     = "harbor"
}

variable "db_backup_retention_days" {
  description = "Automated-backup / PITR retention (days). Aurora keeps continuous backups across this window."
  type        = number
  default     = 14
}
