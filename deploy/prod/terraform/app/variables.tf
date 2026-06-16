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

  validation {
    # Auto-TLS (the derived <mesh_name>-gateway.<mesh_domain> cert: EFS cache, token grant,
    # -acme-domain, https outputs) is wired ONLY on the Fargate gateway. On EC2 a mesh domain
    # would create an orphaned token secret + advertise an https URL the node never serves.
    condition     = var.gateway_runtime == "fargate" || var.mesh_name == "" || var.mesh_domain == ""
    error_message = "a gateway domain (mesh_name + mesh_domain) requires gateway_runtime=fargate; auto-TLS is wired only on the Fargate gateway."
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
# Component DNS names follow one convention: <mesh_name>-<component>.<mesh_domain>, e.g.
# mesh_name="poc" + mesh_domain="mesh.failsafe.net" -> poc-gateway.mesh.failsafe.net and
# poc-harbor.mesh.failsafe.net. Set BOTH to enable auto-TLS (each component obtains its own
# Let's Encrypt cert via ACME DNS-01); leave either empty for the plaintext/-insecure spike.
# The scoped Cloudflare DNS token is NOT a variable — it lives in the Secrets Manager secret
# created here (operator/bootstrap populates it), injected as $NCP_ACME_CLOUDFLARE_TOKEN.
# Cloudflare DNS records + WAF are operator-owned.
variable "mesh_name" {
  description = "Short mesh identifier prefixed onto component DNS names (e.g. \"poc\" -> poc-gateway.<mesh_domain>, poc-harbor.<mesh_domain>). With mesh_domain, enables auto-TLS; empty disables it."
  type        = string
  default     = ""

  validation {
    # A DNS label (also interpolated into the bootstrap shell) — keep it injection-safe.
    condition     = var.mesh_name == "" || can(regex("^[a-z0-9-]+$", var.mesh_name))
    error_message = "mesh_name must be a short DNS label (lowercase letters, digits, hyphens)."
  }
}

variable "mesh_domain" {
  description = "Parent DNS zone for this mesh's component names (e.g. \"mesh.failsafe.net\"). With mesh_name set, gateway/harbor serve LE certs for <mesh_name>-gateway/-harbor.<mesh_domain> via ACME DNS-01. Operators point these names at the gateway NLB / Core's overlay IP. Empty disables auto-TLS."
  type        = string
  default     = ""

  validation {
    condition     = var.mesh_domain == "" || can(regex("^[a-zA-Z0-9.-]+$", var.mesh_domain))
    error_message = "mesh_domain must be a DNS name (letters, digits, dots, hyphens)."
  }
}

variable "acme_email" {
  description = "ACME account email for Let's Encrypt. Empty = an anonymous LE account (valid, but you get NO cert-expiry warnings or account-recovery mail) — SET THIS for a production auto-renewing cert."
  type        = string
  default     = ""

  validation {
    # Also interpolated into the bootstrap shell; reject spaces/metacharacters.
    condition     = var.acme_email == "" || can(regex("^[^[:space:]@]+@[^[:space:]@]+$", var.acme_email))
    error_message = "acme_email must look like an email address (no spaces)."
  }
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

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.flow_log_retention_days)
    error_message = "flow_log_retention_days must be a CloudWatch-allowed retention value (1,3,5,7,14,30,60,90,120,150,180,365,400,545,731,1096,1827,2192,2557,2922,3288,3653)."
  }
}

# ── DR / durability (ADR 0007 Phase 7d) ──────────────────────────────────────
variable "secret_recovery_window_days" {
  description = "Secrets Manager recovery window for the app secrets (gateway/lighthouse config, Cloudflare token). 0 = immediate delete (fast lab iteration); 7-30 = a prod-grade accidental-delete window. Defaults to 7 (prod-safe); set 0 for throwaway labs."
  type        = number
  default     = 7

  validation {
    condition     = var.secret_recovery_window_days == 0 || (var.secret_recovery_window_days >= 7 && var.secret_recovery_window_days <= 30)
    error_message = "secret_recovery_window_days must be 0 (immediate) or 7-30 (AWS's allowed window)."
  }
}

variable "fargate_log_retention_days" {
  description = "CloudWatch retention for the Fargate gateway/lighthouse log groups."
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.fargate_log_retention_days)
    error_message = "fargate_log_retention_days must be a CloudWatch-allowed retention value (1,3,5,7,14,30,60,90,120,150,180,365,400,545,731,1096,1827,2192,2557,2922,3288,3653)."
  }
}

variable "audit_export_bucket_name" {
  description = "Name for the S3 Object-Lock bucket that the hash-chained audit log is exported to (WORM, tamper-evident off-DB copy — Phase 7d). Empty disables the bucket. Must be globally unique."
  type        = string
  default     = ""
}

variable "audit_export_lock_days" {
  description = "Object-Lock retention (days, COMPLIANCE mode) on exported audit objects — they cannot be deleted/overwritten before this elapses, even by root."
  type        = number
  default     = 365
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
