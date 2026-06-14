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
