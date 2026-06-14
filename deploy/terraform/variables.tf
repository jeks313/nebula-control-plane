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
