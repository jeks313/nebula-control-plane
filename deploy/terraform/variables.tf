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
  description = "sha256 of nebula-linux-amd64.tar.gz for nebula_version. Empty skips verification (a supply-chain gap; set it for real use)."
  type        = string
  default     = ""
}

variable "open_gateway_port" {
  description = "If > 0, also open this TCP port to allowed_ssh_cidr for the enrollment gateway (e.g. 8443). 0 = closed."
  type        = number
  default     = 0
}
