variable "region" {
  type        = string
  default     = "ca-central-1"
  description = "AWS region for the foundation (state bucket + KMS trust root)."
}

variable "project" {
  type        = string
  default     = "nebula-control-plane"
  description = "Project tag applied to every resource."
}

variable "name_prefix" {
  type        = string
  default     = "nebula-prod"
  description = "Prefix for resource names / KMS aliases."
}

variable "state_bucket_name" {
  type        = string
  description = "Globally-unique S3 bucket name for Terraform remote state (foundation + app). No default — pick one (e.g. <org>-nebula-tfstate-<acct>)."

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "state_bucket_name must be a valid S3 bucket name (lowercase, 3-63 chars)."
  }
}

variable "key_admin_principal_arns" {
  type        = list(string)
  default     = []
  description = "Optional IAM principal ARNs allowed to ADMINISTER the KMS keys (lifecycle/rotation), beyond the account-root→IAM delegation. Usage (Sign/GetPublicKey) is granted separately via the exported core_kms_sign policy. Empty = rely on account IAM only."
}
