# Consumed by (a) the genesis ceremony / `harbor` flags and (b) the app stack via
# terraform_remote_state.

output "state_bucket" {
  value       = aws_s3_bucket.state.id
  description = "Terraform remote-state bucket (use as the backend bucket for foundation + app)."
}

output "ca_key_arn" {
  value       = aws_kms_key.ca.arn
  description = "CA signing key ARN — pass to `harbor genesis -kms-ca-key-id` and core-api/enroll -kms-ca-key-id."
}

output "config_signing_key_arn" {
  value       = aws_kms_key.config_signing.arn
  description = "Config-signing key ARN — pass to `harbor genesis -kms-config-key-id` and core-api/enroll -kms-config-key-id."
}

output "ca_key_alias" {
  value       = aws_kms_alias.ca.name
  description = "Stable alias for the CA key (usable in place of the ARN)."
}

output "config_signing_key_alias" {
  value       = aws_kms_alias.config_signing.name
  description = "Stable alias for the config-signing key."
}

output "core_kms_sign_policy_arn" {
  value       = aws_iam_policy.core_kms_sign.arn
  description = "IAM policy ARN (kms:Sign + GetPublicKey on both keys) — attach to the Core/harbor instance role in the app stack."
}

output "region" {
  value       = var.region
  description = "Region the trust root lives in."
}
