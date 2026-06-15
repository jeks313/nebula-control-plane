# The app stack reads the isolated foundation stack's outputs (hybrid structure): the KMS
# trust-root key ARNs + the least-priv core_kms_sign policy. The compute layer attaches
# that policy to the Core role; the data/genesis steps use the key ARNs. Foundation must
# be applied FIRST. Read-only — the app never mutates the trust root.
data "terraform_remote_state" "foundation" {
  backend = "s3"
  config = {
    bucket = var.state_bucket_name
    key    = "nebula-control-plane/foundation.tfstate"
    region = var.region
  }
}

locals {
  ca_key_arn               = data.terraform_remote_state.foundation.outputs.ca_key_arn
  config_signing_key_arn   = data.terraform_remote_state.foundation.outputs.config_signing_key_arn
  core_kms_sign_policy_arn = data.terraform_remote_state.foundation.outputs.core_kms_sign_policy_arn
}
