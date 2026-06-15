# The two trust roots, as non-exportable AWS KMS keys (ADR 0007 Phase 2; consumed by
# internal/signer/kms.go). Both are ECC_NIST_P256 / SIGN_VERIFY — the only spec the
# KMSBackend accepts. They are DISTINCT keys (genesis fails closed if the CA and
# config-signing keys are the same) and deletion-protected: a 30-day window (max — gives
# recovery time) plus prevent_destroy so no `terraform destroy`/replace can take out the
# CA the whole mesh trusts. Asymmetric KMS keys have no automatic rotation; rotation is the
# staged dual-CA ceremony (ADR 0007 §key rotation), not in scope here.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_root = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
}

# Key policy: delegate access control to account IAM (AWS-recommended baseline) so the
# least-priv kms:Sign/GetPublicKey grant can live on an IAM policy (iam.tf) attached to the
# Core role by the app stack — avoiding a foundation<->app circular dependency. Optional
# explicit key administrators are added when key_admin_principal_arns is set.
data "aws_iam_policy_document" "trust_root_key" {
  statement {
    sid       = "EnableIAMPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }
  }

  dynamic "statement" {
    for_each = length(var.key_admin_principal_arns) > 0 ? [1] : []
    content {
      sid    = "KeyAdministrators"
      effect = "Allow"
      # Lifecycle administration only — read + enable/disable/describe + tag + delete window.
      # Deliberately NOT kms:PutKeyPolicy (would let an admin rewrite the policy to grant
      # itself kms:Sign — admin→use escalation) and NOT kms:CreateGrant/kms:Sign. Usage is
      # the separate core_kms_sign IAM policy (iam.tf). Read verbs stay wildcarded (all
      # non-mutating); mutating verbs are enumerated so no Put*/Update* sneaks PutKeyPolicy in.
      actions = [
        "kms:Describe*", "kms:Get*", "kms:List*",
        "kms:EnableKey", "kms:DisableKey", "kms:UpdateKeyDescription",
        "kms:TagResource", "kms:UntagResource",
        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
      ]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.key_admin_principal_arns
      }
    }
  }
}

resource "aws_kms_key" "ca" {
  description              = "${var.name_prefix} Nebula CA signing key (cert v2 leaves)"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  policy                   = data.aws_iam_policy_document.trust_root_key.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "ca" {
  name          = "alias/${var.name_prefix}-ca"
  target_key_id = aws_kms_key.ca.key_id
}

resource "aws_kms_key" "config_signing" {
  description              = "${var.name_prefix} Nebula config-signing key (signs bundles Pilot pins)"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  policy                   = data.aws_iam_policy_document.trust_root_key.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "config_signing" {
  name          = "alias/${var.name_prefix}-config-signing"
  target_key_id = aws_kms_key.config_signing.key_id
}
