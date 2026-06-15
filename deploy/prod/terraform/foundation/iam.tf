# Least-privilege usage grant for the trust-root keys: ONLY kms:Sign + kms:GetPublicKey,
# scoped to exactly the two key ARNs. The app stack attaches this managed policy to the
# Core (harbor) instance role — Core is the only thing that signs. Defining it here keeps
# the grant with the keys; exporting the ARN (outputs.tf) lets the app stack attach it
# without a circular dependency. No kms:Decrypt/Encrypt/CreateGrant/* — signing only.

data "aws_iam_policy_document" "core_kms_sign" {
  statement {
    sid       = "SignAndGetPublicKey"
    effect    = "Allow"
    actions   = ["kms:Sign", "kms:GetPublicKey"]
    resources = [aws_kms_key.ca.arn, aws_kms_key.config_signing.arn]
  }
}

resource "aws_iam_policy" "core_kms_sign" {
  name_prefix = "${var.name_prefix}-core-kms-sign-"
  description = "Allow the Nebula Core (harbor) role to sign with the CA + config-signing KMS keys (Sign/GetPublicKey only)."
  policy      = data.aws_iam_policy_document.core_kms_sign.json
}
