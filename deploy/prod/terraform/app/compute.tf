# Compute layer (ADR 0007): give the Core (harbor) node a DEDICATED instance role with
# exactly the production privileges Core needs — sign with the KMS trust-root keys
# (foundation's least-priv core_kms_sign: kms:Sign + GetPublicKey) and read the Aurora
# master credential from Secrets Manager (decrypting it via the RDS CMK, but ONLY through
# Secrets Manager). Every other node keeps the minimal permission-less `node` role
# (main.tf). IMDSv2 + encrypted EBS are already enforced on the instances (main.tf), and
# the Core→DB network path is the harbor SG's 5432 egress + the DB SG ingress (data.tf).
#
# The genesis bootstrap then runs Core with `-backend kms -kms-ca-key-id <ca> \
# -kms-config-key-id <cfg>` + the Aurora DSN (the master secret fetched at runtime) — the
# ARNs/endpoints are terraform outputs (outputs.tf). Wiring the bootstrap invocation +
# moving the durable queue off SQLite are the code follow-ups noted in data.tf.

resource "aws_iam_role" "core" {
  name_prefix        = "${var.name_prefix}-core-"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json # reused from main.tf
}

resource "aws_iam_instance_profile" "core" {
  name_prefix = "${var.name_prefix}-core-"
  role        = aws_iam_role.core.name
}

# Sign with the trust-root keys (foundation's exported least-priv policy).
resource "aws_iam_role_policy_attachment" "core_kms_sign" {
  role       = aws_iam_role.core.name
  policy_arn = local.core_kms_sign_policy_arn
}

# Read + decrypt the Aurora master credential. kms:Decrypt is scoped via kms:ViaService to
# Secrets-Manager-mediated calls only — Core can decrypt the secret but not use the RDS CMK
# for arbitrary decryption.
data "aws_iam_policy_document" "core_db_secret" {
  statement {
    sid       = "ReadDBMasterSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [aws_rds_cluster.aurora.master_user_secret[0].secret_arn]
  }
  statement {
    sid       = "DecryptDBSecretViaSecretsManager"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.rds.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "core_db_secret" {
  name_prefix = "db-secret-"
  role        = aws_iam_role.core.id
  policy      = data.aws_iam_policy_document.core_db_secret.json
}
