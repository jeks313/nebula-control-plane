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

# Read the scoped Cloudflare DNS token so Core CAN obtain its own Let's Encrypt cert via
# ACME DNS-01 (harbor terminates TLS for core-api + console — autotls/internal). Granted
# only when harbor_domain is set; the secret is created in acme.tf (harbor_domain != ""
# implies local.acme_token == 1, so the secret exists).
#
# GRANT-ONLY for now: this hands Core the read permission, but the genesis bootstrap
# (deploy/prod/bootstrap-genesis.sh) does NOT yet export $NCP_ACME_CLOUDFLARE_TOKEN or pass
# -acme-domain to core-api/admin-api — so setting harbor_domain provisions the secret + grant
# but harbor keeps its current transport until that bootstrap wiring lands (tracked in ADR
# 0007). NB: admin-api fatals under -environment=production without in-process TLS, so the
# bootstrap change must add -acme-domain in the same step it flips harbor to production.
resource "aws_iam_role_policy" "core_acme_token" {
  count       = local.harbor_domain != "" ? 1 : 0
  name_prefix = "acme-token-"
  role        = aws_iam_role.core.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.cloudflare_token[0].arn]
    }]
  })
}

# ── EBS root-volume encryption (all nodes) ───────────────────────────────────
# The instances already set root_block_device.encrypted=true (main.tf); pin a customer-
# managed CMK so the at-rest key is controlled/rotated/audited like the Aurora + trust-root
# keys, not the shared aws/ebs default. The node root volumes hold each host's nebula
# private key + cached signed config. EC2 creates a grant on this key at launch (the
# default key policy delegates to account IAM, so no explicit key-policy statement needed).
resource "aws_kms_key" "ebs" {
  description             = "${var.name_prefix} EBS root-volume encryption (mesh/control-plane nodes)"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${var.name_prefix}-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}
