# Edge TLS (ADR 0007, TLS pivot): each component obtains + renews its OWN public
# Let's Encrypt certificate via the ACME DNS-01 challenge (Cloudflare), so every hop
# is encrypted end to end — including the L4 NLB -> application leg (the NLBs are TCP
# passthrough; the app terminates TLS). There is NO ALB and NO ACM: Cloudflare fronts
# the public origins for WAF (operator-owned, added later), and the binaries carry the
# ACME client (internal/autotls). The gateway gets its -acme-* flags via the ECS task
# `command` (gateway_fargate.tf) and the Cloudflare token via the NCP_ACME_CLOUDFLARE_TOKEN
# secret env; see cmd/gateway + the distroless deploy/prod/fargate/Dockerfile.
#
# This file provisions the AWS side of that:
#   • the scoped Cloudflare DNS token (Secrets Manager; populated out-of-band),
#   • the gateway's durable ACME cert cache (EFS — the Fargate task is ephemeral, so the
#     account key + issued certs MUST persist off-container or every restart re-issues and
#     trips Let's Encrypt rate limits), and
#   • the IAM grants letting the gateway (and Core) read the token.
# Harbor runs on EC2; its cache persists on the CMK-encrypted root EBS volume, so it needs
# only the token grant (compute.tf), not EFS.

locals {
  # Component DNS names: <mesh_name>-<component>.<mesh_domain> (both must be set to enable
  # auto-TLS; either empty => plain transport). e.g. poc + mesh.failsafe.net ->
  # poc-gateway.mesh.failsafe.net / poc-harbor.mesh.failsafe.net.
  mesh_tls       = var.mesh_name != "" && var.mesh_domain != ""
  gateway_domain = local.mesh_tls ? "${var.mesh_name}-gateway.${var.mesh_domain}" : ""
  harbor_domain  = local.mesh_tls ? "${var.mesh_name}-harbor.${var.mesh_domain}" : ""
  # In-VPC-only name for Loki (the log sink on the monitoring box). A private-zone A record (see
  # dns_private.tf) points it at the monitoring node's current IP, so log shippers (gateway FireLens,
  # node Alloy) target a STABLE name and survive a monitoring relaunch instead of baking a private IP
  # that goes stale. Plain HTTP, internal only — never public.
  loki_domain = local.mesh_tls ? "${var.mesh_name}-loki.${var.mesh_domain}" : ""

  # The shared Cloudflare DNS token exists when ANY component does ACME.
  acme_token = (local.gateway_domain != "" || local.harbor_domain != "") ? 1 : 0
  # Gateway ACME is on only when the Fargate gateway is built AND a domain is set
  # (local.gw_fargate lives in fargate.tf). The EFS cache is gateway-specific.
  gateway_acme = local.gw_fargate == 1 && local.gateway_domain != "" ? 1 : 0
}

# ── Scoped Cloudflare DNS token (Zone.DNS:Edit only) ─────────────────────────────
# Created OUTSIDE Terraform — by deploy/prod/init-secrets.sh, BEFORE `terraform apply` —
# and only LOOKED UP here. Inverting ownership this way removes the chicken-and-egg: there
# is no Terraform-owned placeholder to populate after apply, and the token value never
# enters Terraform state (a data.aws_secretsmanager_secret reads metadata/ARN only, not the
# secret string). The init script owns the value (idempotent create/update); Terraform owns
# only the IAM grants + the Fargate injection that REFERENCE this ARN. ECS injects the raw
# token as $NCP_ACME_CLOUDFLARE_TOKEN (the env var internal/autotls reads first), so it
# never lands on a command line / in `ps`. The secret uses the AWS-managed aws/secretsmanager
# key (init sets no CMK), matching the other secrets in this stack.
#
# NOTE: when a domain is set (local.acme_token == 1) this lookup REQUIRES the secret to
# already exist — run init-secrets.sh first, or `terraform plan` fails with "secret not found".
data "aws_secretsmanager_secret" "cloudflare_token" {
  count = local.acme_token
  name  = "${var.name_prefix}-cloudflare-dns-token"
}

# ── Gateway ACME cert cache (EFS) ────────────────────────────────────────────────
# Dedicated CMK so the at-rest key for the ACME account key + issued cert private keys is
# controlled/rotated/audited like the Aurora + trust-root keys. Deliberately NO
# prevent_destroy and a short deletion window (unlike the RDS/EBS CMKs): this cache is
# disposable — losing it just re-issues certs on next boot — so it must not block teardown.
resource "aws_kms_key" "efs" {
  count                   = local.gateway_acme
  description             = "${var.name_prefix} gateway ACME cert-cache EFS (LE account key + cert private keys)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "efs" {
  count         = local.gateway_acme
  name          = "alias/${var.name_prefix}-efs"
  target_key_id = aws_kms_key.efs[0].key_id
}

resource "aws_efs_file_system" "gateway_acme" {
  count           = local.gateway_acme
  encrypted       = true
  kms_key_id      = aws_kms_key.efs[0].arn
  throughput_mode = "bursting"

  tags = {
    Name = "${var.name_prefix}-gateway-acme"
  }
}

# Access point: enforce the non-root uid/gid the gateway container runs as (65532, the
# distroless `nonroot` user — see deploy/prod/fargate/Dockerfile) for ALL file operations,
# and own the cache dir as that uid with 0700. So the container drops root AND the cert cache
# stays writable — the EFS least-privilege counterpart to the non-root container. The access
# point is the binding control; combined with the task-SG-only ingress (below) and
# transit_encryption=ENABLED on the mount, it makes a separate aws_efs_file_system_policy
# (SecureTransport deny) redundant enough to omit — that policy can't be apply-tested here and
# a misfire would lock out the live mount, so it's deferred rather than guessed at.
resource "aws_efs_access_point" "gateway_acme" {
  count          = local.gateway_acme
  file_system_id = aws_efs_file_system.gateway_acme[0].id

  posix_user {
    uid = 65532
    gid = 65532
  }
  root_directory {
    path = "/acme"
    creation_info {
      owner_uid   = 65532
      owner_gid   = 65532
      permissions = "0700"
    }
  }

  tags = {
    Name = "${var.name_prefix}-gateway-acme"
  }
}

# The mount target lives in the single edge subnet the gateway service runs in (the network
# layer placed edge in one AZ; one mount target per AZ would be needed for a multi-AZ gateway).
resource "aws_efs_mount_target" "gateway_acme" {
  count           = local.gateway_acme
  file_system_id  = aws_efs_file_system.gateway_acme[0].id
  subnet_id       = aws_subnet.tier["edge"].id
  security_groups = [aws_security_group.gateway_efs[0].id]
}

# NFS reachable ONLY from the gateway task SG. The mount target only responds (NFS is
# stateful inbound), so it needs no egress — explicit `egress = []` denies the default
# allow-all (the AWS provider leaves egress allow-all in place when the block is omitted).
resource "aws_security_group" "gateway_efs" {
  count       = local.gateway_acme
  name_prefix = "${var.name_prefix}-gw-efs-"
  description = "EFS for the gateway ACME cert cache: NFS (2049) from the gateway task only."
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "NFS from the gateway task"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.gateway_task[0].id]
  }

  egress = []

  lifecycle {
    create_before_destroy = true
  }
}

# ── IAM: let the gateway EXECUTION role inject the Cloudflare token ───────────────
# (the gateway reads it from $NCP_ACME_CLOUDFLARE_TOKEN; ECS resolves the secret at task
# launch using the execution role). gateway_acme implies acme_token, so the secret exists.
resource "aws_iam_role_policy" "gateway_acme_token" {
  count = local.gateway_acme
  name  = "read-cloudflare-token"
  role  = aws_iam_role.gateway_exec[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [data.aws_secretsmanager_secret.cloudflare_token[0].arn]
    }]
  })
}
