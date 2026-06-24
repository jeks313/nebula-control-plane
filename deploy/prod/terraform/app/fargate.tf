# Shared scaffolding for the Fargate runtimes. The off-mesh GATEWAY (always
# Fargate-eligible — runs no nebula) and, as a spike, the LIGHTHOUSE (a tun.disabled
# nebula container) can each run as a serverless container instead of an EC2 VM.
# Each component's resources live in its own *_fargate.tf, count-gated on its runtime;
# this file holds the locals + IAM they share.
#
# NOT live-applied here (no AWS creds / no docker in the dev env): `terraform validate`
# is clean in every runtime combination. See deploy/fargate/README.md.

locals {
  gw_fargate  = var.gateway_runtime == "fargate" ? 1 : 0
  lh_fargate  = var.lighthouse_runtime == "fargate" ? 1 : 0
  any_fargate = (local.gw_fargate == 1 || local.lh_fargate == 1) ? 1 : 0

  # HA lighthouses (lighthouse_runtime = "fargate"): N independent identities, each with its own
  # cert/overlay-IP (minted by genesis/bootstrap) AND its own NLB+EIP, so a rotation redeploy of one
  # never blacks out discovery (the others keep serving). Keyed by name. The FIRST keeps the legacy
  # single-lighthouse AWS resource names ("ncp-lighthouse"/"ncp-lighthouse-config") so enabling HA
  # does NOT destroy/recreate the live one (see the moved blocks in lighthouse_fargate.tf); the rest
  # are suffixed (ncp-lighthouse-2, ...). Empty for the ec2 runtime. Overlay IPs are NOT set here —
  # genesis assigns them; terraform only needs the set of identities to stand up infra for.
  lighthouse_names = var.lighthouse_runtime == "fargate" ? [for i in range(var.lighthouse_count) : "lighthouse-${i + 1}"] : []
  lighthouses = { for i, n in local.lighthouse_names : n => {
    name  = n
    rname = i == 0 ? "${var.name_prefix}-lighthouse" : "${var.name_prefix}-${n}"
  } }

  # Image URIs: an explicit override, else the ECR repo created here, tag "latest".
  gateway_image    = var.gateway_image != "" ? var.gateway_image : "${try(aws_ecr_repository.gateway[0].repository_url, "")}:latest"
  lighthouse_image = var.lighthouse_image != "" ? var.lighthouse_image : "${try(aws_ecr_repository.lighthouse[0].repository_url, "")}:latest"
}

# ECS task assume-role, shared by every Fargate task execution role here. count is
# any_fargate, so index [0] exists whenever either component is on Fargate.
data "aws_iam_policy_document" "ecs_assume" {
  count = local.any_fargate
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}
