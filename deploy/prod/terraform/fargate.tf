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
