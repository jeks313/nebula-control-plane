# Interface VPC endpoints (ADR 0007 hardening): keep node↔AWS-API traffic IN-VPC once
# harbor/client/monitoring go private — no IGW/NAT hop for KMS / Secrets Manager / STS / SSM,
# and no ECR/Logs hop for the Fargate gateway + lighthouse. The S3 GATEWAY endpoint already
# exists (network_hardening.tf, now also on the private route table). private_dns_enabled lets
# the AWS SDKs resolve each service's public name to the in-VPC ENI automatically — no client
# config, the calls just stop leaving the VPC.

# One security group for all interface endpoints: HTTPS in from anything in the VPC (the nodes
# + the Fargate tasks). Endpoints only answer, and the stateful rule covers the response, so no
# egress rule is needed.
resource "aws_security_group" "endpoints" {
  name_prefix = "${var.name_prefix}-endpoints-"
  description = "VPC interface endpoints: HTTPS (443) from in-VPC sources only."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from the VPC (nodes + Fargate tasks reaching AWS service endpoints)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${var.name_prefix}-endpoints" }
}

locals {
  # Always present: harbor's trust-root signing (KMS), the rotating DB cred + Cloudflare token +
  # Fargate config (Secrets Manager), sigv4-attestation verification (STS), and the SSM trio that
  # gives Session Manager / SSH-over-SSM access to the now-private nodes.
  base_interface_endpoints = ["kms", "secretsmanager", "sts", "ssm", "ssmmessages", "ec2messages"]
  # Only when a component runs on Fargate: image pulls (ECR api + dkr; layer blobs ride the S3
  # gateway endpoint) and task logs (CloudWatch Logs). local.any_fargate lives in fargate.tf.
  fargate_interface_endpoints = local.any_fargate == 1 ? ["ecr.api", "ecr.dkr", "logs"] : []
  interface_endpoints         = toset(concat(local.base_interface_endpoints, local.fargate_interface_endpoints))
}

# Single ENI per endpoint, in the control subnet: the tier subnets are all in one AZ, and the
# VPC's implicit local route makes the ENI reachable from every subnet — so one ENI serves the
# whole VPC. (Add more subnet_ids here if the tiers ever span AZs, for per-AZ endpoint resilience.)
resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_endpoints
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.tier["control"].id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${var.name_prefix}-${replace(each.value, ".", "-")}" }
}
