# Production network hardening, on top of the tiered subnets + per-role SGs + edge NACL
# (network.tf): VPC flow logs, a locked-down default SG, an S3 gateway endpoint, and the
# private multi-AZ data tier the Aurora layer (next) needs.

# ── VPC flow logs → CloudWatch ───────────────────────────────────────────────
# Forensics + the observability layer can alarm on them. ALL traffic (accept + reject).
resource "aws_cloudwatch_log_group" "flow" {
  name_prefix       = "/nebula/${var.name_prefix}-vpc-flow-"
  retention_in_days = var.flow_log_retention_days
}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow" {
  name_prefix        = "${var.name_prefix}-vpc-flow-"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json
}

data "aws_iam_policy_document" "flow_publish" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow" {
  name_prefix = "publish-"
  role        = aws_iam_role.flow.id
  policy      = data.aws_iam_policy_document.flow_publish.json
}

resource "aws_flow_log" "vpc" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow.arn
  iam_role_arn    = aws_iam_role.flow.arn
}

# ── Lock down the VPC's default security group ───────────────────────────────
# Adopt + empty it (no ingress/egress) so nothing can fall back to a permissive default
# SG (CIS). Every node uses an explicit per-role SG (main.tf).
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name_prefix}-default-locked" }
}

# ── S3 gateway endpoint ──────────────────────────────────────────────────────
# Keep S3 traffic (Terraform state, the artifact bucket the self-update layer adds,
# package/bootstrap fetches from S3) in-VPC — no IGW/NAT path, no data-egress charge.
# Gateway endpoints are free and attach to route tables.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id, aws_route_table.data.id]
  tags              = { Name = "${var.name_prefix}-s3" }
}

# ── Private, multi-AZ data tier (for Aurora — next layer) ────────────────────
# Aurora requires subnets in >= 2 AZs. These are PRIVATE: no public IP, no IGW/NAT route
# (the data tier has no internet path; it is reached only from the control tier in-VPC).
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name_prefix}-data" } # local route only — no 0.0.0.0/0
}

locals {
  data_subnets = {
    a = { cidr = cidrsubnet(var.vpc_cidr, 8, 10), az = data.aws_availability_zones.available.names[0] }
    b = { cidr = cidrsubnet(var.vpc_cidr, 8, 11), az = data.aws_availability_zones.available.names[1] }
  }
}

resource "aws_subnet" "data" {
  for_each          = local.data_subnets
  vpc_id            = aws_vpc.main.id
  cidr_block        = each.value.cidr
  availability_zone = each.value.az
  tags              = { Name = "${var.name_prefix}-data-${each.key}", Tier = "data" }
}

resource "aws_route_table_association" "data" {
  for_each       = aws_subnet.data
  subnet_id      = each.value.id
  route_table_id = aws_route_table.data.id
}
