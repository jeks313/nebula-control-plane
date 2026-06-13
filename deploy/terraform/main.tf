# Minimal lab: two EC2 nodes (a Harbor/lighthouse box and a Pilot member) in the
# default VPC, your personal SSH key, an instance IAM role (so they're ready for
# M5 sigv4 attestation), IMDSv2-only, and encrypted EBS.

# Latest Amazon Linux 2023 AMI, resolved via SSM (no hard-coded AMI IDs).
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Your personal public key becomes the EC2 key pair. pathexpand handles "~".
resource "aws_key_pair" "personal" {
  key_name   = "${var.name_prefix}-personal"
  public_key = file(pathexpand(var.ssh_public_key_path))
}

resource "aws_security_group" "node" {
  name_prefix = "${var.name_prefix}-node-"
  description = "Nebula control-plane node: SSH (you), Nebula UDP, egress."
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from allowed_ssh_cidr only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  ingress {
    description = "Nebula overlay handshake / lighthouse (UDP 4242)"
    from_port   = 4242
    to_port     = 4242
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    for_each = var.open_gateway_port > 0 ? [1] : []
    content {
      description = "Enrollment gateway"
      from_port   = var.open_gateway_port
      to_port     = var.open_gateway_port
      protocol    = "tcp"
      cidr_blocks = [var.allowed_ssh_cidr]
    }
  }

  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Instance role. Deliberately permission-less: a role still lets the instance
# call sts:GetCallerIdentity, which is all the M5 sigv4 attestation needs. Add a
# DescribeInstances policy here only on the Core/Harbor node if you wire 5.3.
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name_prefix        = "${var.name_prefix}-node-"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_instance_profile" "node" {
  name_prefix = "${var.name_prefix}-node-"
  role        = aws_iam_role.node.name
}

locals {
  # Roles are just tags + bootstrap hints here; the box is otherwise identical.
  nodes = {
    harbor = { role = "harbor" } # control plane + lighthouse
    pilot  = { role = "pilot" }  # mesh member / agent
  }
}

resource "aws_instance" "node" {
  for_each = local.nodes

  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.instance_type
  subnet_id                   = element(data.aws_subnets.default.ids, 0)
  key_name                    = aws_key_pair.personal.key_name
  vpc_security_group_ids      = [aws_security_group.node.id]
  iam_instance_profile        = aws_iam_instance_profile.node.name
  associate_public_ip_address = true

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    role           = each.value.role
    nebula_version = var.nebula_version
    nebula_sha256  = var.nebula_sha256
  })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only — matches awsattest.FetchInstanceCredentials
    http_put_response_hop_limit = 2          # so a containerized Pilot can still reach IMDS
  }

  root_block_device {
    volume_size = 16
    encrypted   = true # EBS encrypted at rest
  }

  tags = {
    Name = "${var.name_prefix}-${each.key}"
    Role = each.value.role
  }
}
