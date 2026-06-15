# Test topology: a lighthouse, a harbor (control plane), and a test client in the
# default VPC. Lighthouse + harbor get Elastic IPs (stable public addresses — the
# lighthouse address is baked into every host's static_host_map, and harbor's is
# the gateway URL pilots target). Security groups are split by role; the off-cloud
# iMac is NOT managed here — it's your host, it just runs `pilot`.

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# VPC, tiered subnets, and the edge NACL live in network.tf.

# Your personal public key becomes the EC2 key pair. pathexpand handles "~".
resource "aws_key_pair" "personal" {
  key_name   = "${var.name_prefix}-personal"
  public_key = file(pathexpand(var.ssh_public_key_path))
}

# ── Security groups (split by role) ─────────────────────────────────────────
# Only two things face the internet: the lighthouse's UDP discovery port and
# harbor's TCP enrollment gateway. Core's API (8444) is bound to harbor's overlay
# IP and is in NO security group — reachable only once you're on the mesh.

resource "aws_security_group" "lighthouse" {
  name_prefix = "${var.name_prefix}-lighthouse-"
  description = "Lighthouse: public Nebula UDP discovery + admin SSH."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from you"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }
  ingress {
    description = "Nebula overlay handshake / lighthouse discovery"
    from_port   = var.nebula_port
    to_port     = var.nebula_port
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # Locked egress: mesh UDP (data plane + DNS) + bootstrap package fetch. No
  # arbitrary outbound TCP.
  egress {
    description = "Nebula data plane + DNS (UDP)"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Bootstrap package fetch (https/http)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "harbor" {
  name_prefix = "${var.name_prefix}-harbor-"
  description = "Harbor: Nebula UDP (mesh node) + admin SSH. The enrollment gateway is now a SEPARATE off-mesh node (ADR 0005) - Harbor reaches OUT to it (egress) and PULLS; it is NOT exposed here. Core API (8444) is overlay-only, NOT here."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from you"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }
  ingress {
    description = "Nebula overlay (Harbor is itself a mesh node)"
    from_port   = var.nebula_port
    to_port     = var.nebula_port
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # Locked egress: PULL the gateway's collect port (to the edge subnet — a CIDR,
  # not the gateway SG, to avoid an SG<->SG dependency cycle) + mesh UDP + bootstrap.
  egress {
    description = "Pull the off-mesh gateway collect API (ADR 0005)"
    from_port   = var.collect_port
    to_port     = var.collect_port
    protocol    = "tcp"
    cidr_blocks = [local.tier_cidr["edge"]]
  }
  egress {
    # Core -> Aurora (data tier). Core INITIATES this, so it is harbor's egress; the DB SG
    # (data.tf) has only the matching stateful ingress + deny-all egress. Target the
    # data-subnet CIDRs (not the DB SG) to avoid an SG<->SG egress cycle, like collect above.
    description = "Aurora PostgreSQL (data tier)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [for s in values(local.data_subnets) : s.cidr]
  }
  egress {
    description = "Nebula data plane + DNS (UDP)"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Bootstrap package fetch (https/http)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle {
    create_before_destroy = true
  }
}

# The pull-based enrollment gateway (ADR 0005): the one internet-facing node, and
# deliberately OFF the mesh. Inbound only — the public enroll port + the collect
# port reachable ONLY from Harbor's security group; it initiates nothing toward the
# mesh and holds no overlay identity. (Egress is left open for bootstrap package
# installs; production would drop it — a gateway needs no outbound.)
resource "aws_security_group" "gateway" {
  name_prefix = "${var.name_prefix}-gateway-"
  description = "Enrollment gateway (ADR 0005): public enroll + Harbor-only collect port; NOT on the mesh."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from you"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }
  ingress {
    description = "Public enrollment (credential-less, rate-limited): nonce / enroll / poll"
    from_port   = var.gateway_port
    to_port     = var.gateway_port
    protocol    = "tcp"
    cidr_blocks = [var.gateway_cidr]
  }
  ingress {
    description     = "Harbor collect API (mTLS) - Harbor security group ONLY (the protected side pulls)"
    from_port       = var.collect_port
    to_port         = var.collect_port
    protocol        = "tcp"
    security_groups = [aws_security_group.harbor.id]
  }
  # Locked egress (ADR 0005 "initiates nothing"): ONLY bootstrap fetch + DNS. No
  # Nebula UDP, no SSH-out, no path into the control/mesh tiers — responses to the
  # public enroll + Harbor's pull ride the STATEFUL inbound rules, needing no egress.
  egress {
    description = "Bootstrap package fetch (https)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Bootstrap package fetch (http)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "client" {
  name_prefix = "${var.name_prefix}-client-"
  description = "Test client: admin SSH + Nebula UDP; no control-plane exposure."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from you"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }
  ingress {
    description = "Nebula overlay (mesh responder / hole-punch)"
    from_port   = var.nebula_port
    to_port     = var.nebula_port
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # Locked egress: mesh UDP (data plane + DNS) + enroll to the gateway + bootstrap.
  egress {
    description = "Nebula data plane + DNS (UDP)"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    # A pilot member must reach the enrollment gateway to enroll. In-VPC it uses the
    # gateway's INTERNAL NLB (edge subnet) — a public NLB isn't reachable from the VPC.
    description = "Enroll to the gateway (TCP gateway_port, in-VPC via the edge subnet)"
    from_port   = var.gateway_port
    to_port     = var.gateway_port
    protocol    = "tcp"
    cidr_blocks = [local.tier_cidr["edge"]]
  }
  egress {
    description = "Bootstrap package fetch (https/http)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle {
    create_before_destroy = true
  }
}

# ── Instance IAM role ───────────────────────────────────────────────────────
# Permission-less: enough for sts:GetCallerIdentity (M5 sigv4 attestation). Add a
# DescribeInstances policy to the harbor role only if/when you wire 5.3.
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

# ── Nodes ───────────────────────────────────────────────────────────────────
locals {
  base_nodes = {
    harbor = { role = "harbor", eip = true }  # control-plane mesh node — routes core-api over the overlay, needs a real TUN
    client = { role = "client", eip = false } # cloud test member
  }
  # The lighthouse and gateway are EC2 nodes only under their "ec2" runtime; under
  # "fargate" each becomes a serverless container (lighthouse_fargate.tf /
  # gateway_fargate.tf) fronted by an NLB, and gets no VM.
  ec2_lighthouse = var.lighthouse_runtime == "ec2" ? { lighthouse = { role = "lighthouse", eip = true } } : {} # stable address for static_host_map
  ec2_gateway    = var.gateway_runtime == "ec2" ? { gateway = { role = "gateway", eip = true } } : {}
  nodes          = merge(local.base_nodes, local.ec2_lighthouse, local.ec2_gateway)
  sg_for = {
    lighthouse = aws_security_group.lighthouse.id # used by the EC2 node when present
    harbor     = aws_security_group.harbor.id
    gateway    = aws_security_group.gateway.id # used by the EC2 node when present
    client     = aws_security_group.client.id
  }
}

resource "aws_instance" "node" {
  for_each = local.nodes

  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.tier[local.node_tier[each.key]].id
  key_name               = aws_key_pair.personal.key_name
  vpc_security_group_ids = [local.sg_for[each.key]]
  # Core (harbor) gets the elevated role (KMS sign + DB-secret read, compute.tf); every
  # other node keeps the minimal permission-less profile.
  iam_instance_profile        = each.key == "harbor" ? aws_iam_instance_profile.core.name : aws_iam_instance_profile.node.name
  associate_public_ip_address = true

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    role           = each.value.role
    nebula_version = var.nebula_version
    nebula_sha256  = var.nebula_sha256
  })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only — matches awsattest.FetchInstanceCredentials
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_size = 16
    encrypted   = true
  }

  tags = {
    Name = "${var.name_prefix}-${each.key}"
    Role = each.value.role
  }
}

# Stable public addresses for the nodes that need them.
resource "aws_eip" "node" {
  for_each = { for k, v in local.nodes : k => v if v.eip }

  instance   = aws_instance.node[each.key].id
  domain     = "vpc"
  tags       = { Name = "${var.name_prefix}-${each.key}" }
  depends_on = [aws_internet_gateway.igw] # EIP association needs the VPC's IGW attached
}
