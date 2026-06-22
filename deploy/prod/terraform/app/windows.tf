# Windows Server 2022 client (opt-in: enable_windows_client) on the PROD/poc stack — the
# Windows analogue of the Linux `client` node + the off-cloud Mac. It exercises the pilot
# Windows SCM service backend (ADR 0008 Phase 4) and the embedded nebula/Wintun staging
# (ADR 0003 Phase 2) on a real host, and joins the LIVE poc mesh alongside the other members.
#
# Like the Linux client it is PRIVATE: no public IP, no inbound SSH. It is reached via SSM
# (Session Manager / SSH-over-SSM by instance id) — the SSM agent (preinstalled on the Windows
# Server AMI) dials OUT to the ssm/ssmmessages/ec2messages interface endpoints (vpc_endpoints.tf)
# over the client tier's NAT + in-VPC endpoint path; the `node` instance profile carries
# AmazonSSMManagedInstanceCore (compute.tf). A `-target=aws_instance.windows` apply brings up just
# this box (+ its SG); it then enrolls KEYLESS via `-aws-sigv4` (its IAM role) into the live mesh.

data "aws_ssm_parameter" "windows2022" {
  count = var.enable_windows_client ? 1 : 0
  name  = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
}

# SG mirrors the Linux client (aws_security_group.client): Nebula UDP + locked egress; NO inbound
# SSH (the box is private — admin access is SSM, not a public IP).
resource "aws_security_group" "windows" {
  count       = var.enable_windows_client ? 1 : 0
  name_prefix = "${var.name_prefix}-winclient-"
  description = "Windows test client (poc): Nebula UDP + locked egress; private, no inbound SSH (reached via SSM)."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Nebula overlay (mesh responder / hole-punch)"
    from_port   = var.nebula_port
    to_port     = var.nebula_port
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # Locked egress: mesh UDP (data plane + DNS) + enroll to the gateway (in-VPC) + https/http
  # (Windows Update for the OpenSSH feature, the SSM interface endpoints, and artifact/pin fetch
  # — all via the client tier's NAT + the in-VPC interface endpoints).
  egress {
    description = "Nebula data plane + DNS (UDP)"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Enroll to the gateway (TCP gateway_port, in-VPC via the edge subnet)"
    from_port   = var.gateway_port
    to_port     = var.gateway_port
    protocol    = "tcp"
    cidr_blocks = [local.tier_cidr["edge"]]
  }
  egress {
    description = "SSM endpoints + Windows Update + artifact/pin fetch (https)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Package fetch (http)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_instance" "windows" {
  count = var.enable_windows_client ? 1 : 0

  ami           = data.aws_ssm_parameter.windows2022[0].value
  instance_type = var.windows_instance_type
  subnet_id     = aws_subnet.tier["client"].id # private client tier (no public IP; NAT + SSM endpoints)
  # The EC2 key pair only governs the (unused) Windows RDP password — SSH auth is the
  # user_data-injected administrators_authorized_keys, tunnelled over SSM. Set it for parity.
  key_name                    = aws_key_pair.personal.key_name
  vpc_security_group_ids      = [aws_security_group.windows[0].id]
  iam_instance_profile        = aws_iam_instance_profile.node.name # carries AmazonSSMManagedInstanceCore (compute.tf)
  associate_public_ip_address = false                              # PRIVATE — reached via SSM, not a public IP

  user_data = templatefile("${path.module}/user_data.ps1.tftpl", {
    ssh_public_key = trimspace(file(pathexpand(var.ssh_public_key_path)))
  })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only — matches awsattest.FetchInstanceCredentials
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_size = 50 # the Windows Server base image needs ~30 GiB; leave headroom
    encrypted   = true
    kms_key_id  = aws_kms_key.ebs.arn # customer-managed CMK (compute.tf)
  }

  tags = {
    Name = "${var.name_prefix}-windows"
    Role = "client-windows"
  }
}
