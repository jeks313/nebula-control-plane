# Windows Server 2022 test client (opt-in: enable_windows_client). It exists to
# exercise the pilot Windows SCM service backend (ADR 0008 Phase 4) on a real
# Windows host — the analogue of the off-cloud Mac used for the launchd backend.
#
# It lands in the client tier alongside the Linux cloud member, carries the same
# IAM instance profile (so keyless `-aws-sigv4` enroll via IMDS works), and runs
# OpenSSH Server (set up by user_data) so we can drop pilot.exe over scp and run
# `pilot install`. Key auth only — the key is ed25519, so the EC2 password path
# (RDP) is not usable; SSH is the way in. A `-target=aws_instance.windows` apply
# brings up just this box + the VPC/subnet it depends on (no mesh) for the
# service-mechanics test; a full apply lets it enroll into the live mesh.

data "aws_ssm_parameter" "windows2022" {
  count = var.enable_windows_client ? 1 : 0
  name  = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
}

resource "aws_security_group" "windows_client" {
  count       = var.enable_windows_client ? 1 : 0
  name_prefix = "${var.name_prefix}-winclient-"
  description = "Windows test client: admin SSH (+ RDP fallback) + Nebula UDP; no control-plane exposure."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from you (OpenSSH Server, set up in user_data)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }
  ingress {
    # Manual break-glass only: no EC2 key pair is attached (Windows rejects ed25519),
    # so RDP needs a password set via SSM/console. Kept in case sshd setup fails.
    description = "RDP from you (manual fallback)"
    from_port   = 3389
    to_port     = 3389
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

  # Locked egress — mirrors the Linux client: mesh UDP (data plane + DNS) + enroll
  # to the gateway + package/feature fetches.
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
    description = "Feature-on-demand + package fetch / Windows Update (https)"
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
  subnet_id     = aws_subnet.tier["client"].id
  # No EC2 key_name: AWS rejects ed25519 key pairs on Windows AMIs, and we don't
  # need one — SSH auth is the user_data-injected administrators_authorized_keys.
  # (The EC2 key pair only governs the Windows password / RDP, unused here.)
  vpc_security_group_ids      = [aws_security_group.windows_client[0].id]
  iam_instance_profile        = aws_iam_instance_profile.node.name
  associate_public_ip_address = true

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
  }

  tags = {
    Name = "${var.name_prefix}-windows"
    Role = "client-windows"
  }
}
