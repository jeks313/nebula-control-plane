# SPIKE — Fargate gateway (gateway_runtime = "fargate"). The off-mesh enrollment
# gateway runs no `nebula` (no TUN), so it fits a serverless container: this runs
# `cmd/gateway` as a Fargate task instead of an EC2 VM, fronted by a network LB for
# a stable address. The ADR-0005 posture holds — the public enroll port faces the
# internet, the collect port is reachable ONLY from Harbor's security group, and the
# gateway initiates nothing. Config (nonce key + mTLS certs) is injected from Secrets
# Manager. Everything here is created ONLY when gateway_runtime = "fargate".
#
# NOT live-applied (no AWS creds / no docker here): `terraform validate` clean. To
# run it: deploy/fargate/build-push.sh gateway (image -> ECR), populate the config
# secret (the bootstrap does this post-genesis), then force a new ECS deployment.
#
# Shared locals (local.gw_fargate, local.gateway_image) + the ECS assume-role policy
# live in fargate.tf.

resource "aws_ecr_repository" "gateway" {
  count                = local.gw_fargate
  name                 = "${var.name_prefix}-gateway"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_cloudwatch_log_group" "gateway" {
  count             = local.gw_fargate
  name              = "/${var.name_prefix}/gateway"
  retention_in_days = var.fargate_log_retention_days
}

# The gateway's runtime config (nonce HMAC key + leaf-pinned mTLS material), created
# empty here and populated out-of-band by the genesis bootstrap. ECS injects each JSON
# field as an NCP_GW_* env var the shell-less gateway binary reads directly (no entrypoint).
resource "aws_secretsmanager_secret" "gateway" {
  count                   = local.gw_fargate
  name                    = "${var.name_prefix}-gateway-config"
  recovery_window_in_days = var.secret_recovery_window_days # 0 = immediate (lab); 7-30 = prod accidental-delete window
}

resource "aws_secretsmanager_secret_version" "gateway" {
  count     = local.gw_fargate
  secret_id = aws_secretsmanager_secret.gateway[0].id
  secret_string = jsonencode({
    hmac_key_b64      = "" # base64url nonce key (shared with Harbor)
    queue_key_b64     = "" # base64url local-queue key (gateway-internal)
    collect_cert_pem  = "" # the gateway's mTLS server cert (its leaf is pinned in Harbor's registry)
    collect_key_pem   = "" # its key
    harbor_client_pem = "" # Harbor's pinned client cert
  })
  lifecycle {
    ignore_changes = [secret_string] # the bootstrap owns the real values
  }
}

# ── IAM: task EXECUTION role (pull ECR image, write logs, read the config secret) ─
# (the assume-role policy is the shared data.aws_iam_policy_document.ecs_assume in fargate.tf)
resource "aws_iam_role" "gateway_exec" {
  count              = local.gw_fargate
  name_prefix        = "${var.name_prefix}-gw-exec-"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume[0].json
}

resource "aws_iam_role_policy_attachment" "gateway_exec" {
  count      = local.gw_fargate
  role       = aws_iam_role.gateway_exec[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "gateway_secret" {
  count = local.gw_fargate
  name  = "read-gateway-config"
  role  = aws_iam_role.gateway_exec[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.gateway[0].arn]
    }]
  })
}

# ── Two NLBs (audit fix) ────────────────────────────────────────────────────────
# An internet-facing NLB is NOT reachable from inside the same VPC via its public DNS
# (the lookup returns public IPs; same-VPC traffic hairpins the IGW and is dropped —
# AWS's documented behavior). So in-VPC consumers (Harbor pulling collect, the cloud
# client enrolling) cannot use a public NLB. We therefore run two:
#   • PUBLIC  (internet-facing): enroll :8443 only — for the OFF-cloud client (the iMac).
#   • INTERNAL (internal=true):  enroll :8443 + collect :9443 — for IN-VPC consumers,
#                                resolving to private edge-subnet IPs Harbor/the cloud
#                                client can reach (and that the SG-source-match needs).
# The ADR-0005 posture is unchanged: collect is reachable ONLY from Harbor's SG, on the
# internal NLB; enroll is public on the internet-facing NLB (and private on the internal
# one). Tasks accept only the NLBs.

resource "aws_security_group" "gateway_nlb" {
  count       = local.gw_fargate
  name_prefix = "${var.name_prefix}-gw-nlb-"
  description = "Fargate gateway PUBLIC NLB: internet enroll only (ADR 0005)."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Public enrollment (off-cloud clients)"
    from_port   = var.gateway_port
    to_port     = var.gateway_port
    protocol    = "tcp"
    cidr_blocks = [var.gateway_cidr]
  }
  egress {
    # Forward to the gateway tasks (edge subnet). Target the subnet CIDR, not the task
    # SG, so the NLB and task SGs don't reference each other (cycle).
    description = "Forward enroll to the gateway tasks (edge subnet)"
    from_port   = var.gateway_port
    to_port     = var.gateway_port
    protocol    = "tcp"
    cidr_blocks = [local.tier_cidr["edge"]]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "gateway_internal_nlb" {
  count       = local.gw_fargate
  name_prefix = "${var.name_prefix}-gw-int-nlb-"
  description = "Fargate gateway INTERNAL NLB: in-VPC enroll + Harbor-only collect (ADR 0005)."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "In-VPC enrollment (e.g. the cloud client)"
    from_port   = var.gateway_port
    to_port     = var.gateway_port
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  ingress {
    description     = "Collect (mTLS) - Harbor security group ONLY (the protected side pulls)"
    from_port       = var.collect_port
    to_port         = var.collect_port
    protocol        = "tcp"
    security_groups = [aws_security_group.harbor.id]
  }
  egress {
    description = "Forward enroll+collect to the gateway tasks (edge subnet)"
    from_port   = var.gateway_port
    to_port     = var.collect_port
    protocol    = "tcp"
    cidr_blocks = [local.tier_cidr["edge"]]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "gateway_task" {
  count       = local.gw_fargate
  name_prefix = "${var.name_prefix}-gw-task-"
  description = "Fargate gateway task: accepts only the NLBs; egress only for image/secret/DNS."
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Enroll from the public NLB"
    from_port       = var.gateway_port
    to_port         = var.gateway_port
    protocol        = "tcp"
    security_groups = [aws_security_group.gateway_nlb[0].id]
  }
  ingress {
    description     = "Enroll + collect from the internal NLB"
    from_port       = var.gateway_port
    to_port         = var.collect_port
    protocol        = "tcp"
    security_groups = [aws_security_group.gateway_internal_nlb[0].id]
  }
  egress {
    description = "ECR / Secrets Manager / package fetch (https/http)"
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
  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # NFS to the ACME cert-cache EFS — only when auto-TLS is on. Targets the edge subnet
  # CIDR (the mount target lives there), not the EFS SG, so the two SGs don't reference
  # each other (cycle); the EFS SG already source-matches this task SG on ingress.
  dynamic "egress" {
    for_each = local.gateway_acme == 1 ? [1] : []
    content {
      description = "NFS to the ACME cert-cache EFS (edge subnet)"
      from_port   = 2049
      to_port     = 2049
      protocol    = "tcp"
      cidr_blocks = [local.tier_cidr["edge"]]
    }
  }
  lifecycle {
    create_before_destroy = true
  }
}

# ── Network Load Balancers (stable address; Fargate task IPs are ephemeral) ─────
resource "aws_lb" "gateway" {
  count              = local.gw_fargate
  name_prefix        = "ncpgw-"
  load_balancer_type = "network"
  internal           = false # internet-facing: enroll for off-cloud clients
  subnets            = [aws_subnet.tier["edge"].id]
  security_groups    = [aws_security_group.gateway_nlb[0].id]
}

resource "aws_lb" "gateway_internal" {
  count              = local.gw_fargate
  name_prefix        = "ncpgi-"
  load_balancer_type = "network"
  internal           = true # in-VPC: Harbor's collect pull + the cloud client's enroll
  subnets            = [aws_subnet.tier["edge"].id]
  security_groups    = [aws_security_group.gateway_internal_nlb[0].id]
}

# enroll on the public NLB (off-cloud) and on the internal NLB (in-VPC) are separate
# target groups — an NLB target group binds to a single load balancer.
resource "aws_lb_target_group" "enroll" {
  count              = local.gw_fargate
  name_prefix        = "ncpen-"
  port               = var.gateway_port
  protocol           = "TCP"
  vpc_id             = aws_vpc.main.id
  target_type        = "ip"
  preserve_client_ip = false
}

resource "aws_lb_target_group" "enroll_internal" {
  count              = local.gw_fargate
  name_prefix        = "ncpei-"
  port               = var.gateway_port
  protocol           = "TCP"
  vpc_id             = aws_vpc.main.id
  target_type        = "ip"
  preserve_client_ip = false
}

resource "aws_lb_target_group" "collect" {
  count              = local.gw_fargate
  name_prefix        = "ncpco-"
  port               = var.collect_port
  protocol           = "TCP"
  vpc_id             = aws_vpc.main.id
  target_type        = "ip"
  preserve_client_ip = false # harbor reaches it via the internal NLB; mTLS authenticates, SG restricts
}

resource "aws_lb_listener" "enroll" {
  count             = local.gw_fargate
  load_balancer_arn = aws_lb.gateway[0].arn
  port              = var.gateway_port
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.enroll[0].arn
  }
}

resource "aws_lb_listener" "enroll_internal" {
  count             = local.gw_fargate
  load_balancer_arn = aws_lb.gateway_internal[0].arn
  port              = var.gateway_port
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.enroll_internal[0].arn
  }
}

resource "aws_lb_listener" "collect" {
  count             = local.gw_fargate
  load_balancer_arn = aws_lb.gateway_internal[0].arn
  port              = var.collect_port
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.collect[0].arn
  }
}

# ── ECS Fargate cluster / task / service ────────────────────────────────────────
resource "aws_ecs_cluster" "gateway" {
  count = local.gw_fargate
  name  = "${var.name_prefix}-gateway"
}

resource "aws_ecs_task_definition" "gateway" {
  count                    = local.gw_fargate
  family                   = "${var.name_prefix}-gateway"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.gateway_fargate_cpu
  memory                   = var.gateway_fargate_memory
  execution_role_arn       = aws_iam_role.gateway_exec[0].arn

  container_definitions = jsonencode([{
    name      = "gateway"
    image     = local.gateway_image
    essential = true
    user      = "65532" # distroless nonroot; matches the EFS access point's enforced uid (acme.tf)
    portMappings = [
      { containerPort = var.gateway_port, protocol = "tcp" },
      { containerPort = var.collect_port, protocol = "tcp" },
    ]
    # Operational (non-secret) flags — the shell-less distroless binary gets them as `command`
    # args. Enroll TLS posture: auto-TLS (the gateway's own Let's Encrypt cert via ACME DNS-01)
    # when a domain is set, else -insecure (plain HTTP behind the L4 NLB).
    command = concat(
      [
        "-addr", "0.0.0.0:${var.gateway_port}",
        "-collect-addr", "0.0.0.0:${var.collect_port}",
        "-queue-dsn", "/tmp/queue.db?_pragma=busy_timeout(5000)",
      ],
      local.gateway_acme == 1 ? concat(
        ["-acme-domain", local.gateway_domain, "-acme-cache", "/var/lib/gateway/acme"],
        var.acme_email != "" ? ["-acme-email", var.acme_email] : [],
        var.acme_staging ? ["-acme-staging"] : []
      ) : ["-insecure"]
    )
    # Secret MATERIAL from Secrets Manager — the binary reads each straight from its env var
    # (no shell to materialize files). The Cloudflare token (auto-TLS only) is the whole secret
    # value -> the plain env var internal/autotls reads.
    secrets = concat(
      [
        { name = "NCP_GW_HMAC_KEY_B64", valueFrom = "${aws_secretsmanager_secret.gateway[0].arn}:hmac_key_b64::" },
        { name = "NCP_GW_QUEUE_KEY_B64", valueFrom = "${aws_secretsmanager_secret.gateway[0].arn}:queue_key_b64::" },
        { name = "NCP_GW_COLLECT_CERT_PEM", valueFrom = "${aws_secretsmanager_secret.gateway[0].arn}:collect_cert_pem::" },
        { name = "NCP_GW_COLLECT_KEY_PEM", valueFrom = "${aws_secretsmanager_secret.gateway[0].arn}:collect_key_pem::" },
        { name = "NCP_GW_HARBOR_CLIENT_PEM", valueFrom = "${aws_secretsmanager_secret.gateway[0].arn}:harbor_client_pem::" },
      ],
      local.gateway_acme == 1 ? [
        { name = "NCP_ACME_CLOUDFLARE_TOKEN", valueFrom = aws_secretsmanager_secret.cloudflare_token[0].arn },
      ] : []
    )
    # The auto-renewing cert cache (durable across task restarts) — the EFS volume below.
    mountPoints = local.gateway_acme == 1 ? [
      { sourceVolume = "acme", containerPath = "/var/lib/gateway/acme", readOnly = false },
    ] : []
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.gateway[0].name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "gateway"
      }
    }
  }])

  # EFS-backed ACME cert cache, mounted at /var/lib/gateway/acme (auto-TLS only). Transit
  # encryption forces TLS for the NFS mount; the EFS is CMK-encrypted at rest; and the access
  # point enforces the container's non-root uid (65532) so the cache is writable without root.
  # (With an access point, root_directory must be "/" — the access point's /acme path applies.)
  dynamic "volume" {
    for_each = local.gateway_acme == 1 ? [1] : []
    content {
      name = "acme"
      efs_volume_configuration {
        file_system_id     = aws_efs_file_system.gateway_acme[0].id
        transit_encryption = "ENABLED"
        root_directory     = "/"
        authorization_config {
          access_point_id = aws_efs_access_point.gateway_acme[0].id
          iam             = "DISABLED" # NFS reachability is gated by the EFS SG (task-SG-only)
        }
      }
    }
  }
}

resource "aws_ecs_service" "gateway" {
  count           = local.gw_fargate
  name            = "${var.name_prefix}-gateway"
  cluster         = aws_ecs_cluster.gateway[0].id
  task_definition = aws_ecs_task_definition.gateway[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  # Auto-TLS makes the first boot slow + mount-ordered:
  #  • the gateway BLOCKS on the first Let's Encrypt issuance (DNS-01 TXT propagation + LE
  #    validation — tens of seconds on a cold EFS cache) before it opens the enroll port, so
  #    give NLB health checks room before ECS recycles the task (default grace is 0).
  health_check_grace_period_seconds = local.gateway_acme == 1 ? 300 : null

  network_configuration {
    subnets          = [aws_subnet.tier["edge"].id]
    security_groups  = [aws_security_group.gateway_task[0].id]
    assign_public_ip = true # edge subnet routes to the IGW; lets the task pull ECR/Secrets without a NAT
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.enroll[0].arn # public enroll (off-cloud)
    container_name   = "gateway"
    container_port   = var.gateway_port
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.enroll_internal[0].arn # in-VPC enroll (cloud client)
    container_name   = "gateway"
    container_port   = var.gateway_port
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.collect[0].arn # Harbor collect (internal)
    container_name   = "gateway"
    container_port   = var.collect_port
  }
  # The mount target must be `available` before the service schedules a task, or the first
  # Fargate task fails to mount the cert cache (ECS retries, but it churns the rollout). The
  # counted ref is [] when auto-TLS is off, so this is a no-op then.
  depends_on = [
    aws_lb_listener.enroll, aws_lb_listener.enroll_internal, aws_lb_listener.collect,
    aws_efs_mount_target.gateway_acme,
  ]
}
