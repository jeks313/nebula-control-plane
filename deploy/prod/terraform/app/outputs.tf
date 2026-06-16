locals {
  # Prefer the Elastic IP where a node has one, else the auto-assigned public IP.
  public_ip = { for k, n in aws_instance.node :
  k => try(aws_eip.node[k].public_ip, n.public_ip) }
}

output "public_ips" {
  description = "Public IPv4 per node (Elastic IP where allocated)."
  value       = local.public_ip
}

output "ssh" {
  description = "Ready-to-paste SSH commands (Amazon Linux user is ec2-user)."
  value       = { for k, ip in local.public_ip : k => "ssh ec2-user@${ip}" }
}

output "instance_ids" {
  value = { for k, n in aws_instance.node : k => n.id }
}

output "lighthouse_addr" {
  description = "Lighthouse underlay address for static_host_map / genesis -lighthouse-addr. EC2: the node's Elastic IP; Fargate: the NLB's Elastic IP."
  value       = var.lighthouse_runtime == "fargate" ? "${one(aws_eip.lighthouse_nlb[*].public_ip)}:${var.nebula_port}" : "${lookup(local.public_ip, "lighthouse", "")}:${var.nebula_port}"
}

output "lighthouse_runtime" {
  description = "Which lighthouse runtime is active (ec2 | fargate)."
  value       = var.lighthouse_runtime
}

output "lighthouse_ecr_repo" {
  description = "ECR repo URL for the Fargate lighthouse image (empty unless lighthouse_runtime=fargate). Push to it with deploy/fargate/build-push.sh lighthouse."
  value       = one(aws_ecr_repository.lighthouse[*].repository_url)
}

output "gateway_url" {
  description = "PUBLIC enrollment URL for OFF-CLOUD clients (the iMac). With a mesh domain set the gateway terminates HTTPS (Let's Encrypt) as <mesh_name>-gateway.<mesh_domain>, so clients MUST connect by that name (operator points DNS/Cloudflare at the public NLB); else http to the internet-facing NLB (EC2: the node's public IP). In-VPC clients use gateway_url_internal."
  value = (
    local.gateway_domain != "" ? "https://${local.gateway_domain}:${var.gateway_port}" :
    var.gateway_runtime == "fargate" ? "http://${one(aws_lb.gateway[*].dns_name)}:${var.gateway_port}" :
    "http://${lookup(local.public_ip, "gateway", "")}:${var.gateway_port}"
  )
}

output "gateway_url_internal" {
  description = "IN-VPC enrollment URL (e.g. the cloud client). With a mesh domain set, connect by <mesh_name>-gateway.<mesh_domain> (split-horizon DNS must resolve it to the INTERNAL NLB, since the gateway serves a cert for that hostname); else http to the internal NLB (EC2: the node's private IP)."
  value = (
    local.gateway_domain != "" ? "https://${local.gateway_domain}:${var.gateway_port}" :
    var.gateway_runtime == "fargate" ? "http://${one(aws_lb.gateway_internal[*].dns_name)}:${var.gateway_port}" :
    "http://${try(aws_instance.node["gateway"].private_ip, "")}:${var.gateway_port}"
  )
}

output "gateway_collect_addr" {
  description = "The gateway's Harbor-facing collect endpoint — what `harbor gateway add -url` registers. Must be reachable from Harbor inside the VPC. EC2: the node's private IP; Fargate: the INTERNAL NLB's private DNS name."
  value       = var.gateway_runtime == "fargate" ? "https://${one(aws_lb.gateway_internal[*].dns_name)}:${var.collect_port}" : "https://${try(aws_instance.node["gateway"].private_ip, "")}:${var.collect_port}"
}

output "gateway_runtime" {
  description = "Which gateway runtime is active (ec2 | fargate)."
  value       = var.gateway_runtime
}

output "gateway_ecr_repo" {
  description = "ECR repo URL for the Fargate gateway image (empty unless gateway_runtime=fargate). Push to it with deploy/fargate/build-push.sh."
  value       = one(aws_ecr_repository.gateway[*].repository_url)
}

output "region" {
  description = "AWS region (for the build/deploy scripts)."
  value       = var.region
}

output "name_prefix" {
  description = "Resource name prefix (for the bootstrap's ECS/Secrets Manager calls — cluster/service/secret are <name_prefix>-<component>)."
  value       = var.name_prefix
}

output "bootstrap_hint" {
  description = "How to run the genesis bootstrap (control plane + data plane)."
  value       = "SSH_KEY=~/.ssh/absolute bash ../../bootstrap-genesis.sh   # run from app/; reads these outputs via 'terraform output -json'"
}

output "monitoring_hint" {
  description = "Stand up the monitoring stack (ADR 0007 Phase 7b) after the genesis bootstrap: `SSH_KEY=~/.ssh/absolute bash deploy/prod/monitoring/deploy.sh` (enrolls the monitoring node + brings up Prometheus/Alertmanager/Grafana). Reach the UIs via SSH tunnel to the monitoring node (Grafana :3000, Prometheus :9090, Alertmanager :9093)."
  value       = "monitoring node: ${try("ssh ec2-user@${local.public_ip["monitoring"]}", "<applied with the monitoring node>")}  ·  deploy: deploy/prod/monitoring/deploy.sh"
}

output "console_hint" {
  description = "The admin console is mesh-only (Harbor's overlay IP, default 10.44.0.2:8445). After the bootstrap, reach it from an enrolled mesh member, or SSH-tunnel ports 8445+8446 to Harbor (see deploy README / the bootstrap output)."
  value       = "mesh-only — http://<harbor-overlay>:8445 (default 10.44.0.2); not exposed in any security group by design"
}

# ── Trust root (re-exported from the foundation stack) ───────────────────────
# So the genesis bootstrap can read every value it needs from this one stack's
# outputs. Key MATERIAL never leaves KMS — these are just ARNs/identifiers.
output "ca_key_arn" {
  description = "CA signing KMS key ARN — `harbor genesis -kms-ca-key-id` / core-api -kms-ca-key-id."
  value       = local.ca_key_arn
}

output "config_signing_key_arn" {
  description = "Config-signing KMS key ARN — `harbor genesis -kms-config-key-id` / core-api -kms-config-key-id."
  value       = local.config_signing_key_arn
}

output "core_kms_sign_policy_arn" {
  description = "IAM policy (kms:Sign + GetPublicKey on both keys) attached to the Core role in the compute layer."
  value       = local.core_kms_sign_policy_arn
}

# ── Data layer (Aurora) — consumed by the compute layer to point Core at the DB ──
output "db_cluster_endpoint" {
  description = "Aurora writer endpoint (Core connects here)."
  value       = aws_rds_cluster.aurora.endpoint
}

output "db_reader_endpoint" {
  description = "Aurora reader endpoint (read replicas)."
  value       = aws_rds_cluster.aurora.reader_endpoint
}

output "db_port" {
  value = aws_rds_cluster.aurora.port
}

output "db_name" {
  value = aws_rds_cluster.aurora.database_name
}

output "db_master_secret_arn" {
  description = "Secrets Manager ARN of the RDS-managed master credential. Core's role gets secretsmanager:GetSecretValue on it (compute layer); the value never enters TF state."
  value       = aws_rds_cluster.aurora.master_user_secret[0].secret_arn
}

output "db_security_group_id" {
  description = "Attach to Core so it can reach Aurora on 5432 (the DB SG ingress is from the harbor SG)."
  value       = aws_security_group.db.id
}

output "rds_kms_key_arn" {
  description = "CMK encrypting Aurora storage + the master secret."
  value       = aws_kms_key.rds.arn
}

# ── Edge TLS (ACME) — consumed by the bootstrap to wire harbor's auto-TLS ──
output "cloudflare_token_secret_arn" {
  description = "Secrets Manager ARN of the scoped Cloudflare DNS token (empty unless gateway_domain or harbor_domain is set). Populate it out-of-band: `aws secretsmanager put-secret-value --secret-id <arn> --secret-string <token>`. Created with a placeholder; ignore_changes keeps TF from clobbering the real value."
  value       = one(aws_secretsmanager_secret.cloudflare_token[*].arn)
}

output "harbor_domain" {
  description = "DNS name harbor's core-api + console serve their own Let's Encrypt cert for — <mesh_name>-harbor.<mesh_domain> (empty = harbor stays plain HTTP on the overlay IP). The genesis bootstrap reads this to wire -acme-domain; operators must resolve it to Core's overlay IP for mesh members."
  value       = local.harbor_domain
}

output "acme_email" {
  description = "ACME account email (passed to harbor's -acme-email by the bootstrap when harbor_domain is set)."
  value       = var.acme_email
}

output "acme_staging" {
  description = "Whether harbor uses the Let's Encrypt STAGING CA (bootstrap passes -acme-staging when true)."
  value       = var.acme_staging
}

output "gateway_acme_efs_id" {
  description = "EFS file system backing the Fargate gateway's ACME cert cache (empty unless the Fargate gateway has auto-TLS on)."
  value       = one(aws_efs_file_system.gateway_acme[*].id)
}
