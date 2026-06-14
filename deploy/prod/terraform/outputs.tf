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
  description = "PUBLIC enrollment URL for OFF-CLOUD clients (the iMac). EC2: the node's public IP; Fargate: the internet-facing NLB's DNS name. (In-VPC clients must use gateway_url_internal — a public NLB is not reachable from inside the VPC by DNS.)"
  value       = var.gateway_runtime == "fargate" ? "http://${one(aws_lb.gateway[*].dns_name)}:${var.gateway_port}" : "http://${lookup(local.public_ip, "gateway", "")}:${var.gateway_port}"
}

output "gateway_url_internal" {
  description = "IN-VPC enrollment URL (e.g. the cloud client). EC2: same as the node (private); Fargate: the INTERNAL NLB's private DNS name."
  value       = var.gateway_runtime == "fargate" ? "http://${one(aws_lb.gateway_internal[*].dns_name)}:${var.gateway_port}" : "http://${try(aws_instance.node["gateway"].private_ip, "")}:${var.gateway_port}"
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
  value       = "SSH_KEY=~/.ssh/absolute bash ../scripts/bootstrap-genesis.sh   # reads these outputs via 'terraform output -json'"
}

output "console_hint" {
  description = "The admin console is mesh-only (Harbor's overlay IP, default 10.44.0.2:8445). After the bootstrap, reach it from an enrolled mesh member, or SSH-tunnel ports 8445+8446 to Harbor (see deploy README / the bootstrap output)."
  value       = "mesh-only — http://<harbor-overlay>:8445 (default 10.44.0.2); not exposed in any security group by design"
}
