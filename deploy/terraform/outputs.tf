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
  description = "Lighthouse underlay address for static_host_map / genesis -lighthouse-addr."
  value       = "${local.public_ip["lighthouse"]}:${var.nebula_port}"
}

output "gateway_url" {
  description = "Public enrollment gateway URL pilots target (the off-mesh gateway node, ADR 0005)."
  value       = "http://${local.public_ip["gateway"]}:${var.gateway_port}"
}

output "gateway_collect_addr" {
  description = "The gateway's Harbor-facing collect endpoint (intra-VPC private IP:collect_port) — what `harbor gateway add -url` registers."
  value       = "https://${aws_instance.node["gateway"].private_ip}:${var.collect_port}"
}

output "bootstrap_hint" {
  description = "How to run the genesis bootstrap (control plane + data plane)."
  value       = "SSH_KEY=~/.ssh/absolute bash ../scripts/bootstrap-genesis.sh   # reads these outputs via 'terraform output -json'"
}

output "console_hint" {
  description = "The admin console is mesh-only (Harbor's overlay IP, default 10.44.0.2:8445). After the bootstrap, reach it from an enrolled mesh member, or SSH-tunnel ports 8445+8446 to Harbor (see deploy README / the bootstrap output)."
  value       = "mesh-only — http://<harbor-overlay>:8445 (default 10.44.0.2); not exposed in any security group by design"
}
