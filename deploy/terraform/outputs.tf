output "public_ips" {
  description = "Public IPv4 per node."
  value       = { for k, n in aws_instance.node : k => n.public_ip }
}

output "ssh" {
  description = "Ready-to-paste SSH commands (Amazon Linux user is ec2-user)."
  value       = { for k, n in aws_instance.node : k => "ssh ec2-user@${n.public_ip}" }
}

output "instance_ids" {
  value = { for k, n in aws_instance.node : k => n.id }
}
