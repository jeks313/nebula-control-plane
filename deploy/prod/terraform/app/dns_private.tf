# dns_private.tf — Split-horizon DNS for in-VPC mesh name resolution.
#
# The public (Cloudflare) zone points <mesh>-gateway at the INTERNET-FACING gateway NLB, which
# in-VPC clients can't reach (NLB hairpinning: an instance in the VPC can't loop back through the
# public NLB to a target in the same VPC). A Route53 PRIVATE hosted zone for mesh_domain,
# associated with this VPC, shadows the public zone for in-VPC queries and resolves the gateway
# name to the INTERNAL NLB instead. The hostname is unchanged, so the gateway's Let's Encrypt cert
# still validates. Off-cloud clients (e.g. the iMac) are unaffected — they use the public zone.
#
# Because a private hosted zone shadows the ENTIRE mesh_domain namespace inside the VPC (no
# fall-through to public), it must also carry the harbor name, or in-VPC nodes lose harbor
# resolution. Created only for a Fargate gateway with a mesh domain (local.gateway_acme); EC2-gateway
# or no-domain deployments keep public-only DNS unchanged.

variable "harbor_overlay_ip" {
  description = "Harbor's overlay IP — must match the genesis bootstrap's HARBOR_OVERLAY (default 10.44.0.2 in pool 10.44.0.0/16). Used for the in-VPC private-zone A record so mesh members resolve <mesh_name>-harbor.<mesh_domain>."
  type        = string
  default     = "10.44.0.2"
}

resource "aws_route53_zone" "mesh_private" {
  count   = local.gateway_acme
  name    = var.mesh_domain
  comment = "${var.name_prefix} split-horizon: in-VPC mesh name resolution"
  vpc {
    vpc_id = aws_vpc.main.id
  }
}

# <mesh>-gateway -> the INTERNAL gateway NLB (in-VPC enroll path). The public zone keeps this name
# on the internet-facing NLB for off-cloud clients.
resource "aws_route53_record" "gateway_internal" {
  count   = local.gateway_acme
  zone_id = aws_route53_zone.mesh_private[0].zone_id
  name    = local.gateway_domain
  type    = "A"
  alias {
    name                   = aws_lb.gateway_internal[0].dns_name
    zone_id                = aws_lb.gateway_internal[0].zone_id
    evaluate_target_health = true
  }
}

# <mesh>-harbor -> Harbor's overlay IP (reachable once a node is on the mesh). Required in the
# private zone too, since it shadows public for in-VPC queries.
resource "aws_route53_record" "harbor_overlay" {
  count   = local.gateway_acme
  zone_id = aws_route53_zone.mesh_private[0].zone_id
  name    = local.harbor_domain
  type    = "A"
  ttl     = 60
  records = [var.harbor_overlay_ip]
}
