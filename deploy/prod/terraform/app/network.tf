# Dedicated VPC with tiered, NACL-isolated subnets — so the untrusted edge
# (gateway) gets its OWN network, fenced from the control tier (harbor) at L3, as
# defense-in-depth on top of the per-role security groups. Replaces the old
# single-default-subnet layout where all nodes shared one segment and SGs were the
# only filter.
#
# The PUBLIC tiers (edge = gateway enroll NLB, mesh = lighthouse discovery anchor) keep a
# public IP + IGW route. The PRIVATE tiers (control = harbor, client = test client +
# monitoring) get NO public IP: AWS APIs ride VPC interface endpoints (vpc_endpoints.tf)
# and residual egress (dnf/ACME) rides the NAT gateway below. Isolation is by SECURITY
# GROUP (stateful, authoritative) + NACL (stateless, defense-in-depth) + routing.

data "aws_availability_zones" "available" {
  state = "available"
  # Standard regional AZs only — exclude Local Zones / Wavelength / opt-in zones, so the
  # multi-AZ data tier (network_hardening.tf) pins to RDS-eligible zones deterministically.
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name_prefix}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${var.name_prefix}-public" }
}

# ── NAT gateway for the PRIVATE tiers (control, client) ──────────────────────
# harbor/client/monitoring have no public IP, so this is their ONLY path to the public
# internet: OS package updates (dnf), the first-boot nebula fetch (GitHub), and harbor's
# Let's Encrypt ACME (DNS-01). AWS-API traffic does NOT use it — the interface endpoints
# (vpc_endpoints.tf) + the S3 gateway endpoint keep that in-VPC. Single-AZ, like the tiers.
#
# The NAT gets its OWN public subnet — it must NOT sit in the edge subnet, whose restrictive
# gateway NACL (below) silently DROPS the NAT's transit traffic on arbitrary outbound ports
# (that NACL only admits the gateway's enroll/collect/ssh/ephemeral ports). A plain public
# subnet with the VPC's default (permissive) NACL lets the NAT forward to any destination.
resource "aws_subnet" "nat" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 5)
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "${var.name_prefix}-nat" }
}

resource "aws_route_table_association" "nat" {
  subnet_id      = aws_subnet.nat.id
  route_table_id = aws_route_table.public.id # IGW route; default permissive NACL
}

resource "aws_eip" "nat" {
  domain     = "vpc"
  tags       = { Name = "${var.name_prefix}-nat" }
  depends_on = [aws_internet_gateway.igw]
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.nat.id
  tags          = { Name = "${var.name_prefix}-nat" }
  depends_on    = [aws_internet_gateway.igw]
}

# Private route table: 0.0.0.0/0 → NAT. The control + client subnets attach to this; the S3
# gateway endpoint is added to it (network_hardening.tf) so S3 still stays in-VPC.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = { Name = "${var.name_prefix}-private" }
}

locals {
  # One /24 per tier (10.99.1/2/3/4.0/24 by default).
  tier_cidr = {
    control = cidrsubnet(var.vpc_cidr, 8, 1) # harbor (control plane)
    edge    = cidrsubnet(var.vpc_cidr, 8, 2) # gateway (off-mesh, untrusted)
    mesh    = cidrsubnet(var.vpc_cidr, 8, 3) # lighthouse
    client  = cidrsubnet(var.vpc_cidr, 8, 4) # cloud member
  }
  # Which tier each node lands in.
  node_tier = {
    harbor     = "control"
    gateway    = "edge"
    lighthouse = "mesh"
    client     = "client"
    monitoring = "client" # a cloud mesh member, like the client
  }
  # Tiers that stay PUBLIC (auto-assign public IP + IGW route): edge hosts the gateway's
  # internet-facing enroll NLB; mesh hosts the lighthouse, the public discovery anchor.
  # control (harbor) + client (test client + monitoring) are PRIVATE — no public IP.
  public_tiers = ["edge", "mesh"]
}

resource "aws_subnet" "tier" {
  for_each                = local.tier_cidr
  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = contains(local.public_tiers, each.key)
  tags                    = { Name = "${var.name_prefix}-${each.key}" }
}

resource "aws_route_table_association" "tier" {
  for_each       = aws_subnet.tier
  subnet_id      = each.value.id
  route_table_id = contains(local.public_tiers, each.key) ? aws_route_table.public.id : aws_route_table.private.id
}

# ── Edge (gateway) NACL — the L3 fence on the untrusted tier ─────────────────
# STATELESS: every allowed flow needs its matching ephemeral-return rule. The deny
# that matters: NO UDP egress except DNS — so even at L3 the off-mesh gateway
# cannot send Nebula UDP (4242) into the control/mesh tiers; it can only answer
# inbound (public enroll + Harbor's pull) and do DNS + package fetches outbound.
# The other tiers keep the default allow-all NACL (they are trusted mesh members
# whose data plane uses arbitrary UDP ports that are unsafe to NACL; their egress
# is locked at the security group).
resource "aws_network_acl" "edge" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.tier["edge"].id]
  tags       = { Name = "${var.name_prefix}-edge" }

  # ── inbound ──
  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "tcp"
    from_port  = var.gateway_port
    to_port    = var.gateway_port
    cidr_block = var.gateway_cidr # public enrollment (off-cloud, via the internet-facing NLB)
  }
  ingress {
    rule_no    = 105
    action     = "allow"
    protocol   = "tcp"
    from_port  = var.gateway_port
    to_port    = var.gateway_port
    cidr_block = var.vpc_cidr # in-VPC enrollment (e.g. the cloud client, via the internal NLB) — robust even if gateway_cidr is tightened
  }
  ingress {
    rule_no    = 110
    action     = "allow"
    protocol   = "tcp"
    from_port  = var.collect_port
    to_port    = var.collect_port
    cidr_block = local.tier_cidr["control"] # Harbor's pull ONLY (control tier)
  }
  ingress {
    rule_no    = 120
    action     = "allow"
    protocol   = "tcp"
    from_port  = 22
    to_port    = 22
    cidr_block = var.allowed_ssh_cidr
  }
  ingress {
    rule_no    = 130
    action     = "allow"
    protocol   = "tcp"
    from_port  = 1024
    to_port    = 65535
    cidr_block = "0.0.0.0/0" # TCP return traffic (responses to the gateway's bootstrap fetches)
  }
  ingress {
    rule_no    = 140
    action     = "allow"
    protocol   = "udp"
    from_port  = 1024
    to_port    = 65535
    cidr_block = "0.0.0.0/0" # UDP return traffic (DNS responses)
  }

  # ── outbound ──
  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "tcp"
    from_port  = 1024
    to_port    = 65535
    cidr_block = "0.0.0.0/0" # TCP responses (enroll replies to clients, collect replies to Harbor)
  }
  egress {
    rule_no    = 110
    action     = "allow"
    protocol   = "tcp"
    from_port  = 443
    to_port    = 443
    cidr_block = "0.0.0.0/0" # bootstrap (https package fetch)
  }
  egress {
    rule_no    = 120
    action     = "allow"
    protocol   = "tcp"
    from_port  = 80
    to_port    = 80
    cidr_block = "0.0.0.0/0" # bootstrap (http)
  }
  egress {
    rule_no    = 130
    action     = "allow"
    protocol   = "udp"
    from_port  = 53
    to_port    = 53
    cidr_block = "0.0.0.0/0" # DNS — the ONLY UDP the gateway may send (no Nebula 4242 into the mesh)
  }
}
