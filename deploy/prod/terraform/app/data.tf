# Data layer (ADR 0007 Phase 1): Aurora PostgreSQL, Multi-AZ, in the PRIVATE data subnets
# (network_hardening.tf). Replaces Core's single-file SQLite with an HA, point-in-time-
# recoverable managed store. Credentials are RDS-managed in Secrets Manager (never in TF
# state); storage + the secret are encrypted with a customer-managed KMS key; the DB is
# reachable ONLY from the control tier (harbor) and ONLY over TLS.
#
# NOTE: this provisions the datastore. Pointing Core at it (the DSN from the secret) +
# moving the durable queue off its SQLite pin are the compute layer + a code follow-up
# (internal/queue is still SQLite-backed).

# ── KMS CMK for RDS storage + the master-credential secret ───────────────────
# Operational data-encryption key (symmetric, rotated) — distinct from the foundation
# trust-root signing keys. prevent_destroy: losing it makes the DB + its backups
# unrecoverable.
resource "aws_kms_key" "rds" {
  description             = "${var.name_prefix} Aurora storage + master-secret encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.name_prefix}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# ── Subnet group across the private, multi-AZ data tier ──────────────────────
resource "aws_db_subnet_group" "aurora" {
  name_prefix = "${var.name_prefix}-aurora-"
  subnet_ids  = [for s in aws_subnet.data : s.id]
  tags        = { Name = "${var.name_prefix}-aurora" }
}

# ── DB security group: 5432 from the control tier (harbor) ONLY ──────────────
resource "aws_security_group" "db" {
  name_prefix = "${var.name_prefix}-db-"
  description = "Aurora: PostgreSQL 5432 from the control tier (harbor/Core) only; no egress needed."
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from Core (harbor SG)"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.harbor.id]
  }
  # Deny ALL egress: a database initiates nothing outbound, and Core's queries are stateful
  # inbound (the ingress rule). aws_security_group egress is Optional+Computed, so an OMITTED
  # block leaves AWS's default allow-all in place — an EXPLICIT `egress = []` is required to
  # strip it. (Core's side of reaching the DB is the harbor SG's egress, main.tf.)
  egress = []

  lifecycle {
    create_before_destroy = true
  }
}

# ── Force TLS on every connection ────────────────────────────────────────────
resource "aws_rds_cluster_parameter_group" "aurora" {
  name_prefix = "${var.name_prefix}-aurora-pg-"
  # Derive the family from the engine major so the two can't drift (16.x -> aurora-postgresql16).
  family      = "aurora-postgresql${split(".", var.aurora_engine_version)[0]}"
  description = "${var.name_prefix} Aurora PostgreSQL — force SSL."

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Stable suffix for the final-snapshot id (see final_snapshot_identifier below).
resource "random_id" "final_snapshot" {
  byte_length = 4
  keepers     = { cluster = "${var.name_prefix}-aurora" }
}

# ── The cluster ──────────────────────────────────────────────────────────────
resource "aws_rds_cluster" "aurora" {
  cluster_identifier = "${var.name_prefix}-aurora"
  engine             = "aurora-postgresql"
  engine_version     = var.aurora_engine_version
  database_name      = var.db_name
  port               = 5432

  master_username = "harbor"
  # RDS creates + rotates the master password in Secrets Manager — it never enters TF state.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.rds.arn

  db_subnet_group_name            = aws_db_subnet_group.aurora.name
  vpc_security_group_ids          = [aws_security_group.db.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.aurora.name

  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  backup_retention_period = var.db_backup_retention_days
  preferred_backup_window = "07:00-08:00"
  copy_tags_to_snapshot   = true
  deletion_protection     = true
  skip_final_snapshot     = false
  # Unique suffix so a deliberate recreate can't collide with a prior final snapshot
  # (a snapshot id must be unique in the account/region). Stable via the keeper — it only
  # rotates if the cluster identifier changes, so it doesn't churn on every plan.
  final_snapshot_identifier = "${var.name_prefix}-aurora-final-${random_id.final_snapshot.hex}"

  allow_major_version_upgrade = false

  lifecycle {
    prevent_destroy = true
  }
}

# ── Writer + reader instances, one per data-tier AZ (Multi-AZ) ───────────────
resource "aws_rds_cluster_instance" "aurora" {
  for_each = aws_subnet.data

  identifier                      = "${var.name_prefix}-aurora-${each.key}"
  cluster_identifier              = aws_rds_cluster.aurora.id
  engine                          = aws_rds_cluster.aurora.engine
  engine_version                  = aws_rds_cluster.aurora.engine_version
  instance_class                  = var.db_instance_class
  db_subnet_group_name            = aws_db_subnet_group.aurora.name
  availability_zone               = each.value.availability_zone
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds.arn
  ca_cert_identifier              = "rds-ca-rsa2048-g1"
}
