# Audit export bucket (ADR 0007 Phase 7d): a WORM, tamper-evident off-DB copy of Harbor's
# hash-chained audit log. S3 Object-Lock in COMPLIANCE mode means an exported object cannot be
# deleted or overwritten before its retention elapses — not even by the account root — so a DB
# compromise (or a rogue admin) cannot quietly erase the audit trail. Opt-in: created only when
# audit_export_bucket_name is set. The `harbor audit export` writer that populates it is a code
# follow-up; this is the infra (bucket + least-priv write grant). Core gets PutObject ONLY
# (write-once — it never needs to delete, and Object-Lock would refuse anyway).
locals {
  audit_export = var.audit_export_bucket_name != "" ? 1 : 0
}

resource "aws_s3_bucket" "audit_export" {
  count               = local.audit_export
  bucket              = var.audit_export_bucket_name
  object_lock_enabled = true # immutable at creation; the whole point of this bucket

  lifecycle {
    prevent_destroy = true
  }
}

# Object-Lock requires versioning.
resource "aws_s3_bucket_versioning" "audit_export" {
  count  = local.audit_export
  bucket = aws_s3_bucket.audit_export[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

# Default COMPLIANCE retention applied to every exported object — truly immutable for the
# window (tune audit_export_lock_days to the commitment you want).
resource "aws_s3_bucket_object_lock_configuration" "audit_export" {
  count      = local.audit_export
  bucket     = aws_s3_bucket.audit_export[0].id
  depends_on = [aws_s3_bucket_versioning.audit_export] # PutObjectLockConfiguration needs versioning first (explicit, robust to refactors)
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.audit_export_lock_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_export" {
  count                   = local.audit_export
  bucket                  = aws_s3_bucket.audit_export[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_export" {
  count  = local.audit_export
  bucket = aws_s3_bucket.audit_export[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # S3-managed keys; a CMK is an optional hardening
    }
  }
}

# Refuse any non-TLS access (matches the foundation state bucket). depends_on the BPA so it
# applies first — block_public_policy can reject PutBucketPolicy; harmless for this Deny-only
# policy, but guards a future Allow statement (same rationale as foundation/state.tf).
resource "aws_s3_bucket_policy" "audit_export" {
  count      = local.audit_export
  bucket     = aws_s3_bucket.audit_export[0].id
  depends_on = [aws_s3_bucket_public_access_block.audit_export]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.audit_export[0].arn,
        "${aws_s3_bucket.audit_export[0].arn}/*",
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# Core (the harbor role, compute.tf) may WRITE exports — and only write.
resource "aws_iam_role_policy" "core_audit_export" {
  count       = local.audit_export
  name_prefix = "audit-export-"
  role        = aws_iam_role.core.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject"]
      Resource = ["${aws_s3_bucket.audit_export[0].arn}/*"]
    }]
  })
}

output "audit_export_bucket" {
  description = "The S3 Object-Lock bucket for hash-chained audit exports (empty unless audit_export_bucket_name is set). Wire `harbor audit export` to write here."
  value       = one(aws_s3_bucket.audit_export[*].bucket)
}
