# Artifact bucket (ADR 0007 — the "artifacts (S3)" layer): public-read hosting for the pilot +
# nebula data-plane binaries that the self-update rollout lanes (ADR 0003) point at. Each host's
# SIGNED bundle carries the (version, sha256, url) tuple; the pilot fetches the url, verifies the
# sha256, and only then swaps/re-execs — so the SOURCE NEED NOT BE TRUSTED (the -nebula-url /
# -pilot-url flag docs say exactly this). That is why public-read hosting is safe: a tampered or
# swapped object fails the hash check and is rejected at the pilot, never trusted. No CloudFront
# (direct S3 HTTPS), so it is reachable by OFF-CLOUD hosts with no AWS creds (the iMac) and in-VPC
# hosts alike. Opt-in: created only when artifacts_bucket_name is set (S3 names are globally
# unique, so the operator must choose one). Populate it with deploy/prod/artifacts/publish.sh.
#
# NOTE: objects here are RAW executables, not tarballs — both pilotupdate and nebulaupdate
# sha256 the raw bytes and chmod 0755 them directly (no untar). publish.sh extracts nebula's raw
# binary from the GitHub tarball before upload.
locals {
  artifacts = var.artifacts_bucket_name != "" ? 1 : 0
}

resource "aws_s3_bucket" "artifacts" {
  count  = local.artifacts
  bucket = var.artifacts_bucket_name
  # No prevent_destroy: unlike the state/audit buckets, these binaries are reproducible
  # (rebuild + re-publish). force_destroy stays at its default (false), so `terraform destroy`
  # still fails safely on a non-empty versioned bucket rather than silently nuking a live fleet's
  # update source — empty it deliberately first if you really mean to tear it down.
}

# ACLs disabled (modern default) — public read is granted by the bucket POLICY below, never ACLs.
resource "aws_s3_bucket_ownership_controls" "artifacts" {
  count  = local.artifacts
  bucket = aws_s3_bucket.artifacts[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Versioned: a re-published binary keeps its predecessor, and an accidental overwrite is
# recoverable. The registry pins each release to a version-scoped key path anyway.
resource "aws_s3_bucket_versioning" "artifacts" {
  count  = local.artifacts
  bucket = aws_s3_bucket.artifacts[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  count  = local.artifacts
  bucket = aws_s3_bucket.artifacts[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # transparent for public GETs; keeps at-rest encryption on by default
    }
    bucket_key_enabled = true
  }
}

# Public read is the whole point of this bucket, so — UNLIKE every other bucket in the stack —
# the policy blocks must be OFF (block_public_policy / restrict_public_buckets = false). ACL-based
# public access stays blocked: we never use ACLs (BucketOwnerEnforced above), so leave those true.
resource "aws_s3_bucket_public_access_block" "artifacts" {
  count                   = local.artifacts
  bucket                  = aws_s3_bucket.artifacts[0].id
  block_public_acls       = true  # no ACLs in play; keep the ACL path locked
  ignore_public_acls      = true  # ditto
  block_public_policy     = false # we intentionally attach a public-read bucket policy
  restrict_public_buckets = false # public GET is the design
}

data "aws_iam_policy_document" "artifacts" {
  count = local.artifacts

  # Anyone may download a binary. Integrity is anchored by the bundle's sha256, so a public
  # object that has been tampered with is rejected at the pilot — public read leaks nothing
  # sensitive (these are just the agent/data-plane binaries) and grants no write.
  statement {
    sid       = "PublicReadBinaries"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts[0].arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }

  # Refuse non-TLS access (pilots fetch over HTTPS; this just forbids the http alternative so a
  # plaintext GET can't be silently MITM'd — defense in depth on top of the sha check).
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts[0].arn, "${aws_s3_bucket.artifacts[0].arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  count  = local.artifacts
  bucket = aws_s3_bucket.artifacts[0].id
  policy = data.aws_iam_policy_document.artifacts[0].json

  # The public-access-block must be applied FIRST: with block_public_policy still true, S3 would
  # reject this PutBucketPolicy as "public". Ordering matters here (unlike the Deny-only state
  # policy) because PublicReadBinaries genuinely is a public Allow.
  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}
