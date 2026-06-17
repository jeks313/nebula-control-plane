# ── Harbor's durable config bundle (ADR 0007) ────────────────────────────────
# Harbor is the last component still holding irreplaceable state on local disk — the
# Fargate gateway + lighthouse already read their config from Secrets Manager. This secret
# makes harbor a cattle node too: its CA CERTIFICATE (the public trust anchor — the CA KEY
# stays in KMS), the config-signing pin, harbor's own nebula identity, and the shared
# enrollment secrets (the nonce HMAC + the leaf-pinned harbor<->gateway mTLS material) live
# here. So a destroyed/recreated harbor restores byte-identical from Secrets Manager + KMS +
# Aurora — NO re-genesis and NO new CA cert (a regenerated CA cert has a new fingerprint, and
# nebula pins the CA by its certificate fingerprint, so that would break every enrolled
# member). Created empty; the genesis bootstrap populates it (put-secret-value), exactly like
# the Fargate config secrets — and a recreate reads it back.
resource "aws_secretsmanager_secret" "harbor_config" {
  name                    = "${var.name_prefix}-harbor-config"
  recovery_window_in_days = var.secret_recovery_window_days # 0 = immediate (lab); 7-30 = prod accidental-delete window
}

resource "aws_secretsmanager_secret_version" "harbor_config" {
  secret_id = aws_secretsmanager_secret.harbor_config.id
  secret_string = jsonencode({
    ca_crt_pem              = "" # the public CA cert (trust anchor; the CA private KEY is in KMS)
    config_signing_pub_pem  = "" # the public config-signing pin Pilot verifies
    host_key_pem            = "" # harbor's own nebula host key (so a recreate is byte-identical)
    host_crt_pem            = "" # harbor's nebula (control-plane) cert
    host_config_yml         = "" # harbor's nebula config.yml (static_host_map + firewall baseline)
    hmac_key_b64            = "" # shared nonce key (MUST match the gateway, which holds the same)
    harbor_collect_cert_pem = "" # harbor's mTLS client cert (the gateway pins its leaf)
    harbor_collect_key_pem  = "" # its key
    queue_key_b64           = "" # admin-api local issuance/approval-queue key
    gw_collect_cert_pem     = "" # the gateway's mTLS server cert harbor pins
    acme_cache_tgz_b64      = "" # tar.gz (base64) of ~/ncp/acme — the LE account + issued cert, so recover reuses it
  })
  lifecycle {
    ignore_changes = [secret_string] # the bootstrap owns the real values (placeholder only at create)
  }
}

# Harbor's instance (core) role reads the bundle at boot to restore/self-heal. The operator's
# own credentials WRITE it during the genesis bootstrap (put-secret-value); harbor only reads.
resource "aws_iam_role_policy" "core_harbor_config" {
  name_prefix = "harbor-config-"
  role        = aws_iam_role.core.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource = [aws_secretsmanager_secret.harbor_config.arn]
    }]
  })
}
