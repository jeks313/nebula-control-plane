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
    # ── SSO enrollment material (ADR 0004, OPTIONAL) ─────────────────────────────
    # Empty by default => SSO off => recover reconstructs the same (SSO-disabled) gateway +
    # Core it had at genesis. When the operator enables SSO, the bootstrap snapshots this
    # material here so MODE=recover restores it EXACTLY (the assertion keypair Core pins +
    # the gateway signs with, the STABLE SP keypair the IdP app pins, the IdP metadata, and
    # the ACS/entity/issuer knobs). Without it, a recovered gateway would lose its SP identity
    # (the IdP app pins the SP cert) and a recovered Core would lose the pinned assertion key.
    sso_assert_priv_pem = "" # genesis sso-assert.key — the gateway's assertion-signing PRIVATE half (S6)
    sso_assert_pub_pem  = "" # genesis sso-assert.pub — the PUBLIC half Core pins (-sso-assert-pub)
    sso_sp_cert_pem     = "" # the STABLE SAML SP signing cert (the IdP app pins it; minted once at genesis)
    sso_sp_key_pem      = "" # the SAML SP signing key
    sso_idp_metadata    = "" # the enrollment-portal SAML app's IdP metadata XML
    sso_acs_url         = "" # PUBLIC ACS URL (presence is the gateway SSO trigger)
    sso_entity_id       = "" # SAML SP entity id (the enrollment-portal app's Identifier)
    sso_issuer          = "" # assertion realm (iss), fed to Core's usertrust.Match
    sso_groups_attr     = "" # SAML group-claim attribute (empty => the gateway's "groups" default)
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
