# Production Terraform — `foundation` stack (layer 0)

The **isolated trust root** for a full-AWS Nebula control plane (ADR 0007). Deliberately a
separate stack with its own state, deletion-protected and rarely touched, so a routine
change to the `app/` stack can never take out the CA the whole mesh trusts.

It creates:

- **`aws_s3_bucket.state`** — the Terraform remote-state bucket for **both** stacks
  (versioned, AES256-encrypted, public-access-blocked, TLS-only, `prevent_destroy`).
- **Two KMS keys** — `ECC_NIST_P256` / `SIGN_VERIFY`, the only spec `internal/signer/kms.go`
  accepts: the **CA** key (signs cert v2 leaves) and the **config-signing** key (signs the
  bundles Pilot pins). Distinct keys (genesis fails closed if they're the same), 30-day
  deletion window + `prevent_destroy`. Asymmetric keys have no auto-rotation — rotation is
  the staged dual-CA ceremony, out of scope here.
- **`core_kms_sign`** — an IAM policy granting **only** `kms:Sign` + `kms:GetPublicKey` on
  those two keys. The `app/` stack attaches it to the Core (harbor) instance role; the key
  policy itself just delegates to account IAM (avoids a foundation↔app circular dep).

## Bootstrap (one time)

The stack's own state lives in the bucket it creates, so the first apply uses local state,
then migrates:

```bash
cd deploy/prod/terraform/foundation
cp terraform.tfvars.example terraform.tfvars   # set state_bucket_name (globally unique)

terraform init                                  # local state (backend block still commented)
terraform apply                                 # creates the bucket + KMS keys + IAM policy

# Now point the backend at the bucket it just made, then migrate state into it:
#   edit versions.tf -> uncomment the backend "s3" block, set bucket = your name
terraform init -migrate-state                   # moves foundation.tfstate into the bucket
```

From then on the foundation state is remote, encrypted, and S3-locked (`use_lockfile`).

## Wiring the trust root into Harbor

After apply, `terraform output` gives the ARNs the control plane uses (no key material ever
leaves KMS):

```bash
CA=$(terraform output -raw ca_key_arn)
CFG=$(terraform output -raw config_signing_key_arn)

# Genesis ceremony (self-signs the CA cert from the KMS key; writes NO ca.key/config-signing.key):
harbor genesis -backend kms -kms-ca-key-id "$CA" -kms-config-key-id "$CFG" \
  -kms-region ca-central-1 -out ./genesis -operator-a … -operator-b … -lighthouse-pub …

# Runtime Core (issues certs + signs bundles via KMS):
harbor core-api -backend kms -kms-ca-key-id "$CA" -kms-config-key-id "$CFG" -kms-region ca-central-1 …
```

The Core EC2/Fargate role must carry `core_kms_sign_policy_arn` (the `app/` stack attaches
it). `signer.New` fails closed at startup if a key id's public key doesn't match the CA
cert, so a wrong ARN can't silently mint untrusted certs.

## Next layers (`app/` stack)

Network → Data (Aurora + Secrets Manager) → Compute (Core/gateway/lighthouse, role gets
`core_kms_sign`) → Edge (ALB + ACM + WAF) → Artifacts (S3 + CloudFront) → Observability/DR.
The `app/` stack reads these outputs via `terraform_remote_state`.
