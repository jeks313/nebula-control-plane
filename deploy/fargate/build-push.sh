#!/usr/bin/env bash
# Build the Fargate gateway container (static gateway binary + alpine) and push it to
# the ECR repo terraform created (gateway_runtime=fargate). Run after `terraform
# apply -var gateway_runtime=fargate`, then force a new ECS deployment.
#
# Requires: go, docker, terraform, aws.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TFDIR="$ROOT/deploy/terraform"

for t in go docker terraform aws; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done

REPO="$(terraform -chdir="$TFDIR" output -raw gateway_ecr_repo 2>/dev/null || true)"
[[ -n "$REPO" ]] || { echo "no gateway_ecr_repo output — run 'terraform apply -var gateway_runtime=fargate' first" >&2; exit 1; }
REGION="$(terraform -chdir="$TFDIR" output -raw region 2>/dev/null)"
REGISTRY="${REPO%/*}"

echo "==> building static gateway (linux/amd64, cgo-free)"
( cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$HERE/gateway" ./cmd/gateway )

echo "==> ECR login + build + push: $REPO:latest"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY"
docker build -t "$REPO:latest" "$HERE"
docker push "$REPO:latest"
rm -f "$HERE/gateway"

echo "==> done. Populate the config secret (the genesis bootstrap does this), then:"
echo "    aws ecs update-service --cluster ${NAME_PREFIX:-ncp}-gateway --service ${NAME_PREFIX:-ncp}-gateway --force-new-deployment --region $REGION"
