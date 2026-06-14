#!/bin/sh
# Fargate gateway entrypoint. ECS injects the gateway's config from Secrets Manager
# as env vars; the gateway reads keys/certs from FILE paths, so materialize them to
# a tmp dir, then exec the gateway with the ADR-0005 dual listener: public enroll +
# the Harbor-only mTLS collect API over a local (ephemeral) queue.
#
# -insecure: the public enroll port is plain HTTP behind the NLB (TCP passthrough)
# in this spike; production terminates TLS at the NLB (ACM) or in the gateway. The
# collect port is mTLS regardless (the gateway terminates it, leaf-pinned).
set -eu

d="$(mktemp -d)"
printf '%s' "${HMAC_KEY_B64:?missing HMAC_KEY_B64}"           > "$d/hmac.b64"
printf '%s' "${QUEUE_KEY_B64:?missing QUEUE_KEY_B64}"         > "$d/queue.b64"
printf '%s' "${COLLECT_CERT_PEM:?missing COLLECT_CERT_PEM}"   > "$d/gw.crt"
printf '%s' "${COLLECT_KEY_PEM:?missing COLLECT_KEY_PEM}"     > "$d/gw.key"
printf '%s' "${HARBOR_CLIENT_PEM:?missing HARBOR_CLIENT_PEM}" > "$d/harbor.crt"

exec /usr/local/bin/gateway -insecure \
  -addr "0.0.0.0:${NCP_GW_PORT:-8443}" -hmac-key "$d/hmac.b64" \
  -queue-dsn "/tmp/queue.db?_pragma=busy_timeout(5000)" -queue-key "$d/queue.b64" \
  -collect-addr "0.0.0.0:${NCP_COLLECT_PORT:-9443}" -collect-cert "$d/gw.crt" \
  -collect-key "$d/gw.key" -harbor-client-cert "$d/harbor.crt"
