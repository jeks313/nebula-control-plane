# Container image for the Fargate LIGHTHOUSE runtime (lighthouse_runtime=fargate).
# A lighthouse runs `nebula` with `tun.disabled` — no TUN, no privilege — so a plain
# alpine image works. The nebula release is downloaded + sha-verified at build time
# (pin matches the terraform nebula_version / nebula_sha256 defaults). The entrypoint
# materializes the Secrets-Manager-injected identity + renders the lighthouse config.
# Build via deploy/fargate/build-push.sh lighthouse.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS fetch
ARG NEBULA_VERSION=1.10.3
ARG NEBULA_SHA256=""
RUN apk add --no-cache curl tar
RUN set -eu; \
    curl -fsSL -o /tmp/nebula.tgz \
      "https://github.com/slackhq/nebula/releases/download/v${NEBULA_VERSION}/nebula-linux-amd64.tar.gz"; \
    if [ -n "$NEBULA_SHA256" ]; then echo "${NEBULA_SHA256}  /tmp/nebula.tgz" | sha256sum -c -; fi; \
    tar -xzf /tmp/nebula.tgz -C /usr/local/bin nebula

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates
COPY --from=fetch /usr/local/bin/nebula /usr/local/bin/nebula
COPY nebula-entrypoint.sh /usr/local/bin/nebula-entrypoint.sh
RUN chmod +x /usr/local/bin/nebula-entrypoint.sh /usr/local/bin/nebula
EXPOSE 4242/udp 8080/tcp
ENTRYPOINT ["/usr/local/bin/nebula-entrypoint.sh"]
