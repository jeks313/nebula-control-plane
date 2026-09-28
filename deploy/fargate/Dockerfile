# Container image for the Fargate gateway runtime (ADR 0005, gateway_runtime=fargate).
# The gateway is a static, cgo-free Go binary; alpine gives a tiny image with a shell
# for the entrypoint that materializes Secrets-Manager-injected config to files.
# Build via deploy/fargate/build-push.sh (it stages the `gateway` binary alongside).
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates
COPY gateway /usr/local/bin/gateway
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/gateway
EXPOSE 8443 9443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
