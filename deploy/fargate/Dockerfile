# Container image for the Fargate gateway runtime (ADR 0005, gateway_runtime=fargate).
# The gateway is a static, cgo-free Go binary; alpine gives a tiny image with a shell
# for the entrypoint that materializes Secrets-Manager-injected config to files.
# Build via deploy/fargate/build-push.sh (it stages the `gateway` binary alongside).
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache ca-certificates
COPY gateway /usr/local/bin/gateway
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/gateway
EXPOSE 8443 9443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
