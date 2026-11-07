# Container image for the Fargate gateway runtime (ADR 0005, gateway_runtime=fargate).
# The gateway is a static, cgo-free Go binary; alpine gives a tiny image with a shell
# for the entrypoint that materializes Secrets-Manager-injected config to files.
# Build via deploy/fargate/build-push.sh (it stages the `gateway` binary alongside).
FROM alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a
RUN apk add --no-cache ca-certificates
COPY gateway /usr/local/bin/gateway
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/gateway
EXPOSE 8443 9443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
