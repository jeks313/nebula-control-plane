# Container image for the Fargate LIGHTHOUSE runtime (ADR 0006: distroless, shell-less, nonroot).
# A lighthouse runs `nebula` with `tun.disabled` — no TUN, no privilege — so it runs as the
# distroless nonroot user. nebula is a third-party binary that can't read env or render its
# own config, so the static `cmd/nebula-boot` shim does that (materialize the injected
# CA/cert/key + render config.yml, then exec nebula) — replacing the old shell entrypoint.
#
# The fetch stage (alpine, build-time only) downloads + sha-verifies the pinned nebula
# release; the final distroless image carries only nebula + the shim.
# Build via deploy/prod/fargate/build-push.sh lighthouse (it stages the static `nebula-boot`).
# TODO (ADR 0006 Phase 3): pin the distroless base by @sha256 digest for reproducible builds.
FROM alpine:3.20 AS fetch
ARG NEBULA_VERSION=1.10.3
ARG NEBULA_SHA256=""
RUN apk add --no-cache curl tar
RUN set -eu; \
    curl -fsSL -o /tmp/nebula.tgz \
      "https://github.com/slackhq/nebula/releases/download/v${NEBULA_VERSION}/nebula-linux-amd64.tar.gz"; \
    if [ -n "$NEBULA_SHA256" ]; then echo "${NEBULA_SHA256}  /tmp/nebula.tgz" | sha256sum -c -; fi; \
    tar -xzf /tmp/nebula.tgz -C /usr/local/bin nebula

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=fetch /usr/local/bin/nebula /usr/local/bin/nebula
COPY nebula-boot /usr/local/bin/nebula-boot
EXPOSE 4242/udp 8080/tcp
ENTRYPOINT ["/usr/local/bin/nebula-boot"]
