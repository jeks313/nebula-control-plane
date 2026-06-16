# Container image for the Fargate gateway runtime (ADR 0006: distroless, shell-less, nonroot).
# cmd/gateway is a static, CGO-free Go binary that reads its key/cert MATERIAL from env vars
# (the Secrets-Manager values ECS injects, $NCP_GW_*) and its operational flags from the ECS
# `command` — so no shell entrypoint is needed to materialize files. distroless/static ships
# ca-certificates + tzdata + a nonroot user (uid 65532); it has no shell and no package
# manager, so rebuilds are driven by the Go payload, not an OS-distro CVE treadmill.
#
# Build via deploy/prod/fargate/build-push.sh (it stages the static `gateway` binary here).
# TODO (ADR 0006 Phase 3): pin this base by @sha256 digest for reproducible builds.
FROM gcr.io/distroless/static-debian12:nonroot
COPY gateway /gateway
EXPOSE 8443 9443
ENTRYPOINT ["/gateway"]
