# Artifact hosting — pilot + nebula binary distribution

Public-read S3 bucket that hosts the **pilot** and **nebula** data-plane binaries the self-update
rollout lanes fetch (ADR 0003). This is the "artifacts (S3)" layer of ADR 0007.

## Why public-read is safe

Every host's **signed** config bundle carries the desired `(version, sha256, url)` for nebula and
pilot. The pilot fetches the `url`, **verifies the sha256 of the raw bytes**, and only then swaps
the binary / re-execs. The `-nebula-url` / `-pilot-url` flag docs say it outright: *"sha-verified,
so the source need not be trusted."* A tampered or swapped object fails the hash and is rejected at
the pilot — so a public bucket leaks nothing sensitive (these are just the agent/data-plane
binaries) and grants no write. That is the whole reason we can skip CloudFront/auth: the integrity
guarantee lives in the bundle, not the transport. No-creds reachability also means the **off-cloud
iMac** can self-update over the plain internet.

## Layout (raw binaries, not tarballs)

Both `pilotupdate` and `nebulaupdate` sha256 the **raw bytes** and `chmod 0755` them directly —
there is **no untar** on the host. So the bucket holds raw executables:

```
s3://<bucket>/pilot/<version>/pilot-<os>-<arch>
s3://<bucket>/nebula/<version>/nebula-<os>-<arch>   # raw binary extracted from GitHub's archive (linux .tar.gz / darwin .zip)
```

## Enable + publish

1. Set `artifacts_bucket_name = "poc-artifacts.mesh.failsafe.net"` (or any globally-unique name) in
   the app stack and `terraform apply`. The bucket + public-read policy come from
   `deploy/prod/terraform/app/artifacts.tf`.
2. Build + upload, then register with Harbor:

   ```bash
   # from anywhere with aws creds + the repo (reads the bucket/region from terraform output):
   deploy/prod/artifacts/publish.sh both <pilot-ver> <nebula-ver>
   # e.g. publish.sh both 0.5.0 1.10.3
   ```

   It prints the `harbor pilot add …` / `harbor nebula add …` commands (with the computed sha256
   and the S3 URL). **Run those where Harbor + its DB are reachable** (the control-plane host) —
   they write the registry. Then `harbor pilot release -gen <n>` / `harbor nebula release -gen <n>`
   stages the generation as a canary on its lane; core-api drives convergence on heartbeats and the
   pilots self-update.

The `{version}`-token URL templates are also exposed as `terraform output artifacts_pilot_url` /
`artifacts_nebula_url` for scripting (Harbor substitutes `{version}` at `add` time).

## Mixed-arch fleets (per-arch releases)

A release **generation** can carry a different binary per `(goos, goarch)`, so **one** staged
generation serves a mixed-arch fleet (linux/amd64 cloud + darwin/arm64 iMac). The pilot reports
its `runtime.GOOS/GOARCH` (at enrollment and each heartbeat); Core stamps each host the artifact
matching its own platform, and leaves a host alone (no update) if its arch isn't registered for
the staged generation — it never serves a wrong-arch binary.

`release` applies **arch affinity**: it stages only hosts whose arch the generation actually ships
and reports the rest (a host whose arch is unregistered would never converge and would trip the
rollout's observe-window auto-rollback). So register every platform for a generation
(`add` + `add-artifact`) **before** `release`; if you forget one, `release` tells you which hosts
it skipped and how to add their arch.

`publish.sh` defaults to **linux/amd64** (the cloud fleet the rollout drives). Publish another
platform with `GOOS=… GOARCH=… publish.sh …` (the iMac is `GOOS=darwin GOARCH=arm64`; nebula's
darwin asset is the **universal `nebula-darwin.zip`** — a zip, not a tarball — which `publish.sh`
unzips to the raw `nebula` binary, so `unzip` is required for the darwin lane).

Register the platforms of one version against a **single generation**: the first `add` creates the
generation (it is the *default* artifact, defaulting to linux/amd64); each other platform attaches
to it with `add-artifact -gen <gen>`. Then `release -gen <gen>` stages the whole generation:

```bash
# build + upload both platforms (run publish.sh once per platform)
GOOS=linux  GOARCH=amd64 deploy/prod/artifacts/publish.sh nebula 1.10.3
GOOS=darwin GOARCH=arm64 deploy/prod/artifacts/publish.sh nebula 1.10.3
# register them against ONE generation (publish.sh prints these with the right sha/url):
harbor nebula add          -version 1.10.3 -os linux  -arch amd64 -sha256 <amd64sha> -url <amd64url>   # -> gen N
harbor nebula add-artifact -gen N          -os darwin -arch arm64 -sha256 <arm64sha> -url <arm64url>
harbor nebula list          # shows gen N with its per-arch artifacts indented
harbor nebula release -gen N # stages gen N fleet-wide; each host fetches its own arch
```

A single-arch fleet ignores all of this: plain `harbor nebula add` (no `-os/-arch`) registers a
linux/amd64 default and behaves exactly as before.

## What this is *not*

Harbor itself still does not host binaries (`harbor … add` records a URL; it serves the tuple in
the bundle). nebula's **initial** install (EC2 `user_data`, the Fargate lighthouse image) still
pulls the pinned tarball straight from GitHub — this bucket is for **self-update distribution**,
where the pilot needs a raw binary at a stable, sha-pinned URL. Re-hosting nebula here also
decouples self-update from GitHub's availability.
