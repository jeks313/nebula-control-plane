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

## Other architectures (e.g. the iMac)

`publish.sh` defaults to **linux/amd64** (the cloud fleet the rollout drives). Publish another
platform with `GOOS=… GOARCH=… publish.sh …` (the iMac is `GOOS=darwin GOARCH=arm64`; nebula's
darwin asset is the **universal `nebula-darwin.zip`** — a zip, not a tarball — which `publish.sh`
unzips to the raw `nebula` binary, so `unzip` is required for the darwin lane).

**Caveat:** the registry stores **one URL per release generation**, so a mixed-arch fleet can't be
served by a single gen. Publish each arch and `release` the matching generation to the hosts of
that arch (or run a per-arch lane). Per-arch URL selection within one generation is a Harbor
follow-up.

## What this is *not*

Harbor itself still does not host binaries (`harbor … add` records a URL; it serves the tuple in
the bundle). nebula's **initial** install (EC2 `user_data`, the Fargate lighthouse image) still
pulls the pinned tarball straight from GitHub — this bucket is for **self-update distribution**,
where the pilot needs a raw binary at a stable, sha-pinned URL. Re-hosting nebula here also
decouples self-update from GitHub's availability.
