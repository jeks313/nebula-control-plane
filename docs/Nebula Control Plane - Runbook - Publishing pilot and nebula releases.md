# Runbook — Publishing pilot & nebula releases

How to ship a new version of the **pilot** (control-plane agent) or **nebula** (data-plane)
binary to a running mesh, and how it reaches the fleet. No assumed knowledge.

## The model (read this once)

- A **public-read S3 bucket** (`artifacts_bucket_name`, the `app` stack) hosts the **raw**
  pilot/nebula binaries — not tarballs. Public-read is safe because integrity is anchored by a
  **sha256**: pilot verifies the hash before it swaps/re-execs, so a tampered object simply fails.
- Harbor's registry tracks **generations**. A generation carries **one binary per `(os, arch)`**.
  The **first** platform you register *creates* the generation (and becomes its **default**
  artifact); each **additional** platform is added to that same generation.
- A **rollout lane** (ADR 0003) stages a generation as a **canary**, then advances wave-by-wave to
  the fleet as hosts converge and stay healthy. **Arch affinity**: only hosts whose `(os, arch)`
  the generation ships get staged — so register *every* arch you have in the fleet *before* you
  release, or the un-shipped hosts never converge and the lane stalls/rolls back.
- How a host picks it up: `pilot supervise` polls core-api; core-api hands each host the artifact
  URL **matching its reported arch**; pilot downloads the raw binary, checks the sha256, then
  swaps + re-execs itself (pilot) or restarts nebula (nebula).

## Prerequisites

- The artifacts bucket exists: `artifacts_bucket_name` set in `deploy/prod/terraform/app/terraform.tfvars`
  and applied. Check: `terraform -chdir=deploy/prod/terraform/app output artifacts_base_url` is non-empty.
- On the **publishing host** (your laptop): `aws`, `terraform`, `go` (builds pilot), `curl`, and
  `unzip` (nebula's darwin asset is a zip). AWS creds in the environment.
- To **register**, run the `harbor …` commands **where Harbor + its DB are reachable** — on this
  mesh that's the **harbor node**, and because this mesh runs on **Aurora**, every `harbor` CLI call
  needs the DB flags (see below). The publish step does *not* touch Harbor; only register/release do.

### This mesh's DB flags (Aurora)

`harbor` CLI calls that read/write the control-plane DB must carry:

```
-driver postgres \
-dsn "postgres://ncp-aurora.cluster-c3sz1gv66azn.ca-central-1.rds.amazonaws.com:5432/harbor?sslmode=require" \
-db-secret-arn "arn:aws:secretsmanager:ca-central-1:308040853462:secret:rds!cluster-989db997-7db1-47a7-a3a2-8f76813085d8-ed3Wrl" \
-db-secret-region ca-central-1
```

(The harbor node's instance role resolves the rotating secret per-connection — no password on the
command line. Get the current values any time from `terraform -chdir=deploy/prod/terraform/app output`.)

## Step 1 — Build + upload every platform

Use `deploy/prod/artifacts/publish.sh`. It builds/fetches the binary, uploads the **raw** bytes, and
prints the sha256 + the exact `harbor … add` / `add-artifact` commands.

```
publish.sh pilot  <version>                 # build cmd/pilot, upload
publish.sh nebula <version>                 # fetch slackhq/nebula <version>, extract + upload the raw binary
publish.sh both   <pilot-ver> <nebula-ver>  # both
```

Default platform is `linux/amd64`. Override with `GOOS=… GOARCH=…`. **Publish the cloud fleet's
platform (`linux/amd64`) first** so it becomes the generation's default, then any others:

```bash
# from the repo root, with AWS creds in the env:
GOOS=linux  GOARCH=amd64 deploy/prod/artifacts/publish.sh both <pilot-ver> <nebula-ver>
GOOS=darwin GOARCH=arm64 deploy/prod/artifacts/publish.sh both <pilot-ver> <nebula-ver>   # off-cloud iMac (Apple Silicon)
```

Copy the printed sha256 + URL for each platform — you need them to register. (nebula's darwin asset
is a **universal** binary, so one darwin upload covers Intel + Apple Silicon.)

## Step 2 — Register the generation with Harbor

Run on the harbor node, with the **DB flags** above appended to every command. **First** platform
creates the generation (note the gen number it prints); **additional** platforms attach to that gen.

```bash
# pilot — first (linux/amd64) creates gen N:
harbor pilot add          -version <ver> -os linux  -arch amd64 -sha256 <sha-linux>  -url <url-linux>   <DB FLAGS>
# pilot — additional platform onto gen N:
harbor pilot add-artifact -gen N         -os darwin -arch arm64 -sha256 <sha-darwin> -url <url-darwin>  <DB FLAGS>

# nebula — same shape:
harbor nebula add          -version <ver> -os linux  -arch amd64 -sha256 <sha-linux>  -url <url-linux>   <DB FLAGS>
harbor nebula add-artifact -gen M          -os darwin -arch arm64 -sha256 <sha-darwin> -url <url-darwin>  <DB FLAGS>
```

Confirm a generation ships every fleet arch before releasing it — otherwise un-shipped hosts can't
converge. `harbor pilot list` / `harbor nebula list` (with DB flags) show the registered gens + arches.

## Step 3 — Release (stage the rollout)

```bash
harbor pilot  release -gen N   <DB FLAGS>   # stages gen N as a canary on the pilot lane
harbor nebula release -gen M   <DB FLAGS>   # same for nebula
```

The rollout engine then advances canary → waves → fleet as hosts apply the version and stay healthy.
Watch it:

```bash
harbor rollout status  <DB FLAGS>
harbor fleet           <DB FLAGS>
```

- A canary/wave that goes **unhealthy** or stays silent past the observe window **auto-rolls back**.
- Abort a bad rollout yourself: `harbor rollout abort -actor <you> <DB FLAGS>`.

## Off-cloud install (the iMac) — first-time bootstrap of a node

An off-cloud host has no AWS creds and no pre-installed binaries. It pulls them from the public
bucket, then enrolls. (After it joins, governed self-updates from Step 3 apply normally.)

```bash
B=https://ncp-artifacts-308040853462.s3.ca-central-1.amazonaws.com
curl -fsSL "$B/pilot/<pilot-ver>/pilot-darwin-arm64"   -o /tmp/pilot
curl -fsSL "$B/nebula/<nebula-ver>/nebula-darwin-arm64" -o /tmp/nebula
# integrity (compare against the sha publish.sh printed):
shasum -a 256 /tmp/pilot /tmp/nebula
chmod +x /tmp/pilot /tmp/nebula && sudo mv /tmp/pilot /tmp/nebula /usr/local/bin/
# pin: copy deploy/prod/terraform/app/config-signing.pub to the host (or curl "$B/config-signing.pub")
sudo pilot enroll -dir ~/.nebula -gateway <public-gateway-url> -join-key <join-key> \
  -config-pub config-signing.pub -name <node-name>
# approve it (console, or `harbor enroll approve …` with DB flags), then re-run enroll to fetch the bundle,
# then supervise:
sudo pilot supervise -dir ~/.nebula -config ~/.nebula/config.yml -core <https-core-url> -config-pub config-signing.pub
```

## Notes / gotchas

- **Raw binaries, not archives.** pilot/nebula self-update fetch a raw binary and chmod it — no untar
  on the host. publish.sh re-hosts the extracted raw nebula binary precisely because GitHub's nebula
  asset is an archive that wouldn't work directly.
- **In-VPC vs off-cloud gateway URL.** Off-cloud hosts use the public gateway URL; in-VPC hosts resolve
  it to the internal NLB via the Route53 private zone (`dns_private.tf`). The artifact *download* is
  plain HTTPS to S3 and works from anywhere.
- **Versioning.** The version string is the S3 key path + the registry label. Keep nebula's matching
  the real slackhq release tag (publish.sh fetches `v<version>`); pilot's is your own label.
- **Bucket disabled?** If `artifacts_base_url` is empty, `artifacts_bucket_name` isn't set — the
  registries then must point at external raw-binary URLs instead.
