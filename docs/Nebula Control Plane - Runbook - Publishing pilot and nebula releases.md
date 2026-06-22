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

## Versioning & the one-command release (`release-pilot.sh`)

The repo-root **`VERSION`** file is the single source of truth (currently `0.1.0`). Every build —
the genesis bootstrap, `publish.sh`, and the Fargate gateway image — stamps `main.version` from it
via `-ldflags`, so `pilot version` (and harbor/gateway) report the real version, **not `dev`**.

**Cut a pilot release in one command** (laptop, AWS creds set) — it builds + publishes the
version-stamped binary for every fleet arch and prints the register/release lines:

```bash
deploy/prod/artifacts/release-pilot.sh            # version from VERSION
# or pin explicitly:
deploy/prod/artifacts/release-pilot.sh 0.1.0
```

To **bump**: edit `VERSION` (e.g. `0.1.0` → `0.1.1`), `git commit` + `git tag v0.1.1`, then run
`release-pilot.sh`. The arch list is at the top of the script: the SAFE lanes (`linux/amd64` +
`darwin/arm64`, plain cgo-free builds) publish fatally, then `windows/amd64` publishes LAST and
NON-FATALLY — it is built **embedded** (`-tags embed_nebula`, so the `pilot.exe` carries nebula +
the Wintun driver and self-stages the data plane on first `supervise`), which needs `make` + `curl`
+ `unzip` + network on the publishing host; a Windows hiccup warns + exits non-zero but never strands
the safe lanes or the synced `install.sh`. Extend the lists as the fleet grows. nebula is slackhq's
prebuilt binary, published separately (`publish.sh nebula <slackhq-version>`) on its own cadence —
the Windows nebula ships as a `.zip` (nebula.exe + Wintun), and `publish.sh nebula` (GOOS=windows)
also uploads the `wintun/<ver>/wintun-windows-<arch>.dll` companion artifact.

Steps 1–3 below are the underlying manual flow; `release-pilot.sh` automates step 1 across arches.

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
-db-secret-arn "arn:aws:secretsmanager:ca-central-1:123456789012:secret:rds!cluster-11111111-1111-1111-1111-111111111111-ed3Wrl" \
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

An off-cloud host has no AWS creds and no pre-installed binaries. The **`install.sh`** at the bucket
root does the whole download in one line — it detects the host's OS/arch, fetches the matching pilot
+ nebula + the config-signing pin, **sha256-verifies each against its `.sha256` sidecar (fail closed)**,
installs to `/usr/local/bin`, and prints the enroll steps:

```bash
curl -fsSL https://ncp-artifacts-123456789012.s3.ca-central-1.amazonaws.com/install.sh | bash
```

`release-pilot.sh` re-uploads `install.sh` on every release (defaulting it to the latest pilot
version); override per-run with `NCP_PILOT_VERSION` / `NCP_NEBULA_VERSION` / `NCP_INSTALL_DIR`, etc.
Source: `deploy/prod/artifacts/install.sh`. As with any `curl | bash`, read it first — the bucket is
public-read + write-protected and every binary is sha-verified, but trust is yours to confirm.

Then enroll (off-cloud = join key + manual approval), exactly as `install.sh` prints:

```bash
# 1) on harbor, mint a join key (with the DB flags): harbor joinkey create -name <node> -groups laptops <DB FLAGS>
# 2) enroll:
sudo pilot enroll -dir ~/.nebula -gateway https://poc-gateway.mesh.failsafe.net:8443 \
  -join-key <njk_...> -config-pub ~/.nebula/config-signing.pub -name <node>
# 3) approve (console, or `harbor enroll approve <id>` with DB flags), re-run the enroll, then:
sudo pilot supervise -dir ~/.nebula -config ~/.nebula/config.yml \
  -core https://poc-harbor.mesh.failsafe.net:8444 -config-pub ~/.nebula/config-signing.pub
```

After it joins, governed self-updates (Step 3) apply normally.

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
