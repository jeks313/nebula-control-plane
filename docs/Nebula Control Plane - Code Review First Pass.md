---
title: "Code Review — First Pass"
created: 2026-06-14
source: claude-code
status: review
tags: [nebula, code-review, golangci-lint, structure, idiomatic-go, concurrency, security]
---

# Nebula Control Plane — Code Review (First Pass)

A first-pass cleanliness review covering (1) **lint** — setting up golangci-lint and clearing
the auto-fixable / safe findings — and (2) a deeper **structural + idiomatic Go** review across
package structure, error handling, concurrency, and API design. Scope: `./cmd/...` + `./internal/...`
(`spike/` excluded). Date: 2026-06-14.

The structural pass ran as a 33-agent workflow (4 review dimensions, each finding adversarially
verified by an independent agent): **29 findings confirmed, 0 rejected.**

---

## 1. golangci-lint

Installed **golangci-lint v2.12.2** and added `.golangci.yml` (standard set + revive, gocritic,
misspell, unconvert, errorlint, bodyclose, copyloopvar, nilerr; `spike/` excluded). Findings went
**92 -> 18**; build, tests, and gofmt are all clean.

**Fixed (committed `b463a9f`):**

- **errorlint** — `errors.Is` for wrapped sentinels (`http.ErrServerClosed`, `rollout.ErrNone`) and
  `%w` (not `%v`) wrapping (dualcontrol, enrollment, gatewayreg). The highest-value lint catch.
- **gofmt** — 3 unformatted files (genesis + two tests).
- **gocritic** — modern `0o` octal literals, `http.NoBody`, `s != ""` over `len(s) > 0`,
  `paramTypeCombine`, `%q` for quoted strings.
- **staticcheck** quickfixes (ST1023, QF1001, QF1008).
- **nilerr** — `//nolint` on the `if ctx.Err() != nil { return nil }` clean-shutdown idiom (false positives).
- Tuned out noise: `hugeParam`, `rangeValCopy`, `builtinShadow`, `unnamedResult`.

**Remaining baseline (18, tracked — task #34/#35):** 3 crypto deprecations (SA1019), 11 `revive: exported`
doc comments (a policy call for internal packages), 3 `exitAfterDefer` in the cmd mains, 1
`sloppyReassign` false-positive on a named return.

---

## 2. Structural & idiomatic review

29 findings, grouped by severity. Each was confirmed against the actual code by an independent verifier.

### High (7)

#### [structure] cmd/harbor/main.go is a 2078-LOC god-file holding 17 subcommand groups, ignoring the package's own one-file-per-command convention

- **Location:** `cmd/harbor/main.go:57-2078`
- **Issue:** main.go dispatches 21 top-level subcommands (main:63-112) and then inlines the full implementation of most of them: migrate/audit/ipam/joinkey/enroll(worker,pending,approve)/collect/lighthouse/gateway/blocklist/rollout/policy(propose,approve,deny,list,active)/fleet/core-api/admin-api/genesis/ca-init/issue-cert. This is the single largest file in the codebase by ~880 LOC. The package ALREADY established a clean split convention — admintoken.go, cloudtrust.go, seeddemo.go, adminauth_wire.go, logging.go each own one command group — so main.go is simply the un-split residue, not a design constraint. Concretely tangled in one file: CA ceremony/issuance wiring (cmdGenesis 1717-1848, cmdCAInit 1867-1945, cmdIssueCert 1947-2043), the long-running services (cmdCoreAPI 1480-1557, cmdAdminAPI 1563-1691, enrollWorker 644-678, cmdCollect 685-772), the fleet-registry CRUD commands (cmdLighthouse 820-880, cmdGateway 886-949), and the dual-control policy/rollout/blocklist ops (cmdBlocklist 957-1098, cmdRollout 1102-1160, cmdPolicy 1181-1403). Beyond size, this couples unrelated review surfaces: a change to issuance flags forces re-reading 2000 lines of unrelated console/service wiring.
- **Fix:** Follow the convention already in the package and split by command group into sibling files in package main: ca.go (cmdCAInit, cmdIssueCert, addBackendFlags/backendFlags.load, writeKeyExcl/writeOut), genesis.go (cmdGenesis), serve.go or coreapi.go/adminapi_cmd.go (cmdCoreAPI, cmdAdminAPI), enroll.go (cmdEnrollCore + enrollWorker/Pending/Approve + cmdCollect + the coreFlags methods build/buildConsumer/loadBackend), registry.go (cmdLighthouse, cmdGateway), policy.go (cmdPolicy + policyPropose/Approve/Deny/List/Active + newPolicyController + activePolicy/activeCloudTrust), rollout.go (cmdRollout, cmdBlocklist, printRolloutStatus), and keep main.go as just main()+usage()+the dispatch switch + the shared tiny helpers (dbFlags/resolveDSN/openStore/fatalf/parseCSV/parsePrefixes/readB64Key). No behavior change, pure file-level cohesion.

#### [duplication] Dual-control commit-validation for policy.publish / cloudtrust.publish is re-implemented at 4 production call sites — a leaky abstraction

- **Location:** `cmd/harbor/main.go:1228-1244; internal/adminapi/adminapi.go:162-174; cmd/harbor/cloudtrust.go:89-92; cmd/harbor/seeddemo.go:182-200`
- **Issue:** The knowledge of WHAT it means to commit a policy or cloud-trust change (re-parse the payload, and for policy also CheckInvariants) is duplicated as inline dc.Register closures in four separate places: harbor's newPolicyController (main.go:1231-1242), adminapi.New (adminapi.go:162-174), publishCloudTrust (cloudtrust.go:89-92), and the demo seeder (seeddemo.go:182-200). The domain packages own the verbs (policy.Parse/CheckInvariants at policy.go:53/121, cloudtrust.Parse at cloudtrust.go:56) but NOT the dual-control committer that ties them to dualcontrol.PublishKind. This is exactly the kind of correctness-sensitive invariant that must not drift: if policy commit-validation gains a step (e.g. a new invariant), three of these four sites can silently keep the old behaviour and commit a change the others would reject. The committer is the security gate for 'two admins published a config that fails validation' — it should be defined once next to the domain.
- **Fix:** Have each domain package export its own committer + a one-call registrar, e.g. policy.RegisterCommitter(dc) and cloudtrust.RegisterCommitter(dc) (or func PublishCommitter() dualcontrol.Committer). Then every wiring site calls dc.Register(policy.PublishKind, policy.PublishCommitter()) — or a single helper dualcontrol-wiring func that registers both. This collapses 4 copies to 1 authoritative definition co-located with Parse/CheckInvariants, so the validation can never diverge by call site.

#### [error-handling] Enrollment record() silently ignores its Create error, defeating idempotency and orphaning issued certs

- **Location:** `internal/enrollment/enrollment.go:636-660 (record), called from Process:263/279, processAttested:340/355`
- **Issue:** record() ends with `_ = c.cfg.Store.DB.WithContext(ctx).Create(&e).Error` — the write of the authoritative `enrollments` row is fire-and-forget. In the auto-issue and attested-auto-issue paths the ordering is issue() (allocates IP + signs a real cert) -> buildBundle -> record (ignored) -> writeResult (delivers the bundle). If Create fails transiently, the host still receives a signed cert via writeResult, but Core holds no enrollments row. Consequences are concrete: (1) idempotency is broken — Process() guards re-issue via existing(), which queries the enrollments table by enrollment_id (line 491-497); with no row, a normal queue Nack/redelivery of the same leased candidate re-enters Process, allocates a SECOND overlay IP and signs a SECOND cert; (2) the host is invisible to coreapi.device() (renew/heartbeat lookup is by overlay_ip + status=issued), so it can never renew and cannot be blocklisted by device/overlay IP — a real gap for a CA/enrollment control plane. The pending path has the same flaw (a dropped pending row means the host polls forever and an operator never sees it in the approval queue).
- **Fix:** Make record() return error and have Process/processAttested treat a failed Create as a transient (non-terminal) failure: do NOT call writeResult and return a non-terminal error so the queue nacks for redelivery (existing() will then short-circuit once the row lands). For the issue paths, the IP+cert were already minted, so on a failed record either release the IP before returning the retryable error, or rely on the existing-row idempotency once the retry succeeds — but never deliver a bundle for an unrecorded issuance.

#### [error-handling] coreapi renew swallows the fingerprint-update error, leaving stale fingerprints that defeat blocklist-by-device

- **Location:** `internal/coreapi/coreapi.go:352-353`
- **Issue:** After re-signing on renew, the handler does `_ = s.cfg.Store.DB...Update("fingerprint", fp).Error`. The fingerprint rotates with the key on every renewal and is documented (enrollment.go:69-72) as the blocklist key resolved from -device/overlay IP. If this UPDATE fails, the renew still succeeds and the host gets its new cert, but the stored fingerprint is now stale. A later `harbor blocklist add -device <ip>` resolves the OLD fingerprint (main.go cmdBlocklist resolve()), so the operator believes a host is blocked while its current cert is not — a silent security-control failure in a security-sensitive path. The audit append on the next line is also ignored, so there is no trace.
- **Fix:** Check the Update error; on failure return wire.CodeInternal ("renew bookkeeping failed") rather than delivering a renewed bundle whose fingerprint Core didn't record, or at minimum log + audit the failure loudly so the stale-fingerprint condition is observable. Treat the fingerprint write as part of the renewal's success criteria.

#### [concurrency] Pilot shutdown does not wait for in-flight renew/drift writes (torn-write on stop)

- **Location:** `cmd/pilot/main.go:329-357`
- **Issue:** The three background loops are launched fire-and-forget: `go func(){ _ = mgr.Run(ctx) }()` (renew, 329), `go func(){ _ = hb.Run(ctx) }()` (heartbeat, 350), `go func(){ _ = dm.Run(ctx) }()` (drift, 354). `serve` then blocks only on `sup.Run(ctx)` (357). When ctx is cancelled (SIGTERM/SCM stop), `sup.Run` returns, `serve` returns, `runSupervisor` returns, and `cmdSupervise` returns -> process exits. Nothing waits for the loops. A renewal can be mid-`RenewNow` -> `enrollclient.Renew`, which writes HostKey (atomic) then CABundle/HostCert/Bundle/Config via plain non-atomic os.WriteFile (enrollclient.go:399-415); drift can be mid-`Sync` os.WriteFile of Config (drift.go:94). Killing the process between those writes leaves a host with a rotated key but a stale/partial cert or config — a security-sensitive identity desync that needs an operator to recover. The loops correctly honor ctx for their *sleep* phase but their *work* phase is not drained on shutdown.
- **Fix:** Run the three loops under a sync.WaitGroup (or golang.org/x/sync/errgroup tied to ctx). After `sup.Run(ctx)` returns, `wg.Wait()` (with its own bounded timeout) before `serve` returns, so an in-flight renewal/drift revert completes its file writes before exit. Alternatively gate the file-mutating sections so they run to completion once started.

#### [concurrency] renew and drift write the same identity/config files concurrently with no mutex

- **Location:** `internal/renew/renew.go:147-159 + internal/drift/drift.go:64-103`
- **Issue:** renew.RenewNow (via enrollclient.writeArtifacts, enrollclient.go:399-415) and drift.Sync (drift.go:64-104) run in two independent goroutines (cmd/pilot/main.go:329 and :354) over the SAME paths.Layout. renew writes HostKey -> HostPub -> CABundle -> HostCert -> Bundle -> Config; drift reads Bundle+CABundle+HostCert+HostKey, re-renders, then writes Config. None of this is serialized. An overlapping renewal+drift-sync can interleave: drift renders config against a cert/CA that renew is mid-swap on, or both write Config near-simultaneously, or drift reverts a Config that renew just rewrote. The result is a config.yml that disagrees with the on-disk cert/key, then a Reload() onto an inconsistent set.
- **Fix:** Introduce a single mutex (or a serialized 'apply' goroutine consuming a command channel) that guards every operation touching the host layout — renew, drift revert, and apply_bundle/FetchConfig (cmd/pilot/main.go:340-347) all mutate the same files and must not interleave. Hold it for the whole write sequence, and make multi-file updates atomic (write to temp + rename) so a reader never sees a half-applied set.

#### [concurrency] Data race in Supervisor.defaults(): Run and Restart mutate unsynchronized fields concurrently

- **Location:** `internal/supervisor/supervisor.go:56-73 (called from :79 Run and :189 Restart)`
- **Issue:** defaults() lazily initializes MinBackoff/MaxBackoff/StableAfter/GracePeriod/Logger with plain field writes, then `s.initOnce.Do(...)` for restartCh. Only the restartCh creation is Once-guarded; the scalar/Logger writes are not. defaults() is called from Run() (the serve goroutine, :79) AND from Restart() (:189). In cmd/pilot/main.go the supervisor's Restart is wired as a heartbeat command handler (:339) running on the heartbeat goroutine (:350), while sup.Run(ctx) runs on the serve goroutine (:357). A Core-issued `restart` command that lands while Run is still in defaults() is a concurrent read/write of those fields -> a genuine data race (would be flagged by `go test -race`), and Restart even risks operating on a not-yet-defaulted GracePeriod.
- **Fix:** Move all default-filling into New()/a constructor run once before any goroutine starts, or guard the scalar writes under s.mu (Restart already has no need to call defaults() beyond ensuring restartCh — make restartCh creation the only thing Restart triggers, via a dedicated sync.Once, and never let it touch the tuning/Logger fields).

### Medium (11)

#### [structure] internal/adminapi/adminapi.go (1198 LOC) bundles four distinct concerns despite a partial split already existing in the package

- **Location:** `internal/adminapi/adminapi.go:40-1199`
- **Issue:** The package was clearly mid-refactor: enroll_ops.go, mutate_ops.go, device_provenance.go, rbac.go, and openapi.go already peel off cohesive slices. But adminapi.go still mixes (1) server scaffolding + auth: Identity/IdentityProvider/ChainProvider/DevHeaderProvider/Config/Server/New/authMiddleware (40-297); (2) read-only fleet handlers: handleMe/handleFleetHealth/handleDevices/handleAudit/handleAuditVerify/handleLighthouses + their view structs (299-638); (3) the entire dual-control + policy + cloudtrust handler family: handleApprovals/Approval/Approve/Deny, handlePolicyActive/Propose/Compile/Reachability/Matrix/Tests/Diff, handleCloudTrustActive/Propose, mapDCErr (640-1132); and (4) generic HTTP plumbing: pathID/readJSON/writeJSON/writeProblem/rfc3339/queryInt (1134-1199). Concern (3) alone is ~490 LOC and is the natural peer of the existing mutate_ops.go. Concern (4) is reusable boilerplate that has nothing API-specific in it.
- **Fix:** Extract two files in-package: policy_ops.go for the dual-control/policy/cloudtrust handler family + changeView/Change/Signoff/CompileResult/nebulaRule/toRules/mapDCErr (matching the enroll_ops.go / mutate_ops.go naming), and httpx.go (or response.go) for pathID/readJSON/writeJSON/writeProblem/rfc3339/queryInt. That leaves adminapi.go as server core (Config/Server/New/routeTable/Handler/authMiddleware) + the read-only fleet handlers — a coherent ~400 LOC entry file. This is mechanical (same package, no import changes) and finishes the split the package already started.

#### [structure] coreFlags is a god-struct that fuses CA-backend, queue, IPAM, lighthouse, policy, blocklist and cloud-trust wiring into one flag bag

- **Location:** `cmd/harbor/main.go:434-480`
- **Issue:** coreFlags carries ~25 pointer fields spanning at least six unrelated subsystems: DB driver/dsn, CA + config-signing backend selection (software/pkcs11 paths and labels), the durable queue (queueDSN/queueKey), nonce HMAC key, IPAM pool, nebula bundle stamping (tunDev/listenPort/certLifetime), the signing circuit-breaker, lighthouse static-vs-DB source, blocklist-DB source, central policy file-vs-DB source, and cloud-trust-DB source. It is shared verbatim by enroll worker, enroll approve, collect, core-api, and admin-api (addCoreFlags called at 646,687,802,1482,1565) even though several of those modes use only a subset — e.g. cmdAdminAPI in read-only mode ignores all the CA/queue fields, and cmdCollect ignores the queue. The methods hanging off it (buildConsumer 543-586, build 588-599, loadBackend 601-626, policy/cloudTrust/lighthouseSource/blocklistSource) make it the de-facto wiring kernel of the whole control plane living in package main.
- **Fix:** Move the consumer/signer assembly out of cmd into internal: introduce something like internal/coreboot (or extend the existing coreapi/enrollment packages) exposing a typed Config + a Build(Config) (*enrollment.Consumer, ...) so the wiring is testable without flag parsing or os.Exit, mirroring how cloudtrust.go:85 already factored publishCloudTrust into a testable core 'free of flag-parsing / os.Exit'. At minimum, group the flag struct into sub-structs (backendFlags already exists at 326; add queueFlags, bundleFlags, sourceFlags) so each command composes only the sub-bags it needs and the 'unused in this mode' fields stop being implicit.

#### [duplication] Resolving the active committed policy/cloud-trust into a typed config is reimplemented in cmd and adminapi

- **Location:** `cmd/harbor/main.go:1248-1280; internal/adminapi/adminapi.go:754-846,1069-1078`
- **Issue:** The pattern 'dc.LatestCommitted(kind) -> if ok, Parse the payload into the typed config, treating a parse failure of our own committed state as an error' is written out at least four times: activeCloudTrust (main.go:1248-1262), activePolicy (main.go:1266-1280), handlePolicyActive (adminapi.go:754-777), handleCloudTrustActive (adminapi.go:823-846), and again inline in handlePolicyDiff (adminapi.go:1069-1078). Each re-derives 'the active policy is the latest committed change of policy.PublishKind' independently. This is the authoritative definition of 'what is the fleet's current policy' and it is scattered across the cmd and adminapi layers, so the cmd's `policy active`/-policy-db view and the console's /policy/active view can diverge in edge handling (e.g. how an unparseable committed payload is treated).
- **Fix:** Give the domain packages an accessor for their own active state, e.g. policy.Active(ctx, dc) (Policy, bool, error) and cloudtrust.Active(ctx, dc) (Config, bool, error), each encapsulating LatestCommitted+Parse. cmd's activePolicy/activeCloudTrust and adminapi's handlePolicyActive/handleCloudTrustActive/handlePolicyDiff then call the single accessor and only format the result. Removes the cmd/adminapi split-brain and keeps 'what is active' next to Parse.

#### [naming] signer.Policy and policy.Policy are two unrelated concepts sharing the name 'Policy'

- **Location:** `internal/signer/signer.go:45 and internal/policy/policy.go:39`
- **Issue:** signer.Policy is a cert-issuance validation envelope (AllowedNetwork / AllowedGroups / MaxLifetime); policy.Policy is the mesh firewall ruleset. They are genuinely different domain objects but both read as 'the policy'. They appear side by side in the same functions — genesis.go:158 constructs signer.Policy{...} while the surrounding code threads policy.Policy, and harbor main.go:560 does the same next to coreFlags.policy() which returns *policy.Policy. A reader must constantly disambiguate by package prefix, and a future move/embed could silently cross them.
- **Fix:** Rename signer.Policy to signer.IssuePolicy (or signer.Constraints / signer.Limits). It is referenced in only ~3 places (signer.Config field, genesis.go:158, harbor main.go:560), so the rename is cheap and removes the clash permanently.

#### [api-design] Bundle-assembly config duplicated verbatim across coreapi.Config and enrollment.Config, kept in sync only by a comment

- **Location:** `internal/coreapi/coreapi.go:54 (esp. comment at :79) and internal/enrollment/enrollment.go:104`
- **Issue:** Ten fields — ConfigBackend, ConfigKeyID, CABundlePEM, Lighthouses, LighthouseSource, BlocklistSource, Policy, TunDev, ListenPort, CertLifetime — are declared identically in both Config structs, with matching doc comments. The only safeguard against divergence is the prose at coreapi.go:79 ('TunDev + ListenPort ... MUST match enrollment.Config's, or a renew/refresh would flip a device's tun/port'). Both feed the same bundle.Build path, so a field added/changed in one and not the other produces enroll-vs-renew bundles that disagree on tun device or listen port for the same host — a correctness hazard the type system currently can't catch.
- **Fix:** Extract the shared set into one type (e.g. bundle.Settings or a coreapi/enrollment-shared BundleConfig) and embed it in both Config structs. The 'must match' invariant then becomes structural (one definition) instead of a comment, and the bundle builder can take that single type directly.

#### [api-design] Three different data-access conventions for the same store

- **Location:** `internal/joinkey/joinkey.go:71 (free funcs over *store.Store); internal/rollout/rollout.go:134 & lighthouse/revocation/gatewayreg New(db *gorm.DB,...); internal/ipam/ipam.go:75 NewAllocator(*store.Store) that only uses s.DB`
- **Issue:** Persistence is accessed three inconsistent ways: (1) joinkey and genesis use package-level free functions that each take *store.Store as the first arg (Create/List/Revoke/Update); (2) rollout, lighthouse, revocation, gatewayreg take a raw *gorm.DB plus an audit func into a stateful Engine/Registry; (3) ipam.NewAllocator takes *store.Store but then immediately discards everything except s.DB (line 87). adminapi.New even reaches through store.Store.DB to construct rollout/lighthouse engines. The result is no single rule for how a feature talks to the DB, and Store is simultaneously 'the data layer' and a hollow holder of an exported *gorm.DB.
- **Fix:** Pick one seam. Either (a) let everything depend on *store.Store and add the few needed methods, or (b) standardize the Engine/Registry packages on accepting *gorm.DB and make ipam do the same instead of taking the whole Store just to grab .DB. At minimum, change NewAllocator(s *store.Store, ...) to NewAllocator(db *gorm.DB, ...) so it stops depending on a type it doesn't use.

#### [api-design] store.Store.DB is an exported *gorm.DB; the abstraction is bypassed everywhere

- **Location:** `internal/store/store.go:37-41 (DB field); dualcontrol.go:123 Controller.DB() re-exposes it`
- **Issue:** Store documents itself as 'Harbor's data layer', but the only real method-bearing behavior it adds is the serialized audit chain (AppendAudit/VerifyAudit). Every other package reaches straight into the exported *gorm.DB — enrollment.go:659 `c.cfg.Store.DB.WithContext(ctx).Create(&e)`, plus 70+ direct .DB accesses across ~20 packages. dualcontrol additionally re-exports the handle via Controller.DB(). Leaking the ORM handle means the 'data layer' boundary provides no encapsulation: query construction, table names, and transaction policy are scattered, and a future store swap (or even GORM upgrade) touches every package. This is the leaky-abstraction / too-wide-surface anti-pattern, and it matters more here because audit-chain integrity is a security property that callers can trivially route around by using .DB directly.
- **Fix:** Either own it honestly — make .DB unexported and add the handful of typed accessors callers need (or expose a constrained query seam) — or drop the pretense and have packages depend on *gorm.DB directly, keeping Store only for the audit chain. Don't keep both an exported DB and a 'data layer' framing. Remove dualcontrol.Controller.DB() in favor of passing the dependency it actually needs.

#### [error-handling] adminauth.New panics on crypto/rand failure while its sibling constructors return errors

- **Location:** `internal/adminauth/auth.go:102-118 (panic at :117)`
- **Issue:** adminauth.New(cfg Config) *Service calls newCookieSigner() and panic()s if crypto/rand fails, because its signature has no error return. Every neighboring constructor in the same package DOES return an error and threads it (NewOIDC, NewSAML, mockidp.New, samlmock.New). A library constructor that panics is an API-safety smell — it forces the caller (cmd/harbor) to either accept a process crash or wrap in recover, and it's inconsistent with the rest of adminauth. The comment ('crypto/rand failure at startup is unrecoverable') argues intent, but the decision to abort belongs to the caller (main), not the library.
- **Fix:** Change to func New(cfg Config) (*Service, error) and return the newCookieSigner error; let cmd/harbor decide to os.Exit. This also makes adminauth.New match the other New* in the package.

#### [concurrency] Collector builds a fresh http.Transport on every CollectOnce, churning connections in a long-running daemon

- **Location:** `internal/collect/collector.go:102-108 (httpClient closure), invoked at 116 from CollectOnce, looped in Run:158-181`
- **Issue:** New() sets c.httpClient to a closure that allocates a brand-new &http.Client{Transport: &http.Transport{...}} on each call, and CollectOnce calls it once per invocation. `harbor collect` (cmd/harbor/main.go:770 coll.Run) runs this indefinitely: the inner drain loop (Run:164-173) calls CollectOnce repeatedly per gateway, and the outer loop repeats every interval (default 5s) across every registered gateway. Each call gets a fresh transport with its own connection pool — so the claim/results/ack triple within one call reuses a connection, but every subsequent call to the same gateway opens a fresh TLS connection instead of reusing the idle pool, and the abandoned transports' idle connections/goroutines linger until their idle timeout + GC. Over a long-lived collector polling N gateways this is needless TLS-handshake churn and transient connection/goroutine accumulation.
- **Fix:** Build one http.Client per Gateway once and cache it (keyed by gateway name/pin), or construct the clients when the gateway set is resolved and reuse across cycles. The TLSClientConfig only depends on the (static) client cert and the gateway's pin, so a per-gateway client is safe to keep for the collector's lifetime.

#### [concurrency] Gateway enroll-server and collect-server shutdowns are not joined; process can exit mid-drain

- **Location:** `cmd/gateway/main.go:113-131 + :168-180`
- **Issue:** main() starts the public enroll server and, when -collect-addr is set, the Harbor-facing collect server (startCollect, :158-179). Each has its OWN `go func(){ <-ctx.Done(); srv.Shutdown(5s) }()` (lines 115 and 168). main blocks only on the enroll server's httpserve.Serve (:128). On SIGTERM both Shutdown goroutines fire concurrently, but as soon as the enroll server drains, main returns and the process exits — it never waits for the collect server's Shutdown to finish, so an in-flight Harbor claim/ack/put-result over mTLS can be cut off (and at-least-once redelivery then has to re-ship). The collect server's ListenAndServeTLS error/return is also only logged, never used to gate exit.
- **Fix:** Join both servers' lifecycles: run each under a shared WaitGroup or errgroup and Wait() before main returns, or have startCollect return its srv so main can Shutdown both and wait for both to report ErrServerClosed before exiting.

#### [concurrency] GetResult one-time-bundle read is a cross-process TOCTOU

- **Location:** `internal/queue/durable.go:285-291`
- **Issue:** For an issued result, GetResult reads r.ReadCount (loaded by the First() at :271), checks `if r.ReadCount > 0 { return ErrResultGone }`, then issues a SEPARATE `UpdateColumn(read_count = read_count + 1)`. The check and the increment are not atomic. Within one process SetMaxOpenConns(1) (OpenDurable:105) serializes SQLite access, but the design explicitly shares one queue file across SEPARATE processes (gateway + `enroll worker` + collector, comment at :106-111). Two concurrent polls from different processes can both pass the `ReadCount==0` guard before either increments, so the supposedly one-time issued bundle is released twice. The bundle is verified/pinned client-side so this is not a forgery, but it defeats the intended single-consume retrieval-secret semantics.
- **Fix:** Make the consume atomic and conditional: `UPDATE queue_results SET read_count = read_count + 1 WHERE id = ? AND status='issued' AND read_count = 0` and treat RowsAffected==0 as ErrResultGone, returning the bundle only when the guarded update wins. That closes the window regardless of process count.

### Low (11)

#### [naming] main.go re-exports policy.PublishKind as a local KindPolicyPublish const, obscuring the canonical source

- **Location:** `cmd/harbor/main.go:1220-1223`
- **Issue:** const KindPolicyPublish = policy.PublishKind creates a second name for the same change-kind string used five times within main.go (1231,1268,1305,1394). Meanwhile the cloud-trust equivalent is referenced directly as cloudtrust.PublishKind in the very same file (1239,1250). The asymmetry (alias one, use the other directly) makes the policy kind look like it has a harbor-local identity when it is the shared domain constant, and a reader grepping for policy.PublishKind in cmd will miss four of the usages.
- **Fix:** Delete the KindPolicyPublish alias and use policy.PublishKind directly at the five sites, matching how cloudtrust.PublishKind is already used in the same file. One canonical name for the protocol constant.

#### [naming] policy.PolicyGroups stutters

- **Location:** `internal/policy/analysis.go:109`
- **Issue:** Exported func is called as policy.PolicyGroups — textbook package-name stutter. Sibling exported analysis funcs in the same file (Reachable, Matrix, FlowDiff, BlastRadius, RunTests) are all clean single words, so this one stands out as inconsistent rather than just verbose.
- **Fix:** Rename to policy.Groups (call site is policy.Groups(p)). Only one caller (Matrix, same package) plus tests, so the rename is mechanical.

#### [duplication] AuditFunc redeclared identically in 5 packages and inlined in 3 more

- **Location:** `internal/{dualcontrol,revocation,gatewayreg,rollout,lighthouse}/*.go (e.g. rollout.go:124) plus signer.go:73/86, store-adapter in cmd/harbor/main.go:1992`
- **Issue:** `type AuditFunc func(ctx context.Context, actor, action, target, details string) error` is defined verbatim in dualcontrol, revocation, gatewayreg, rollout, and lighthouse, and the same signature is inlined as an anonymous func field in signer.Config (Audit), the adminapi audit adapter, and cmd/harbor/main.go. They all ultimately wrap store.AppendAudit. The repetition means the canonical audit-callback shape lives in 8 places; widening it (e.g. adding a return of the written row, or a typed action) is an 8-site edit.
- **Fix:** Declare the type once next to its source of truth — e.g. store.AuditFunc (store already owns AppendAudit) or a tiny internal/audit package — and have the consumers reference store.AuditFunc. signer.Config.Audit can adopt the same named type.

#### [api-design] enrollment.Terminal is a thin exported wrapper over unexported terminal()

- **Location:** `internal/enrollment/enrollment.go:187 (Terminal) and :191 (terminal)`
- **Issue:** func Terminal(err error) bool { return terminal(err) } exists solely so collect.Collector (collector.go:133) can ask 'is this error a terminal/business outcome vs a transient infra failure'. The package keeps both an exported Terminal and an identical unexported terminal used internally (Drain at :175). The duplicate is harmless but pointless; one function can serve both, and the public name 'Terminal' is ambiguous out of context (terminal what?).
- **Fix:** Delete the unexported terminal and make the single function exported (use Terminal internally too), or rename to something self-describing like IsTerminal / IsBusinessOutcome. One function, exported, used by both the internal Drain and the external collector.

#### [api-design] Adjacent same-type parameters create silent transposition hazards

- **Location:** `internal/enrollment/enrollment.go:636 (record: ...groups, status string, ... ip, fingerprint string...) and internal/genesis/genesis.go:89 (Run: caBackend, configBackend signer.Backend)`
- **Issue:** Several functions take runs of identically-typed positional params the compiler cannot distinguish: record() has `groups, status string` and later `ip, fingerprint string` (transposing either pair compiles fine and writes the wrong column); genesis.Run takes `caBackend, configBackend signer.Backend` adjacent — swapping them would sign certs with the config key and vice-versa, a serious-but-silent security mistake. These are foot-guns in code where the values are security-relevant.
- **Fix:** For record(), fold the swappable strings into a small struct (it already takes an `ev evidence` struct — extend that pattern). For genesis.Run, move caBackend/configBackend into the existing Params struct (named fields) so transposition is impossible, or wrap them in distinct types (CABackend/ConfigBackend).

#### [idiom] Inconsistent constructor naming: New(cfg Config) vs New<Type>(positional)

- **Location:** `internal/{rollout,lighthouse,revocation,gatewayreg}.New(db, audit); internal/ipam.NewAllocator; internal/nonce.NewKeyring; vs the New(cfg Config) majority (signer, gateway, enrollment, coreapi, adminapi, adminauth, heartbeat, drift, renew, collect)`
- **Issue:** The codebase has a strong, good convention — New(cfg Config) *T with defaulting — used by ~10 packages. A handful break it two ways: (a) positional New(db *gorm.DB, audit AuditFunc) (rollout/lighthouse/revocation/gatewayreg), which both bypasses the Config pattern and inlines the duplicated AuditFunc; (b) New<TypeName> forms (NewAllocator, NewKeyring, NewMemory, NewSoftwareBackend, NewCaptureSink, NewServer) in packages that have a single obvious primary type and could just expose New. The mix means a caller can't predict the constructor shape per package.
- **Fix:** Where a package has one principal type, prefer plain New (e.g. ipam.New, nonce.New). For the rollout/lighthouse/revocation/gatewayreg group, move db+audit into a Config so they match the dominant New(cfg Config) convention and pick up the shared AuditFunc type. Leave genuinely multi-backend factories (NewSoftwareBackend/NewPKCS11Backend) as-is.

#### [error-handling] gateway daemon never closes its durable queue (SQLite) on shutdown

- **Location:** `cmd/gateway/main.go:86-132 (openQueue result q is never Closed)`
- **Issue:** main() opens the durable queue via openQueue (line 86) — a real SQLite handle (queue.Durable has Close() that closes the *sql.DB pool) — but never defers or calls q.Close(), even on the clean SIGINT/SIGTERM shutdown path (the signal goroutine only Shutdowns the HTTP servers). Every harbor subcommand that opens the queue defers q.Close() (e.g. main.go:656, 810, 1593), so the gateway is the odd one out. No data is lost (the queue commits per statement), but the connection pool / WAL is never cleanly released on shutdown — a resource-hygiene gap inconsistent with the rest of the codebase, and it matters more once the queue backend is swapped for something with real teardown semantics.
- **Fix:** After openQueue succeeds, `defer closeQueue(q)` where closeQueue type-asserts to io.Closer (the in-memory queue has nothing to close) and closes it, mirroring the harbor commands.

#### [api-design] PKCS#11 backend (HSM session) opened for the daemon lifetime is never Closed

- **Location:** `internal/signer/signer.go:23-30 (Backend interface has no Close); internal/signer/pkcs11.go:72 (only concrete pkcs11Backend has Close); built in cmd/harbor/main.go:601-626 loadBackend, used by core-api (1518-1519), enroll worker (build:592-598), admin-api`
- **Issue:** The signer.Backend interface intentionally has no Close(), but the PKCS#11 implementation holds a live crypto11.Context (an HSM/SoftHSM session) and exposes Close(). In the long-running daemons (core-api, enroll worker, admin-api issuance mode) the CA + config-signing backends are created once at startup via loadBackend and the concrete *pkcs11Backend is immediately widened to the Backend interface, so nothing ever calls Close() — the HSM session is leaked for the process lifetime and not released on clean shutdown. It is one session per process (not per request), so this is hygiene rather than a growing leak, but on a real HSM an un-released session can hold a finite slot.
- **Fix:** Either add an optional Close() to the Backend contract (or type-assert to io.Closer at the cmd layer) and defer-close the CA/config backends in core-api / enroll worker / admin-api, so a SIGTERM cleanly tears down the HSM session.

#### [error-handling] gateway enroll collapses all queue.Publish errors to a generic 500, masking backpressure

- **Location:** `internal/gateway/gateway.go:207-210`
- **Issue:** On publish, every error becomes wire.CodeInternal "enrollment queue unavailable". queue.Publish has distinct sentinels: ErrBackpressure (queue at capacity — a load condition the client should back off from, normally a 503/429) and ErrDuplicate (idempotent no-op). Mapping ErrBackpressure to a 500 misrepresents an expected load condition as a server fault and gives clients no signal to retry-with-backoff; the gateway already has a rate-limit code (CodeRateLimited) for exactly this shape.
- **Fix:** Branch on the sentinel: errors.Is(err, queue.ErrBackpressure) -> CodeRateLimited / 503; treat ErrDuplicate as success (the candidate is already queued); only genuinely unexpected errors -> CodeInternal.

#### [error-handling] Hash-chained audit appends are fail-open across security-relevant events

- **Location:** `internal/enrollment/enrollment.go:265,342,357,461 (and broadly via the audit(...) helper / AppendAudit callers in adminapi/mutate_ops.go:224,329,373,394, coreapi.go:354)`
- **Issue:** Audit writes are consistently fire-and-forget (`_ = c.audit(...)`, `_, _ = s.cfg.Store.AppendAudit(...)`). AppendAudit is correctly serialized and chains off the last *persisted* row, so a dropped append does not corrupt the chain (verified in store/audit.go) — but it does mean security-relevant events (enroll-denied, enroll-approved, enroll-quota-exceeded, joinkey-revoke, cert-renewed) can silently fail to be recorded, weakening the tamper-evident log's completeness guarantee. This is a deliberate availability-over-completeness tradeoff, but it is applied uniformly with no logging when an append is dropped, so a persistent audit-write failure would be invisible.
- **Fix:** Keep audit non-fatal for the request, but log at WARN when AppendAudit returns an error (today the error is discarded entirely) so a chronic audit-write failure is observable; consider distinguishing the few events where a missing audit entry is itself a compliance problem.

#### [error-handling] IMDS token request error is discarded, risking a nil-pointer panic in the credential-fetch goroutine

- **Location:** `internal/awsattest/awsattest.go:198-199`
- **Issue:** `tokReq, _ := http.NewRequestWithContext(ctx, "PUT", base+"/latest/api/token", http.NoBody)` discards the construction error, then immediately dereferences `tokReq.Header.Set(...)`. The same pattern recurs at :209 (`r, _ := http.NewRequestWithContext(...)`). NewRequestWithContext returns (nil, err) on a malformed URL or nil ctx; with a bad -region/BaseURL override this panics inside FetchInstanceCredentials, which runs on the enroll path (enrollclient.enrollCredential, enrollclient.go:54). A panic here is uncaught and crashes the agent rather than failing the enrollment cleanly.
- **Fix:** Check and return the error from both NewRequestWithContext calls (e.g. `if err != nil { return Credentials{}, "", fmt.Errorf("awsattest: imds token request: %w", err) }`) instead of discarding it with `_`.

---

## 3. Follow-up tasks

| Task | Scope |
|------|-------|
| **#31** | Pilot runtime concurrency hardening — `Supervisor.defaults()` race, renew/drift file-write race, shutdown not joining in-flight writes |
| **#32** | Fix the two swallowed-error data-loss bugs (`enrollment.record()` Create, coreapi renew fingerprint Update) |
| **#33** | Split `cmd/harbor/main.go` (2078 LOC) per the package convention + dedup the dual-control committer into the domain packages |
| **#34** | Migrate off deprecated crypto APIs (SA1019) to `crypto/ecdh` |
| **#35** | golangci-lint baseline backlog + idiom/hygiene cleanup (naming clashes, constructor consistency, AuditFunc dedup, resource Close on shutdown, TOCTOU) |

Recommended order: **#31 + #32 first** (genuine bugs — concurrency races + dropped data in
security-sensitive paths); the rest are cleanliness/refactors that can follow.

*Provenance: golangci-lint v2.12.2; structural review workflow run `wf_0abe32de-06c`.*
