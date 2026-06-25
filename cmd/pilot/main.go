// Command pilot is the Nebula Control Plane host agent. It supervises a local
// nebula process and (in later milestones) handles enrollment, renewal, config
// rendering, and drift control. See docs/ and CLAUDE.md.
package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/binverify"
	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/clilog"
	"github.com/jeks313/nebula-control-plane/internal/clock"
	"github.com/jeks313/nebula-control-plane/internal/drift"
	"github.com/jeks313/nebula-control-plane/internal/enrollclient"
	"github.com/jeks313/nebula-control-plane/internal/heartbeat"
	"github.com/jeks313/nebula-control-plane/internal/nebulaboot"
	"github.com/jeks313/nebula-control-plane/internal/nebulaupdate"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/pilotservice"
	"github.com/jeks313/nebula-control-plane/internal/pilotsetup"
	"github.com/jeks313/nebula-control-plane/internal/pilotupdate"
	"github.com/jeks313/nebula-control-plane/internal/renew"
	"github.com/jeks313/nebula-control-plane/internal/supervisor"
	"github.com/slackhq/nebula/cert"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Baseline structured logger (env-tunable); `supervise` refines it via flags.
	clilog.Setup(clilog.Options{Format: os.Getenv("PILOT_LOG_FORMAT"), Level: os.Getenv("PILOT_LOG_LEVEL")})
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "install":
		cmdInstall(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "info":
		cmdInfo(os.Args[2:])
	case "uninstall":
		cmdUninstall(os.Args[2:])
	case "init":
		cmdInit(os.Args[2:])
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "renew":
		cmdRenew(os.Args[2:])
	case "clock-check":
		cmdClockCheck(os.Args[2:])
	case "supervise":
		cmdSupervise(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("pilot %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "pilot: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `pilot — Nebula Control Plane host agent

usage:
  pilot install -gateway <url> -core <url> -config-pub <pem> (-join-key <secret> | -aws-sigv4 | --sso) [-mesh <id>] [-name N] [-groups a,b]
  pilot status [-mesh <id>]
  pilot info [--json] [-mesh <id>] [-dir <path>]
  pilot uninstall [-mesh <id>] [-purge] | -all
  pilot init [-dir <path>] [-values <values.yml>] [-am-lighthouse]
  pilot enroll -gateway <url> -config-pub <pem> (-join-key <secret> | -aws-sigv4 | --sso) [-dir <path>] [-name N] [-groups a,b]
  pilot renew -core <url> -config-pub <pem> [-dir <path>]
  pilot clock-check [-server <host>] [-max-skew <dur>] [-timeout <dur>]
  pilot supervise -config <nebula.yml> [-nebula <path>] [-sha256 <hex>] [-core <url> -config-pub <pem> -dir <path>]
  pilot version

commands:
  install     one-shot, idempotent host join: clock-check -> init -> enroll ->
              write+enable a per-mesh service -> supervise. Re-runnable; per-mesh
              (a host can join multiple meshes). Linux (systemd), macOS (launchd),
              Windows (SCM).
  status      show a mesh's local state (key/cert/config) + service state.
  info        diagnostic + onboarding: node identity, each mesh's membership
              (overlay IP/cert/groups/expiry/lighthouses/bundle), best-effort
              Harbor reachability, and the CLOUD ATTESTATION IDENTITY this node
              would present (AWS account/role/ARN + a cloudtrust onboarding hint;
              Azure is informational). Scans the multi-mesh StateRoot AND
              auto-detects the single-mesh -dir layout (/etc/nebula); -dir <path>
              reports an arbitrary state dir. --json for scripted onboarding.
  uninstall   disable+stop a mesh's service (-purge deletes its identity; -all tears
              down every mesh + the shared unit for a full host cleanup).
  init        lay out the host dir, generate the host key (P256), and render
              config.yml. Does NOT overwrite an existing host key.
  enroll      join the mesh: gen key -> nonce -> signed submit -> poll -> verify
              the bundle against the pinned config-signing key -> write files`)
	fmt.Fprint(os.Stderr, `
  clock-check check local clock skew vs an NTP reference; exit 1 if beyond
              max-skew (fail-closed for identity ops), exit 2 if undeterminable
  supervise   run and supervise the nebula subprocess (restart w/ backoff,
              clean shutdown on SIGINT/SIGTERM, SIGHUP hot-reloads nebula on
              Unix, optional binary digest check)
`)
}

// cmdRenew rotates to a fresh key and re-certifies the same identity over the
// mesh (M4.4). The Core API authenticates us by our overlay IP.
func cmdRenew(args []string) {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	dir := fs.String("dir", "", "host directory (default: platform-specific)")
	core := fs.String("core", "", "Core API base URL, reached over the mesh (required)")
	configPub := fs.String("config-pub", "", "pinned config-signing public key PEM (required)")
	_ = fs.Parse(args)
	if *core == "" || *configPub == "" {
		fatalf("renew: -core and -config-pub are required")
	}
	pubPEM, err := os.ReadFile(*configPub)
	if err != nil {
		fatalf("renew: read -config-pub: %v", err)
	}
	pinned, err := enrollclient.ParsePinnedConfigPub(pubPEM)
	if err != nil {
		fatalf("renew: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	layout := paths.New(*dir)
	res, err := enrollclient.Renew(ctx, enrollclient.RenewParams{CoreURL: *core, Layout: layout, PinnedConfigPub: pinned})
	if err != nil {
		fatalf("renew: %v", err)
	}
	fmt.Printf("renewed: overlay IP %s (new key + cert written)\n", res.OverlayIP)
	fmt.Printf("  hot-reload the running node: systemctl reload pilot  (or: kill -HUP <pilot-pid>)\n")
}

// cmdEnroll runs the full join flow (M3.7): nonce -> signed submit -> poll ->
// verify the bundle against the pinned config-signing key -> write files. The
// credential is a join key, an AWS-SigV4 instance attestation, or — with --sso — a
// browser IdP round-trip (loopback authorization-code, ADR 0004 / S9).
func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	dir := fs.String("dir", "", "host directory (default: platform-specific)")
	gateway := fs.String("gateway", "", "enrollment gateway base URL (required)")
	joinKey := fs.String("join-key", "", "join key secret (required unless -aws-sigv4 / --sso)")
	awsSigV4 := fs.Bool("aws-sigv4", false, "attest via this instance's IAM role (IMDS) instead of a join key (M5)")
	sso := fs.Bool("sso", false, "enroll via browser SSO (loopback authorization-code; opens your browser to the IdP)")
	region := fs.String("region", "", "STS region for -aws-sigv4 (default: the instance's IMDS-derived region)")
	configPub := fs.String("config-pub", "", "pinned config-signing public key PEM (required)")
	name := fs.String("name", "", "requested device name (cosmetic)")
	groups := fs.String("groups", "", "requested groups (advisory; the join key / cloud-trust / user-trust config decides)")
	timeout := fs.Duration("timeout", 60*time.Second, "max time to wait for the result")
	ssoWait := fs.Duration("sso-wait", 3*time.Minute, "max time to wait for the browser SSO sign-in (--sso)")
	_ = fs.Parse(args)
	if *gateway == "" || *configPub == "" {
		fatalf("enroll: -gateway and -config-pub are required")
	}
	// Exactly one credential source.
	sources := 0
	for _, on := range []bool{*joinKey != "", *awsSigV4, *sso} {
		if on {
			sources++
		}
	}
	if sources != 1 {
		fatalf("enroll: provide exactly one credential source: -join-key, -aws-sigv4, or --sso")
	}

	pubPEM, err := os.ReadFile(*configPub)
	if err != nil {
		fatalf("enroll: read -config-pub: %v", err)
	}
	pinned, err := enrollclient.ParsePinnedConfigPub(pubPEM)
	if err != nil {
		fatalf("enroll: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	layout := paths.New(*dir)
	var res enrollclient.Result
	if *sso {
		res, err = enrollclient.EnrollSSO(ctx, enrollclient.SSOParams{
			GatewayURL: *gateway, Layout: layout,
			RequestedName: *name, RequestedGroups: splitCSV(*groups),
			PinnedConfigPub: pinned, PollTimeout: *timeout, SSOWait: *ssoWait,
		})
	} else {
		res, err = enrollclient.Enroll(ctx, enrollclient.Params{
			GatewayURL: *gateway, JoinKey: *joinKey, AWSSigV4: *awsSigV4, Region: *region, Layout: layout,
			RequestedName: *name, RequestedGroups: splitCSV(*groups),
			PinnedConfigPub: pinned, PollTimeout: *timeout,
		})
	}
	if err != nil {
		fatalf("enroll: %v", err)
	}
	switch res.Status {
	case "issued":
		fmt.Printf("enrolled: overlay IP %s\n", res.OverlayIP)
		fmt.Printf("  wrote %s, %s, %s\n", layout.HostCert(), layout.CABundle(), layout.Config())
		fmt.Printf("  start the node: pilot supervise -config %s\n", layout.Config())
	case "pending":
		if *sso {
			// SSO admission defaults to PENDING (S8): the assertion was accepted and the
			// enrollment is queued for an admin to approve. Not an error — exit 0.
			fmt.Println("enroll --sso: submitted — awaiting admin approval.")
			fmt.Println("  Your SSO sign-in was accepted and the enrollment is queued. A certificate")
			fmt.Println("  is issued only after an admin approves it. Re-run `pilot enroll --sso` later")
			fmt.Println("  to fetch the bundle once approved (no second sign-in is needed).")
			return
		}
		fmt.Println("enroll: submitted — awaiting manual approval.")
		fmt.Println("  This enrollment requires an admin to approve it before a certificate is")
		fmt.Println("  issued. Re-run enroll later to fetch the bundle once it's approved.")
	case "denied":
		fatalf("enroll denied: %s", res.Reason)
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cmdInit prepares a host: secure layout dir, P256 host key (generated once,
// never clobbered), and a rendered config.yml. The signed cert + CA bundle are
// provisioned separately by enrollment (M3); init reports they're still needed.
func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "", "base directory for host identity (default: platform-specific)")
	valuesPath := fs.String("values", "", "optional YAML values file for config policy")
	amLH := fs.Bool("am-lighthouse", false, "render this node as a lighthouse")
	_ = fs.Parse(args)

	layout := paths.New(*dir)
	res, err := pilotsetup.Init(pilotsetup.InitParams{Layout: layout, ValuesPath: *valuesPath, AmLighthouse: *amLH})
	if err != nil {
		fatalf("init: %v", err)
	}

	fmt.Printf("pilot init: base dir %s\n", layout.Base)
	if res.KeyGenerated {
		fmt.Printf("  generated host key   %s\n", layout.HostKey())
		fmt.Printf("  wrote public key     %s  (submit to control plane for signing)\n", layout.HostPub())
	} else {
		fmt.Printf("  host key exists      %s  (left untouched)\n", layout.HostKey())
	}
	fmt.Printf("  rendered config      %s\n", layout.Config())
	fmt.Printf("  still needed before start: %s (CA bundle) and %s (signed cert) — see enrollment (M3)\n",
		layout.CABundle(), layout.HostCert())
}

// cmdClockCheck verifies the host clock against an NTP reference (M1.13). The
// identity model (nonce TTLs, cert validity, attestation freshness) assumes
// synced clocks, so this is the fail-closed gate the enroll/renew flow (M3) will
// call before presenting time-sensitive material. Exit codes are distinct so a
// caller can tell "skewed" (1) from "couldn't determine time" (2).
func cmdClockCheck(args []string) {
	fs := flag.NewFlagSet("clock-check", flag.ExitOnError)
	server := fs.String("server", "pool.ntp.org", "NTP server to check against")
	maxSkew := fs.Duration("max-skew", 5*time.Second, "max tolerated clock skew (fail-closed beyond this)")
	timeout := fs.Duration("timeout", 5*time.Second, "query timeout")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	r, err := clock.Query(ctx, *server, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pilot clock-check: %v\n", err)
		os.Exit(2) //nolint:gocritic // CLI fatal exit; deferred stop() best-effort (time undeterminable)
	}

	dir := "ahead of"
	if r.Offset < 0 {
		dir = "behind"
	}
	fmt.Printf("clock-check: local clock %s %s reference by %s (rtt %s, server %s)\n",
		dir, r.Server, absDur(r.Offset).Round(time.Millisecond), r.RTT.Round(time.Millisecond), r.Server)

	if absDur(r.Offset) > *maxSkew {
		fmt.Fprintf(os.Stderr, "pilot clock-check: skew %s exceeds max %s — fail-closed\n",
			r.Offset.Round(time.Millisecond), *maxSkew)
		os.Exit(1)
	}
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "pilot: "+format+"\n", a...)
	os.Exit(1)
}

// nebulaVersion runs `<path> -version` and returns the reported version (e.g.
// "1.10.3"), or "" if it can't be determined. It reads the on-disk binary (a fresh
// short-lived invocation, independent of the running tunnel), so it reflects a
// version that changed under a self-update. Reported in heartbeats for fleet DISPLAY.
func nebulaVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-version").Output()
	if err != nil {
		return ""
	}
	// nebula prints "Version: X.Y.Z".
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "Version:"))
}

// cachedFileSHA returns a function that reports the sha256 of an on-disk binary (ADR
// 0003 convergence key — used for both the nebula path (1c) and the pilot's own binary
// (3c)), recomputing only when the file changes (by mtime+size) so it tracks a
// self-update / revert without re-hashing the whole binary every heartbeat. "" if the
// binary can't be read.
func cachedFileSHA(path string) func() string {
	var (
		mu      sync.Mutex
		sha     string
		modTime time.Time
		size    int64
	)
	return func() string {
		fi, err := os.Stat(path)
		if err != nil {
			return ""
		}
		mu.Lock()
		defer mu.Unlock()
		if sha != "" && fi.ModTime().Equal(modTime) && fi.Size() == size {
			return sha
		}
		got, err := binverify.FileSHA256(path)
		if err != nil {
			return ""
		}
		sha, modTime, size = got, fi.ModTime(), fi.Size()
		return sha
	}
}

// nebulaHealthFn derives the heartbeat health string from the supervised nebula. It
// reports "unhealthy" only once the data plane has been continuously unhealthy — down, or
// up but younger than minUptime (a crash-loop look-alike) — for unhealthyAfter of
// WALL-CLOCK time. A wall-clock window (rather than a count of beats) keeps the verdict
// independent of the heartbeat interval: a single legitimate restart (nebula is briefly
// down, then young) recovers well inside unhealthyAfter and never escalates, so it can't
// trip a spurious auto-rollback — one "unhealthy" beat fails a host's rollout wave
// immediately (rollout.healthBad). unhealthyAfter matches the nebula-update health-gate
// timeout: "unhealthy" means nebula hasn't held minUptime within the window we'd already
// grant a new binary to come up.
//
// Limitation: this is an uptime heuristic. It catches a FAST crash-loop (cycles shorter
// than minUptime) but not a SLOW one that holds past minUptime each cycle — such a host
// reports "ok". Catching that degraded steady state would need restart-frequency tracking
// in the supervisor and is out of scope here.
func nebulaHealthFn(health func() supervisor.Health, now func() time.Time) func() string {
	const minUptime = 30 * time.Second      // matches the nebula-update health gate's min uptime
	const unhealthyAfter = 90 * time.Second // matches the nebula-update health gate's timeout
	var badSince time.Time
	return func() string {
		if health().Healthy(minUptime) {
			badSince = time.Time{}
			return "ok"
		}
		if badSince.IsZero() {
			badSince = now()
		}
		if now().Sub(badSince) >= unhealthyAfter {
			return "unhealthy"
		}
		return "ok"
	}
}

// desiredPilot resolves the pilot binary to converge on (ADR 0003 Phase 3c): the
// all-or-nothing manual override (-pilot-version/-sha/-url, the 3b live-test trigger)
// when fully set, else the signed bundle's pilot_* fields verified against the pinned
// config-signing key. Empty strings mean no target (Sync no-ops). A missing bundle
// (normal before first enrollment) returns nil; a bundle that can't be read or verified
// returns a warn error for the caller to log (don't act on an unverified tuple).
func desiredPilot(bundlePath string, pinned *ecdsa.PublicKey, ovVer, ovSHA, ovURL string) (ver, sha, url string, warn error) {
	if ovVer != "" && ovSHA != "" && ovURL != "" {
		return ovVer, ovSHA, ovURL, nil
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", "", nil
		}
		return "", "", "", fmt.Errorf("read bundle: %w", err)
	}
	b, err := bundle.Verify(raw, pinned)
	if err != nil {
		return "", "", "", fmt.Errorf("verify bundle: %w", err)
	}
	return b.PilotVersion, b.PilotSHA256, b.PilotURL, nil
}

func cmdSupervise(args []string) {
	fs := flag.NewFlagSet("supervise", flag.ExitOnError)
	nebulaPath := fs.String("nebula", "nebula", "path to the nebula binary")
	configPath := fs.String("config", "", "path to nebula config.yml (required)")
	sha := fs.String("sha256", "", "optional: expected hex sha256 of the nebula binary (verified before exec)")
	// Proactive renewal (M4.4): if -core + -config-pub are set, supervise also
	// auto-renews the cert at ~⅔ life (with jitter) and hot-reloads nebula.
	dir := fs.String("dir", "", "host directory (for auto-renew; default: platform-specific)")
	core := fs.String("core", "", "Core API base URL (enables proactive renewal)")
	configPub := fs.String("config-pub", "", "pinned config-signing public key PEM (required with -core)")
	logFormat := fs.String("log-format", "auto", "log format: auto (text on a TTY, JSON as a service) | text | json")
	logLevel := fs.String("log-level", "info", "log level: debug | info | warn | error")
	// Pilot self-update (ADR 0003 Phase 3). -adopt-nebula-pid is set by the re-exec so
	// the new pilot re-adopts the running nebula instead of forking. -pilot-* are the
	// manual/test trigger for the re-exec mechanism (Phase 3c replaces them with the
	// bundle's pilot_version/sha/url).
	adoptNebulaPid := fs.Int("adopt-nebula-pid", 0, "re-adopt this running nebula PID instead of forking (set by the self-update re-exec; ADR 0003 Phase 3)")
	pilotVersion := fs.String("pilot-version", "", "desired pilot version to self-update to (Phase 3 manual trigger)")
	pilotSHA := fs.String("pilot-sha256", "", "hex sha256 of the desired pilot binary (the integrity anchor)")
	pilotURL := fs.String("pilot-url", "", "URL to fetch the desired pilot binary from (sha-verified)")
	_ = fs.Parse(args)

	// Validate required flags BEFORE any service-mode setup: under the Windows SCM
	// a bare os.Exit here (after dispatch) would look like a failed start and trip
	// the restart recovery on a permanent fault. install always passes -config, so
	// this is a guard for hand-run / mis-edited argv.
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "pilot supervise: -config is required")
		os.Exit(2)
	}

	// On Windows the SCM launches us without a console; send our logs + nebula's
	// stdout/stderr to <dir>/pilot.log before the logger is built. No-op elsewhere.
	prepareServiceLogging(*dir)
	log := clilog.Setup(clilog.Options{Format: *logFormat, Level: *logLevel})

	// serve runs the supervise work until ctx is cancelled. runSupervisor supplies
	// that ctx: SIGINT/SIGTERM on Unix, the SCM Stop/Shutdown control on Windows.
	serve := func(ctx context.Context) error {
		// Pilot self-update (ADR 0003 Phase 3). self is the running pilot binary; the
		// nebula PID handoff lives in the state dir (when -dir is set).
		self, _ := os.Executable()
		nebulaPidPath := ""
		if *dir != "" {
			nebulaPidPath = paths.New(*dir).NebulaPid()
		}
		pu := pilotupdate.New(pilotupdate.Config{
			SelfPath: self, NebulaPidPath: nebulaPidPath, Args: os.Args,
		})
		// Before supervising anything: if a prior self-update re-exec'd but never
		// confirmed health (it crashed/hung and the service restarted us), revert the
		// pilot binary to last-good and exit non-zero so the service relaunches the good
		// one (which re-adopts the still-running nebula via the pidfile).
		if reverted, err := pu.CheckRevert(); err != nil {
			// Revert was needed but impossible (no last-good / fs error). Looping (exit +
			// service-restart) would just relaunch the same bad binary, so run the current
			// one and alert loudly — a visible, heartbeating host an operator can recover
			// beats a host that looks dead.
			log.Error("pilot self-update: REVERT FAILED — running the current binary; manual recovery may be needed", "err", err)
		} else if reverted {
			return fmt.Errorf("pilot self-update reverted to last-good; relaunching")
		}

		// Re-adopt a nebula a previous pilot left running across a re-exec: the flag
		// (re-exec lineage) takes precedence, else the persisted pidfile (a service
		// restart after a revert) — so the data plane survives a pilot swap.
		adoptPID := *adoptNebulaPid
		if adoptPID == 0 && nebulaPidPath != "" {
			adoptPID = pilotupdate.ReadAdoptPID(nebulaPidPath)
		}
		sup := &supervisor.Supervisor{
			NebulaPath:     *nebulaPath,
			ConfigPath:     *configPath,
			ExpectedSHA256: *sha,
			AdoptPID:       adoptPID,
		}
		// Fail-open on the nebula stats port: if it's already taken, nebula would refuse to
		// start (fatal) and take the data plane with it — so disable stats instead and bring
		// the tunnel up regardless. A metrics port must never sink the tunnel.
		disableStatsOnPortConflict(*configPath, log)
		// ADR 0003 Phase 2: on a fresh host with no nebula binary yet, materialize the
		// one embedded in this pilot (offline first-boot). No-op once a binary exists
		// (Phase 1 owns updates from then on) or in a build that embedded nothing.
		if wrote, err := nebulaboot.MaterializeEmbedded(*nebulaPath, log); err != nil {
			// err wraps which step failed ("materialize wintun" vs the nebula write); on
			// Windows a wintun failure means the overlay won't come up even though nebula
			// itself may have been written.
			log.Warn("nebula bootstrap: could not materialize embedded nebula/wintun", "err", err)
		} else if wrote {
			log.Info("nebula bootstrap: wrote embedded binary for offline first-boot", "path", *nebulaPath)
		}
		installReload(ctx, sup, log) // SIGHUP -> hot reload nebula (Unix); no-op on Windows
		log.Info("pilot supervise starting", "config", *configPath, "nebula", *nebulaPath, "version", version)

		var wg sync.WaitGroup // the background loops, joined on shutdown
		if *core != "" {
			if *configPub == "" {
				return fmt.Errorf("supervise: -core requires -config-pub")
			}
			pubPEM, err := os.ReadFile(*configPub)
			if err != nil {
				return fmt.Errorf("supervise: read -config-pub: %w", err)
			}
			pinned, err := enrollclient.ParsePinnedConfigPub(pubPEM)
			if err != nil {
				return fmt.Errorf("supervise: %w", err)
			}
			layout := paths.New(*dir)
			// One lock serializes every writer of the host layout — renew, drift
			// revert, and apply_bundle — so concurrent loops can't tear config.yml or
			// the identity files.
			var applyMu sync.Mutex
			mgr := renew.New(renew.Config{
				Layout: layout, CoreURL: *core, PinnedConfigPub: pinned,
				Reload: sup.Reload, Locker: &applyMu,
			})
			wg.Add(1)
			go func() { defer wg.Done(); _ = mgr.Run(ctx) }()

			// Heartbeat + typed command channel (4.6): report state; act on the
			// closed command set. Core-issued renew reuses the renewal path;
			// apply_bundle (7.1b) does a config-only refresh (GET /v1/config) so a
			// blocklist/policy/lighthouse change applies fast without a cert re-issue.
			hb := heartbeat.New(heartbeat.Config{
				CoreURL: *core, Layout: layout, PilotVersion: version, PinnedConfigPub: pinned,
				// Report the RUNNING nebula binary each beat: its sha (the convergence key
				// Harbor maps to a release generation to drive nebula-lane rollout +
				// auto-rollback, 1c) and its version string (fleet display).
				NebulaVersionFn: func() string { return nebulaVersion(*nebulaPath) },
				NebulaSHAFn:     cachedFileSHA(*nebulaPath),
				PilotSHAFn:      cachedFileSHA(self), // the pilot's OWN binary, for the pilot lane (3c)
				// Report real data-plane health so Harbor auto-rollback can fail a wave on a
				// host reporting unhealth, not only on silence. Debounced (below) so an
				// in-flight restart can't trip a spurious rollback.
				HealthFn: nebulaHealthFn(sup.Health, time.Now),
				Handlers: heartbeat.Handlers{
					Renew:   mgr.RenewNow,
					Restart: sup.Restart,
					ApplyBundle: func(ctx context.Context, _ int) error {
						applyMu.Lock()
						defer applyMu.Unlock()
						if _, err := enrollclient.FetchConfig(ctx, enrollclient.RenewParams{
							CoreURL: *core, Layout: layout, PinnedConfigPub: pinned,
						}); err != nil {
							return err
						}
						return sup.Reload()
					},
				},
			})
			wg.Add(1)
			go func() { defer wg.Done(); _ = hb.Run(ctx) }()

			// Drift detection (M6.7): re-assert the signed config over any local edit.
			dm := drift.New(drift.Config{Layout: layout, PinnedConfigPub: pinned, Reload: sup.Reload, Locker: &applyMu})
			wg.Add(1)
			go func() { defer wg.Done(); _ = dm.Run(ctx) }()

			// Nebula self-update (ADR 0003 Phase 1): converge the data-plane binary on
			// the version the signed bundle pins; a swap is a supervised Restart. The
			// Healthy gate (Phase 1c) reverts to last-good if the new binary doesn't
			// stay up for 30s within 90s — pilot-local recovery for a host whose new
			// nebula would otherwise isolate it from the mesh (and from Harbor).
			nu := nebulaupdate.New(nebulaupdate.Config{
				Layout: layout, PinnedConfigPub: pinned, NebulaPath: *nebulaPath, Restart: sup.Restart,
				Healthy: func(ctx context.Context, restartedAt time.Time) bool {
					return sup.WaitHealthy(ctx, restartedAt, 30*time.Second, 90*time.Second)
				},
			})
			wg.Add(1)
			go func() { defer wg.Done(); _ = nu.Run(ctx) }()

			// Pilot self-update (ADR 0003 Phase 3c): converge the pilot binary on the
			// version the signed bundle pins (or the -pilot-* manual override, Phase 3b
			// live-test). Once nebula is up (so the re-exec'd pilot has something to
			// re-adopt), a desired pilot != the running one is fetched + sha-verified +
			// applied via re-exec/re-adopt (which does not return on success).
			puLoop := pilotupdate.New(pilotupdate.Config{
				SelfPath: self, NebulaPidPath: nebulaPidPath, Args: os.Args,
				NebulaPID: func() int { return sup.Health().Pid },
			})
			wg.Add(1)
			go func() {
				defer wg.Done()
				t := time.NewTicker(60 * time.Second)
				defer t.Stop()
				for {
					if sup.Health().Pid > 0 {
						// Desired pilot: the all-or-nothing -pilot-* override (3b live-test
						// trigger) else the verified bundle's pilot_* fields (the normal 3c path).
						ver, sha2, url, warn := desiredPilot(layout.Bundle(), pinned, *pilotVersion, *pilotSHA, *pilotURL)
						if warn != nil {
							log.Warn("pilot self-update: bundle read/verify failed", "err", warn)
						}
						if _, err := puLoop.Sync(ver, sha2, url); err != nil {
							log.Warn("pilot self-update: sync failed; will retry", "err", err)
						}
					}
					select {
					case <-ctx.Done():
						return
					case <-t.C:
					}
				}
			}()
			log.Info("pilot background tasks enabled", "renew", true, "heartbeat", true, "drift", true, "nebula_update", true, "pilot_update", true, "core", *core)
		}

		// Pilot self-update (ADR 0003 Phase 3). If THIS pilot is a re-exec on trial,
		// confirm once it has stayed up a grace window (a proxy for "the new pilot came up
		// healthy"); a crash before then leaves the marker, so the next start reverts.
		if pu.Pending() {
			log.Info("pilot self-update: on trial; confirming after a health grace window")
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case <-time.After(30 * time.Second):
					if err := pu.Confirm(version); err != nil {
						log.Warn("pilot self-update: confirm failed", "err", err)
					}
				case <-ctx.Done():
				}
			}()
		}
		err := sup.Run(ctx)
		// On shutdown, give in-flight renew/drift/apply writes a bounded window to
		// finish so we never exit mid-write (a torn config.yml / identity). The loops
		// already return promptly on ctx.Done(); this only waits out an op in flight.
		stopped := make(chan struct{})
		go func() { wg.Wait(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			log.Warn("supervise: background tasks did not stop within 5s")
		}
		return err
	}

	if err := runSupervisor(serve, log); err != nil {
		log.Error("pilot supervise exited", "err", err)
		os.Exit(1)
	}
	log.Info("pilot supervise stopped")
}

// cmdInstall is the one-shot, idempotent host join (ADR 0008 Phase 1): clock-check
// -> enroll -> write+enable a per-mesh systemd service -> supervise. Per-mesh (a
// host can join multiple meshes; each gets its own /var/lib/pilot/<mesh> dir +
// pilot@<mesh> service) and safe to re-run. enroll itself ensures the dir, reuses
// the live host key, and writes config.yml from the signed bundle — so install does
// not separately init or set local config (the config, incl. the TUN/port, is
// Harbor's signed bundle; a local override would be reverted by drift control).
func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	mesh := fs.String("mesh", "default", "mesh id — namespaces the install (per-mesh state dir + service)")
	gateway := fs.String("gateway", "", "enrollment gateway base URL (required)")
	core := fs.String("core", "", "Core API base URL over the mesh, for renew/heartbeat (required)")
	configPub := fs.String("config-pub", "", "pinned config-signing public key PEM (required)")
	joinKey := fs.String("join-key", "", "join key secret (required unless -aws-sigv4)")
	awsSigV4 := fs.Bool("aws-sigv4", false, "attest via this instance's IAM role (IMDS) instead of a join key")
	region := fs.String("region", "", "STS region for -aws-sigv4 (default: IMDS-derived)")
	sso := fs.Bool("sso", false, "enroll via browser SSO (loopback authorization-code; opens your browser to the IdP)")
	ssoWait := fs.Duration("sso-wait", 3*time.Minute, "max time to wait for the browser SSO sign-in (--sso)")
	name := fs.String("name", "", "requested device name (cosmetic)")
	groups := fs.String("groups", "", "requested groups (advisory; cloud-trust / join key decides)")
	nebulaPath := fs.String("nebula", defaultNebulaPath, "path to the nebula binary the service runs")
	timeout := fs.Duration("timeout", 60*time.Second, "max time to wait for the enroll result")
	clockServer := fs.String("clock-server", "pool.ntp.org", "NTP server for the pre-flight clock check")
	maxSkew := fs.Duration("max-skew", 5*time.Second, "max tolerated clock skew (fail-closed)")
	skipClock := fs.Bool("skip-clock-check", false, "skip the pre-flight clock check (airgapped hosts)")
	dryRun := fs.Bool("dry-run", false, "preview the resolved paths + service definition, then exit (no enroll, no write, no root)")
	_ = fs.Parse(args)

	if *core == "" {
		fmt.Fprintln(os.Stderr, "pilot install: -core is required")
		os.Exit(2)
	}
	if !validMeshID(*mesh) {
		fatalf("install: invalid -mesh %q (letters/digits/_/-, start alphanumeric, <=32 chars)", *mesh)
	}

	base := filepath.Join(pilotservice.StateRoot, *mesh)
	layout := paths.New(base)
	spec := pilotservice.Spec{Mesh: *mesh, StateDir: base, CoreURL: *core, NebulaPath: *nebulaPath}

	// -dry-run: preview the resolved paths + the exact service definition this would
	// install, then exit. No clock-check, enroll, write, or root — handy on the macOS
	// path (validate the LaunchDaemon plist with `plutil -lint`) and before committing.
	if *dryRun {
		fmt.Printf("install (dry-run) — mesh %q, service %s\n", *mesh, pilotservice.ServiceLabel(*mesh))
		fmt.Printf("  state dir : %s\n", base)
		fmt.Printf("  config    : %s\n", layout.Config())
		fmt.Printf("  pin       : %s\n", filepath.Join(base, "config-signing.pub"))
		fmt.Printf("  nebula    : %s\n", *nebulaPath)
		fmt.Printf("--- service definition ---\n%s\n", pilotservice.Render(spec))
		return
	}

	if *gateway == "" || *configPub == "" {
		fmt.Fprintln(os.Stderr, "pilot install: -gateway and -config-pub are required")
		os.Exit(2)
	}
	sources := 0
	for _, on := range []bool{*joinKey != "", *awsSigV4, *sso} {
		if on {
			sources++
		}
	}
	if sources != 1 { // exactly one credential source
		fatalf("install: provide exactly one credential source: -join-key, -aws-sigv4, or --sso")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Pre-flight clock check — identity ops (nonce/cert/attestation) are
	// clock-sensitive, so fail closed on skew unless explicitly skipped.
	if !*skipClock {
		r, err := clock.Query(ctx, *clockServer, 5*time.Second)
		if err != nil {
			fatalf("install: clock check failed (use -skip-clock-check to bypass): %v", err)
		}
		if absDur(r.Offset) > *maxSkew {
			fatalf("install: clock skew %s exceeds max %s — fail-closed (fix the clock or -skip-clock-check)",
				r.Offset.Round(time.Millisecond), *maxSkew)
		}
	}

	pubPEM, err := os.ReadFile(*configPub)
	if err != nil {
		fatalf("install: read -config-pub: %v", err)
	}
	pinned, err := enrollclient.ParsePinnedConfigPub(pubPEM)
	if err != nil {
		fatalf("install: %v", err)
	}

	// 2. Enroll unless this mesh already holds a signed cert (idempotent re-run:
	// don't re-enroll an enrolled host — just (re)install the service).
	if fileExists(layout.HostCert()) {
		fmt.Printf("install: mesh %q already enrolled (%s present) — ensuring the service\n", *mesh, layout.HostCert())
	} else {
		var res enrollclient.Result
		if *sso {
			res, err = enrollclient.EnrollSSO(ctx, enrollclient.SSOParams{
				GatewayURL: *gateway, Layout: layout,
				RequestedName: *name, RequestedGroups: splitCSV(*groups),
				PinnedConfigPub: pinned, PollTimeout: *timeout, SSOWait: *ssoWait,
			})
		} else {
			res, err = enrollclient.Enroll(ctx, enrollclient.Params{
				GatewayURL: *gateway, JoinKey: *joinKey, AWSSigV4: *awsSigV4, Region: *region, Layout: layout,
				RequestedName: *name, RequestedGroups: splitCSV(*groups), PinnedConfigPub: pinned, PollTimeout: *timeout,
			})
		}
		if err != nil {
			fatalf("install: enroll: %v", err)
		}
		switch res.Status {
		case "issued":
			fmt.Printf("install: enrolled mesh %q — overlay IP %s\n", *mesh, res.OverlayIP)
		case "pending":
			if *sso {
				// SSO admission defaults to PENDING (S8): sign-in accepted, queued for an
				// admin to approve. Re-run after approval to fetch the bundle (no second sign-in).
				fmt.Println("install --sso: submitted — awaiting admin approval.")
				fmt.Printf("  Re-run `pilot install -mesh %s --sso ...` after approval to finish; the service is NOT yet started.\n", *mesh)
				return
			}
			fmt.Println("install: enrollment submitted — awaiting manual approval.")
			fmt.Printf("  Re-run `pilot install -mesh %s ...` after approval to finish; the service is NOT yet started.\n", *mesh)
			return
		case "denied":
			fatalf("install: enrollment denied: %s", res.Reason)
		}
	}

	// Multi-mesh safety (ADR 0008 Phase 3): a host joining multiple meshes needs
	// DISJOINT overlay pools, or two tun devices cover the same CIDR and the host's
	// route into it is ambiguous. Best-effort warning, not fatal.
	warnOverlappingCIDR(*mesh, base)

	// 3. Place the pin where the service's `supervise` reads it (-config-pub).
	if err := os.WriteFile(filepath.Join(base, "config-signing.pub"), pubPEM, 0o644); err != nil {
		fatalf("install: write config-signing.pub: %v", err)
	}

	// 4. Install + enable the per-mesh service; it runs `supervise` (hand-off to ADR 0003).
	if err := pilotservice.Install(pilotservice.Spec{
		Mesh: *mesh, StateDir: base, CoreURL: *core, NebulaPath: *nebulaPath,
	}); err != nil {
		fatalf("install: service: %v", err)
	}
	fmt.Printf("install: service %s enabled + started (supervising nebula; renew/heartbeat to %s)\n", pilotservice.ServiceLabel(*mesh), *core)
	fmt.Printf("  status: pilot status -mesh %s    logs: %s\n", *mesh, pilotservice.LogHint(*mesh))
}

// cmdStatus reports a mesh's local identity/config state + its service state.
func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	mesh := fs.String("mesh", "default", "mesh id")
	_ = fs.Parse(args)
	base := filepath.Join(pilotservice.StateRoot, *mesh)
	layout := paths.New(base)
	fmt.Printf("mesh %q  (%s)\n", *mesh, base)
	fmt.Printf("  host key:   %s\n", existWord(layout.HostKey()))
	fmt.Printf("  host cert:  %s\n", existWord(layout.HostCert()))
	fmt.Printf("  ca bundle:  %s\n", existWord(layout.CABundle()))
	fmt.Printf("  config:     %s\n", existWord(layout.Config()))
	if rep, err := pilotservice.Status(*mesh); err != nil {
		fmt.Printf("  service:    %v\n", err)
	} else {
		fmt.Printf("  service:    %s\n", rep)
	}
}

// cmdUninstall disables+stops a mesh's service; -purge also deletes its identity;
// -all tears down every mesh + the shared unit (full host cleanup). The pilot/nebula
// binaries are always left in place (a mesh teardown shouldn't delete host binaries).
func cmdUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	mesh := fs.String("mesh", "default", "mesh id")
	purge := fs.Bool("purge", false, "also delete the mesh's identity + state dir (irreversible)")
	all := fs.Bool("all", false, "tear down ALL meshes + remove the shared systemd unit (full host cleanup; implies -purge)")
	_ = fs.Parse(args)

	if *all {
		meshes := listMeshes()
		if len(meshes) == 0 {
			fmt.Printf("uninstall -all: no meshes under %s\n", pilotservice.StateRoot)
		}
		for _, m := range meshes {
			if err := pilotservice.Uninstall(m); err != nil {
				fmt.Fprintf(os.Stderr, "uninstall: %s: %v\n", pilotservice.ServiceLabel(m), err)
			} else {
				fmt.Printf("uninstall: service %s disabled + stopped\n", pilotservice.ServiceLabel(m))
			}
			base := filepath.Join(pilotservice.StateRoot, m)
			if err := os.RemoveAll(base); err != nil {
				fatalf("uninstall: purge %s: %v", base, err)
			}
			fmt.Printf("  purged %s\n", base)
		}
		removeHostArtifacts()
		fmt.Println("uninstall -all: complete (the pilot + nebula binaries are left in place)")
		return
	}

	if !validMeshID(*mesh) {
		fatalf("uninstall: invalid -mesh %q", *mesh)
	}
	if err := pilotservice.Uninstall(*mesh); err != nil {
		fatalf("uninstall: %v", err)
	}
	fmt.Printf("uninstall: service %s disabled + stopped\n", pilotservice.ServiceLabel(*mesh))
	base := filepath.Join(pilotservice.StateRoot, *mesh)
	if !*purge {
		fmt.Printf("  kept state at %s (re-run install to re-enable; -purge to delete; -all for full cleanup)\n", base)
		return
	}
	if err := os.RemoveAll(base); err != nil {
		fatalf("uninstall: purge %s: %v", base, err)
	}
	fmt.Printf("  purged %s (identity destroyed)\n", base)
	// If that was the last mesh, also remove the shared unit (full cleanup).
	if len(listMeshes()) == 0 {
		removeHostArtifacts()
	}
}

// removeHostArtifacts removes the shared systemd template unit + the (now-empty)
// state root — the host-level footprint shared across meshes. The pilot/nebula
// binaries are intentionally left (a mesh teardown shouldn't delete host binaries).
func removeHostArtifacts() {
	if err := pilotservice.RemoveTemplate(); err != nil {
		fmt.Fprintf(os.Stderr, "uninstall: remove shared unit: %v\n", err)
	} else {
		fmt.Println("  removed the shared service unit (if any)")
	}
	if err := os.Remove(pilotservice.StateRoot); err == nil {
		fmt.Printf("  removed %s\n", pilotservice.StateRoot)
	}
}

// listMeshes returns the mesh ids that have a state dir under StateRoot.
func listMeshes() []string {
	ents, err := os.ReadDir(pilotservice.StateRoot)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// meshOverlay returns the masked overlay prefix a mesh sits in (e.g. 10.44.0.0/16),
// derived from its host cert's network. ok is false if the cert is missing/unparseable.
func meshOverlay(base string) (netip.Prefix, bool) {
	pem, err := os.ReadFile(paths.New(base).HostCert())
	if err != nil {
		return netip.Prefix{}, false
	}
	c, _, err := cert.UnmarshalCertificateFromPEM(pem)
	if err != nil {
		return netip.Prefix{}, false
	}
	nets := c.Networks()
	if len(nets) == 0 {
		return netip.Prefix{}, false
	}
	return nets[0].Masked(), true
}

// overlappingMeshes returns the names of meshes (from others) whose overlay range
// overlaps mine — sorted. Multi-mesh on one host needs disjoint pools (ADR 0008):
// two tun devices covering the same CIDR give the host an ambiguous route.
func overlappingMeshes(mine netip.Prefix, others map[string]netip.Prefix) []string {
	var hits []string
	for name, p := range others {
		if mine.Overlaps(p) {
			hits = append(hits, name)
		}
	}
	sort.Strings(hits)
	return hits
}

// warnOverlappingCIDR prints a best-effort warning if this mesh's overlay range
// overlaps an already-installed mesh's. Not fatal — the operator may be bridging
// intentionally, or needs to repoint the mesh's Harbor -pool to a distinct range.
func warnOverlappingCIDR(mesh, base string) {
	mine, ok := meshOverlay(base)
	if !ok {
		return
	}
	others := map[string]netip.Prefix{}
	for _, m := range listMeshes() {
		if m == mesh {
			continue
		}
		if p, ok := meshOverlay(filepath.Join(pilotservice.StateRoot, m)); ok {
			others[m] = p
		}
	}
	for _, m := range overlappingMeshes(mine, others) {
		fmt.Fprintf(os.Stderr,
			"install: WARNING: mesh %q overlay %s overlaps already-installed mesh %q (%s).\n"+
				"  Multi-mesh on one host needs disjoint overlay pools (ADR 0008) — two tun devices on the\n"+
				"  same CIDR give an ambiguous route. Repoint a mesh's Harbor -pool to a distinct range.\n",
			mesh, mine, m, others[m])
	}
}

// validMeshID accepts ids safe as both a path segment and a systemd instance name:
// start alphanumeric, then [A-Za-z0-9_-], length 1..32.
func validMeshID(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if i > 0 {
			ok = ok || r == '_' || r == '-'
		}
		if !ok {
			return false
		}
	}
	return true
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func existWord(p string) string {
	if fileExists(p) {
		return "present  (" + p + ")"
	}
	return "MISSING  (" + p + ")"
}
