// Command pilot is the Nebula Control Plane host agent. It supervises a local
// nebula process and (in later milestones) handles enrollment, renewal, config
// rendering, and drift control. See docs/ and CLAUDE.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/clilog"
	"github.com/jeks313/nebula-control-plane/internal/clock"
	"github.com/jeks313/nebula-control-plane/internal/drift"
	"github.com/jeks313/nebula-control-plane/internal/enrollclient"
	"github.com/jeks313/nebula-control-plane/internal/heartbeat"
	"github.com/jeks313/nebula-control-plane/internal/nebulaupdate"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/pilotservice"
	"github.com/jeks313/nebula-control-plane/internal/pilotsetup"
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
  pilot install -gateway <url> -core <url> -config-pub <pem> (-join-key <secret> | -aws-sigv4) [-mesh <id>] [-name N] [-groups a,b]
  pilot status [-mesh <id>]
  pilot uninstall [-mesh <id>] [-purge] | -all
  pilot init [-dir <path>] [-values <values.yml>] [-am-lighthouse]
  pilot enroll -gateway <url> -join-key <secret> -config-pub <pem> [-dir <path>] [-name N] [-groups a,b]
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
// verify the bundle against the pinned config-signing key -> write files.
func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	dir := fs.String("dir", "", "host directory (default: platform-specific)")
	gateway := fs.String("gateway", "", "enrollment gateway base URL (required)")
	joinKey := fs.String("join-key", "", "join key secret (required unless -aws-sigv4)")
	awsSigV4 := fs.Bool("aws-sigv4", false, "attest via this instance's IAM role (IMDS) instead of a join key (M5)")
	region := fs.String("region", "", "STS region for -aws-sigv4 (default: the instance's IMDS-derived region)")
	configPub := fs.String("config-pub", "", "pinned config-signing public key PEM (required)")
	name := fs.String("name", "", "requested device name (cosmetic)")
	groups := fs.String("groups", "", "requested groups (advisory; the join key / cloud-trust config decides)")
	timeout := fs.Duration("timeout", 60*time.Second, "max time to wait for the result")
	_ = fs.Parse(args)
	if *gateway == "" || *configPub == "" {
		fatalf("enroll: -gateway and -config-pub are required")
	}
	if *awsSigV4 == (*joinKey != "") { // exactly one credential source
		fatalf("enroll: provide either -join-key or -aws-sigv4 (not both, not neither)")
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
	res, err := enrollclient.Enroll(ctx, enrollclient.Params{
		GatewayURL: *gateway, JoinKey: *joinKey, AWSSigV4: *awsSigV4, Region: *region, Layout: layout,
		RequestedName: *name, RequestedGroups: splitCSV(*groups),
		PinnedConfigPub: pinned, PollTimeout: *timeout,
	})
	if err != nil {
		fatalf("enroll: %v", err)
	}
	switch res.Status {
	case "issued":
		fmt.Printf("enrolled: overlay IP %s\n", res.OverlayIP)
		fmt.Printf("  wrote %s, %s, %s\n", layout.HostCert(), layout.CABundle(), layout.Config())
		fmt.Printf("  start the node: pilot supervise -config %s\n", layout.Config())
	case "pending":
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
		sup := &supervisor.Supervisor{
			NebulaPath:     *nebulaPath,
			ConfigPath:     *configPath,
			ExpectedSHA256: *sha,
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
			// the version the signed bundle pins; a swap is a supervised Restart.
			nu := nebulaupdate.New(nebulaupdate.Config{Layout: layout, PinnedConfigPub: pinned, NebulaPath: *nebulaPath, Restart: sup.Restart})
			wg.Add(1)
			go func() { defer wg.Done(); _ = nu.Run(ctx) }()
			log.Info("pilot background tasks enabled", "renew", true, "heartbeat", true, "drift", true, "nebula_update", true, "core", *core)
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
	if *awsSigV4 == (*joinKey != "") { // exactly one credential source
		fatalf("install: provide either -join-key or -aws-sigv4 (not both, not neither)")
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
		res, err := enrollclient.Enroll(ctx, enrollclient.Params{
			GatewayURL: *gateway, JoinKey: *joinKey, AWSSigV4: *awsSigV4, Region: *region, Layout: layout,
			RequestedName: *name, RequestedGroups: splitCSV(*groups), PinnedConfigPub: pinned, PollTimeout: *timeout,
		})
		if err != nil {
			fatalf("install: enroll: %v", err)
		}
		switch res.Status {
		case "issued":
			fmt.Printf("install: enrolled mesh %q — overlay IP %s\n", *mesh, res.OverlayIP)
		case "pending":
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
