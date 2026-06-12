// Command pilot is the Nebula Control Plane host agent. It supervises a local
// nebula process and (in later milestones) handles enrollment, renewal, config
// rendering, and drift control. See docs/ and CLAUDE.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/clock"
	"github.com/jeks313/nebula-control-plane/internal/enrollclient"
	"github.com/jeks313/nebula-control-plane/internal/hostkey"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/renew"
	"github.com/jeks313/nebula-control-plane/internal/supervisor"
	"gopkg.in/yaml.v3"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
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
  pilot init [-dir <path>] [-values <values.yml>] [-am-lighthouse]
  pilot enroll -gateway <url> -join-key <secret> -config-pub <pem> [-dir <path>] [-name N] [-groups a,b]
  pilot renew -core <url> -config-pub <pem> [-dir <path>]
  pilot clock-check [-server <host>] [-max-skew <dur>] [-timeout <dur>]
  pilot supervise -config <nebula.yml> [-nebula <path>] [-sha256 <hex>] [-core <url> -config-pub <pem> -dir <path>]
  pilot version

commands:
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
	joinKey := fs.String("join-key", "", "join key secret (required)")
	configPub := fs.String("config-pub", "", "pinned config-signing public key PEM (required)")
	name := fs.String("name", "", "requested device name (cosmetic)")
	groups := fs.String("groups", "", "requested groups (advisory; the join key decides)")
	timeout := fs.Duration("timeout", 60*time.Second, "max time to wait for the result")
	_ = fs.Parse(args)
	if *gateway == "" || *joinKey == "" || *configPub == "" {
		fatalf("enroll: -gateway, -join-key and -config-pub are required")
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
		GatewayURL: *gateway, JoinKey: *joinKey, Layout: layout,
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
		fmt.Println("  This host joined via a join key, which requires an admin to approve it")
		fmt.Println("  before a certificate is issued. Re-run enroll later, or have an admin approve it.")
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
	if err := layout.Ensure(); err != nil {
		fatalf("init: %v", err)
	}

	// 1. Host key (M1.4): generate once; never overwrite a live key.
	keyGenerated := false
	if _, err := os.Stat(layout.HostKey()); errors.Is(err, os.ErrNotExist) {
		kp, err := hostkey.Generate()
		if err != nil {
			fatalf("init: %v", err)
		}
		if err := kp.WritePrivateKey(layout.HostKey()); err != nil {
			fatalf("init: %v", err)
		}
		if err := kp.WritePublicKey(layout.HostPub()); err != nil {
			fatalf("init: %v", err)
		}
		keyGenerated = true
	} else if err != nil {
		fatalf("init: stat host key: %v", err)
	}

	// 2. Config (M1.7): policy from values file (if any), PKI paths from layout.
	var v nebulaconfig.Values
	if *valuesPath != "" {
		raw, err := os.ReadFile(*valuesPath)
		if err != nil {
			fatalf("init: read values: %v", err)
		}
		if err := yaml.Unmarshal(raw, &v); err != nil {
			fatalf("init: parse values: %v", err)
		}
	}
	if *amLH {
		v.AmLighthouse = true
	}
	v.CACertPath = layout.CABundle()
	v.CertPath = layout.HostCert()
	v.KeyPath = layout.HostKey()
	v.Defaults()

	cfg, err := nebulaconfig.Render(v)
	if err != nil {
		fatalf("init: %v", err)
	}
	if err := os.WriteFile(layout.Config(), cfg, 0644); err != nil {
		fatalf("init: write config: %v", err)
	}

	fmt.Printf("pilot init: base dir %s\n", layout.Base)
	if keyGenerated {
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
		os.Exit(2) // time could not be determined
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
	_ = fs.Parse(args)

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "pilot supervise: -config is required")
		os.Exit(2)
	}

	// translate SIGINT/SIGTERM into ctx cancellation for a clean shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sup := &supervisor.Supervisor{
		NebulaPath:     *nebulaPath,
		ConfigPath:     *configPath,
		ExpectedSHA256: *sha,
	}
	installReload(ctx, sup) // SIGHUP -> hot reload nebula (Unix); no-op on Windows

	if *core != "" {
		if *configPub == "" {
			fatalf("supervise: -core requires -config-pub")
		}
		pubPEM, err := os.ReadFile(*configPub)
		if err != nil {
			fatalf("supervise: read -config-pub: %v", err)
		}
		pinned, err := enrollclient.ParsePinnedConfigPub(pubPEM)
		if err != nil {
			fatalf("supervise: %v", err)
		}
		mgr := renew.New(renew.Config{
			Layout: paths.New(*dir), CoreURL: *core, PinnedConfigPub: pinned,
			Reload: sup.Reload,
		})
		go func() { _ = mgr.Run(ctx) }()
	}

	if err := sup.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "pilot: %v\n", err)
		os.Exit(1)
	}
}
