package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/collect"
	"github.com/jeks313/nebula-control-plane/internal/gatewayreg"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
)

// Harbor fleet-registry commands: lighthouse + gateway add/remove/list (split from main.go).

// cmdLighthouse manages the lighthouse fleet registry (6.8) plus scheduled cert
// rotation. Core serves the active rows into every bundle's static_host_map when run
// with -lighthouse-db. This is a SINGLE positional-dispatch switch over every
// subcommand (the cli_surface_test extractor models exactly one switch per function);
// the registry actions, which share a flagset, live in cmdLighthouseRegistry, and
// rotate-cert — which needs its OWN flagset (-ca-cert/-backend/-lifetime/...) — gets
// dispatched before any shared parse.
func cmdLighthouse(args []string) {
	if len(args) < 1 {
		fatalf("lighthouse: want add|replace|remove|list|mint|rotate-cert|rotation-record")
	}
	sub := args[0]
	switch sub {
	case "mint":
		cmdLighthouseMint(args[1:])
	case "rotate-cert":
		cmdLighthouseRotateCert(args[1:])
	case "rotation-record":
		cmdLighthouseRotationRecord(args[1:])
	case "add", "replace", "remove", "list":
		cmdLighthouseRegistry(args)
	default:
		fatalf("lighthouse: unknown subcommand %q", sub)
	}
}

// cmdLighthouseRegistry handles the add/replace/remove/list registry actions, which
// all share one flagset (db + ip/addrs/name/actor). Split from cmdLighthouse so the
// latter stays a single positional switch the CLI-surface extractor can read.
func cmdLighthouseRegistry(args []string) {
	sub := args[0]
	fs := flag.NewFlagSet("lighthouse "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	ip := fs.String("ip", "", "lighthouse overlay IP")
	addrs := fs.String("addrs", "", "comma-separated public underlay addrs host:port")
	name := fs.String("name", "", "optional friendly hostname")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	staticHM := fs.Bool("static-host-map", false, "list: emit ACTIVE lighthouses as machine-readable 'overlay_ip<TAB>json-addrs' lines (the registry is the source of truth; used by recover to reseed harbor's config)")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	reg := lighthouse.New(s.DB, audit)
	ctx := context.Background()

	switch sub {
	case "add":
		if *ip == "" || *addrs == "" {
			fatalf("lighthouse add: -ip and -addrs are required")
		}
		if _, err := reg.Add(ctx, *ip, *name, parseCSV(*addrs), *actor); err != nil {
			fatalf("lighthouse add: %v", err)
		}
		fmt.Printf("added lighthouse %s (%s)\n", *ip, *addrs)
		startLighthouseConvergence(s, "add "+*ip)
	case "replace":
		if *ip == "" || *addrs == "" {
			fatalf("lighthouse replace: -ip and -addrs are required")
		}
		if _, err := reg.Replace(ctx, *ip, parseCSV(*addrs), *actor); err != nil {
			fatalf("lighthouse replace: %v", err)
		}
		fmt.Printf("re-addressed lighthouse %s -> %s\n", *ip, *addrs)
		startLighthouseConvergence(s, "re-address "+*ip)
	case "remove":
		if *ip == "" {
			fatalf("lighthouse remove: -ip is required")
		}
		if err := reg.Remove(ctx, *ip, *actor); err != nil {
			fatalf("lighthouse remove: %v", err)
		}
		fmt.Printf("removed lighthouse %s (no longer advertised)\n", *ip)
		startLighthouseConvergence(s, "remove "+*ip)
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("lighthouse list: %v", err)
		}
		if *staticHM {
			// Machine-readable: ACTIVE lighthouses only, 'overlay_ip<TAB>json-addrs' per line.
			// The registry is the source of truth (it carries the REAL overlay IPs, which can
			// differ from the deterministic terraform scheme after a day-2 add) — recover uses
			// this to reseed harbor's static_host_map + lighthouse.hosts.
			for _, r := range rows {
				if r.State != lighthouse.StateActive {
					continue
				}
				b, _ := json.Marshal(r.Addrs())
				fmt.Printf("%s\t%s\n", r.OverlayIP, b)
			}
			return
		}
		if len(rows) == 0 {
			fmt.Println("no lighthouses registered")
			return
		}
		fmt.Printf("%-16s %-9s %-20s %s\n", "OVERLAY_IP", "STATE", "HOSTNAME", "PUBLIC_ADDRS")
		for _, r := range rows {
			fmt.Printf("%-16s %-9s %-20s %v\n", r.OverlayIP, r.State, r.Hostname, r.Addrs())
		}
	default:
		fatalf("lighthouse: unknown subcommand %q", sub)
	}
}

// startLighthouseConvergence stages a fleet-wide bundle refetch after a lighthouse registry
// change, so ALREADY-RUNNING hosts pick up the new discovery topology. Without it, a lighthouse
// add/remove reaches a running host only at its next UNRELATED refetch (re-enroll / policy
// rollout) — multi-lighthouse HA would silently fail to reach the live fleet. (This is the
// "harbor stuck on lighthouse-1" bug: the bundle's lighthouse set is rendered always-latest from
// the registry, but a pilot only refetches on an apply_bundle, which Core issues solely on a
// version increase — and a lighthouse change does NOT bump the policy version.)
//
// We ride the BLOCKLIST convergence lane: the existing "always-latest content + monotonic
// generation" lane (rollout.go) that every deployed pilot already converges on cleanly (it
// reports applied_blocklist_version). So this is backward-compatible — no new wire field, no
// pilot update, no churn — and a single apply_bundle refetches the FULL bundle, carrying the
// latest lighthouse set along with the (unchanged) blocklist content. Best-effort: a failure
// here never fails the registry change (the change is already committed; hosts still converge
// at their next refetch).
func startLighthouseConvergence(s *store.Store, desc string) {
	ctx := context.Background()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	eng := rollout.New(s.DB, audit)
	var ips []string
	if err := s.DB.WithContext(ctx).Table("heartbeats").Order("overlay_ip ASC").Pluck("overlay_ip", &ips).Error; err != nil {
		fmt.Printf("note: lighthouse change saved, but reading the fleet to converge failed (%v); hosts pick it up at their next bundle refetch\n", err)
		return
	}
	target := eng.BlocklistVersion(ctx) + 1
	r, err := eng.Start(ctx, rollout.StartConfig{
		Lane: rollout.LaneBlocklist, Description: "lighthouse: " + desc,
		TargetVersion: target, PrevVersion: target - 1, Hosts: ips,
		CanarySize: 1, WaveSize: 0, Observe: 5 * time.Minute, MissingAfter: 3 * time.Minute, Actor: "lighthouse",
	})
	switch {
	case errors.Is(err, rollout.ErrNoHosts):
		fmt.Println("note: no fleet heartbeats yet — the new lighthouse set propagates at each host's next bundle refetch")
	case errors.Is(err, rollout.ErrActiveExists):
		fmt.Println("note: a convergence rollout is already in flight — this change rides the latest bundle and converges with it")
	case err != nil:
		fmt.Printf("note: lighthouse change saved, but the convergence rollout did not start (%v); hosts pick it up at their next refetch\n", err)
	default:
		fmt.Printf("staged fleet convergence (blocklist lane v%d) over %d host(s); core-api drives the refetch on heartbeats\n", r.TargetVersion, len(ips))
	}
}

// cmdGateway manages the pull-based enrollment-gateway registry (ADR 0005). The
// collector (`harbor collect`) polls the active gateways here over leaf-pinned
// mTLS. Adding a gateway pins its self-signed server cert; removing it stops the
// collector polling it. Mirrors `harbor lighthouse`.
func cmdGateway(args []string) {
	if len(args) < 1 {
		fatalf("gateway: want add|remove|list")
	}
	sub := args[0]
	fs := flag.NewFlagSet("gateway "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	name := fs.String("name", "", "gateway name")
	url := fs.String("url", "", "gateway collect URL (https://host:port)")
	certPath := fs.String("cert", "", "gateway's server cert PEM (its leaf is pinned)")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	reg := gatewayreg.New(s.DB, audit)
	ctx := context.Background()

	switch sub {
	case "add":
		if *name == "" || *url == "" || *certPath == "" {
			fatalf("gateway add: -name, -url and -cert are required")
		}
		certPEM, err := os.ReadFile(*certPath)
		if err != nil {
			fatalf("gateway add: read -cert: %v", err)
		}
		if _, err := reg.Add(ctx, *name, *url, string(certPEM), *actor); err != nil {
			fatalf("gateway add: %v", err)
		}
		pin, _ := collect.PinFromCertPEM(certPEM)
		fmt.Printf("registered gateway %s (%s)\npinned leaf (sha256): %x\n", *name, *url, pin)
	case "remove":
		if *name == "" {
			fatalf("gateway remove: -name is required")
		}
		if err := reg.Remove(ctx, *name, *actor); err != nil {
			fatalf("gateway remove: %v", err)
		}
		fmt.Printf("removed gateway %s (no longer polled)\n", *name)
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("gateway list: %v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no gateways registered")
			return
		}
		fmt.Printf("%-16s %-9s %-36s %s\n", "NAME", "STATE", "URL", "PIN")
		for _, r := range rows {
			var pinStr string
			if pin, err := collect.PinFromCertPEM([]byte(r.CertPEM)); err == nil {
				pinStr = fmt.Sprintf("%x", pin[:8])
			} else {
				pinStr = "(bad cert)"
			}
			fmt.Printf("%-16s %-9s %-36s %s…\n", r.Name, r.State, r.URL, pinStr)
		}
	default:
		fatalf("gateway: unknown subcommand %q", sub)
	}
}
