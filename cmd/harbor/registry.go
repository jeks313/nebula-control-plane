package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/jeks313/nebula-control-plane/internal/collect"
	"github.com/jeks313/nebula-control-plane/internal/gatewayreg"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
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
	case "replace":
		if *ip == "" || *addrs == "" {
			fatalf("lighthouse replace: -ip and -addrs are required")
		}
		if _, err := reg.Replace(ctx, *ip, parseCSV(*addrs), *actor); err != nil {
			fatalf("lighthouse replace: %v", err)
		}
		fmt.Printf("re-addressed lighthouse %s -> %s\n", *ip, *addrs)
	case "remove":
		if *ip == "" {
			fatalf("lighthouse remove: -ip is required")
		}
		if err := reg.Remove(ctx, *ip, *actor); err != nil {
			fatalf("lighthouse remove: %v", err)
		}
		fmt.Printf("removed lighthouse %s (no longer advertised)\n", *ip)
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("lighthouse list: %v", err)
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
