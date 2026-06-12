// Command pilot is the Nebula Control Plane host agent. It supervises a local
// nebula process and (in later milestones) handles enrollment, renewal, config
// rendering, and drift control. See docs/ and CLAUDE.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeks313/nebula-control-plane/internal/supervisor"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
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
  pilot supervise -config <nebula.yml> [-nebula <path>] [-sha256 <hex>]
  pilot version

commands:
  supervise   run and supervise the nebula subprocess (restart w/ backoff,
              clean shutdown on SIGINT/SIGTERM, optional binary digest check)
`)
}

func cmdSupervise(args []string) {
	fs := flag.NewFlagSet("supervise", flag.ExitOnError)
	nebulaPath := fs.String("nebula", "nebula", "path to the nebula binary")
	configPath := fs.String("config", "", "path to nebula config.yml (required)")
	sha := fs.String("sha256", "", "optional: expected hex sha256 of the nebula binary (verified before exec)")
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
	if err := sup.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "pilot: %v\n", err)
		os.Exit(1)
	}
}
