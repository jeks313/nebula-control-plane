//go:build !windows

package main

import (
	"context"
	"log/slog"
	"os/signal"
	"syscall"
)

// defaultNebulaPath is where `pilot install` expects the nebula binary on Unix.
const defaultNebulaPath = "/usr/local/bin/nebula"

// prepareServiceLogging is a no-op on Unix: systemd captures the service's
// stdout/stderr to the journal, and launchd redirects them to the plist's
// StandardOut/StandardErrorPath. Only the Windows SCM (no console) needs pilot to
// open its own log file.
func prepareServiceLogging(string) {}

// runSupervisor runs serve with a context cancelled on SIGINT/SIGTERM — the stop
// signal systemd and launchd send. serve returns nil on a clean shutdown.
func runSupervisor(serve func(context.Context) error, _ *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx)
}
