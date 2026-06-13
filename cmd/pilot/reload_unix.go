//go:build !windows

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeks313/nebula-control-plane/internal/supervisor"
)

// installReload makes SIGHUP to pilot trigger a hot-reload of nebula (M1.8).
// This is the operator/-policy path for firewall/lighthouse/PKI changes that
// Nebula can apply in place without dropping tunnels.
func installReload(ctx context.Context, sup *supervisor.Supervisor, log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				if err := sup.Reload(); err != nil {
					log.Error("nebula reload failed (SIGHUP)", "err", err)
				} else {
					log.Info("nebula reloaded (SIGHUP)")
				}
			}
		}
	}()
}
