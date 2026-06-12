//go:build windows

package main

import (
	"context"

	"github.com/jeks313/nebula-control-plane/internal/supervisor"
)

// Windows has no SIGHUP, so there is no signal-driven hot-reload path. Config
// changes apply via a supervised restart instead (M1.8 / M1.10).
func installReload(_ context.Context, _ *supervisor.Supervisor) {}
