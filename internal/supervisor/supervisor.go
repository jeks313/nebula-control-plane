// Package supervisor runs and supervises the nebula subprocess
// (implementation-plan M1.6): start, monitor, exponential-backoff restart,
// digest verification before each exec (M1.5), and clean shutdown.
package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/binverify"
)

// Supervisor owns a single nebula child process.
type Supervisor struct {
	NebulaPath     string // path to the nebula binary
	ConfigPath     string // path to nebula config.yml
	ExpectedSHA256 string // optional: verified before every exec (M1.5)

	// Backoff tuning (zero values get sane defaults).
	MinBackoff  time.Duration // first restart delay
	MaxBackoff  time.Duration // cap
	StableAfter time.Duration // a run this long resets backoff to MinBackoff
	GracePeriod time.Duration // wait after SIGTERM before SIGKILL on shutdown

	Logger *slog.Logger
}

func (s *Supervisor) defaults() {
	if s.MinBackoff <= 0 {
		s.MinBackoff = time.Second
	}
	if s.MaxBackoff <= 0 {
		s.MaxBackoff = 30 * time.Second
	}
	if s.StableAfter <= 0 {
		s.StableAfter = 60 * time.Second
	}
	if s.GracePeriod <= 0 {
		s.GracePeriod = 10 * time.Second
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
}

// Run supervises nebula until ctx is cancelled, restarting it with backoff if it
// exits on its own. Returns nil on clean shutdown (ctx cancelled), or an error
// for unrecoverable conditions (e.g. digest verification failure).
func (s *Supervisor) Run(ctx context.Context) error {
	s.defaults()
	backoff := s.MinBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		if s.ExpectedSHA256 != "" {
			if err := binverify.SHA256(s.NebulaPath, s.ExpectedSHA256); err != nil {
				return fmt.Errorf("refusing to exec nebula: %w", err)
			}
			s.Logger.Info("nebula binary digest verified", "path", s.NebulaPath)
		}

		start := time.Now()
		runErr := s.runOnce(ctx)
		ran := time.Since(start)

		if ctx.Err() != nil {
			s.Logger.Info("shutdown complete")
			return nil
		}

		if ran >= s.StableAfter {
			backoff = s.MinBackoff // it ran healthily; reset
		}
		s.Logger.Warn("nebula exited; restarting",
			"ran", ran.Round(time.Millisecond), "err", runErr, "backoff", backoff)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = nextBackoff(backoff, s.MaxBackoff)
	}
}

// runOnce starts nebula and blocks until it exits or ctx is cancelled. On
// cancellation it asks nebula to stop (SIGTERM), then SIGKILLs after GracePeriod.
func (s *Supervisor) runOnce(ctx context.Context) error {
	cmd := exec.Command(s.NebulaPath, "-config", s.ConfigPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	setSysProcAttr(cmd) // own process group, so we can stop children too
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start nebula: %w", err)
	}
	s.Logger.Info("nebula started", "pid", cmd.Process.Pid)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		s.Logger.Info("stopping nebula", "pid", cmd.Process.Pid)
		_ = terminate(cmd)
		select {
		case <-done:
		case <-time.After(s.GracePeriod):
			s.Logger.Warn("grace period elapsed; killing nebula")
			_ = forceKill(cmd)
			<-done
		}
		return ctx.Err()
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	n := cur * 2
	if n > max {
		return max
	}
	return n
}
