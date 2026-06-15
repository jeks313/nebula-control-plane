// Package supervisor runs and supervises the nebula subprocess
// (implementation-plan M1.6): start, monitor, exponential-backoff restart,
// digest verification before each exec (M1.5), and clean shutdown. It also
// exposes the two control primitives the reload/restart matrix needs (M1.8):
// Reload (SIGHUP, hot-reload of firewall/lighthouse/PKI on Unix) and Restart (a
// supervised stop+start, used for changes Nebula can't hot-reload and as the
// Windows fallback where there is no SIGHUP).
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/binverify"
)

// ErrNotRunning is returned by Reload when there is no live child to signal.
var ErrNotRunning = errors.New("supervisor: nebula is not currently running")

// ErrReloadUnsupported is returned by Reload on platforms without SIGHUP
// (Windows). Callers should fall back to Restart (this is the M1.8 matrix).
var ErrReloadUnsupported = errors.New("supervisor: hot reload not supported on this platform")

// errIntentionalRestart is returned internally by runOnce when Restart() asked
// for a cycle, so Run restarts immediately (no backoff) and does not treat it as
// a crash.
var errIntentionalRestart = errors.New("supervisor: intentional restart")

// Supervisor owns a single nebula child process.
type Supervisor struct {
	NebulaPath     string // path to the nebula binary
	ConfigPath     string // path to nebula config.yml
	ExpectedSHA256 string // optional: verified before every exec (M1.5)
	// AdoptPID, if >0, is a nebula PID a previous pilot left running across a re-exec
	// self-update (ADR 0003 Phase 3). Run monitors it (signal-0 poll) instead of
	// forking a fresh nebula, so the data plane never drops; when it exits or a restart
	// is requested, Run falls through to normal fork supervision. Unix-only.
	AdoptPID int

	// Backoff tuning (zero values get sane defaults).
	MinBackoff  time.Duration // first restart delay
	MaxBackoff  time.Duration // cap
	StableAfter time.Duration // a run this long resets backoff to MinBackoff
	GracePeriod time.Duration // wait after SIGTERM before SIGKILL on shutdown

	Logger *slog.Logger

	initOnce  sync.Once
	restartCh chan struct{}

	mu         sync.Mutex
	cmd        *exec.Cmd // the currently running forked child, or nil
	adoptedPid int       // an adopted (not forked) nebula PID, or 0 (ADR 0003 Phase 3)
	startedAt  time.Time // when cmd/adoptedPid was last set (zero when not running)
}

// Health is a point-in-time view of the supervised child, for the self-update
// health gate (ADR 0003 Phase 1c). A binary that won't come up shows Running=false
// or an Uptime that keeps resetting near zero (it crash-loops under backoff), so a
// caller that waits for a SUSTAINED Uptime can distinguish "came up and held" from
// "flapping" — the signal the nebula updater uses to revert a bad swap.
type Health struct {
	Running   bool
	Pid       int
	StartedAt time.Time // when the current child started (zero if not running)
	Uptime    time.Duration
}

// defaults fills zero-valued config + creates restartCh. It runs exactly once
// (sync.Once): Run and Restart both call it, and Restart fires from the heartbeat
// goroutine, so filling the fields outside the Once would race the scalar writes.
// The Once also publishes the writes (happens-before) to every later reader.
func (s *Supervisor) defaults() {
	s.initOnce.Do(func() {
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
		s.restartCh = make(chan struct{}, 1)
	})
}

// Run supervises nebula until ctx is cancelled, restarting it with backoff if it
// exits on its own. Returns nil on clean shutdown (ctx cancelled), or an error
// for unrecoverable conditions (e.g. digest verification failure).
func (s *Supervisor) Run(ctx context.Context) error {
	s.defaults()
	// ADR 0003 Phase 3: if launched to re-adopt a nebula a previous pilot left running
	// (re-exec self-update), monitor that PID instead of forking — zero data-plane
	// drop. When it exits or a restart is requested, fall through to the fork loop.
	if s.AdoptPID > 0 && adoptSupported() {
		_ = s.adoptOnce(ctx, s.AdoptPID)
		if ctx.Err() != nil {
			return nil //nolint:nilerr // ctx cancelled during adoption is a clean shutdown
		}
	}
	backoff := s.MinBackoff
	for {
		if ctx.Err() != nil {
			return nil //nolint:nilerr // ctx cancelled is a clean shutdown, not an error
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
			return nil //nolint:nilerr // ctx cancelled is a clean shutdown, not an error
		}

		// An operator-requested restart is not a crash: cycle immediately and
		// reset backoff so the next real crash starts from MinBackoff again.
		if errors.Is(runErr, errIntentionalRestart) {
			s.Logger.Info("restarting nebula on request")
			backoff = s.MinBackoff
			continue
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

// runOnce starts nebula and blocks until it exits, ctx is cancelled, or a
// restart is requested. On cancellation/restart it asks nebula to stop
// (SIGTERM), then SIGKILLs after GracePeriod.
func (s *Supervisor) runOnce(ctx context.Context) error {
	cmd := exec.Command(s.NebulaPath, "-config", s.ConfigPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	setSysProcAttr(cmd) // own process group, so we can stop children too
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start nebula: %w", err)
	}
	s.setCmd(cmd)
	defer s.setCmd(nil)
	s.Logger.Info("nebula started", "pid", cmd.Process.Pid)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-s.restartCh:
		s.Logger.Info("stopping nebula for restart", "pid", cmd.Process.Pid)
		s.stop(cmd, done)
		return errIntentionalRestart
	case <-ctx.Done():
		s.Logger.Info("stopping nebula", "pid", cmd.Process.Pid)
		s.stop(cmd, done)
		return ctx.Err()
	}
}

// adoptOnce monitors an already-running nebula (pid) that this pilot did NOT fork —
// the re-exec self-update path (ADR 0003 Phase 3). It polls liveness (signal-0; it
// can't Wait() a non-child) and returns when: the adopted process exits (nil → Run
// forks a fresh nebula), a restart is requested (stop it, errIntentionalRestart → Run
// forks), or ctx is cancelled (stop it on shutdown, ctx.Err()).
func (s *Supervisor) adoptOnce(ctx context.Context, pid int) error {
	if !processAlive(pid) {
		return nil // already gone — nothing to adopt; Run forks a fresh nebula
	}
	s.setAdopted(pid)
	defer s.setAdopted(0)
	s.Logger.Info("adopted running nebula (re-exec self-update)", "pid", pid)
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	for {
		select {
		case <-poll.C:
			if !processAlive(pid) {
				s.Logger.Warn("adopted nebula exited; starting a fresh one", "pid", pid)
				return nil
			}
		case <-s.restartCh:
			s.Logger.Info("stopping adopted nebula for restart", "pid", pid)
			s.stopPID(pid)
			return errIntentionalRestart
		case <-ctx.Done():
			s.Logger.Info("stopping adopted nebula", "pid", pid)
			s.stopPID(pid)
			return ctx.Err()
		}
	}
}

// stopPID gracefully stops an adopted nebula by PID (SIGTERM, escalating to SIGKILL
// after GracePeriod), polling for it to actually exit. The adopt analogue of stop.
func (s *Supervisor) stopPID(pid int) {
	_ = terminatePID(pid)
	deadline := time.After(s.GracePeriod)
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-deadline:
			s.Logger.Warn("grace period elapsed; killing adopted nebula", "pid", pid)
			_ = forceKillPID(pid)
			return
		case <-t.C:
			if !processAlive(pid) {
				return
			}
		}
	}
}

func (s *Supervisor) setAdopted(pid int) {
	s.mu.Lock()
	s.adoptedPid = pid
	switch {
	case pid != 0:
		s.startedAt = time.Now()
	case s.cmd == nil:
		s.startedAt = time.Time{}
	}
	s.mu.Unlock()
}

// stop terminates the child's process group gracefully, escalating to SIGKILL
// after GracePeriod, and waits for it to be reaped.
func (s *Supervisor) stop(cmd *exec.Cmd, done <-chan error) {
	_ = terminate(cmd)
	select {
	case <-done:
	case <-time.After(s.GracePeriod):
		s.Logger.Warn("grace period elapsed; killing nebula")
		_ = forceKill(cmd)
		<-done
	}
}

// Reload asks the running nebula to hot-reload its config in place (SIGHUP on
// Unix). In Nebula v1.10.x this reloads firewall rules, lighthouse/static host
// map, punchy, logging, and the PKI cert + CA bundle — as long as the cert's
// overlay networks and curve are unchanged. Returns ErrReloadUnsupported on
// Windows (caller should Restart) and ErrNotRunning if there is no child.
func (s *Supervisor) Reload() error {
	s.mu.Lock()
	cmd := s.cmd
	pid := s.adoptedPid
	s.mu.Unlock()
	switch {
	case cmd != nil && cmd.Process != nil:
		return signalReload(cmd)
	case pid != 0:
		return signalReloadPID(pid) // an adopted nebula reloads by PID (ADR 0003 Phase 3)
	default:
		return ErrNotRunning
	}
}

// Restart requests a supervised stop+start of nebula. It returns once the
// request is queued; the running supervisor performs the cycle. Used for changes
// Nebula cannot hot-reload (listen socket, tun device, cert IP/curve) and as the
// Windows reload fallback.
func (s *Supervisor) Restart() error {
	s.defaults()
	select {
	case s.restartCh <- struct{}{}:
	default: // a restart is already pending; coalesce
	}
	return nil
}

func (s *Supervisor) setCmd(cmd *exec.Cmd) {
	s.mu.Lock()
	s.cmd = cmd
	if cmd != nil {
		s.startedAt = time.Now()
	} else {
		s.startedAt = time.Time{}
	}
	s.mu.Unlock()
}

// Health returns whether nebula is currently running and, if so, how long the
// CURRENT child has been up (ADR 0003 Phase 1c).
func (s *Supervisor) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.cmd != nil && s.cmd.Process != nil:
		return Health{Running: true, Pid: s.cmd.Process.Pid, StartedAt: s.startedAt, Uptime: time.Since(s.startedAt)}
	case s.adoptedPid != 0:
		return Health{Running: true, Pid: s.adoptedPid, StartedAt: s.startedAt, Uptime: time.Since(s.startedAt)}
	default:
		return Health{}
	}
}

// Healthy is the point-in-time data-plane verdict: nebula is up AND has held for at
// least minUptime. The uptime floor distinguishes "came up and stayed" from a FAST
// crash-loop (cycles shorter than minUptime, which keep resetting Uptime near zero under
// backoff); a slower crash-loop that holds past minUptime each cycle still reads healthy.
// Callers that report health should debounce a single negative — right after a legitimate
// restart Uptime is briefly below the floor — so a transient is not mistaken for failure.
func (h Health) Healthy(minUptime time.Duration) bool {
	return h.Running && h.Uptime >= minUptime
}

// WaitHealthy blocks until the child that started AFTER notBefore has stayed up
// CONTINUOUSLY for minUptime (it came up and held -> true), or until ctx is done /
// timeout elapses without that (it never stabilized -> false; e.g. a bad binary
// crash-looping). It is the health gate the nebula updater consults after a swap so
// it can revert to last-good when the new binary won't come up (ADR 0003 Phase 1c).
//
// notBefore guards against a false pass: Restart only QUEUES a cycle, so the OLD
// (healthy, long-up) process is still running for a moment — without the
// StartedAt>notBefore check WaitHealthy would immediately approve it and never judge
// the NEW binary. Pass the instant just before Restart was requested.
func (s *Supervisor) WaitHealthy(ctx context.Context, notBefore time.Time, minUptime, timeout time.Duration) bool {
	s.defaults()
	deadline := time.Now().Add(timeout)
	poll := min(max(minUptime/4, 100*time.Millisecond), 2*time.Second)
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		if h := s.Health(); h.Running && h.StartedAt.After(notBefore) && h.Uptime >= minUptime {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	n := cur * 2
	if n > max {
		return max
	}
	return n
}
