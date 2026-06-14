//go:build windows

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
)

// defaultNebulaPath is where `pilot install` expects the nebula binary on Windows.
// Override with `pilot install -nebula <path>` if nebula.exe lives elsewhere.
const defaultNebulaPath = `C:\Program Files\Nebula\nebula.exe`

// prepareServiceLogging redirects this process's stdout+stderr to <dir>\pilot.log
// when supervise is launched by the Windows SCM. A service has no console, so
// clilog's writes to os.Stderr and nebula's inherited stdout/stderr would
// otherwise be discarded. Mirrors the launchd StandardOut/StandardErrorPath ->
// pilot.log. Must run before clilog.Setup so the logger targets the file. No-op
// when run interactively (the Ctrl+C path) or without -dir.
func prepareServiceLogging(dir string) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return
	}
	logPath := filepath.Join(os.TempDir(), "nebula-pilot.log") // used when -dir is empty
	if dir != "" {
		_ = os.MkdirAll(dir, 0o755) // self-heal a missing StateDir
		logPath = filepath.Join(dir, "pilot.log")
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil && dir != "" {
		// <dir>\pilot.log is unwritable; fall back to %TEMP% rather than run blind,
		// so the open failure (and every later log line) leaves a breadcrumb instead
		// of vanishing into the service's null console.
		f, err = os.OpenFile(filepath.Join(os.TempDir(), "nebula-pilot.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	}
	if err != nil {
		return
	}
	os.Stdout = f
	os.Stderr = f
}

// runSupervisor drives serve. Under the SCM it runs inside the service control
// loop (Stop/Shutdown -> ctx cancel, with status reporting). Run interactively it
// falls back to Ctrl+C, mirroring the Unix SIGINT path.
func runSupervisor(serve func(context.Context) error, log *slog.Logger) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return serve(ctx)
	}
	// The name is informational: the SCM binds the handler to the service it
	// launched this process under, not to this string.
	return svc.Run("nebula-pilot", &superviseHandler{serve: serve, log: log})
}

// superviseHandler adapts the cross-platform supervise loop to the SCM Handler
// interface: Execute starts serve, reports Running, and on Stop/Shutdown cancels
// the context and waits for nebula to be torn down before reporting Stopped.
type superviseHandler struct {
	serve func(context.Context) error
	log   *slog.Logger
}

func (h *superviseHandler) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.serve(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-done:
			// serve exited on its own — an unrecoverable supervise error (e.g. a
			// binary-digest mismatch). Return a service-specific failure (exit 1);
			// the SCM runs the configured ServiceRestart actions because Install
			// set SetRecoveryActionsOnNonCrashFailures(true) (without that flag a
			// STOPPED-with-nonzero-exit is treated as a clean stop and never restarts).
			status <- svc.Status{State: svc.Stopped}
			if err != nil {
				h.log.Error("pilot supervise exited", "err", err)
				return true, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 20000}
				cancel()
				err := <-done // let the supervisor stop nebula before we report Stopped
				status <- svc.Status{State: svc.Stopped}
				if err != nil {
					// A crash that raced the stop: report a failure so recovery can
					// act, rather than laundering the crash into a clean exit.
					h.log.Error("pilot supervise exited during stop", "err", err)
					return true, 1
				}
				return false, 0
			default:
				h.log.Warn("unexpected service control request", "cmd", uint32(c.Cmd))
			}
		}
	}
}
