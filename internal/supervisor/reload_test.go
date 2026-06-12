package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// countLines returns how many newline-terminated entries a file currently holds.
func countLines(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "\n")
}

// waitForCount polls until path has at least n lines, or fails after a timeout.
func waitForCount(t *testing.T, path string, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if countLines(path) >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to reach %d lines (have %d)", path, n, countLines(path))
}

// TestReloadSendsSIGHUPWithoutRestart is the Unix half of the M1.8 matrix: a
// hot-reload signals the *same* nebula process (SIGHUP) and never cycles it.
func TestReloadSendsSIGHUPWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	starts := filepath.Join(dir, "starts")
	hups := filepath.Join(dir, "hups")
	body := "echo start >> " + starts + "\n" +
		"trap 'echo hup >> " + hups + "' HUP\n" +
		"trap 'exit 0' TERM\n" +
		"while true; do sleep 0.05; done"
	bin := writeScript(t, body)

	s := &Supervisor{NebulaPath: bin, ConfigPath: "x", GracePeriod: time.Second, Logger: quietLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitForCount(t, starts, 1) // child is up

	for i := 1; i <= 3; i++ {
		if err := s.Reload(); err != nil {
			t.Fatalf("Reload #%d: %v", i, err)
		}
		waitForCount(t, hups, i)
	}

	if c := countLines(starts); c != 1 {
		t.Fatalf("starts = %d, want 1 (reload must not restart the process)", c)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestRestartCyclesChild is the other half: Restart performs a supervised
// stop+start (one extra start), used for changes nebula can't hot-reload and as
// the Windows reload fallback.
func TestRestartCyclesChild(t *testing.T) {
	dir := t.TempDir()
	starts := filepath.Join(dir, "starts")
	body := "echo start >> " + starts + "\n" +
		"trap 'exit 0' TERM\n" +
		"while true; do sleep 0.05; done"
	bin := writeScript(t, body)

	s := &Supervisor{
		NebulaPath: bin, ConfigPath: "x",
		MinBackoff: 5 * time.Millisecond, MaxBackoff: 10 * time.Millisecond,
		GracePeriod: time.Second, Logger: quietLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitForCount(t, starts, 1)
	if err := s.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	waitForCount(t, starts, 2) // cycled exactly once more

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestReloadNotRunning returns a clear error when there is no child to signal.
func TestReloadNotRunning(t *testing.T) {
	s := &Supervisor{NebulaPath: "x", ConfigPath: "x", Logger: quietLogger()}
	if err := s.Reload(); err == nil {
		t.Fatal("Reload with no running child should error")
	}
}
