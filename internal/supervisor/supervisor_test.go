package supervisor

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeScript creates an executable shell script that ignores its args.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script based test; not for Windows")
	}
	p := filepath.Join(t.TempDir(), "fake-nebula")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNextBackoff(t *testing.T) {
	max := 8 * time.Second
	cases := []struct{ in, want time.Duration }{
		{1 * time.Second, 2 * time.Second},
		{4 * time.Second, 8 * time.Second},
		{8 * time.Second, 8 * time.Second}, // capped
		{16 * time.Second, 8 * time.Second},
	}
	for _, c := range cases {
		if got := nextBackoff(c.in, max); got != c.want {
			t.Errorf("nextBackoff(%v,%v)=%v want %v", c.in, max, got, c.want)
		}
	}
}

func TestRunDigestMismatchFailsFast(t *testing.T) {
	bin := writeScript(t, "sleep 5")
	s := &Supervisor{NebulaPath: bin, ConfigPath: "x", ExpectedSHA256: "deadbeef", Logger: quietLogger()}
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("expected error on digest mismatch, got nil")
	}
}

func TestRunShutdownIsClean(t *testing.T) {
	bin := writeScript(t, "sleep 30")
	s := &Supervisor{NebulaPath: bin, ConfigPath: "x", GracePeriod: time.Second, Logger: quietLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("clean shutdown should return nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return promptly after cancel")
	}
}

// TestWaitHealthy is the ADR 0003 Phase 1c health-gate signal: a binary that stays
// up satisfies WaitHealthy (came up and held), while one that crash-loops never
// does (it times out false) — the discriminator the nebula updater uses to keep or
// revert a swap.
func TestWaitHealthy(t *testing.T) {
	t.Run("stays up -> healthy", func(t *testing.T) {
		bin := writeScript(t, "sleep 30")
		s := &Supervisor{NebulaPath: bin, ConfigPath: "x", MinBackoff: 10 * time.Millisecond, Logger: quietLogger()}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		before := time.Now()
		go func() { _ = s.Run(ctx) }()
		if !s.WaitHealthy(ctx, before, 300*time.Millisecond, 3*time.Second) {
			t.Fatal("a binary that stays up should report healthy")
		}
	})

	t.Run("crash-loops -> never healthy", func(t *testing.T) {
		bin := writeScript(t, "exit 1") // dies immediately, forever
		s := &Supervisor{
			NebulaPath: bin, ConfigPath: "x",
			MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond, Logger: quietLogger(),
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		before := time.Now()
		go func() { _ = s.Run(ctx) }()
		if s.WaitHealthy(ctx, before, 300*time.Millisecond, time.Second) {
			t.Fatal("a crash-looping binary must never report healthy")
		}
	})

	// The race-fix guard: a long-up process that started BEFORE notBefore must not
	// count (it's the old binary still shutting down), so WaitHealthy times out false.
	t.Run("ignores the pre-notBefore process", func(t *testing.T) {
		bin := writeScript(t, "sleep 30")
		s := &Supervisor{NebulaPath: bin, ConfigPath: "x", MinBackoff: 10 * time.Millisecond, Logger: quietLogger()}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = s.Run(ctx) }()
		// Let the (old) process get well established, THEN set the reference point.
		time.Sleep(200 * time.Millisecond)
		notBefore := time.Now()
		if s.WaitHealthy(ctx, notBefore, 100*time.Millisecond, 600*time.Millisecond) {
			t.Fatal("a process that started before notBefore must not satisfy the gate")
		}
	})

	t.Run("ctx cancel -> false", func(t *testing.T) {
		bin := writeScript(t, "sleep 30")
		s := &Supervisor{NebulaPath: bin, ConfigPath: "x", MinBackoff: 10 * time.Millisecond, Logger: quietLogger()}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = s.Run(ctx) }()
		go func() { time.Sleep(50 * time.Millisecond); cancel() }()
		if s.WaitHealthy(ctx, time.Time{}, 5*time.Second, 10*time.Second) {
			t.Fatal("cancelled wait must return false")
		}
	})
}

func TestRunRestartsOnExit(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "runs")
	bin := writeScript(t, "echo x >> "+counter+"; exit 1")
	s := &Supervisor{
		NebulaPath: bin, ConfigPath: "x",
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
		Logger: quietLogger(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := s.Run(ctx); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	data, _ := os.ReadFile(counter)
	runs := strings.Count(string(data), "x")
	if runs < 2 {
		t.Fatalf("expected nebula to be restarted (>=2 runs), got %d", runs)
	}
}
