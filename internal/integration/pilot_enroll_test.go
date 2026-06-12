package integration

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollclient"
	"github.com/jeks313/nebula-control-plane/internal/gateway"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/paths"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// drainer runs Core's queue consumer in the background until ctx is cancelled.
func (e enrollEnv) drainer(ctx context.Context) {
	go func() {
		for ctx.Err() == nil {
			_, _ = e.cons.Drain(ctx, e.d, 10, time.Minute)
			time.Sleep(20 * time.Millisecond)
		}
	}()
}

// TestPilotEnrollAutoIssue is the M3.7 acceptance: a bare host runs the enroll
// client and joins — gen key → nonce → signed submit → poll → verify the bundle
// against the pinned key → write files. With nebula present, the rendered node
// config is startable.
func TestPilotEnrollAutoIssue(t *testing.T) {
	e := setupEnroll(t)
	srv := httptest.NewServer(gateway.New(gateway.Config{Nonces: e.ring, Queue: e.d, Results: e.d}).Handler())
	defer srv.Close()

	secret, _, _ := joinkey.Create(context.Background(), e.store,
		joinkey.Params{Name: "k", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())

	dir := t.TempDir()
	layout := paths.New(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.drainer(ctx)

	res, err := enrollclient.Enroll(ctx, enrollclient.Params{
		GatewayURL: srv.URL, JoinKey: secret, Layout: layout,
		RequestedName: "host-z", PinnedConfigPub: e.pinned, PollTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if res.Status != "issued" {
		t.Fatalf("status = %s, want issued", res.Status)
	}
	if !e.pool.Contains(mustAddr(t, res.OverlayIP)) {
		t.Fatalf("overlay IP %s not in pool", res.OverlayIP)
	}

	for _, f := range []string{layout.HostKey(), layout.HostCert(), layout.CABundle(), layout.Config()} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("expected %s: %v", f, err)
		}
	}
	if perm := mustMode(t, layout.HostKey()); perm != 0o600 {
		t.Fatalf("host.key mode = %o, want 0600", perm)
	}

	// If nebula is installed, the enrolled node config is valid + startable.
	if nebula, err := exec.LookPath("nebula"); err == nil {
		out, err := exec.Command(nebula, "-test", "-config", layout.Config()).CombinedOutput()
		if err != nil {
			t.Fatalf("nebula -test on enrolled config failed: %v\n%s", err, out)
		}
	}
}

// TestPilotEnrollPendingByDefault: a join key without auto_issue leaves the host
// awaiting approval — no cert written.
func TestPilotEnrollPendingByDefault(t *testing.T) {
	e := setupEnroll(t)
	srv := httptest.NewServer(gateway.New(gateway.Config{Nonces: e.ring, Queue: e.d, Results: e.d}).Handler())
	defer srv.Close()

	secret, _, _ := joinkey.Create(context.Background(), e.store,
		joinkey.Params{Name: "manual", Groups: []string{"web"}, MaxUses: 0}, time.Now()) // auto_issue=false

	dir := t.TempDir()
	layout := paths.New(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.drainer(ctx)

	res, err := enrollclient.Enroll(ctx, enrollclient.Params{
		GatewayURL: srv.URL, JoinKey: secret, Layout: layout,
		RequestedName: "host-pending", PinnedConfigPub: e.pinned, PollTimeout: 1500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if res.Status != "pending" {
		t.Fatalf("status = %s, want pending (manual approval default)", res.Status)
	}
	if _, err := os.Stat(layout.HostCert()); !os.IsNotExist(err) {
		t.Fatal("no cert should be written while pending")
	}
}
