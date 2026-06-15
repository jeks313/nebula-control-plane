package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/pilotupdate"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/supervisor"
)

// TestNebulaHealthFnDebounce: down/young is tolerated within the wall-clock window
// (so an in-flight restart never escalates), escalates to "unhealthy" only once sustained
// past it, recovery resets — and crucially it's INTERVAL-INDEPENDENT (many rapid bad
// beats inside the window never escalate), which is what makes a lower heartbeat interval
// safe.
func TestNebulaHealthFnDebounce(t *testing.T) {
	var h supervisor.Health
	now := time.Unix(1_700_000_000, 0)
	fn := nebulaHealthFn(func() supervisor.Health { return h }, func() time.Time { return now })

	up := supervisor.Health{Running: true, Uptime: time.Hour}
	down := supervisor.Health{Running: false}
	young := supervisor.Health{Running: true, Uptime: 2 * time.Second} // crash-loop look-alike

	// Healthy -> ok.
	h = up
	if got := fn(); got != "ok" {
		t.Fatalf("healthy = %q, want ok", got)
	}

	// Down, but within the 90s window -> tolerated (a restart in flight).
	h = down
	if got := fn(); got != "ok" {
		t.Fatalf("first down = %q, want ok (within window)", got)
	}
	now = now.Add(60 * time.Second)
	if got := fn(); got != "ok" {
		t.Fatalf("down 60s = %q, want ok (still within window)", got)
	}
	// Past the window -> unhealthy.
	now = now.Add(40 * time.Second) // 100s since first bad
	if got := fn(); got != "unhealthy" {
		t.Fatalf("down 100s = %q, want unhealthy", got)
	}

	// Recovery clears the window; a later brief transient is tolerated again.
	h, now = up, now.Add(10*time.Second)
	if got := fn(); got != "ok" {
		t.Fatalf("recovered = %q, want ok", got)
	}
	h, now = young, now.Add(10*time.Second)
	if got := fn(); got != "ok" {
		t.Fatalf("brief young after recovery = %q, want ok", got)
	}

	// Interval-independence: a flurry of rapid bad beats inside the window never escalates
	// (the prior beat-count debounce would have fired on beat 2 regardless of spacing).
	h, now = up, now.Add(time.Hour) // reset to a clean healthy baseline
	_ = fn()
	h = down
	base := now
	for i := 0; i < 6; i++ {
		now = base.Add(time.Duration(i*10) * time.Second) // 0..50s, all < 90s
		if got := fn(); got != "ok" {
			t.Fatalf("rapid bad beat at +%ds = %q, want ok (interval-independent)", i*10, got)
		}
	}
}

// TestDesiredPilotResolution covers the override-vs-bundle glue that the live 3b test
// (which used overrides) never exercised on the bundle side.
func TestDesiredPilotResolution(t *testing.T) {
	signing, _ := signer.NewSoftwareBackend()
	pubBytes, _ := signing.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pubBytes)
	layout := paths.New(t.TempDir())

	// Full override wins (bundle not consulted).
	if v, s, u, warn := desiredPilot(layout.Bundle(), pinned, "9.9.9", "deadbeef", "http://x/p"); warn != nil || v != "9.9.9" || s != "deadbeef" || u != "http://x/p" {
		t.Fatalf("override: %q/%q/%q warn=%v", v, s, u, warn)
	}
	// Partial override is ignored -> falls through to the (absent) bundle -> empty, no warn.
	if v, s, u, warn := desiredPilot(layout.Bundle(), pinned, "9.9.9", "", ""); warn != nil || v != "" || s != "" || u != "" {
		t.Fatalf("partial override should be ignored: %q/%q/%q warn=%v", v, s, u, warn)
	}
	// Missing bundle (pre-enrollment) is normal: empty, no warn.
	if v, s, u, warn := desiredPilot(layout.Bundle(), pinned, "", "", ""); warn != nil || v != "" || s != "" || u != "" {
		t.Fatalf("missing bundle: %q/%q/%q warn=%v", v, s, u, warn)
	}
	// A bundle signed by a DIFFERENT key fails verification -> no tuple + a warn (never act
	// on an unverified pilot_*).
	other, _ := signer.NewSoftwareBackend()
	signedOther, _ := bundle.Sign(other, "k", bundle.Bundle{
		Device: bundle.Device{Name: "h"}, Certificate: "c", CABundle: []string{"ca"},
		PilotVersion: "2.0.0", PilotSHA256: "abc", PilotURL: "http://x",
	})
	if err := os.WriteFile(layout.Bundle(), signedOther, 0o644); err != nil {
		t.Fatal(err)
	}
	if v, _, _, warn := desiredPilot(layout.Bundle(), pinned, "", "", ""); warn == nil || v != "" {
		t.Fatalf("bundle signed by another key must warn + yield no tuple: warn=%v v=%q", warn, v)
	}
}

// TestBundleDrivenPilotSelfUpdate exercises the full 3c bundle-driven path end-to-end —
// the glue the live 3b validation skipped by using -pilot-* overrides: a SIGNED bundle
// carrying pilot_* -> desiredPilot verifies it against the pinned config-signing key and
// extracts the tuple -> pilotupdate.Sync fetches + sha-verifies + swaps + re-execs. Only
// the real syscall.Exec is elided (validated live; injected here).
func TestBundleDrivenPilotSelfUpdate(t *testing.T) {
	signing, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := signing.PublicKey()
	pinned, err := jws.ParseP256PublicPoint(pubBytes)
	if err != nil {
		t.Fatal(err)
	}

	// The new pilot artifact + its integrity anchor; served over HTTP.
	newPilot := bytes.Repeat([]byte("PILOT-vNEXT"), 4096)
	sum := sha256.Sum256(newPilot)
	newSHA := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(newPilot) }))
	defer srv.Close()

	// A SIGNED bundle pinning that pilot (the integrity anchor rides inside the JWS).
	signed, err := bundle.Sign(signing, "kid-1", bundle.Bundle{
		BundleVersion: 7,
		Device:        bundle.Device{Name: "h", OverlayIP: "100.64.0.9"},
		Certificate:   "CERT", CABundle: []string{"CA"},
		PilotVersion: "2.0.0", PilotSHA256: newSHA, PilotURL: srv.URL + "/pilot",
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	layout := paths.New(dir)
	if err := os.WriteFile(layout.Bundle(), signed, 0o644); err != nil {
		t.Fatal(err)
	}

	// Resolve the tuple from the verified bundle (no override).
	ver, sha, url, warn := desiredPilot(layout.Bundle(), pinned, "", "", "")
	if warn != nil {
		t.Fatalf("desiredPilot warn: %v", warn)
	}
	if ver != "2.0.0" || sha != newSHA || url != srv.URL+"/pilot" {
		t.Fatalf("desiredPilot = %q/%q/%q, want 2.0.0/%s/%s", ver, sha, url, newSHA, srv.URL+"/pilot")
	}

	// Sync drives fetch + sha-verify + swap + re-exec on that tuple.
	self := filepath.Join(dir, "pilot")
	if err := os.WriteFile(self, []byte("PILOT-vPREV"), 0o755); err != nil {
		t.Fatal(err)
	}
	reexeced := false
	m := pilotupdate.New(pilotupdate.Config{
		SelfPath: self, NebulaPidPath: filepath.Join(dir, "nebula.pid"),
		NebulaPID:  func() int { return 4242 },
		Args:       []string{self},
		ReExec:     func([]string) error { reexeced = true; return nil },
		HTTPClient: srv.Client(),
	})
	began, err := m.Sync(ver, sha, url)
	if err != nil || !began {
		t.Fatalf("Sync(bundle tuple): began=%v err=%v", began, err)
	}
	if got, _ := os.ReadFile(self); !bytes.Equal(got, newPilot) {
		t.Fatal("the bundle-pinned pilot must be installed on disk")
	}
	if !reexeced {
		t.Fatal("a re-exec into the new pilot must be invoked")
	}
}

func TestOverlappingMeshes(t *testing.T) {
	p := netip.MustParsePrefix
	mine := p("10.44.0.0/16")
	cases := []struct {
		name   string
		others map[string]netip.Prefix
		want   []string
	}{
		{"disjoint", map[string]netip.Prefix{"prod": p("10.45.0.0/16")}, nil},
		{"identical", map[string]netip.Prefix{"prod": p("10.44.0.0/16")}, []string{"prod"}},
		{"subset", map[string]netip.Prefix{"prod": p("10.44.1.0/24")}, []string{"prod"}},
		{"superset", map[string]netip.Prefix{"prod": p("10.0.0.0/8")}, []string{"prod"}},
		{"mixed sorted", map[string]netip.Prefix{"z": p("10.44.9.0/24"), "a": p("10.44.1.0/24"), "x": p("10.45.0.0/16")}, []string{"a", "z"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := overlappingMeshes(mine, tc.others)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMeshOverlayMultiMesh is the 2nd-mesh exercise (ADR 0008 Phase 3): lay down
// three meshes' real host certs on one host and confirm meshOverlay reads each
// pool back and the disjoint-CIDR check flags only the overlapping one.
func TestMeshOverlayMultiMesh(t *testing.T) {
	root := t.TempDir()
	writeMeshCert(t, root, "default", netip.MustParsePrefix("10.44.0.5/16")) // this host's mesh
	writeMeshCert(t, root, "prod", netip.MustParsePrefix("10.45.0.5/16"))    // disjoint pool — fine
	writeMeshCert(t, root, "staging", netip.MustParsePrefix("10.44.9.9/16")) // same /16 as default — conflict

	mine, ok := meshOverlay(filepath.Join(root, "default"))
	if !ok || mine.String() != "10.44.0.0/16" {
		t.Fatalf("default overlay = %v (ok=%v), want 10.44.0.0/16", mine, ok)
	}
	others := map[string]netip.Prefix{}
	for _, m := range []string{"prod", "staging"} {
		p, ok := meshOverlay(filepath.Join(root, m))
		if !ok {
			t.Fatalf("meshOverlay(%s) failed", m)
		}
		others[m] = p
	}
	if got, want := overlappingMeshes(mine, others), []string{"staging"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("overlaps = %v, want %v (prod is disjoint; staging shares default's /16)", got, want)
	}
}

// writeMeshCert issues a real host cert in overlay's pool and writes it to
// <root>/<mesh>/host.crt, where meshOverlay reads it.
func writeMeshCert(t *testing.T, root, mesh string, overlay netip.Prefix) {
	t.Helper()
	pool := overlay.Masked()
	be, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	_, caPEM, err := signer.SelfSignCA(be, signer.CATemplate{
		Name: mesh + "-ca", Networks: []netip.Prefix{pool},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM, Backend: be,
		Policy: signer.IssuePolicy{AllowedNetwork: pool, MaxLifetime: 24 * time.Hour},
		Audit:  func(context.Context, string, string, string, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, certPEM, err := sg.Issue(context.Background(), "test", signer.Template{
		Name: "host", Networks: []netip.Prefix{overlay}, Groups: []string{"g"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		PublicKey: k.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, mesh)
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.New(base).HostCert(), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
}
