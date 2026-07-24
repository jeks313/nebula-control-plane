package nebulaupdate_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nebulaupdate"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/signer"
)

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// writeBundle signs (with be) a bundle pinning the given nebula version/sha/url and
// writes it to the host's bundle path, so meshOverlay/desired() can read it.
func writeBundle(t *testing.T, be *signer.SoftwareBackend, layout paths.Layout, ver, sha, url string) {
	t.Helper()
	b := bundle.Bundle{
		BundleVersion: 1, Certificate: "C", CABundle: []string{"CA"}, NotAfter: "2026-07-12T00:00:00Z",
		NebulaVersion: ver, NebulaSHA256: sha, NebulaURL: url,
	}
	jwsBytes, err := bundle.Sign(be, "kid", b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.Bundle(), jwsBytes, 0o644); err != nil {
		t.Fatal(err)
	}
}

// serve returns an httptest server that responds with body for any path.
func serve(t *testing.T, body []byte) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSyncInstallsAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	layout := paths.New(dir)
	nebPath := filepath.Join(dir, "nebula")

	neb := bytes.Repeat([]byte("N"), 4096) // stand-in nebula binary
	srv := serve(t, neb)

	be, _ := signer.NewSoftwareBackend()
	pub, _ := be.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pub)
	writeBundle(t, be, layout, "9.9.9", sha256hex(neb), srv.URL+"/nebula")

	restarts := 0
	m := nebulaupdate.New(nebulaupdate.Config{
		Layout: layout, PinnedConfigPub: []*ecdsa.PublicKey{pinned}, NebulaPath: nebPath,
		Restart: func() error { restarts++; return nil }, HTTPClient: srv.Client(),
	})

	updated, err := m.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("want updated=true on first sync")
	}
	if got, _ := os.ReadFile(nebPath); !bytes.Equal(got, neb) {
		t.Fatal("installed binary content mismatch")
	}
	if restarts != 1 {
		t.Fatalf("restarts=%d, want 1", restarts)
	}

	// Idempotent: the on-disk sha now matches -> no fetch, no install, no restart.
	updated2, err := m.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if updated2 || restarts != 1 {
		t.Fatalf("second sync should be a no-op: updated=%v restarts=%d", updated2, restarts)
	}
}

func TestSyncKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	layout := paths.New(dir)
	nebPath := filepath.Join(dir, "nebula")

	v1 := bytes.Repeat([]byte("1"), 2048)
	v2 := bytes.Repeat([]byte("2"), 2048)
	srv1 := serve(t, v1)
	srv2 := serve(t, v2)

	be, _ := signer.NewSoftwareBackend()
	pub, _ := be.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pub)

	writeBundle(t, be, layout, "1.0.0", sha256hex(v1), srv1.URL+"/n")
	m := nebulaupdate.New(nebulaupdate.Config{Layout: layout, PinnedConfigPub: []*ecdsa.PublicKey{pinned}, NebulaPath: nebPath, HTTPClient: srv1.Client()})
	if _, err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Roll to v2; the previous binary must be kept as <path>.last-good.
	writeBundle(t, be, layout, "2.0.0", sha256hex(v2), srv2.URL+"/n")
	m2 := nebulaupdate.New(nebulaupdate.Config{Layout: layout, PinnedConfigPub: []*ecdsa.PublicKey{pinned}, NebulaPath: nebPath, HTTPClient: srv2.Client()})
	if updated, err := m2.Sync(context.Background()); err != nil || !updated {
		t.Fatalf("v2 sync: updated=%v err=%v", updated, err)
	}
	if got, _ := os.ReadFile(nebPath); !bytes.Equal(got, v2) {
		t.Fatal("current binary should be v2")
	}
	if got, _ := os.ReadFile(nebPath + ".last-good"); !bytes.Equal(got, v1) {
		t.Fatal("last-good should be v1")
	}
}

// TestSyncRevertsWhenNewBinaryFailsToComeUp is the ADR 0003 Phase 1c pilot-local
// rollback acceptance: when the health gate reports the new nebula did NOT come up,
// the updater restores <path>.last-good, sets the bad binary aside, and quarantines
// the bad sha so it is not re-attempted (no crash-loop) until the bundle pins a
// different one.
func TestSyncRevertsWhenNewBinaryFailsToComeUp(t *testing.T) {
	dir := t.TempDir()
	layout := paths.New(dir)
	nebPath := filepath.Join(dir, "nebula")

	v1 := bytes.Repeat([]byte("1"), 2048)
	v2 := bytes.Repeat([]byte("2"), 2048)
	srv1 := serve(t, v1)
	srv2 := serve(t, v2)

	be, _ := signer.NewSoftwareBackend()
	pub, _ := be.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pub)

	restarts := 0
	healthy := true // v1 comes up fine; v2 will be made to fail
	m := nebulaupdate.New(nebulaupdate.Config{
		Layout: layout, PinnedConfigPub: []*ecdsa.PublicKey{pinned}, NebulaPath: nebPath,
		Restart:    func() error { restarts++; return nil },
		Healthy:    func(context.Context, time.Time) bool { return healthy },
		HTTPClient: srv1.Client(),
	})

	// Install a healthy v1 -> becomes the last-good we expect to fall back to.
	writeBundle(t, be, layout, "1.0.0", sha256hex(v1), srv1.URL+"/n")
	if updated, err := m.Sync(context.Background()); err != nil || !updated {
		t.Fatalf("v1 sync: updated=%v err=%v", updated, err)
	}
	if restarts != 1 {
		t.Fatalf("after healthy v1 install, restarts=%d want 1", restarts)
	}

	// Roll to v2, which fails to come up: revert to v1 + one extra restart + error.
	healthy = false
	writeBundle(t, be, layout, "2.0.0", sha256hex(v2), srv2.URL+"/n")
	updated, err := m.Sync(context.Background())
	if err == nil || updated {
		t.Fatalf("failed-to-come-up sync must error + not update: updated=%v err=%v", updated, err)
	}
	if got, _ := os.ReadFile(nebPath); !bytes.Equal(got, v1) {
		t.Fatal("after revert, the live binary must be the last-good v1")
	}
	if got, _ := os.ReadFile(nebPath + ".failed"); !bytes.Equal(got, v2) {
		t.Fatal("the failed v2 binary should be set aside as <path>.failed")
	}
	if restarts != 3 { // 1 (v1) + 1 (v2 attempt) + 1 (revert)
		t.Fatalf("restarts=%d, want 3 (install, failed attempt, revert)", restarts)
	}

	// Quarantine: re-syncing the same (still-pinned, still-bad) v2 is a no-op — no
	// re-fetch, no re-install, no extra restart (would otherwise crash-loop).
	updated2, err2 := m.Sync(context.Background())
	if updated2 || err2 != nil {
		t.Fatalf("quarantined sha must be a clean no-op: updated=%v err=%v", updated2, err2)
	}
	if restarts != 3 {
		t.Fatalf("quarantined re-sync must not restart: restarts=%d want 3", restarts)
	}
	if got, _ := os.ReadFile(nebPath); !bytes.Equal(got, v1) {
		t.Fatal("quarantined re-sync must leave the live binary on v1")
	}
}

// TestSyncFirstInstallFailureDoesNotBrickOrLoop covers the no-last-good case the
// review flagged: a FIRST install (fresh host, nothing to fall back to) that fails
// the health gate must error cleanly — leave the binary at <path>, set nothing
// aside, NOT quarantine — and the next Sync must be a clean no-op (the on-disk binary
// already matches the desired sha) rather than a re-fetch crash-loop.
func TestSyncFirstInstallFailureDoesNotBrickOrLoop(t *testing.T) {
	dir := t.TempDir()
	layout := paths.New(dir)
	nebPath := filepath.Join(dir, "nebula") // does not exist yet (fresh host)

	v1 := bytes.Repeat([]byte("1"), 2048)
	srv := serve(t, v1)
	be, _ := signer.NewSoftwareBackend()
	pub, _ := be.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pub)

	restarts := 0
	m := nebulaupdate.New(nebulaupdate.Config{
		Layout: layout, PinnedConfigPub: []*ecdsa.PublicKey{pinned}, NebulaPath: nebPath,
		Restart:    func() error { restarts++; return nil },
		Healthy:    func(context.Context, time.Time) bool { return false }, // first binary never comes up
		HTTPClient: srv.Client(),
	})
	writeBundle(t, be, layout, "1.0.0", sha256hex(v1), srv.URL+"/n")

	updated, err := m.Sync(context.Background())
	if err == nil || updated {
		t.Fatalf("first-install failure must error + not update: updated=%v err=%v", updated, err)
	}
	if got, _ := os.ReadFile(nebPath); !bytes.Equal(got, v1) {
		t.Fatal("with no last-good, the (failed) binary must remain at path — never a missing binary")
	}
	if _, statErr := os.Stat(nebPath + ".last-good"); statErr == nil {
		t.Fatal("a first install must not create a last-good")
	}
	if _, statErr := os.Stat(nebPath + ".failed"); statErr == nil {
		t.Fatal("revert must set nothing aside when there is no last-good (it errors first)")
	}

	// Next Sync: on-disk already matches the desired sha -> clean short-circuit no-op,
	// no re-fetch crash-loop.
	updated2, err2 := m.Sync(context.Background())
	if updated2 || err2 != nil {
		t.Fatalf("second sync must be a clean no-op: updated=%v err=%v", updated2, err2)
	}
	if restarts != 1 {
		t.Fatalf("first-install failure should restart exactly once (the install); got %d", restarts)
	}
}

// TestSyncCtxCancelDuringGateSkipsRevert covers the shutdown case the review flagged:
// if the health gate returns false because ctx was cancelled (SIGTERM mid-gate), the
// updater must NOT treat that as a binary failure — no revert, no quarantine — so a
// healthy binary is not needlessly rolled back every shutdown.
func TestSyncCtxCancelDuringGateSkipsRevert(t *testing.T) {
	dir := t.TempDir()
	layout := paths.New(dir)
	nebPath := filepath.Join(dir, "nebula")

	v1 := bytes.Repeat([]byte("1"), 2048)
	v2 := bytes.Repeat([]byte("2"), 2048)
	srv1 := serve(t, v1)
	srv2 := serve(t, v2)
	be, _ := signer.NewSoftwareBackend()
	pub, _ := be.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pub)

	restarts := 0
	ctx, cancel := context.WithCancel(context.Background())
	gateHealthy := true
	m := nebulaupdate.New(nebulaupdate.Config{
		Layout: layout, PinnedConfigPub: []*ecdsa.PublicKey{pinned}, NebulaPath: nebPath,
		Restart: func() error { restarts++; return nil },
		Healthy: func(c context.Context, _ time.Time) bool {
			if gateHealthy {
				return true
			}
			cancel() // simulate SIGTERM arriving while the gate is waiting
			return false
		},
		HTTPClient: srv1.Client(),
	})

	// Install a healthy v1 (establishes a last-good when v2 lands, so a revert WOULD be
	// possible — proving the skip is due to cancellation, not a missing last-good).
	writeBundle(t, be, layout, "1.0.0", sha256hex(v1), srv1.URL+"/n")
	if updated, err := m.Sync(ctx); err != nil || !updated {
		t.Fatalf("v1 sync: updated=%v err=%v", updated, err)
	}

	// v2 lands; the gate cancels ctx then reports unhealthy -> Sync must skip revert.
	gateHealthy = false
	writeBundle(t, be, layout, "2.0.0", sha256hex(v2), srv2.URL+"/n")
	updated, err := m.Sync(ctx)
	if updated || err == nil {
		t.Fatalf("cancelled gate must not update + must return ctx error: updated=%v err=%v", updated, err)
	}
	if got, _ := os.ReadFile(nebPath); !bytes.Equal(got, v2) {
		t.Fatal("on cancellation the new binary must be KEPT (not reverted) — shutdown is not a failure")
	}
	if restarts != 2 { // v1 install + v2 install; NO revert restart
		t.Fatalf("cancelled gate must not trigger a revert restart: restarts=%d want 2", restarts)
	}
}

func TestSyncShaMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	layout := paths.New(dir)
	nebPath := filepath.Join(dir, "nebula")
	srv := serve(t, []byte("TAMPERED-OR-WRONG-ARTIFACT"))

	be, _ := signer.NewSoftwareBackend()
	pub, _ := be.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pub)
	// Pin a sha the served bytes won't match.
	writeBundle(t, be, layout, "9.9.9", hex.EncodeToString(make([]byte, 32)), srv.URL+"/n")

	m := nebulaupdate.New(nebulaupdate.Config{Layout: layout, PinnedConfigPub: []*ecdsa.PublicKey{pinned}, NebulaPath: nebPath, HTTPClient: srv.Client()})
	updated, err := m.Sync(context.Background())
	if err == nil {
		t.Fatal("want a sha-mismatch error")
	}
	if updated {
		t.Fatal("must not install on sha mismatch")
	}
	if _, statErr := os.Stat(nebPath); statErr == nil {
		t.Fatal("nebula must not be written when the sha doesn't match")
	}
}

func TestSyncNoPinnedVersionNoop(t *testing.T) {
	dir := t.TempDir()
	layout := paths.New(dir)
	be, _ := signer.NewSoftwareBackend()
	pub, _ := be.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pub)
	writeBundle(t, be, layout, "", "", "") // no nebula fields

	m := nebulaupdate.New(nebulaupdate.Config{Layout: layout, PinnedConfigPub: []*ecdsa.PublicKey{pinned}, NebulaPath: filepath.Join(dir, "nebula")})
	if updated, err := m.Sync(context.Background()); err != nil || updated {
		t.Fatalf("no pinned version must be a no-op: updated=%v err=%v", updated, err)
	}
}
