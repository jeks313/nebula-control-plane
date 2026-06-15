package nebulaupdate_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
		Layout: layout, PinnedConfigPub: pinned, NebulaPath: nebPath,
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
	m := nebulaupdate.New(nebulaupdate.Config{Layout: layout, PinnedConfigPub: pinned, NebulaPath: nebPath, HTTPClient: srv1.Client()})
	if _, err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Roll to v2; the previous binary must be kept as <path>.last-good.
	writeBundle(t, be, layout, "2.0.0", sha256hex(v2), srv2.URL+"/n")
	m2 := nebulaupdate.New(nebulaupdate.Config{Layout: layout, PinnedConfigPub: pinned, NebulaPath: nebPath, HTTPClient: srv2.Client()})
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

	m := nebulaupdate.New(nebulaupdate.Config{Layout: layout, PinnedConfigPub: pinned, NebulaPath: nebPath, HTTPClient: srv.Client()})
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

	m := nebulaupdate.New(nebulaupdate.Config{Layout: layout, PinnedConfigPub: pinned, NebulaPath: filepath.Join(dir, "nebula")})
	if updated, err := m.Sync(context.Background()); err != nil || updated {
		t.Fatalf("no pinned version must be a no-op: updated=%v err=%v", updated, err)
	}
}
