package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/signer"
)

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
