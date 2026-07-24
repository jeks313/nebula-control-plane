package drift

import (
	"context"
	"crypto/ecdsa"
	"os"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/signer"
)

func setup(t *testing.T) (paths.Layout, []byte /*bundle JWS*/, []byte /*canonical config*/, *Monitor, *int) {
	t.Helper()
	layout := paths.New(t.TempDir())
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	cfgB, _ := signer.NewSoftwareBackend()
	pub, _ := cfgB.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pub)

	b := bundle.Bundle{
		Device:      bundle.Device{Name: "web-1", OverlayIP: "100.64.0.5", Groups: []string{"web"}},
		Certificate: "CERT", CABundle: []string{"CA"},
		Lighthouses: []bundle.Lighthouse{{OverlayIP: "100.64.0.1", PublicAddrs: []string{"1.2.3.4:4242"}}},
		Firewall: &bundle.Firewall{
			Inbound:  []nebulaconfig.Rule{{Proto: "tcp", Port: "443", Host: "any"}},
			Outbound: []nebulaconfig.Rule{{Proto: "tcp", Port: "5432", Group: "db"}},
		},
	}
	raw, err := bundle.Sign(cfgB, "k", b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.Bundle(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	vb, _ := bundle.Verify(raw, []*ecdsa.PublicKey{pinned})
	want, _ := bundle.RenderNebulaConfig(vb, layout.CABundle(), layout.HostCert(), layout.HostKey())

	reloads := 0
	m := New(Config{Layout: layout, PinnedConfigPub: []*ecdsa.PublicKey{pinned}, Reload: func() error { reloads++; return nil }})
	return layout, raw, want, m, &reloads
}

// TestSyncRevertsDrift is the M6.7 acceptance: a manual edit to config.yml is
// reverted to the signed version and reported.
func TestSyncRevertsDrift(t *testing.T) {
	layout, _, want, m, reloads := setup(t)
	ctx := context.Background()

	// First sync writes the canonical config (no prior config = drift).
	if rev, err := m.Sync(ctx); err != nil || !rev {
		t.Fatalf("initial sync reverted=%v err=%v", rev, err)
	}

	// Tamper: append a rogue rule.
	tampered := append(append([]byte{}, want...), []byte("\n# rogue\n")...)
	if err := os.WriteFile(layout.Config(), tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	rev, err := m.Sync(ctx)
	if err != nil || !rev {
		t.Fatalf("sync should revert drift: reverted=%v err=%v", rev, err)
	}
	got, _ := os.ReadFile(layout.Config())
	if string(got) != string(want) {
		t.Fatalf("config not reverted to signed version:\n got=%q\nwant=%q", got, want)
	}
	if *reloads < 2 { // once for initial write, once for the revert
		t.Fatalf("reload not triggered on revert (count=%d)", *reloads)
	}

	// No drift now -> no revert.
	if rev, err := m.Sync(ctx); err != nil || rev {
		t.Fatalf("clean config should not revert: reverted=%v err=%v", rev, err)
	}
}

func TestSyncIgnoresTamperedBundle(t *testing.T) {
	layout, raw, _, m, _ := setup(t)
	// Corrupt the stored bundle file itself.
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(layout.Bundle(), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Sync(context.Background()); err == nil {
		t.Fatal("a tampered bundle file must not be applied")
	}
}

func TestSyncNoBundle(t *testing.T) {
	layout := paths.New(t.TempDir())
	_ = layout.Ensure()
	m := New(Config{Layout: layout})
	if rev, err := m.Sync(context.Background()); err != nil || rev {
		t.Fatalf("no bundle -> nothing to enforce: reverted=%v err=%v", rev, err)
	}
}
