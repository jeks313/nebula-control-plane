package pilotsetup_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/pilotsetup"
)

func TestInitFreshThenIdempotent(t *testing.T) {
	base := t.TempDir()
	layout := paths.New(base)

	res, err := pilotsetup.Init(pilotsetup.InitParams{Layout: layout, TunDev: "neb-dev", ListenPort: 4243})
	if err != nil {
		t.Fatalf("Init fresh: %v", err)
	}
	if !res.KeyGenerated {
		t.Fatal("KeyGenerated = false on a fresh dir, want true")
	}
	for _, f := range []string{layout.HostKey(), layout.HostPub(), layout.Config()} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("expected %s to exist: %v", f, err)
		}
	}

	// The per-mesh TUN dev + port must land in the rendered config.
	cfg, err := os.ReadFile(layout.Config())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "neb-dev") {
		t.Errorf("config missing per-mesh tun dev 'neb-dev':\n%s", cfg)
	}
	if !strings.Contains(string(cfg), "4243") {
		t.Errorf("config missing per-mesh listen port 4243:\n%s", cfg)
	}

	// Re-run must NOT regenerate the key (idempotent identity).
	keyBefore, _ := os.ReadFile(layout.HostKey())
	res2, err := pilotsetup.Init(pilotsetup.InitParams{Layout: layout, TunDev: "neb-dev", ListenPort: 4243})
	if err != nil {
		t.Fatalf("Init re-run: %v", err)
	}
	if res2.KeyGenerated {
		t.Fatal("KeyGenerated = true on re-run, want false (must reuse the live key)")
	}
	keyAfter, _ := os.ReadFile(layout.HostKey())
	if string(keyBefore) != string(keyAfter) {
		t.Fatal("host key changed on re-run — install would re-enroll a fresh identity")
	}
}

func TestInitDefaultsWhenUnset(t *testing.T) {
	layout := paths.New(t.TempDir())
	if _, err := pilotsetup.Init(pilotsetup.InitParams{Layout: layout}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg, _ := os.ReadFile(layout.Config())
	if !strings.Contains(string(cfg), "nebula1") {
		t.Errorf("config missing default tun dev 'nebula1':\n%s", cfg)
	}
	// PKI paths must point back into the base dir.
	if !strings.Contains(string(cfg), filepath.Join(layout.Base, "host.key")) {
		t.Errorf("config missing key path:\n%s", cfg)
	}
}
