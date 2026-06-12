// Package integration holds cross-package acceptance tests that exercise the
// real `nebula` / `nebula-cert` binaries. They skip when those tools aren't on
// PATH, so `go test ./...` stays green on a bare machine while CI (with nebula
// installed, M1.11) runs the full check.
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/hostkey"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/paths"
)

// TestPilotInitProducesConfigNebulaAccepts is the M1.4 + M1.7 acceptance: a host
// key generated in-process (P256) can be signed by a P256 CA, and the config
// pilot renders is one `nebula -test` accepts with that key+cert loaded.
func TestPilotInitProducesConfigNebulaAccepts(t *testing.T) {
	nebula, err := exec.LookPath("nebula")
	if err != nil {
		t.Skip("nebula not on PATH; skipping integration acceptance")
	}
	nebulaCert, err := exec.LookPath("nebula-cert")
	if err != nil {
		t.Skip("nebula-cert not on PATH; skipping integration acceptance")
	}

	dir := t.TempDir()
	layout := paths.New(dir)
	if err := layout.Ensure(); err != nil {
		t.Fatalf("layout.Ensure: %v", err)
	}

	// What `pilot init` does: generate + persist the host key, render config.
	kp, err := hostkey.Generate()
	if err != nil {
		t.Fatalf("hostkey.Generate: %v", err)
	}
	if err := kp.WritePrivateKey(layout.HostKey()); err != nil {
		t.Fatalf("WritePrivateKey: %v", err)
	}
	if err := kp.WritePublicKey(layout.HostPub()); err != nil {
		t.Fatalf("WritePublicKey: %v", err)
	}

	v := nebulaconfig.Values{
		AmLighthouse: true,
		CACertPath:   layout.CABundle(),
		CertPath:     layout.HostCert(),
		KeyPath:      layout.HostKey(),
	}
	v.Defaults()
	cfg, err := nebulaconfig.Render(v)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := os.WriteFile(layout.Config(), cfg, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Stand in for enrollment (M3): a P256 CA signs the pilot-generated pubkey.
	caKey := filepath.Join(dir, "ca-test.key")
	run(t, nebulaCert, "ca", "-curve", "P256", "-name", "m1-test-ca",
		"-out-crt", layout.CABundle(), "-out-key", caKey)
	run(t, nebulaCert, "sign", "-ca-crt", layout.CABundle(), "-ca-key", caKey,
		"-in-pub", layout.HostPub(), "-name", "m1-host",
		"-networks", "100.64.0.1/16", "-out-crt", layout.HostCert())

	// The actual acceptance: nebula loads + validates everything.
	run(t, nebula, "-test", "-config", layout.Config())
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}
