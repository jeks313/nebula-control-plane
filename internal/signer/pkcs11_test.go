//go:build pkcs11

package signer

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// findSoftHSMModule returns the libsofthsm2 path, or "" if not installed.
func findSoftHSMModule() string {
	for _, p := range []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// TestPKCS11SoftHSMEndToEnd proves the SoftHSM-backed signer (M2.3 with a
// non-exportable CA key): a SoftHSM P256 key signs a self-signed CA and a leaf,
// and Nebula verifies the leaf against that CA. Skips if SoftHSM tooling is
// absent. Run: go test -tags pkcs11 ./internal/signer
func TestPKCS11SoftHSMEndToEnd(t *testing.T) {
	module := findSoftHSMModule()
	if module == "" {
		t.Skip("libsofthsm2.so not found; skipping SoftHSM integration")
	}
	for _, tool := range []string{"softhsm2-util", "pkcs11-tool"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH; skipping SoftHSM integration", tool)
		}
	}

	const (
		token    = "harbor-signer-test"
		pin      = "1234"
		soPin    = "5678"
		keyLabel = "harbor-ca-key"
		keyID    = "01"
	)

	// Isolate token state under a temp dir so we never touch a system token store.
	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "softhsm2.conf")
	if err := os.WriteFile(conf, []byte("directories.tokendir = "+tokenDir+"\nobjectstore.backend = file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOFTHSM2_CONF", conf)

	mustRun(t, "softhsm2-util", "--init-token", "--free",
		"--label", token, "--pin", pin, "--so-pin", soPin)
	mustRun(t, "pkcs11-tool", "--module", module, "--token-label", token,
		"--login", "--pin", pin, "--keypairgen", "--key-type", "EC:prime256v1",
		"--label", keyLabel, "--id", keyID)

	backend, err := NewPKCS11Backend(PKCS11Config{
		ModulePath: module, TokenLabel: token, Pin: pin, KeyLabel: keyLabel,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Backend: %v", err)
	}
	if c, ok := backend.(interface{ Close() error }); ok {
		t.Cleanup(func() { c.Close() })
	}

	caPEM := testCA(t, backend) // self-signed by the SoftHSM key
	audit := &recordingAudit{}
	s, err := New(Config{
		CACertPEM: caPEM,
		Backend:   backend,
		Policy: Policy{
			AllowedNetwork: netip.MustParsePrefix("100.64.0.0/16"),
			MaxLifetime:    90 * 24 * time.Hour,
		},
		MaxCertsPerHour: 100,
		Audit:           audit.fn,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	c, _, err := s.Issue(context.Background(), "tester", goodTemplate(t))
	if err != nil {
		t.Fatalf("Issue via SoftHSM: %v", err)
	}
	pool, err := cert.NewCAPoolFromPEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.VerifyCertificate(time.Now(), c); err != nil {
		t.Fatalf("SoftHSM-signed leaf does not verify: %v", err)
	}
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}
