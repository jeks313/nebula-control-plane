package autotls

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestTLSConfigValidation: the fail-closed guards reject an incomplete config before any
// ACME/network work (the success path needs a real Let's Encrypt + Cloudflare and is an
// integration concern, not a unit test).
func TestTLSConfigValidation(t *testing.T) {
	ctx := context.Background()
	cases := map[string]Config{
		"no domains":   {CloudflareToken: "t", CacheDir: "/tmp/x"},
		"no token":     {Domains: []string{"h.example.com"}, CacheDir: "/tmp/x"},
		"no cache dir": {Domains: []string{"h.example.com"}, CloudflareToken: "t"},
	}
	for name, c := range cases {
		if _, err := TLSConfig(ctx, c); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

func TestToken(t *testing.T) {
	t.Setenv(TokenEnv, "") // ensure a clean baseline

	// Env wins.
	t.Setenv(TokenEnv, "env-token")
	if got, err := Token(""); err != nil || got != "env-token" {
		t.Fatalf("env token = %q, err %v; want env-token", got, err)
	}

	// File fallback when env is empty.
	t.Setenv(TokenEnv, "")
	f := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(f, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Token(f); err != nil || got != "file-token" {
		t.Fatalf("file token = %q, err %v; want file-token (trimmed)", got, err)
	}

	// Neither set -> empty, no error.
	if got, err := Token(""); err != nil || got != "" {
		t.Fatalf("no token = %q, err %v; want empty", got, err)
	}
}
