package hostkey

import (
	"crypto/ecdh"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/slackhq/nebula/cert"
)

func TestGenerateProducesValidP256Pair(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Public key must be Nebula's P256 form and round-trip through its parser.
	pubBytes, _, curve, err := cert.UnmarshalPublicKeyFromPEM(kp.PublicKeyPEM())
	if err != nil {
		t.Fatalf("UnmarshalPublicKeyFromPEM: %v", err)
	}
	if curve != cert.Curve_P256 {
		t.Fatalf("public key curve = %v, want P256", curve)
	}
	if len(pubBytes) != 65 {
		t.Fatalf("public key len = %d, want 65 (uncompressed P256 point)", len(pubBytes))
	}
}

func TestWritePrivateKeyPermsAndFormat(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "host.key")
	if err := kp.WritePrivateKey(path); err != nil {
		t.Fatalf("WritePrivateKey: %v", err)
	}

	// Owner-only perms are the on-disk half of the P1 boundary (POSIX only).
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0600 {
			t.Fatalf("private key mode = %o, want 0600", perm)
		}
	}

	// The file is a real Nebula P256 private key, and it pairs with the pubkey.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(raw)
	if err != nil {
		t.Fatalf("UnmarshalPrivateKeyFromPEM: %v", err)
	}
	if curve != cert.Curve_P256 {
		t.Fatalf("private key curve = %v, want P256", curve)
	}
	priv, err := ecdh.P256().NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey from written bytes: %v", err)
	}
	wantPub := cert.MarshalPublicKeyToPEM(cert.Curve_P256, priv.PublicKey().Bytes())
	if string(wantPub) != string(kp.PublicKeyPEM()) {
		t.Fatal("written private key does not derive the exported public key")
	}
}

func TestWritePrivateKeyRefusesOverwrite(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "host.key")
	if err := kp.WritePrivateKey(path); err != nil {
		t.Fatalf("first WritePrivateKey: %v", err)
	}
	err = kp.WritePrivateKey(path)
	if !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second WritePrivateKey err = %v, want ErrKeyExists", err)
	}
}
