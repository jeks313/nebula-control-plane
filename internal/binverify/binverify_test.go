package binverify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSHA256(t *testing.T) {
	data := []byte("hello nebula")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	path := writeTemp(t, data)

	if err := SHA256(path, digest); err != nil {
		t.Errorf("matching digest should pass: %v", err)
	}
	if err := SHA256(path, "  "+digest+"\n"); err != nil {
		t.Errorf("whitespace-padded digest should pass: %v", err)
	}
	if err := SHA256(path, "deadbeef"); err == nil {
		t.Error("wrong digest should fail")
	}
	if err := SHA256(path, ""); err == nil {
		t.Error("empty digest should fail")
	}
	if err := SHA256(filepath.Join(t.TempDir(), "nope"), digest); err == nil {
		t.Error("missing file should fail")
	}
}
