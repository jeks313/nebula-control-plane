// Package binverify checks that an on-disk binary matches an expected digest
// before it is executed (implementation-plan M1.5). Pilot uses this so a local
// attacker swapping the nebula binary is detected and refused.
package binverify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// SHA256 verifies that the file at path has the given hex-encoded SHA-256 digest.
// Comparison is case-insensitive and whitespace-tolerant on the expected value.
func SHA256(path, expectedHex string) error {
	want := strings.ToLower(strings.TrimSpace(expectedHex))
	if want == "" {
		return fmt.Errorf("binverify: empty expected digest")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("binverify: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("binverify: reading %s: %w", path, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("binverify: sha256 mismatch for %s: got %s want %s", path, got, want)
	}
	return nil
}
