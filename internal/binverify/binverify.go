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

// FileSHA256 returns the hex-encoded SHA-256 digest of the file at path. Pilot
// reports this for the running nebula binary so Harbor can map it to a release
// generation (ADR 0003 Phase 1c) — the artifact's own identity, unambiguous across
// rebuilds that share a version string.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("binverify: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("binverify: reading %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256 verifies that the file at path has the given hex-encoded SHA-256 digest.
// Comparison is case-insensitive and whitespace-tolerant on the expected value.
func SHA256(path, expectedHex string) error {
	want := strings.ToLower(strings.TrimSpace(expectedHex))
	if want == "" {
		return fmt.Errorf("binverify: empty expected digest")
	}
	got, err := FileSHA256(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("binverify: sha256 mismatch for %s: got %s want %s", path, got, want)
	}
	return nil
}
