package bundle

import (
	"crypto/ecdsa"
	"path/filepath"
	"testing"

	"github.com/slackhq/nebula/cert"

	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

func mkKey(t *testing.T) (be signer.Backend, pub *ecdsa.PublicKey, pem, kid string) {
	t.Helper()
	b, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := b.PublicKey()
	k, err := jws.ParseP256PublicPoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b, k, string(cert.MarshalSigningPublicKeyToPEM(cert.Curve_P256, raw)), wire.PubkeyHash(raw)
}

// TestTrustedSetUnionDedup: TrustedSet = pins UNION learned-from-file, deduped; a missing file
// yields just the pins (fail-SAFE, never empty/accept-all).
func TestTrustedSetUnionDedup(t *testing.T) {
	_, k1, pem1, _ := mkKey(t)
	_, k2, pem2, _ := mkKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	// No file yet -> just the pin.
	if got := TrustedSet([]*ecdsa.PublicKey{k1}, path); len(got) != 1 || !got[0].Equal(k1) {
		t.Fatalf("no-file TrustedSet = %d keys, want [k1]", len(got))
	}
	// Persist [k1, k2]; TrustedSet(pin=k1) should be {k1, k2} (k1 deduped).
	if err := PersistTrustFile(path, 5, []string{pem1, pem2}); err != nil {
		t.Fatal(err)
	}
	got := TrustedSet([]*ecdsa.PublicKey{k1}, path)
	if len(got) != 2 {
		t.Fatalf("union TrustedSet = %d keys, want 2 (k1 pin deduped with learned)", len(got))
	}
	if !containsKey(got, k1) || !containsKey(got, k2) {
		t.Fatal("union must contain both k1 and k2")
	}
}

// TestPersistTrustFileAntiRollback: a lower-version write is a no-op (keeps the last-good set); an
// empty-keys write is a no-op (a legacy bundle never regresses the set).
func TestPersistTrustFileAntiRollback(t *testing.T) {
	_, _, pem1, _ := mkKey(t)
	_, _, pem2, _ := mkKey(t)
	path := filepath.Join(t.TempDir(), "trust.json")

	if err := PersistTrustFile(path, 10, []string{pem1, pem2}); err != nil {
		t.Fatal(err)
	}
	v, keys := LoadTrustFile(path)
	if v != 10 || len(keys) != 2 {
		t.Fatalf("after v10 write: v=%d keys=%d", v, len(keys))
	}
	// Replayed OLDER version -> no-op.
	if err := PersistTrustFile(path, 3, []string{pem1}); err != nil {
		t.Fatal(err)
	}
	if v2, keys2 := LoadTrustFile(path); v2 != 10 || len(keys2) != 2 {
		t.Fatalf("stale v3 write must be ignored: v=%d keys=%d", v2, len(keys2))
	}
	// Empty keys -> no-op (legacy bundle).
	if err := PersistTrustFile(path, 20, nil); err != nil {
		t.Fatal(err)
	}
	if v3, _ := LoadTrustFile(path); v3 != 10 {
		t.Fatalf("empty-keys write must be ignored: v=%d", v3)
	}
	// A NEWER version with keys advances.
	if err := PersistTrustFile(path, 11, []string{pem1}); err != nil {
		t.Fatal(err)
	}
	if v4, keys4 := LoadTrustFile(path); v4 != 11 || len(keys4) != 1 {
		t.Fatalf("v11 write must advance: v=%d keys=%d", v4, len(keys4))
	}
}

// TestVerifySetAcceptsAnyTrusted: a bundle signed by any key in the set verifies; one signed by a key
// NOT in the set is rejected — INCLUDING a bundle that self-asserts its own signing key in
// config_signing_keys (no bootstrap-trust from the payload).
func TestVerifySetAcceptsAnyTrusted(t *testing.T) {
	b1, k1, _, kid1 := mkKey(t)
	b2, k2, _, kid2 := mkKey(t)
	battacker, _, attackerPEM, kidAtk := mkKey(t)

	signed1, err := Sign(b1, kid1, Bundle{Device: Device{Name: "h"}})
	if err != nil {
		t.Fatal(err)
	}
	// Trusting {k1,k2} verifies a K1-signed bundle.
	if _, err := Verify(signed1, []*ecdsa.PublicKey{k1, k2}); err != nil {
		t.Fatalf("k1-signed must verify under {k1,k2}: %v", err)
	}
	// A K2-signed bundle also verifies under the same set (the overlap property).
	signed2, _ := Sign(b2, kid2, Bundle{Device: Device{Name: "h"}})
	if _, err := Verify(signed2, []*ecdsa.PublicKey{k1, k2}); err != nil {
		t.Fatalf("k2-signed must verify under {k1,k2}: %v", err)
	}
	// Self-asserted attacker: signed by an untrusted key that LISTS ITSELF in config_signing_keys.
	// Must be rejected — Verify never bootstraps trust from the payload.
	evil, _ := Sign(battacker, kidAtk, Bundle{Device: Device{Name: "h"}, ConfigSigningKeys: []string{attackerPEM}})
	if _, err := Verify(evil, []*ecdsa.PublicKey{k1, k2}); err == nil {
		t.Fatal("a bundle signed by an untrusted key that self-asserts its key must be REJECTED")
	}
}
