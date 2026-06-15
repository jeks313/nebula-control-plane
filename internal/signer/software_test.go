package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"testing"
)

// TestSoftwareBackendPEMRoundTrip locks the on-disk private-key format after the
// crypto/ecdsa deprecation migration (#34): PrivateKeyPEM uses PrivateKey.Bytes()
// (SEC1 raw) and LoadSoftwareBackendPEM uses ParseRawPrivateKey — exact inverses.
// A persisted software CA must survive write -> reload with the same identity, a
// stable PEM, and a still-verifiable signature.
func TestSoftwareBackendPEMRoundTrip(t *testing.T) {
	sb, err := NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := sb.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSoftwareBackendPEM(pem)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	// Same identity: the reloaded key has the same public point.
	wantPub, err := sb.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := loaded.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wantPub, gotPub) {
		t.Fatal("reloaded public key differs from the original")
	}

	// Stable format: re-serializing the reloaded key reproduces the exact PEM.
	pem2, err := loaded.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pem, pem2) {
		t.Fatal("PrivateKeyPEM is not stable across a load round-trip")
	}

	// Functional: a signature from the reloaded key verifies under the original public key.
	digest := sha256.Sum256([]byte("software-backend round-trip"))
	der, err := loaded.SignDigest(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), wantPub)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		t.Fatal("signature from the reloaded key does not verify")
	}
}
