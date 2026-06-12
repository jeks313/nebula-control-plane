package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

// SoftwareBackend holds a P256 CA key in process memory. It is for unit tests
// and throwaway local dev only — real deployments use the PKCS#11 (SoftHSM/HSM)
// or KMS backend, where the key is non-exportable.
type SoftwareBackend struct {
	key *ecdsa.PrivateKey
}

// NewSoftwareBackend generates a fresh in-memory P256 CA key.
func NewSoftwareBackend() (*SoftwareBackend, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signer: generate software CA key: %w", err)
	}
	return &SoftwareBackend{key: k}, nil
}

// PublicKey returns the uncompressed P256 point (65 bytes).
func (s *SoftwareBackend) PublicKey() ([]byte, error) {
	ek, err := s.key.PublicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("signer: export software public key: %w", err)
	}
	return ek.Bytes(), nil
}

// SignDigest signs a SHA-256 digest, returning an ASN.1 DER ECDSA signature.
func (s *SoftwareBackend) SignDigest(digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}
