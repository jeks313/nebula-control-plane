package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/slackhq/nebula/cert"
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

// PrivateKeyPEM serializes the CA key in Nebula's signing-key PEM form so local
// dev can persist a software CA across runs. (Software CA only — HSM/KMS keys
// are non-exportable by design.)
func (s *SoftwareBackend) PrivateKeyPEM() ([]byte, error) {
	// SEC1 raw form: the 32-byte big-endian scalar — byte-identical to the old
	// s.key.D.FillBytes(make([]byte, 32)), so PEMs written before this change still
	// load. ParseRawPrivateKey (in LoadSoftwareBackendPEM) is the exact inverse.
	raw, err := s.key.Bytes()
	if err != nil {
		return nil, fmt.Errorf("signer: export software CA key: %w", err)
	}
	return cert.MarshalSigningPrivateKeyToPEM(cert.Curve_P256, raw), nil
}

// LoadSoftwareBackendPEM restores a software CA from PrivateKeyPEM output.
func LoadSoftwareBackendPEM(pemBytes []byte) (*SoftwareBackend, error) {
	raw, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("signer: parse software CA key: %w", err)
	}
	if curve != cert.Curve_P256 {
		return nil, fmt.Errorf("signer: software CA key curve is %s, want P256", curve)
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, fmt.Errorf("signer: load software CA key: %w", err)
	}
	return &SoftwareBackend{key: k}, nil
}
