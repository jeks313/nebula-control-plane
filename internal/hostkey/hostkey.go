// Package hostkey generates and persists a host's Nebula key-agreement keypair
// (implementation-plan M1.4). The curve is P256 — the same curve the KMS/HSM CA
// signs (design §"Cert v2 / PKCS#11"), so a host key generated here can be signed
// by the control-plane CA without a curve mismatch.
//
// Security boundary (design P1): the private key is generated in-process and is
// only ever exposed by writing it to a file with owner-only permissions. There
// is deliberately no exported accessor that returns the raw private scalar —
// callers can export the *public* key, write the private key to disk, or sign;
// nothing more. The key format is produced by Nebula's own cert library so it is
// byte-for-byte what `nebula-cert keygen -curve P256` would write (no bespoke
// crypto, design P11).
package hostkey

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/slackhq/nebula/cert"
)

// ErrKeyExists is returned by WritePrivateKey when the target already holds a
// key. Overwriting a live host key is never something we do silently: it would
// orphan the host's issued certificate and is a classic footgun.
var ErrKeyExists = errors.New("hostkey: private key file already exists")

// KeyPair is a P256 key-agreement keypair. The private key never leaves this
// struct except via WritePrivateKey (to an owner-only file).
type KeyPair struct {
	priv *ecdh.PrivateKey
}

// Generate creates a fresh P256 key-agreement keypair using the same primitive
// Nebula uses internally (crypto/ecdh P256).
func Generate() (*KeyPair, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hostkey: generate P256 key: %w", err)
	}
	return &KeyPair{priv: priv}, nil
}

// Load reads a host private key from a Nebula P256 PEM file.
func Load(path string) (*KeyPair, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hostkey: read %s: %w", path, err)
	}
	b, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("hostkey: parse private key: %w", err)
	}
	if curve != cert.Curve_P256 {
		return nil, fmt.Errorf("hostkey: key curve is %s, want P256", curve)
	}
	priv, err := ecdh.P256().NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("hostkey: load private key: %w", err)
	}
	return &KeyPair{priv: priv}, nil
}

// PublicKeyBytes returns the uncompressed P256 point (65 bytes) — the form used
// in the enrollment CSR and for the pubkey hash.
func (k *KeyPair) PublicKeyBytes() []byte { return k.priv.PublicKey().Bytes() }

// SignDigest signs a digest with the host key (ECDSA P256, ASN.1 DER) — the
// proof-of-possession signature for enrollment. The private key stays in-process
// (P1); it is reconstructed as an ECDSA key from the same scalar.
func (k *KeyPair) SignDigest(digest []byte) ([]byte, error) {
	ek, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), k.priv.Bytes())
	if err != nil {
		return nil, fmt.Errorf("hostkey: derive signing key: %w", err)
	}
	return ecdsa.SignASN1(rand.Reader, ek, digest)
}

// PublicKeyPEM returns the public key in Nebula's "NEBULA P256 PUBLIC KEY" PEM
// form — this is what gets sent to the control plane to be signed.
func (k *KeyPair) PublicKeyPEM() []byte {
	return cert.MarshalPublicKeyToPEM(cert.Curve_P256, k.priv.PublicKey().Bytes())
}

// privateKeyPEM is unexported on purpose: the private key only ever materializes
// on its way to an owner-only file (WritePrivateKey). Keeping this private is the
// enforcement of the P1 boundary.
func (k *KeyPair) privateKeyPEM() []byte {
	return cert.MarshalPrivateKeyToPEM(cert.Curve_P256, k.priv.Bytes())
}

// WritePrivateKey writes the private key to path with owner-only permissions
// (0600 on POSIX; see paths.SecureFileMode). It refuses to overwrite an existing
// file (ErrKeyExists) so a re-run can never clobber a live host key.
func (k *KeyPair) WritePrivateKey(path string) error {
	// O_EXCL makes the create atomic and fail if the file exists.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrKeyExists, path)
		}
		return fmt.Errorf("hostkey: open private key for write: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(k.privateKeyPEM()); err != nil {
		return fmt.Errorf("hostkey: write private key: %w", err)
	}
	return f.Sync()
}

// WritePrivateKeyAtomic writes (and replaces) the private key via a temp file +
// rename — for key rotation at renewal, where deliberately replacing the live
// key is correct (unlike WritePrivateKey's no-clobber initial write).
func (k *KeyPair) WritePrivateKeyAtomic(path string) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, k.privateKeyPEM(), 0600); err != nil {
		return fmt.Errorf("hostkey: write temp private key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("hostkey: replace private key: %w", err)
	}
	return nil
}

// WritePublicKey writes the public key PEM to path (0644 — it is not secret).
func (k *KeyPair) WritePublicKey(path string) error {
	if err := os.WriteFile(path, k.PublicKeyPEM(), 0644); err != nil {
		return fmt.Errorf("hostkey: write public key: %w", err)
	}
	return nil
}
