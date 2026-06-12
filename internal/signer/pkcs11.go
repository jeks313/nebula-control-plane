//go:build pkcs11

// Package signer's PKCS#11 backend (build tag `pkcs11`, cgo). It signs with a
// non-exportable P256 CA key held in a PKCS#11 token — SoftHSM locally, a real
// HSM in production. Kept behind a build tag so the default Harbor build stays
// pure-Go/cgo-free; KMS (also pure-Go) is the other production path.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/ThalesGroup/crypto11"
)

// PKCS11Config locates the CA key inside a token.
type PKCS11Config struct {
	ModulePath string // e.g. /usr/lib/softhsm/libsofthsm2.so
	TokenLabel string
	Pin        string
	KeyLabel   string
}

type pkcs11Backend struct {
	ctx    *crypto11.Context
	signer crypto.Signer
}

// NewPKCS11Backend opens the token and binds to the named key pair.
func NewPKCS11Backend(cfg PKCS11Config) (Backend, error) {
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       cfg.ModulePath,
		TokenLabel: cfg.TokenLabel,
		Pin:        cfg.Pin,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: pkcs11 configure: %w", err)
	}
	s, err := ctx.FindKeyPair(nil, []byte(cfg.KeyLabel))
	if err != nil {
		_ = ctx.Close()
		return nil, fmt.Errorf("signer: pkcs11 find key %q: %w", cfg.KeyLabel, err)
	}
	if s == nil {
		_ = ctx.Close()
		return nil, fmt.Errorf("signer: pkcs11 key %q not found in token %q", cfg.KeyLabel, cfg.TokenLabel)
	}
	if _, ok := s.Public().(*ecdsa.PublicKey); !ok {
		_ = ctx.Close()
		return nil, fmt.Errorf("signer: pkcs11 key %q is not ECDSA", cfg.KeyLabel)
	}
	return &pkcs11Backend{ctx: ctx, signer: s}, nil
}

func (b *pkcs11Backend) PublicKey() ([]byte, error) {
	pub := b.signer.Public().(*ecdsa.PublicKey)
	ek, err := pub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("signer: pkcs11 export public key: %w", err)
	}
	return ek.Bytes(), nil
}

func (b *pkcs11Backend) SignDigest(digest []byte) ([]byte, error) {
	// crypto11's ECDSA signer returns an ASN.1 DER signature, as Nebula expects.
	return b.signer.Sign(rand.Reader, digest, crypto.SHA256)
}

// Close releases the PKCS#11 context.
func (b *pkcs11Backend) Close() error { return b.ctx.Close() }
