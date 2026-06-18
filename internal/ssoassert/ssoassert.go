// Package ssoassert is the portal-signed, no-CA SSO enrollment assertion (ADR 0004
// + decisions S5/S6). The off-mesh gateway (ADR 0005) authenticates the user against
// the IdP and signs a short-lived assertion binding the IdP identity (subject, email,
// issuer, asserted directory groups) to the device requesting enrollment (its pubkey
// hash + the enrollment nonce). The gateway holds NO CA — it can only assert "this IdP
// said this about this device", not issue a cert. Mesh-only Core pins the gateway's
// assertion-signing public key, re-verifies the assertion, and then makes the issuance
// decision (usertrust.Match + the existing approval queue). The internet-facing surface
// holds no issuance authority — that is the ADR 0009 invariant.
//
// The signing key is a DEDICATED ECDSA P-256 keypair (S6), distinct from the CA: the
// gateway gets the private half, Core pins the public half. The assertion is a compact
// ES256 JWS reusing internal/jws (the repo's existing P-256 signed-token primitive),
// so there is one signature scheme across the control plane.
package ssoassert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/jws"
)

// typ is the JWS protected-header type discriminator for SSO enrollment assertions,
// so a token minted for another purpose can't be replayed here.
const typ = "ncp-sso-assertion-v1"

// Errors callers can branch on.
var (
	ErrSignature = errors.New("ssoassert: signature verification failed")
	ErrExpired   = errors.New("ssoassert: assertion expired or not yet valid")
	ErrMalformed = errors.New("ssoassert: malformed assertion")
)

// Assertion is the set of facts the gateway asserts about an SSO enrollment, for Core
// to re-verify and act on. It binds an IdP identity (who) to a specific device (which)
// within a validity window (when).
type Assertion struct {
	// Who: the IdP-asserted identity.
	Subject   string   `json:"sub"`              // IdP subject / NameID
	Email     string   `json:"email,omitempty"`  // IdP-asserted email (informational)
	Issuer    string   `json:"iss"`              // IdP issuer / realm the assertion came from
	IdPGroups []string `json:"groups,omitempty"` // directory groups the IdP asserted (fed to usertrust.Match)
	// Which device: the binding.
	PubkeyHash string `json:"pkh"`   // SHA-256 (or host pubkey hash) the cert will be bound to
	Nonce      string `json:"nonce"` // the enrollment nonce this assertion answers (anti-replay)
	// When: the validity window.
	IssuedAt  int64 `json:"iat"` // unix seconds
	ExpiresAt int64 `json:"exp"` // unix seconds; short-lived (S5)
}

// Sign produces a compact ES256 JWS over a, signed by the gateway's dedicated
// assertion-signing private key (S6). The full Assertion is the JWS payload.
func Sign(priv *ecdsa.PrivateKey, a Assertion) ([]byte, error) {
	payload, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("ssoassert: marshal: %w", err)
	}
	env, err := jws.SignES256(priv, jws.Header{Typ: typ, Ver: 1}, payload)
	if err != nil {
		return nil, fmt.Errorf("ssoassert: sign: %w", err)
	}
	return []byte(env.Protected + "." + env.Payload + "." + env.Signature), nil
}

// Verify checks token against the PINNED gateway public key and the clock. It rejects
// a bad/forged signature (ErrSignature), a token signed with the wrong key
// (ErrSignature), a malformed token or wrong type (ErrMalformed), and a token outside
// its validity window at now (ErrExpired). On success it returns the parsed Assertion.
// Core must still re-run its own checks (nonce single-use, usertrust.Match) — this only
// proves the gateway vouched for these facts.
func Verify(pub *ecdsa.PublicKey, token []byte, now time.Time) (Assertion, error) {
	p1, p2, ok := splitCompact(string(token))
	if !ok {
		return Assertion{}, ErrMalformed
	}
	env := jws.Flattened{Protected: p1, Payload: p2.payload, Signature: p2.sig}

	h, payload, err := jws.Verify(env, pub)
	if err != nil {
		switch {
		case errors.Is(err, jws.ErrSignature):
			return Assertion{}, ErrSignature
		default:
			// ErrMalformed / ErrAlg both mean "not a token we accept".
			return Assertion{}, ErrMalformed
		}
	}
	if h.Typ != typ {
		return Assertion{}, ErrMalformed
	}

	var a Assertion
	if err := json.Unmarshal(payload, &a); err != nil {
		return Assertion{}, ErrMalformed
	}

	nowUnix := now.Unix()
	if a.ExpiresAt != 0 && nowUnix > a.ExpiresAt {
		return Assertion{}, ErrExpired
	}
	if a.IssuedAt != 0 && nowUnix < a.IssuedAt {
		return Assertion{}, ErrExpired // not yet valid
	}
	return a, nil
}

type compactTail struct {
	payload string
	sig     string
}

// splitCompact splits a compact JWS "protected.payload.signature" into its three
// segments without importing strings.Split's allocations into the hot path; it returns
// ok=false unless there are exactly three non-empty dot-separated segments.
func splitCompact(s string) (string, compactTail, bool) {
	first := -1
	second := -1
	for i := 0; i < len(s); i++ {
		if s[i] != '.' {
			continue
		}
		if first < 0 {
			first = i
		} else if second < 0 {
			second = i
		} else {
			return "", compactTail{}, false // more than two dots
		}
	}
	if first < 0 || second < 0 {
		return "", compactTail{}, false // fewer than two dots
	}
	protected := s[:first]
	payload := s[first+1 : second]
	sig := s[second+1:]
	if protected == "" || payload == "" || sig == "" {
		return "", compactTail{}, false
	}
	return protected, compactTail{payload: payload, sig: sig}, true
}

// GenerateKey mints a fresh dedicated assertion-signing keypair (ECDSA P-256). Genesis
// uses this to create the key the gateway signs with and Core pins; tests use it too.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MarshalPrivateKeyPEM encodes priv as a PKCS#8 PRIVATE KEY PEM (the repo's EC private
// key encoding — see collect.GenerateSelfSigned). The gateway is given this half.
func MarshalPrivateKeyPEM(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("ssoassert: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKeyPEM encodes pub as a PKIX PUBLIC KEY PEM. Core pins this half.
func MarshalPublicKeyPEM(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ssoassert: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM parses a PKCS#8 PRIVATE KEY PEM (gateway side) and asserts it is
// an ECDSA P-256 key.
func ParsePrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("ssoassert: not a PKCS#8 PRIVATE KEY PEM")
	}
	any, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ssoassert: parse private key: %w", err)
	}
	priv, ok := any.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("ssoassert: private key is not ECDSA")
	}
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("ssoassert: private key is not P-256")
	}
	return priv, nil
}

// ParsePublicKeyPEM parses a PKIX PUBLIC KEY PEM (Core side) and asserts it is an
// ECDSA P-256 key — the pinned gateway assertion-signing key.
func ParsePublicKeyPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("ssoassert: not a PKIX PUBLIC KEY PEM")
	}
	any, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ssoassert: parse public key: %w", err)
	}
	pub, ok := any.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("ssoassert: public key is not ECDSA")
	}
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("ssoassert: public key is not P-256")
	}
	return pub, nil
}
