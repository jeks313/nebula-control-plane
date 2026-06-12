// Package jws implements the minimal JWS (Flattened JSON Serialization, ES256)
// the protocol spec uses for signed requests and bundles (§3). ES256 signatures
// are fixed-size R‖S (64 bytes), per RFC 7518 — not ASN.1 DER. Pilot signs
// requests with its P256 key (proof of possession); Harbor/Core verify.
package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Alg is the only signature algorithm v1 supports.
const Alg = "ES256"

// Verification errors.
var (
	ErrMalformed = errors.New("jws: malformed envelope")
	ErrAlg       = errors.New("jws: unsupported alg")
	ErrSignature = errors.New("jws: signature verification failed")
)

// Header is the JWS protected header (spec §3).
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Ver int    `json:"ver"`
	Kid string `json:"kid"`
}

// Flattened is a JWS Flattened JSON Serialization object.
type Flattened struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

var b64 = base64.RawURLEncoding

// SignES256 produces a flattened JWS over payload with the given protected
// header, signed by an ECDSA P256 key.
func SignES256(priv *ecdsa.PrivateKey, h Header, payload []byte) (Flattened, error) {
	h.Alg = Alg
	hb, err := json.Marshal(h)
	if err != nil {
		return Flattened{}, err
	}
	protected := b64.EncodeToString(hb)
	pl := b64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(protected + "." + pl))

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return Flattened{}, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return Flattened{Protected: protected, Payload: pl, Signature: b64.EncodeToString(sig)}, nil
}

// Verify checks env against pub and returns the parsed header and payload. It
// enforces alg == ES256; callers MUST additionally check typ/kid as the spec
// requires for their context.
func Verify(env Flattened, pub *ecdsa.PublicKey) (Header, []byte, error) {
	hb, err := b64.DecodeString(env.Protected)
	if err != nil {
		return Header{}, nil, ErrMalformed
	}
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Header{}, nil, ErrMalformed
	}
	if h.Alg != Alg {
		return Header{}, nil, ErrAlg
	}
	sig, err := b64.DecodeString(env.Signature)
	if err != nil || len(sig) != 64 {
		return Header{}, nil, ErrMalformed
	}
	payload, err := b64.DecodeString(env.Payload)
	if err != nil {
		return Header{}, nil, ErrMalformed
	}

	digest := sha256.Sum256([]byte(env.Protected + "." + env.Payload))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return Header{}, nil, ErrSignature
	}
	return h, payload, nil
}

// ParseP256PublicPoint turns a 65-byte uncompressed P256 point (Nebula's host
// public key encoding) into an ecdsa.PublicKey for verification.
func ParseP256PublicPoint(b []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), b)
	if x == nil {
		return nil, fmt.Errorf("jws: invalid P256 public point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
