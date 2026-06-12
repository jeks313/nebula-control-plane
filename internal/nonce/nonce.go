// Package nonce implements the stateless enrollment nonce from the protocol spec
// (§4.3, implementation-plan 3.2). A nonce is `base64url( ts_be8 || mac )` where
// `mac = HMAC-SHA256(k_gw, "ncp-nonce-v1" || ts_be8 || binding)[:16]`. It carries
// its own freshness (the timestamp) and binding (to the requester's pubkey hash),
// so the gateway needs no server-side state to issue it and the verifier needs
// none to check it. Single-use is NOT provided here (stateless can't) — Core
// keeps a short replay cache for that (3.4).
package nonce

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	label  = "ncp-nonce-v1" // domain separation
	macLen = 16
	tsLen  = 8
	// Defaults from the protocol spec.
	DefaultTTL     = 60 * time.Second
	DefaultMaxSkew = 30 * time.Second
)

// Verification outcomes.
var (
	ErrMalformed = errors.New("nonce: malformed")
	ErrExpired   = errors.New("nonce: expired or not yet valid")
	ErrBadMAC    = errors.New("nonce: bad MAC (forged or wrong binding)")
)

// Keyring mints with the primary key and verifies against all keys (primary +
// any previous), so k_gw can rotate with overlap (2.10/4.8) without invalidating
// nonces in flight.
type Keyring struct {
	keys    [][]byte // keys[0] is primary
	ttl     time.Duration
	maxSkew time.Duration
	now     func() time.Time
}

// NewKeyring builds a keyring. keys[0] is the primary (used to mint); the rest
// are accepted on verify. Each key must be at least 16 bytes. ttl/maxSkew <= 0
// take the spec defaults.
func NewKeyring(keys [][]byte, ttl, maxSkew time.Duration) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("nonce: at least one key is required")
	}
	for i, k := range keys {
		if len(k) < 16 {
			return nil, fmt.Errorf("nonce: key %d is shorter than 16 bytes", i)
		}
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if maxSkew <= 0 {
		maxSkew = DefaultMaxSkew
	}
	return &Keyring{keys: keys, ttl: ttl, maxSkew: maxSkew, now: time.Now}, nil
}

// Mint issues a nonce bound to binding (the requester's pubkey hash) and returns
// it with its expiry.
func (k *Keyring) Mint(binding []byte) (string, time.Time) {
	ts := k.now().Unix()
	var tsb [tsLen]byte
	binary.BigEndian.PutUint64(tsb[:], uint64(ts))

	out := make([]byte, 0, tsLen+macLen)
	out = append(out, tsb[:]...)
	out = append(out, mac(k.keys[0], tsb[:], binding)...)
	return base64.RawURLEncoding.EncodeToString(out), time.Unix(ts, 0).Add(k.ttl).UTC()
}

// Verify checks a nonce against binding at the current time. It returns nil if
// the nonce is well-formed, fresh, and authentic for binding under any key.
func (k *Keyring) Verify(nonceB64 string, binding []byte) error {
	raw, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil || len(raw) != tsLen+macLen {
		return ErrMalformed
	}
	ts := int64(binary.BigEndian.Uint64(raw[:tsLen]))
	got := raw[tsLen:]

	age := k.now().Unix() - ts
	if age > int64(k.ttl.Seconds()) || age < -int64(k.maxSkew.Seconds()) {
		return ErrExpired
	}
	for _, key := range k.keys {
		if hmac.Equal(got, mac(key, raw[:tsLen], binding)) {
			return nil
		}
	}
	return ErrBadMAC
}

func mac(key, tsb, binding []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	h.Write(tsb)
	h.Write(binding) // last, variable-length field — no length-prefix ambiguity
	return h.Sum(nil)[:macLen]
}
