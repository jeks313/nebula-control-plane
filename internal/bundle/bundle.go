// Package bundle assembles, signs, and verifies the enrollment config bundle
// (protocol spec §6, implementation-plan 3.6). The bundle carries the signed
// leaf certificate, the CA trust bundle, and the host's config/lighthouses; it
// is itself signed by the **config-signing key** (distinct from the CA key) so
// Pilot verifies it against a pinned public key before trusting anything inside.
package bundle

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// Type is the bundle payload type.
const Type = "config-bundle"

// Lighthouse advertises a lighthouse to a host (overlay IP -> public addrs).
type Lighthouse struct {
	OverlayIP   string   `json:"overlay_ip"`
	PublicAddrs []string `json:"public_addrs"`
}

// Device is the issued identity summary.
type Device struct {
	Name      string   `json:"name"`
	OverlayIP string   `json:"overlay_ip"`
	Groups    []string `json:"groups"`
}

// Bundle is the config bundle payload (spec §6).
type Bundle struct {
	ProtocolVersion int             `json:"protocol_version"`
	Type            string          `json:"type"`
	BundleVersion   int             `json:"bundle_version"`
	IssuedAt        string          `json:"issued_at"`
	Device          Device          `json:"device"`
	Certificate     string          `json:"certificate"` // leaf cert PEM
	CABundle        []string        `json:"ca_bundle"`   // CA cert PEM(s)
	Config          json.RawMessage `json:"config,omitempty"`
	Lighthouses     []Lighthouse    `json:"lighthouses"`
	NotAfter        string          `json:"not_after"`
	NextRenewAfter  string          `json:"next_renew_after,omitempty"`
}

// Sign serializes and signs a bundle with the config-signing key, returning the
// flattened JWS bytes (what gets stored + delivered to Pilot).
func Sign(signer jws.DigestSigner, keyID string, b Bundle) ([]byte, error) {
	b.ProtocolVersion = wire.ProtocolVersion
	b.Type = Type
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	env, err := jws.SignBackendES256(signer, jws.Header{Typ: wire.TypBundle, Ver: 1, Kid: keyID}, payload)
	if err != nil {
		return nil, fmt.Errorf("bundle: sign: %w", err)
	}
	return json.Marshal(env)
}

// Verify checks a bundle JWS against the pinned config-signing public key and
// returns the payload. This is Pilot's gate (spec §6, step 1): nothing inside is
// trusted until the bundle signature verifies against a pinned key.
func Verify(jwsBytes []byte, pinned *ecdsa.PublicKey) (Bundle, error) {
	var env jws.Flattened
	if err := json.Unmarshal(jwsBytes, &env); err != nil {
		return Bundle{}, fmt.Errorf("bundle: not a JWS: %w", err)
	}
	hdr, payload, err := jws.Verify(env, pinned)
	if err != nil {
		return Bundle{}, fmt.Errorf("bundle: signature: %w", err)
	}
	if hdr.Typ != wire.TypBundle {
		return Bundle{}, fmt.Errorf("bundle: wrong typ %q", hdr.Typ)
	}
	var b Bundle
	if err := json.Unmarshal(payload, &b); err != nil {
		return Bundle{}, fmt.Errorf("bundle: payload: %w", err)
	}
	if b.Type != Type {
		return Bundle{}, fmt.Errorf("bundle: wrong type %q", b.Type)
	}
	return b, nil
}
