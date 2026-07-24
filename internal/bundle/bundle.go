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
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/policy"
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

// Firewall is the host's central-policy firewall (M6), compiled by Harbor and
// signed into the bundle. Present only when a central policy is in force; absent
// means Pilot keeps its local default. Because it's inside the signed payload,
// tampering with it breaks bundle verification.
type Firewall struct {
	Inbound  []nebulaconfig.Rule `json:"inbound"`
	Outbound []nebulaconfig.Rule `json:"outbound"`
}

// Bundle is the config bundle payload (spec §6).
type Bundle struct {
	ProtocolVersion int    `json:"protocol_version"`
	Type            string `json:"type"`
	BundleVersion   int    `json:"bundle_version"`
	// BlocklistVersion is the blocklist-lane generation this bundle reflects (7.1b),
	// tracked separately from BundleVersion (the policy-lane version) so a blocklist
	// rollout converges independently of a policy rollout. The host reports it back
	// as applied_blocklist_version.
	BlocklistVersion int             `json:"blocklist_version,omitempty"`
	IssuedAt         string          `json:"issued_at"`
	Device           Device          `json:"device"`
	Certificate      string          `json:"certificate"` // leaf cert PEM
	CABundle         []string        `json:"ca_bundle"`   // CA cert PEM(s)
	// ConfigSigningKeys is the fleet's TRUSTED set of config-signing PUBLIC-key PEMs (M8.5,
	// design §4.6/§4.8). Pilot verifies this bundle against ANY key in its trusted set = its
	// permanent pin UNION these; sourced live from the config-key rotation registry (every
	// NON-RETIRED key) so a STAGED key is trusted fleet-wide before it ever signs ("trust before
	// you sign"). Sorted for byte-stable output; omitempty keeps legacy bundles unaffected (a pilot
	// that sees none falls back to its single pinned key). The config-signing key is the ROOT that
	// verifies this bundle (unlike ca_bundle, a MEMBER), so a premature cut-over fails CLOSED —
	// which is why a cut-over is gated on 100% fleet adoption of the staged key.
	ConfigSigningKeys []string `json:"config_signing_keys,omitempty"`
	// ConfigKeyVersion is the config-key registry generation this bundle reflects (M8.5), its own
	// axis (like BlocklistVersion). Pilot uses it to fail-SAFE against a replayed OLD bundle
	// regressing its learned trusted set: it adopts the set only from a bundle at least as new as
	// the last it applied (the permanent pin is always present + exempt from the guard).
	ConfigKeyVersion int64     `json:"config_key_version,omitempty"`
	Firewall         *Firewall `json:"firewall,omitempty"`
	Config           json.RawMessage `json:"config,omitempty"`
	Lighthouses      []Lighthouse    `json:"lighthouses"`
	// Blocklist is the fleet's revoked cert fingerprints (hex sha256), rendered
	// into nebula's pki.blocklist (M7.1). Enforced PEER-SIDE: every host refuses to
	// handshake with a blocklisted fingerprint (§4.7). It rides inside the signed
	// payload, so tampering breaks bundle verification. Sourced from the active
	// revocations at bundle-build time; ordered for deterministic output.
	Blocklist []string `json:"blocklist,omitempty"`
	// TunDev + ListenPort are the mesh-wide nebula TUN device name and UDP listen
	// port. They ride the signed bundle so a host on MULTIPLE meshes (a bridge node)
	// gets a distinct device + port per mesh and its nebula instances don't collide.
	// Empty/zero -> the renderer's nebula1/4242 defaults, so legacy bundles are
	// unaffected (omitempty keeps them out of older payloads).
	TunDev     string `json:"tun_dev,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
	// NebulaVersion / NebulaSHA256 / NebulaURL distribute the data-plane binary
	// itself (ADR 0003 Phase 1): the version Harbor wants this host to run, the hex
	// SHA-256 the pilot verifies before exec (the integrity anchor — so the URL/CDN
	// need not be trusted), and where to fetch the bytes. All empty -> the host keeps
	// its current nebula; legacy bundles are unaffected (omitempty).
	NebulaVersion string `json:"nebula_version,omitempty"`
	NebulaSHA256  string `json:"nebula_sha256,omitempty"`
	NebulaURL     string `json:"nebula_url,omitempty"`
	// PilotVersion / PilotSHA256 / PilotURL distribute the PILOT (agent) binary the
	// same way (ADR 0003 Phase 3c): the version Harbor wants this host's pilot to run,
	// its integrity-anchor sha, and where to fetch it. The pilot self-updates by
	// re-exec/re-adopt (Phase 3b). All empty -> the host keeps its current pilot.
	PilotVersion   string `json:"pilot_version,omitempty"`
	PilotSHA256    string `json:"pilot_sha256,omitempty"`
	PilotURL       string `json:"pilot_url,omitempty"`
	NotAfter       string `json:"not_after"`
	NextRenewAfter string `json:"next_renew_after,omitempty"`
}

// RenderNebulaConfig renders a bundle into a nebula config.yml: lighthouses +
// PKI paths, with the signed firewall (if present) overriding the local default.
// Shared by the enroll/renew apply path and by drift re-assertion (M6.7) so both
// produce byte-identical output.
func RenderNebulaConfig(b Bundle, caPath, certPath, keyPath string) ([]byte, error) {
	lhs := make([]nebulaconfig.Lighthouse, len(b.Lighthouses))
	for i, l := range b.Lighthouses {
		lhs[i] = nebulaconfig.Lighthouse{OverlayIP: l.OverlayIP, PublicAddrs: l.PublicAddrs}
	}
	v := nebulaconfig.Values{Lighthouses: lhs, CACertPath: caPath, CertPath: certPath, KeyPath: keyPath}
	v.TunDev = b.TunDev         // mesh-wide; "" -> Defaults() fills nebula1
	v.ListenPort = b.ListenPort // mesh-wide; 0 -> Defaults() fills 4242
	v.Defaults()
	if b.Firewall != nil {
		v.Inbound = b.Firewall.Inbound
		v.Outbound = b.Firewall.Outbound
	}
	v.Blocklist = b.Blocklist
	return nebulaconfig.Render(v)
}

// CompileFirewall compiles the central policy for a host's groups into the
// bundle's signed firewall. nil policy -> nil firewall (Pilot keeps its renderer
// default), EXCEPT a control-plane host ALWAYS gets its invariant firewall (compiled
// from an empty policy) so pilot's drift/renew config re-render can never close
// harbor's own API ports — even before any policy is published. This is what lets a
// control-plane node run under `pilot supervise` safely. Non-control-plane hosts are
// unaffected (still nil -> renderer default), so clients keep their current firewall.
func CompileFirewall(p *policy.Policy, groups []string) *Firewall {
	if p == nil {
		if !hasControlPlane(groups) {
			return nil
		}
		c := policy.CompileHost(policy.Policy{}, groups) // baseline invariants only
		return &Firewall{Inbound: c.Inbound, Outbound: c.Outbound}
	}
	c := policy.CompileHost(*p, groups)
	return &Firewall{Inbound: c.Inbound, Outbound: c.Outbound}
}

func hasControlPlane(groups []string) bool {
	for _, g := range groups {
		if g == policy.GroupControlPlane {
			return true
		}
	}
	return false
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

// Verify checks a bundle JWS against the pilot's TRUSTED SET of config-signing public keys and
// returns the payload. This is Pilot's gate (spec §6, step 1): nothing inside is trusted until the
// bundle signature verifies against a trusted key. The set is Pilot's permanent pin UNION the keys
// carried in its last verified bundle's config_signing_keys (M8.5), so a bundle signed by the old OR
// the new config-signing key verifies across a K1->K2 rotation with no rejection. Fail-closed: an
// empty set, or a signature by a non-trusted key, is rejected — as is a tampered payload, since the
// signature covers config_signing_keys itself (no bootstrap-trust from the payload).
func Verify(jwsBytes []byte, trusted []*ecdsa.PublicKey) (Bundle, error) {
	var env jws.Flattened
	if err := json.Unmarshal(jwsBytes, &env); err != nil {
		return Bundle{}, fmt.Errorf("bundle: not a JWS: %w", err)
	}
	hdr, payload, err := jws.VerifyAny(env, trusted)
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
