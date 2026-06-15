// Package signer is Harbor's certificate signing spine (implementation-plan
// M2.3–2.5). It assembles and signs Nebula cert v2 (P256) leaves from a template,
// using a pluggable CA Backend so the same logic runs over SoftHSM/PKCS#11
// locally and AWS KMS in production ("our logic, their guarantees"). Every issue
// is template-validated (2.4) and gated by a fleet-wide circuit breaker (2.5)
// before the CA key is ever touched, and every outcome is audited (2.3).
package signer

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
)

// Backend signs on behalf of the CA key. The private key never leaves the
// backend (HSM/KMS); we only ever hand it a digest.
type Backend interface {
	// PublicKey returns the CA signing public key as an uncompressed P256 point
	// (65 bytes), matching how Nebula encodes a signing key.
	PublicKey() ([]byte, error)
	// SignDigest signs a 32-byte SHA-256 digest and returns an ASN.1 DER ECDSA
	// signature (what Nebula's SignerLambda expects for P256).
	SignDigest(digest []byte) ([]byte, error)
}

// Template is the requested leaf certificate. PKI-policy-relevant fields are
// validated against IssuePolicy before signing.
type Template struct {
	Name      string
	Networks  []netip.Prefix // overlay address(es); host IP within the allocation
	Groups    []string
	NotBefore time.Time
	NotAfter  time.Time
	PublicKey []byte // the host's P256 key-agreement public key (65 bytes)
}

// IssuePolicy is the cert-issuance validation envelope (design §4.3): nothing
// outside the overlay allocation, only sanctioned groups, no insane lifetimes.
// Named IssuePolicy to avoid clashing with policy.Policy (the firewall policy).
type IssuePolicy struct {
	AllowedNetwork netip.Prefix    // host IPs must fall inside this
	AllowedGroups  map[string]bool // if non-empty, groups must be a subset
	MaxLifetime    time.Duration   // NotAfter-NotBefore must not exceed this
}

// Validation errors (2.4) — typed so callers and tests can distinguish them.
var (
	ErrEmptyName         = errors.New("signer: certificate name is empty")
	ErrBadPublicKey      = errors.New("signer: public key is not a 65-byte P256 point")
	ErrNoNetworks        = errors.New("signer: certificate has no networks")
	ErrIPOutOfAllocation = errors.New("signer: network is outside the allowed allocation")
	ErrGroupNotAllowed   = errors.New("signer: group is not in the allowed set")
	ErrInvalidValidity   = errors.New("signer: NotAfter must be after NotBefore")
	ErrLifetimeTooLong   = errors.New("signer: lifetime exceeds the policy maximum")
	ErrExpiresAfterCA    = errors.New("signer: NotAfter is after the CA certificate expiry")
)

// ErrCircuitOpen is returned when the signing circuit breaker has halted issuance.
var ErrCircuitOpen = errors.New("signer: signing halted by circuit breaker")

// Config builds a Signer.
type Config struct {
	CACertPEM       []byte
	Backend         Backend
	Policy          IssuePolicy
	MaxCertsPerHour int
	// Audit records every outcome. Required.
	Audit func(ctx context.Context, actor, action, target, details string) error
	// OnAlarm fires once when the breaker trips (optional; wire to paging).
	OnAlarm func(count int)
	// Now is the clock (tests inject); defaults to time.Now.
	Now func() time.Time
}

// Signer issues leaf certificates.
type Signer struct {
	caCert  cert.Certificate
	backend Backend
	policy  IssuePolicy
	breaker *breaker
	audit   func(ctx context.Context, actor, action, target, details string) error
	onAlarm func(count int)
	now     func() time.Time
}

// New validates config and returns a Signer. It confirms the backend's public
// key actually matches the CA certificate, so a misconfigured backend fails
// fast rather than minting certs no one trusts.
func New(cfg Config) (*Signer, error) {
	if cfg.Audit == nil {
		return nil, fmt.Errorf("signer: Audit callback is required")
	}
	if cfg.Backend == nil {
		return nil, fmt.Errorf("signer: Backend is required")
	}
	ca, _, err := cert.UnmarshalCertificateFromPEM(cfg.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("signer: parse CA cert: %w", err)
	}
	if !ca.IsCA() {
		return nil, fmt.Errorf("signer: provided certificate is not a CA")
	}
	if ca.Curve() != cert.Curve_P256 {
		return nil, fmt.Errorf("signer: CA curve is %s, only P256 is supported", ca.Curve())
	}
	pub, err := cfg.Backend.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("signer: backend public key: %w", err)
	}
	if !bytesEqual(pub, ca.PublicKey()) {
		return nil, fmt.Errorf("signer: backend public key does not match the CA certificate")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Signer{
		caCert:  ca,
		backend: cfg.Backend,
		policy:  cfg.Policy,
		breaker: newBreaker(cfg.MaxCertsPerHour, time.Hour, now),
		audit:   cfg.Audit,
		onAlarm: cfg.OnAlarm,
		now:     now,
	}, nil
}

// Issue validates, rate-limits, signs, and audits a leaf certificate. actor is
// the authenticated requester (for the audit row). It returns the certificate
// and its PEM encoding.
func (s *Signer) Issue(ctx context.Context, actor string, t Template) (cert.Certificate, []byte, error) {
	// 1. Validate before touching the breaker budget or the CA key (2.4).
	if err := s.validate(t); err != nil {
		_ = s.audit(ctx, actor, "issue-cert-rejected", t.Name, err.Error())
		return nil, nil, err
	}

	// 2. Circuit breaker (2.5): halt + alarm + audit on breach.
	allowed, justTripped := s.breaker.acquire()
	if !allowed {
		if justTripped {
			if s.onAlarm != nil {
				s.onAlarm(s.breaker.max)
			}
			_ = s.audit(ctx, "system", "signing-circuit-tripped", t.Name,
				fmt.Sprintf(`{"limit_per_hour":%d}`, s.breaker.max))
		}
		_ = s.audit(ctx, actor, "issue-cert-rejected", t.Name, ErrCircuitOpen.Error())
		return nil, nil, ErrCircuitOpen
	}

	// 3. Assemble + sign (2.3).
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      t.Name,
		Networks:  t.Networks,
		Groups:    t.Groups,
		IsCA:      false,
		NotBefore: t.NotBefore,
		NotAfter:  t.NotAfter,
		PublicKey: t.PublicKey,
		Curve:     cert.Curve_P256,
	}
	c, err := SignTBS(s.backend, tbs, s.caCert)
	if err != nil {
		_ = s.audit(ctx, actor, "issue-cert-error", t.Name, err.Error())
		return nil, nil, fmt.Errorf("signer: sign: %w", err)
	}
	pem, err := c.MarshalPEM()
	if err != nil {
		return nil, nil, fmt.Errorf("signer: marshal cert: %w", err)
	}

	fp, _ := c.Fingerprint()
	details, _ := json.Marshal(map[string]any{
		"fingerprint": fp,
		"networks":    prefixesToStrings(t.Networks),
		"groups":      t.Groups,
		"not_after":   t.NotAfter.UTC().Format(time.RFC3339),
	})
	if err := s.audit(ctx, actor, "issue-cert", t.Name, string(details)); err != nil {
		return nil, nil, fmt.Errorf("signer: audit issued cert: %w", err)
	}
	return c, pem, nil
}

// ResetBreaker clears a tripped circuit breaker (an admin action; should itself
// be dual-controlled when wired into the API, M2.11).
func (s *Signer) ResetBreaker() { s.breaker.reset() }

func (s *Signer) validate(t Template) error {
	if t.Name == "" {
		return ErrEmptyName
	}
	if len(t.PublicKey) != 65 {
		return ErrBadPublicKey
	}
	if len(t.Networks) == 0 {
		return ErrNoNetworks
	}
	if s.policy.AllowedNetwork.IsValid() {
		for _, n := range t.Networks {
			if !s.policy.AllowedNetwork.Contains(n.Addr()) {
				return fmt.Errorf("%w: %s not in %s", ErrIPOutOfAllocation, n, s.policy.AllowedNetwork)
			}
		}
	}
	if len(s.policy.AllowedGroups) > 0 {
		for _, g := range t.Groups {
			if !s.policy.AllowedGroups[g] {
				return fmt.Errorf("%w: %q", ErrGroupNotAllowed, g)
			}
		}
	}
	if !t.NotAfter.After(t.NotBefore) {
		return ErrInvalidValidity
	}
	if s.policy.MaxLifetime > 0 && t.NotAfter.Sub(t.NotBefore) > s.policy.MaxLifetime {
		return fmt.Errorf("%w: %s > %s", ErrLifetimeTooLong, t.NotAfter.Sub(t.NotBefore), s.policy.MaxLifetime)
	}
	if t.NotAfter.After(s.caCert.NotAfter()) {
		return fmt.Errorf("%w (CA expires %s)", ErrExpiresAfterCA, s.caCert.NotAfter().UTC().Format(time.RFC3339))
	}
	return nil
}

// CATemplate describes a self-signed CA certificate.
type CATemplate struct {
	Name      string
	Networks  []netip.Prefix // optional; constrains what leaves may carry
	NotBefore time.Time
	NotAfter  time.Time
}

// SelfSignCA creates a self-signed P256 CA certificate from the backend's key.
// This is the building block for the genesis ceremony (M3.1); for now it backs
// `harbor ca-init` and tests.
func SelfSignCA(b Backend, t CATemplate) (cert.Certificate, []byte, error) {
	pub, err := b.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("signer: backend public key: %w", err)
	}
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      t.Name,
		Networks:  t.Networks,
		IsCA:      true,
		NotBefore: t.NotBefore,
		NotAfter:  t.NotAfter,
		PublicKey: pub,
		Curve:     cert.Curve_P256,
	}
	c, err := SignTBS(b, tbs, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("signer: self-sign CA: %w", err)
	}
	pem, err := c.MarshalPEM()
	if err != nil {
		return nil, nil, fmt.Errorf("signer: marshal CA: %w", err)
	}
	return c, pem, nil
}

// SignTBS signs a to-be-signed certificate with the backend. If ca is nil, tbs
// must be a CA (self-signed) — useful for the genesis ceremony (M3.1) and tests.
func SignTBS(b Backend, tbs *cert.TBSCertificate, ca cert.Certificate) (cert.Certificate, error) {
	lambda := func(certBytes []byte) ([]byte, error) {
		h := sha256.Sum256(certBytes)
		return b.SignDigest(h[:])
	}
	return tbs.SignWith(ca, cert.Curve_P256, lambda)
}

func prefixesToStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
