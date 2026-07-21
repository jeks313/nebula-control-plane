// Package signer is Harbor's certificate signing spine (implementation-plan
// M2.3–2.5). It assembles and signs Nebula cert v2 (P256) leaves from a template,
// using a pluggable CA Backend so the same logic runs over SoftHSM/PKCS#11
// locally and AWS KMS in production ("our logic, their guarantees"). Every issue
// is template-validated (2.4) and gated by a fleet-wide circuit breaker (2.5)
// before the CA key is ever touched, and every outcome is audited (2.3).
package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/slackhq/nebula/cert"
)

// Signing circuit-breaker metrics (Phase 7 observability). Registered to the default
// Prometheus registry at init; shared across the process's signers (one fleet-wide lane).
var (
	metricBreakerOpen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ncp_signer_breaker_open",
		Help: "1 when this Core observes the signing circuit breaker open (issuance halted), else 0.",
	})
	metricBreakerTrips = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ncp_signer_breaker_trips_total",
		Help: "Signing circuit breaker trips observed by this Core (the cert/hour ceiling was breached).",
	})
	// M8.3b online CA-rotation cut-over: incremented each time this process hot-swaps its
	// signing identity to a newly-activated CA (should tick once per rotation per process).
	metricActiveCACutovers = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ncp_signer_active_ca_cutovers_total",
		Help: "Signing CA hot-swaps this process performed (M8.3b online CA rotation cut-over).",
	})
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

// LaneCA is the breaker lane for CA leaf issuance — a single fleet-wide ceiling shared
// by every Core process and every issuing path (enrollment + renewal).
const LaneCA = "ca"

// Breaker is the signing circuit breaker. Two impls live in this package: the in-process
// breaker (default; a single Core) and SQLBreaker (a shared DB table) so an HA Harbor
// enforces the rate ceiling fleet-wide and a trip halts every Core. Methods are
// unexported so only this package's impls satisfy it; external callers wire one via
// Config.Breaker (e.g. NewSQLBreaker).
type Breaker interface {
	// acquire consumes one unit. allowed: may proceed. justTripped: true only on the
	// call that flips the breaker open (so the alarm fires once, fleet-wide). A non-nil
	// err is an infrastructure failure (shared store unreachable) — the signer fails
	// closed (halts) since it cannot confirm it is under the ceiling.
	acquire(ctx context.Context) (allowed, justTripped bool, err error)
	// reset re-arms the breaker (an operator action).
	reset(ctx context.Context) error
	// limit returns the configured ceiling (for the alarm/audit detail).
	limit() int
	// isOpen reports the authoritative open state (the shared latch for the SQL breaker),
	// so an idle Core can reflect a fleet-wide trip in its metric without issuing a cert.
	isOpen(ctx context.Context) (bool, error)
}

// Config builds a Signer.
type Config struct {
	CACertPEM       []byte
	Backend         Backend
	Policy          IssuePolicy
	MaxCertsPerHour int
	// Breaker overrides the circuit breaker. When nil, an in-process breaker bounded by
	// MaxCertsPerHour is used (a single Core). Set a SQLBreaker for HA (fleet-wide).
	Breaker Breaker
	// Audit records every outcome. Required.
	Audit func(ctx context.Context, actor, action, target, details string) error
	// OnAlarm fires once when the breaker trips (optional; wire to paging).
	OnAlarm func(count int)
	// Now is the clock (tests inject); defaults to time.Now.
	Now func() time.Time
}

// signingIdentity is the {CA cert, signing backend} pair the Signer currently signs with. It
// is swapped ATOMICALLY as a unit during an online CA-rotation cut-over (M8.3b) so a leaf is
// never signed by CA_n's backend but chained to CA_m's cert. The fingerprint is precomputed so
// the reconciler can compare cheaply without re-hashing the cert each poll.
type signingIdentity struct {
	caCert      cert.Certificate
	backend     Backend
	fingerprint string // lower-hex caCert.Fingerprint()
}

// newIdentity validates a CA cert + backend the SAME way boot does (parse, IsCA, P256, and the
// backend's public key MUST match the cert) and returns the ready-to-store identity. Used by
// both New (boot) and SwapCA (cut-over), so a hot-swap can never install an identity that boot
// would have rejected.
func newIdentity(caCertPEM []byte, backend Backend) (*signingIdentity, error) {
	if backend == nil {
		return nil, fmt.Errorf("signer: Backend is required")
	}
	ca, _, err := cert.UnmarshalCertificateFromPEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("signer: parse CA cert: %w", err)
	}
	if !ca.IsCA() {
		return nil, fmt.Errorf("signer: provided certificate is not a CA")
	}
	if ca.Curve() != cert.Curve_P256 {
		return nil, fmt.Errorf("signer: CA curve is %s, only P256 is supported", ca.Curve())
	}
	pub, err := backend.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("signer: backend public key: %w", err)
	}
	if !bytes.Equal(pub, ca.PublicKey()) {
		return nil, fmt.Errorf("signer: backend public key does not match the CA certificate")
	}
	fp, _ := ca.Fingerprint()
	return &signingIdentity{caCert: ca, backend: backend, fingerprint: strings.ToLower(strings.TrimSpace(fp))}, nil
}

// Signer issues leaf certificates. The {CA cert, backend} it signs with lives behind an atomic
// pointer so it can be hot-swapped mid-flight (M8.3b); the breaker, policy, audit, and clock are
// process-level and survive a cut-over unchanged (the fleet-wide rate ceiling + audit trail carry
// across a rotation).
type Signer struct {
	identity atomic.Pointer[signingIdentity]
	policy   IssuePolicy
	breaker  Breaker
	audit    func(ctx context.Context, actor, action, target, details string) error
	onAlarm  func(count int)
	now      func() time.Time
}

// New validates config and returns a Signer. It confirms the backend's public
// key actually matches the CA certificate, so a misconfigured backend fails
// fast rather than minting certs no one trusts.
func New(cfg Config) (*Signer, error) {
	if cfg.Audit == nil {
		return nil, fmt.Errorf("signer: Audit callback is required")
	}
	id, err := newIdentity(cfg.CACertPEM, cfg.Backend)
	if err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	br := cfg.Breaker
	if br == nil {
		br = newBreaker(cfg.MaxCertsPerHour, time.Hour, now)
	}
	s := &Signer{
		policy:  cfg.Policy,
		breaker: br,
		audit:   cfg.Audit,
		onAlarm: cfg.OnAlarm,
		now:     now,
	}
	s.identity.Store(id)
	return s, nil
}

// CurrentFingerprint is the lower-hex fingerprint of the CA this Signer is currently signing
// with. The reconciler compares it against the registry's active CA to decide whether to swap.
func (s *Signer) CurrentFingerprint() string {
	if id := s.identity.Load(); id != nil {
		return id.fingerprint
	}
	return ""
}

// CACert returns the CA certificate this Signer is currently signing with (the active CA). Nil
// only before New has stored an identity (never happens for a Signer returned by New).
func (s *Signer) CACert() cert.Certificate {
	if id := s.identity.Load(); id != nil {
		return id.caCert
	}
	return nil
}

// SwapCA atomically re-points the Signer at a new signing CA (M8.3b online CA-rotation cut-over).
// It runs the SAME validation as New (parse, IsCA, P256, backend public key == cert public key)
// and additionally refuses an already-expired CA, so a hot-swap can only ever install an identity
// that is valid to sign with. On ANY failure it returns an error and the current identity keeps
// signing — a botched cut-over never halts issuance (fail-safe). It is idempotent: swapping to
// the CA already in use is a no-op. The breaker/policy/audit/clock are deliberately not touched,
// so the fleet-wide rate ceiling and audit trail survive the rotation.
func (s *Signer) SwapCA(caCertPEM []byte, backend Backend) error {
	id, err := newIdentity(caCertPEM, backend)
	if err != nil {
		return err
	}
	if !id.caCert.NotAfter().After(s.now()) {
		return fmt.Errorf("signer: refusing to cut over to CA %s: it expired %s",
			id.fingerprint, id.caCert.NotAfter().UTC().Format(time.RFC3339))
	}
	if cur := s.identity.Load(); cur != nil && cur.fingerprint == id.fingerprint {
		return nil // already signing with this CA
	}
	s.identity.Store(id)
	return nil
}

// ActiveCARef is the minimal view of the registry's active CA the reconciler needs. cmd/harbor
// adapts ca.Registry.Active into this so the signer package never imports the ca package (no
// cycle). An empty Fingerprint means "no active CA recorded" — the reconciler then keeps the
// current identity rather than swapping to nothing.
type ActiveCARef struct {
	Fingerprint string
	CertPEM     []byte
	KMSKeyID    string // how to reach its signing backend (KMS ARN / "pkcs11:<label>" / "software")
}

// BackendFactory builds the signing Backend for a rotated-in CA from its stored signing-backend
// id (KMSKeyID) and expected public key. Injected by cmd/harbor so this package stays free of
// KMS/PKCS#11 construction. A returned error is logged + retried next tick (the current CA keeps
// signing), e.g. a software-backed process asked to reach a new software CA key it does not hold.
type BackendFactory func(ctx context.Context, kmsKeyID string, caPubKey []byte) (Backend, error)

// ReconcileActiveCA hot-swaps the signing identity to the registry's active CA if it differs from
// the one in use. Returns swapped=true only when a cut-over happened. It is fail-safe at every
// step: a read error, an unparseable cert, a backend-build failure, or a rejected swap all return
// an error WITHOUT disturbing the current identity, so the previous CA keeps signing until the
// problem clears. Safe to call repeatedly (idempotent once converged).
func (s *Signer) ReconcileActiveCA(ctx context.Context, active func(context.Context) (ActiveCARef, error), factory BackendFactory) (bool, error) {
	ref, err := active(ctx)
	if err != nil {
		return false, fmt.Errorf("signer: read active CA: %w", err)
	}
	if ref.Fingerprint == "" {
		return false, nil // nothing active recorded yet — keep the current identity
	}
	if strings.EqualFold(strings.TrimSpace(ref.Fingerprint), s.CurrentFingerprint()) {
		return false, nil // already signing with the active CA
	}
	ca, _, perr := cert.UnmarshalCertificateFromPEM(ref.CertPEM)
	if perr != nil {
		return false, fmt.Errorf("signer: parse active CA cert %s: %w", ref.Fingerprint, perr)
	}
	backend, ferr := factory(ctx, ref.KMSKeyID, ca.PublicKey())
	if ferr != nil {
		return false, fmt.Errorf("signer: build backend for active CA %s: %w", ref.Fingerprint, ferr)
	}
	if serr := s.SwapCA(ref.CertPEM, backend); serr != nil {
		return false, fmt.Errorf("signer: cut over to active CA %s: %w", ref.Fingerprint, serr)
	}
	metricActiveCACutovers.Inc()
	_ = s.audit(ctx, "system", "ca-signing-cutover", ref.Fingerprint, fmt.Sprintf(`{"kms_key_id":%q}`, ref.KMSKeyID))
	return true, nil
}

// RunActiveCAReconciler polls the active-CA source and hot-swaps this process's Signer whenever a
// new CA is activated (M8.3b), until ctx is cancelled. Cut-over latency is bounded by interval,
// which is harmless: `harbor ca activate` only promotes a CA the whole fleet already trusts (the
// 100% adoption gate, 8.1), so a few seconds of the prior CA still signing strands no one. A
// failing tick is logged and retried; the previous CA keeps signing meanwhile.
func (s *Signer) RunActiveCAReconciler(ctx context.Context, active func(context.Context) (ActiveCARef, error), factory BackendFactory, interval time.Duration, log *slog.Logger) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			swapped, err := s.ReconcileActiveCA(ctx, active, factory)
			switch {
			case err != nil && log != nil:
				log.Warn("signer: active-CA cut-over check failed; still signing with the previous CA", "err", err)
			case swapped && log != nil:
				log.Info("signer: hot-swapped signing to the newly-activated CA", "fingerprint", s.CurrentFingerprint())
			}
		}
	}
}

// Issue validates, rate-limits, signs, and audits a leaf certificate. actor is
// the authenticated requester (for the audit row). It returns the certificate
// and its PEM encoding.
func (s *Signer) Issue(ctx context.Context, actor string, t Template) (cert.Certificate, []byte, error) {
	// 0. Snapshot the active signing identity ONCE for the whole call, so a concurrent hot-swap
	//    (M8.3b) can never chain this leaf to one CA's cert while signing it with another's key.
	id := s.identity.Load()

	// 1. Validate before touching the breaker budget or the CA key (2.4).
	if err := s.validate(id.caCert, t); err != nil {
		_ = s.audit(ctx, actor, "issue-cert-rejected", t.Name, err.Error())
		return nil, nil, err
	}

	// 2. Circuit breaker (2.5): halt + alarm + audit on breach.
	allowed, justTripped, berr := s.breaker.acquire(ctx)
	if berr != nil {
		// Fail closed: we couldn't confirm we're under the ceiling, so don't sign.
		_ = s.audit(ctx, actor, "issue-cert-error", t.Name, berr.Error())
		return nil, nil, fmt.Errorf("signer: circuit breaker: %w", berr)
	}
	if !allowed {
		metricBreakerOpen.Set(1)
		if justTripped {
			metricBreakerTrips.Inc()
			if s.onAlarm != nil {
				s.onAlarm(s.breaker.limit())
			}
			_ = s.audit(ctx, "system", "signing-circuit-tripped", t.Name,
				fmt.Sprintf(`{"limit_per_hour":%d}`, s.breaker.limit()))
		}
		_ = s.audit(ctx, actor, "issue-cert-rejected", t.Name, ErrCircuitOpen.Error())
		return nil, nil, ErrCircuitOpen
	}
	metricBreakerOpen.Set(0)

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
	c, err := SignTBS(id.backend, tbs, id.caCert)
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
func (s *Signer) ResetBreaker(ctx context.Context) error {
	if err := s.breaker.reset(ctx); err != nil {
		return err
	}
	metricBreakerOpen.Set(0)
	return nil
}

// RefreshBreakerMetric syncs ncp_signer_breaker_open with the authoritative breaker state.
// For the shared SQL breaker this reads the fleet-wide latch, so an idle Core's gauge
// reflects a trip raised by another Core (Issue only updates it on this process's own path).
func (s *Signer) RefreshBreakerMetric(ctx context.Context) error {
	open, err := s.breaker.isOpen(ctx)
	if err != nil {
		return err
	}
	if open {
		metricBreakerOpen.Set(1)
	} else {
		metricBreakerOpen.Set(0)
	}
	return nil
}

// RunBreakerMetric refreshes the breaker gauge from the authoritative state every interval
// until ctx is done — so an idle Core still reports a fleet-wide trip. Best-effort: a
// transient read error leaves the last value (the next tick reconciles).
func (s *Signer) RunBreakerMetric(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	_ = s.RefreshBreakerMetric(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.RefreshBreakerMetric(ctx)
		}
	}
}

func (s *Signer) validate(caCert cert.Certificate, t Template) error {
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
	if t.NotAfter.After(caCert.NotAfter()) {
		return fmt.Errorf("%w (CA expires %s)", ErrExpiresAfterCA, caCert.NotAfter().UTC().Format(time.RFC3339))
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
