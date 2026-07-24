// Package configsign is the hot-swappable config-signing key for the bundle (M8.5, design §4.6/§4.8).
// It mirrors internal/signer's zero-downtime CA cut-over, but for the config-signing key that signs
// the JWS config bundle Pilot pins. The signing {backend, keyID} live behind an atomic.Pointer so a
// live cut-over during a rotation can never stamp one key's Kid onto another key's signature (a bundle
// no pilot would verify): Sign snapshots the identity ONCE per call. Swap re-points it, running the
// SAME validation as boot and staying FAIL-SAFE — any failure keeps the prior key signing, so a
// botched cut-over never halts issuance. The private key never enters the process: the reconciler
// rebuilds the backend from an injected factory (KMS ARN / pkcs11:<label> id), matching internal/signer.
package configsign

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/slackhq/nebula/cert"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

var metricConfigKeyCutovers = promauto.NewCounter(prometheus.CounterOpts{
	Name: "ncp_signer_active_config_key_cutovers_total",
	Help: "Number of config-signing-key hot-swaps this process has performed (M8.5 config-key rotation cut-over).",
})

// AuditFunc appends one row to the hash-chained audit log (a cut-over is audited).
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// configIdentity is the {backend, keyID} the ConfigSigner currently signs bundles with. keyID is the
// JWS Kid stamped into every bundle = wire.PubkeyHash(pub); fingerprint == keyID (kept separate only
// for parity with signer.signingIdentity). Immutable once built; swapped wholesale via atomic.Store.
type configIdentity struct {
	backend     signer.Backend
	keyID       string
	fingerprint string
}

// newConfigIdentity validates that backend holds a P256 config-signing key and returns its identity.
// The keyID/fingerprint is wire.PubkeyHash of the backend's public point — byte-identical to the
// registry fingerprint and to the Kid the bundle is signed under.
func newConfigIdentity(backend signer.Backend) (*configIdentity, error) {
	if backend == nil {
		return nil, fmt.Errorf("configsign: nil backend")
	}
	pub, err := backend.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("configsign: backend public key: %w", err)
	}
	if _, err := jws.ParseP256PublicPoint(pub); err != nil {
		return nil, fmt.Errorf("configsign: backend key is not a valid P256 point: %w", err)
	}
	kid := wire.PubkeyHash(pub)
	return &configIdentity{backend: backend, keyID: kid, fingerprint: kid}, nil
}

// ConfigSigner signs config bundles with the current active config-signing key, hot-swappable.
type ConfigSigner struct {
	identity atomic.Pointer[configIdentity]
	audit    AuditFunc
	now      func() time.Time
}

// New builds a ConfigSigner over backend (the current active config-signing key). audit may be nil.
func New(backend signer.Backend, audit AuditFunc, now func() time.Time) (*ConfigSigner, error) {
	if now == nil {
		now = time.Now
	}
	id, err := newConfigIdentity(backend)
	if err != nil {
		return nil, err
	}
	s := &ConfigSigner{audit: audit, now: now}
	s.identity.Store(id)
	return s, nil
}

// Sign snapshots the active identity ONCE and signs b under it, so a concurrent Swap can never stamp
// the old key's Kid on a signature made with the new key (or vice-versa) — the bundle is always fully
// one key's.
func (s *ConfigSigner) Sign(b bundle.Bundle) ([]byte, error) {
	id := s.identity.Load()
	if id == nil {
		return nil, fmt.Errorf("configsign: no config-signing identity")
	}
	return bundle.Sign(id.backend, id.keyID, b)
}

// CurrentFingerprint is the fingerprint (base64url wire.PubkeyHash) of the config key this signer is
// currently signing with. The reconciler compares it against the registry's active key to decide
// whether to swap.
func (s *ConfigSigner) CurrentFingerprint() string {
	if id := s.identity.Load(); id != nil {
		return id.fingerprint
	}
	return ""
}

// Swap atomically re-points the signer at backend (M8.5 cut-over). It runs the same validation as
// New; swapping to the key already in use is a no-op; on ANY failure it returns an error and the
// current key keeps signing (fail-safe). The harness drill calls this directly with a pre-built
// (e.g. software) backend; production drives it via the reconciler + injected factory.
func (s *ConfigSigner) Swap(backend signer.Backend) error {
	id, err := newConfigIdentity(backend)
	if err != nil {
		return err
	}
	if cur := s.identity.Load(); cur != nil && cur.fingerprint == id.fingerprint {
		return nil // already signing with this key
	}
	s.identity.Store(id)
	return nil
}

// ActiveConfigKeyRef is the minimal view of the registry's active config-signing key the reconciler
// needs. cmd/harbor adapts configkey.Registry.Active into this so this package never imports configkey
// (no cycle). An empty Fingerprint means "none active recorded" — keep the current identity.
type ActiveConfigKeyRef struct {
	Fingerprint string
	PubPEM      string
	KMSKeyID    string // KMS ARN / "pkcs11:<label>" / "software"
}

// BackendFactory builds the signing Backend for a rotated-in config key from its stored backend id
// (KMSKeyID) and expected public point. Injected by cmd/harbor so this package stays free of
// KMS/PKCS#11 construction. A software key cannot be rebuilt from an id, so the cmd/harbor factory
// refuses it (dev-only); production config keys are KMS-backed.
type BackendFactory func(ctx context.Context, kmsKeyID string, pub []byte) (signer.Backend, error)

// ReconcileActiveConfigKey hot-swaps the signing identity to the registry's active config key if it
// differs from the one in use. Returns swapped=true only when a cut-over happened. Fail-safe at every
// step: a read error, an unparseable pub, a backend-build failure, a factory that built the WRONG key,
// or a rejected swap all return an error WITHOUT disturbing the current identity, so the previous key
// keeps signing until the problem clears. Idempotent once converged.
func (s *ConfigSigner) ReconcileActiveConfigKey(ctx context.Context, active func(context.Context) (ActiveConfigKeyRef, error), factory BackendFactory) (bool, error) {
	ref, err := active(ctx)
	if err != nil {
		return false, fmt.Errorf("configsign: read active config key: %w", err)
	}
	if strings.TrimSpace(ref.Fingerprint) == "" {
		return false, nil // nothing active recorded yet — keep the current identity
	}
	if ref.Fingerprint == s.CurrentFingerprint() {
		return false, nil // already signing with the active key
	}
	pub, _, curve, perr := cert.UnmarshalPublicKeyFromPEM([]byte(ref.PubPEM))
	if perr != nil || curve != cert.Curve_P256 {
		return false, fmt.Errorf("configsign: parse active config key %s: %v", ref.Fingerprint, perr)
	}
	backend, ferr := factory(ctx, ref.KMSKeyID, pub)
	if ferr != nil {
		return false, fmt.Errorf("configsign: build backend for active config key %s: %w", ref.Fingerprint, ferr)
	}
	id, err := newConfigIdentity(backend)
	if err != nil {
		return false, fmt.Errorf("configsign: validate rebuilt backend for %s: %w", ref.Fingerprint, err)
	}
	if id.fingerprint != ref.Fingerprint {
		return false, fmt.Errorf("configsign: factory built the WRONG key for %s (got %s) — refusing to sign under a mismatched key", ref.Fingerprint, id.fingerprint)
	}
	s.identity.Store(id)
	metricConfigKeyCutovers.Inc()
	if s.audit != nil {
		_ = s.audit(ctx, "system", "config-key-signing-cutover", ref.Fingerprint, fmt.Sprintf(`{"kms_key_id":%q}`, ref.KMSKeyID))
	}
	return true, nil
}

// RunReconciler polls the active-config-key source and hot-swaps this process's ConfigSigner whenever
// a new key is activated (M8.5), until ctx is cancelled. Cut-over latency is bounded by interval and
// harmless: `harbor config-key activate` only promotes a key the whole fleet already trusts (the 100%
// adoption gate), so a few seconds of the prior key still signing strands no one. A failing tick is
// logged and retried; the previous key keeps signing meanwhile.
func (s *ConfigSigner) RunReconciler(ctx context.Context, active func(context.Context) (ActiveConfigKeyRef, error), factory BackendFactory, interval time.Duration, log *slog.Logger) {
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
			swapped, err := s.ReconcileActiveConfigKey(ctx, active, factory)
			switch {
			case err != nil && log != nil:
				log.Warn("configsign: active-config-key cut-over check failed; still signing with the previous key", "err", err)
			case swapped && log != nil:
				log.Info("configsign: hot-swapped bundle signing to the newly-activated config key", "fingerprint", s.CurrentFingerprint())
			}
		}
	}
}
