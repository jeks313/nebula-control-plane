// Package heartbeat is Pilot's heartbeat reporter + command processor
// (implementation-plan 4.6). Pilot periodically reports its state to Core over
// the mesh; Core replies with a CLOSED set of typed commands. Pilot executes
// only the known types and REFUSES anything else — the command channel is never
// arbitrary execution.
package heartbeat

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

// Handlers wires the typed command channel to Pilot actions. Any nil handler
// means "ignore that command type"; an UNKNOWN type is always refused.
type Handlers struct {
	Renew       func(ctx context.Context) error
	Restart     func() error
	ApplyBundle func(ctx context.Context, version int) error
}

// Process dispatches the typed commands in resp. It returns an error on the
// first unknown command type and never executes it (closed enum).
func Process(ctx context.Context, resp wire.HeartbeatResponse, h Handlers) error {
	for _, c := range resp.Commands {
		switch c.Type {
		case wire.CmdRenew:
			if h.Renew != nil {
				if err := h.Renew(ctx); err != nil {
					return err
				}
			}
		case wire.CmdRestart:
			if h.Restart != nil {
				if err := h.Restart(); err != nil {
					return err
				}
			}
		case wire.CmdApplyBundle:
			if h.ApplyBundle != nil {
				if err := h.ApplyBundle(ctx, c.BundleVersion); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("heartbeat: refusing unknown command type %q", c.Type)
		}
	}
	return nil
}

// Config builds a Reporter.
type Config struct {
	CoreURL      string
	Layout       paths.Layout
	Interval     time.Duration
	Handlers     Handlers
	PilotVersion string
	// NebulaVersionFn, if set, returns the RUNNING nebula version string each beat —
	// for fleet DISPLAY only (version strings aren't unique across rebuilds).
	NebulaVersionFn func() string
	// NebulaSHAFn, if set, returns the sha256 of the RUNNING nebula binary each beat
	// (ADR 0003 Phase 1c). This is the convergence key: Harbor maps it to a release
	// generation to drive nebula-lane rollout convergence + auto-rollback. Re-evaluated
	// per beat so it reflects a binary that changed (or reverted) under a self-update.
	NebulaSHAFn func() string
	// PilotSHAFn is NebulaSHAFn for the PILOT binary (ADR 0003 Phase 3c): the sha256 of
	// the running pilot, the convergence key for the pilot lane.
	PilotSHAFn func() string
	// HealthFn, if set, returns this host's data-plane health each beat (e.g. "ok" /
	// "unhealthy"); nil reports "ok". A value in the rollout's healthBad set fails the
	// host's wave immediately, so the deriver MUST debounce transients (an in-flight
	// nebula restart) to avoid a spurious auto-rollback.
	HealthFn func() string
	// PinnedConfigPub, if set, lets the reporter read the applied bundle +
	// blocklist versions from the stored signed bundle (7.1b) so Core can track
	// rollout convergence. Reporting only — the bundle is verified against the
	// pinned key before its versions are trusted.
	PinnedConfigPub []*ecdsa.PublicKey
	HTTPClient      *http.Client
	Now             func() time.Time
	Logger          *slog.Logger
}

// Reporter periodically sends heartbeats and processes the command channel.
type Reporter struct{ cfg Config }

// New builds a Reporter.
func New(cfg Config) *Reporter {
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Reporter{cfg: cfg}
}

// Run sends heartbeats on Interval until ctx is cancelled.
func (r *Reporter) Run(ctx context.Context) error {
	for {
		r.beat(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(r.cfg.Interval):
		}
	}
}

func (r *Reporter) beat(ctx context.Context) {
	nebVer, nebSHA, pilotSHA := "", "", ""
	if r.cfg.NebulaVersionFn != nil {
		nebVer = r.cfg.NebulaVersionFn()
	}
	if r.cfg.NebulaSHAFn != nil {
		nebSHA = r.cfg.NebulaSHAFn()
	}
	if r.cfg.PilotSHAFn != nil {
		pilotSHA = r.cfg.PilotSHAFn()
	}
	health := "ok"
	if r.cfg.HealthFn != nil {
		health = r.cfg.HealthFn()
	}
	req := wire.HeartbeatRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "heartbeat",
		PilotVersion: r.cfg.PilotVersion, PilotSHA256: pilotSHA,
		NebulaVersion: nebVer, NebulaSHA256: nebSHA, Health: health,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, // per-arch release selection
	}
	if pem, err := os.ReadFile(r.cfg.Layout.HostCert()); err == nil {
		if c, _, err := cert.UnmarshalCertificateFromPEM(pem); err == nil {
			req.CertNotAfter = c.NotAfter().UTC().Format(time.RFC3339)
		}
	}
	// Report which bundle/blocklist generation we're on (7.1b) so Core can drive
	// and observe rollout convergence — read from the verified stored bundle.
	if r.cfg.PinnedConfigPub != nil {
		// M8.5: report the config-signing keys we ACTUALLY trust for our NEXT bundle verify = the
		// EXACT set bundle.TrustedSet consults (permanent pin UNION the keys persisted in our trust
		// file) — NOT the keys advertised in the last applied bundle.json. Those two can transiently
		// diverge: writeArtifacts writes bundle.json BEFORE PersistTrustFile, so a crash / failed
		// trust-file write between them would leave bundle.json advertising a key the trust file (and
		// thus our verifier) does not yet trust. Reporting bundle.json's set would OVER-report adoption
		// and let a cut-over gate pass while this host can't actually verify the new key -> stranded.
		// Reporting the real verify set makes any trust-file lag UNDER-report (look like a laggard),
		// which correctly blocks the cut-over until the host genuinely trusts the new key. Independent
		// of the applied-bundle read below so it is reported even if bundle.json is missing/stale.
		req.TrustedConfigKeyFingerprints = trustedConfigKeyFingerprints(r.cfg.PinnedConfigPub, r.cfg.Layout.ConfigSigningTrust())
		if raw, err := os.ReadFile(r.cfg.Layout.Bundle()); err == nil {
			if b, err := bundle.Verify(raw, bundle.TrustedSet(r.cfg.PinnedConfigPub, r.cfg.Layout.ConfigSigningTrust())); err == nil {
				req.AppliedBundleVersion = b.BundleVersion
				req.AppliedBlocklistVersion = b.BlocklistVersion
				// M8.1: report which CAs we trust (from the VERIFIED applied ca_bundle) so
				// Core can gate a CA cut-over on 100% adoption (design §4.6).
				req.TrustedCAFingerprints = trustedCAFingerprints(b.CABundle)
			}
		}
	}

	resp, err := r.send(ctx, req)
	if err != nil {
		r.cfg.Logger.Warn("heartbeat: send failed", "err", err)
		return
	}
	if err := Process(ctx, resp, r.cfg.Handlers); err != nil {
		r.cfg.Logger.Warn("heartbeat: command processing", "err", err)
	}
}

// trustedCAFingerprints returns the sorted, deduped lowercase-hex sha256 fingerprints of
// every CA cert in the applied bundle's ca_bundle (M8.1). Robust to a multi-PEM element
// and to one unparseable block among several — a heartbeat must never fail on a partial CA
// set. Empty -> nil so the wire field omits (a pre-M8.1-shaped report).
func trustedCAFingerprints(caPEMs []string) []string {
	seen := map[string]struct{}{}
	for _, p := range caPEMs {
		rest := []byte(p)
		for len(rest) > 0 {
			var c cert.Certificate
			var err error
			c, rest, err = cert.UnmarshalCertificateFromPEM(rest)
			if err != nil || c == nil {
				break
			}
			if fp, err := c.Fingerprint(); err == nil {
				seen[fp] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for fp := range seen {
		out = append(out, fp)
	}
	sort.Strings(out)
	return out
}

// trustedConfigKeyFingerprints returns the sorted, deduped base64url wire.PubkeyHash fingerprints of
// every config-signing key this host will actually VERIFY the next bundle against (M8.5) — i.e. the
// exact set bundle.TrustedSet(pins, trustFilePath) yields = the permanent pin(s) UNION the keys
// persisted in the trust file. Sourcing the report from the same place the verifier reads guarantees
// the adoption gate can never over-count this host (a lagging trust file makes it report FEWER keys,
// safely blocking a cut-over). The fingerprint is wire.PubkeyHash of the uncompressed P256 point (via
// crypto/ecdh) — byte-identical to the registry fingerprint + the JWS Kid, matched CASE-SENSITIVELY by
// Core's AdoptionStatus. Empty -> nil so the wire field omits (a pre-M8.5-shaped report).
func trustedConfigKeyFingerprints(pins []*ecdsa.PublicKey, trustFilePath string) []string {
	seen := map[string]struct{}{}
	for _, k := range bundle.TrustedSet(pins, trustFilePath) {
		if k == nil {
			continue
		}
		// Re-encode to the 65-byte uncompressed point wire.PubkeyHash expects (the same encoding the
		// config-signing key is stored + Kid'd under), via crypto/ecdh.
		if ek, err := k.ECDH(); err == nil {
			seen[wire.PubkeyHash(ek.Bytes())] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for fp := range seen {
		out = append(out, fp)
	}
	sort.Strings(out)
	return out
}

func (r *Reporter) send(ctx context.Context, req wire.HeartbeatRequest) (wire.HeartbeatResponse, error) {
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.CoreURL+"/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return wire.HeartbeatResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := r.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		return wire.HeartbeatResponse{}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return wire.HeartbeatResponse{}, fmt.Errorf("heartbeat: status %d: %s", resp.StatusCode, respBody)
	}
	var hr wire.HeartbeatResponse
	if err := json.Unmarshal(respBody, &hr); err != nil {
		return wire.HeartbeatResponse{}, err
	}
	return hr, nil
}
