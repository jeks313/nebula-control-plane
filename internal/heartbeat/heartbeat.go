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
	CoreURL       string
	Layout        paths.Layout
	Interval      time.Duration
	Handlers      Handlers
	PilotVersion  string
	NebulaVersion string
	// PinnedConfigPub, if set, lets the reporter read the applied bundle +
	// blocklist versions from the stored signed bundle (7.1b) so Core can track
	// rollout convergence. Reporting only — the bundle is verified against the
	// pinned key before its versions are trusted.
	PinnedConfigPub *ecdsa.PublicKey
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
	req := wire.HeartbeatRequest{
		ProtocolVersion: wire.ProtocolVersion, Type: "heartbeat",
		PilotVersion: r.cfg.PilotVersion, NebulaVersion: r.cfg.NebulaVersion, Health: "ok",
	}
	if pem, err := os.ReadFile(r.cfg.Layout.HostCert()); err == nil {
		if c, _, err := cert.UnmarshalCertificateFromPEM(pem); err == nil {
			req.CertNotAfter = c.NotAfter().UTC().Format(time.RFC3339)
		}
	}
	// Report which bundle/blocklist generation we're on (7.1b) so Core can drive
	// and observe rollout convergence — read from the verified stored bundle.
	if r.cfg.PinnedConfigPub != nil {
		if raw, err := os.ReadFile(r.cfg.Layout.Bundle()); err == nil {
			if b, err := bundle.Verify(raw, r.cfg.PinnedConfigPub); err == nil {
				req.AppliedBundleVersion = b.BundleVersion
				req.AppliedBlocklistVersion = b.BlocklistVersion
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
