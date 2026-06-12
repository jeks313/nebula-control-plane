// Package coreapi is Harbor Core's mesh-only API (implementation-plan M4): cert
// renewal (4.3) and heartbeat (4.6), authenticated by the calling tunnel's
// identity (4.2). Core runs as a mesh node bound to its overlay IP (4.1); a
// peer's source overlay IP is cryptographically tied to its Nebula cert (a host
// can only send from the IP it's certified for), so the source IP IS the
// authenticated identity — no nonce/attestation needed over the mesh.
package coreapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Heartbeat is the latest reported state for a device (one row per overlay IP).
type Heartbeat struct {
	ID                   int64  `gorm:"column:id;primaryKey"`
	OverlayIP            string `gorm:"column:overlay_ip"`
	DeviceName           string `gorm:"column:device_name"`
	PilotVersion         string `gorm:"column:pilot_version"`
	NebulaVersion        string `gorm:"column:nebula_version"`
	CertNotAfter         int64  `gorm:"column:cert_not_after"`
	AppliedBundleVersion int    `gorm:"column:applied_bundle_version"`
	ClockOffsetMs        int    `gorm:"column:clock_offset_ms"`
	Health               string `gorm:"column:health"`
	LastSeen             int64  `gorm:"column:last_seen"`
}

func (Heartbeat) TableName() string { return "heartbeats" }

const maxBody = 16 << 10

// Config builds a Core API server.
type Config struct {
	Store         *store.Store
	Signer        *signer.Signer
	ConfigBackend signer.Backend
	ConfigKeyID   string
	CABundlePEM   []byte
	Lighthouses   []bundle.Lighthouse
	// LighthouseSource, if set, is consulted at bundle-build time so registry
	// changes (6.8) propagate live; it overrides the static Lighthouses. On error
	// Core falls back to Lighthouses (a transient registry read must never sever
	// discovery in an issued bundle).
	LighthouseSource func(context.Context) ([]bundle.Lighthouse, error)
	Policy           *policy.Policy // central firewall (M6); nil -> Pilot's local default
	Pool             netip.Prefix
	CertLifetime     time.Duration
	// RenewCommandThreshold: if a heartbeat reports a cert expiring within this
	// window, Core replies with a `renew` command (a backstop to Pilot's own
	// proactive renewal). 0 disables it.
	RenewCommandThreshold time.Duration
	Now                   func() time.Time
}

// Server is the mesh-only Core API.
type Server struct {
	cfg Config
	now func() time.Time
}

// New builds a Core API server.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{cfg: cfg, now: cfg.Now}
}

// Handler returns the Core API routes. In production this is bound to Core's
// overlay IP only (4.1); the public internet must not reach it.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/certs/renew", s.handleRenew)
	mux.HandleFunc("POST /v1/heartbeat", s.handleHeartbeat)
	return mux
}

// lighthouses returns the fleet's lighthouses for a bundle: the live registry
// (6.8) when a source is configured, falling back to the static list on error
// or when no source is set. A failed registry read must never sever discovery.
func (s *Server) lighthouses(ctx context.Context) []bundle.Lighthouse {
	if s.cfg.LighthouseSource == nil {
		return s.cfg.Lighthouses
	}
	lhs, err := s.cfg.LighthouseSource(ctx)
	if err != nil || len(lhs) == 0 {
		return s.cfg.Lighthouses
	}
	return lhs
}

// device resolves the calling tunnel's identity from its source overlay IP
// (4.2). Returns the current issued enrollment at that address.
func (s *Server) device(ctx context.Context, r *http.Request) (enrollment.Enrollment, bool) {
	ip := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = h
	}
	var e enrollment.Enrollment
	err := s.cfg.Store.DB.WithContext(ctx).
		Where("overlay_ip = ? AND status = ?", ip, enrollment.StatusIssued).
		Order("id DESC").First(&e).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return enrollment.Enrollment{}, false
	}
	if err != nil {
		return enrollment.Enrollment{}, false
	}
	return e, true
}

// handleHeartbeat implements POST /v1/heartbeat (4.6): persist the device's
// reported state (fleet visibility) and return the typed command channel.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()

	dev, ok := s.device(ctx, r)
	if !ok {
		wire.WriteError(w, wire.CodeAccountNotAllowed, "no enrolled device at this overlay address")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		wire.WriteError(w, wire.CodeInvalidRequest, "request too large")
		return
	}
	var req wire.HeartbeatRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Type != "heartbeat" {
		wire.WriteError(w, wire.CodeInvalidRequest, "bad heartbeat")
		return
	}

	var certNotAfter int64
	if req.CertNotAfter != "" {
		if t, err := time.Parse(time.RFC3339, req.CertNotAfter); err == nil {
			certNotAfter = t.UnixNano()
		}
	}
	hb := Heartbeat{
		OverlayIP: dev.OverlayIP, DeviceName: dev.DeviceName,
		PilotVersion: req.PilotVersion, NebulaVersion: req.NebulaVersion,
		CertNotAfter: certNotAfter, AppliedBundleVersion: req.AppliedBundleVersion,
		ClockOffsetMs: req.ClockOffsetMs, Health: req.Health, LastSeen: s.now().UnixNano(),
	}
	if err := s.cfg.Store.DB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "overlay_ip"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"device_name", "pilot_version", "nebula_version", "cert_not_after",
			"applied_bundle_version", "clock_offset_ms", "health", "last_seen",
		}),
	}).Create(&hb).Error; err != nil {
		wire.WriteError(w, wire.CodeInternal, "persist heartbeat failed")
		return
	}

	wire.WriteJSON(w, http.StatusOK, wire.HeartbeatResponse{
		ProtocolVersion: wire.ProtocolVersion,
		Commands:        s.commandsFor(certNotAfter),
	})
}

// commandsFor decides the typed commands to return. For 4.6 it's the
// near-expiry renew backstop; M6 adds apply_bundle from central policy.
func (s *Server) commandsFor(certNotAfter int64) []wire.Command {
	var cmds []wire.Command
	if s.cfg.RenewCommandThreshold > 0 && certNotAfter > 0 {
		if time.Unix(0, certNotAfter).Sub(s.now()) < s.cfg.RenewCommandThreshold {
			cmds = append(cmds, wire.Command{Type: wire.CmdRenew})
		}
	}
	return cmds
}

// handleRenew implements POST /v1/certs/renew (4.3): re-sign the calling
// identity with a fresh key, same IP/groups, no re-attestation.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()

	// 4.2 — authenticate by the calling tunnel's overlay IP.
	dev, ok := s.device(ctx, r)
	if !ok {
		wire.WriteError(w, wire.CodeAccountNotAllowed, "no enrolled device at this overlay address")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		wire.WriteError(w, wire.CodeInvalidRequest, "request too large")
		return
	}
	var env jws.Flattened
	if err := json.Unmarshal(body, &env); err != nil {
		wire.WriteError(w, wire.CodeInvalidRequest, "not a JWS envelope")
		return
	}
	plBytes, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		wire.WriteError(w, wire.CodeInvalidRequest, "bad payload")
		return
	}
	var req wire.RenewRequest
	if err := json.Unmarshal(plBytes, &req); err != nil || req.Type != "renew" || req.CSR.Curve != "P256" {
		wire.WriteError(w, wire.CodeInvalidRequest, "bad renew request")
		return
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(req.CSR.PublicKey)
	if err != nil || len(pubBytes) != 65 {
		wire.WriteError(w, wire.CodeInvalidRequest, "invalid csr.public_key")
		return
	}
	pub, err := jws.ParseP256PublicPoint(pubBytes)
	if err != nil {
		wire.WriteError(w, wire.CodeInvalidRequest, "invalid public key point")
		return
	}
	// Proof of possession of the NEW key.
	hdr, _, err := jws.Verify(env, pub)
	if err != nil || hdr.Typ != wire.TypRenewRequest || hdr.Kid != wire.PubkeyHash(pubBytes) {
		wire.WriteError(w, wire.CodeInvalidSignature, "renew signature verification failed")
		return
	}

	// 4.3 — re-sign the SAME identity (IP + groups from the device record).
	var groups []string
	_ = json.Unmarshal([]byte(dev.Groups), &groups)
	overlay, err := netip.ParseAddr(dev.OverlayIP)
	if err != nil {
		wire.WriteError(w, wire.CodeInternal, "bad device record")
		return
	}
	nb := s.now().Add(-5 * time.Minute)
	notAfter := nb.Add(s.cfg.CertLifetime)
	cert, certPEM, err := s.cfg.Signer.Issue(ctx, "renew:"+dev.DeviceName, signer.Template{
		Name:      dev.DeviceName,
		Networks:  []netip.Prefix{netip.PrefixFrom(overlay, s.cfg.Pool.Bits())},
		Groups:    groups,
		NotBefore: nb,
		NotAfter:  notAfter,
		PublicKey: pubBytes,
	})
	if err != nil {
		wire.WriteError(w, wire.CodeInternal, "re-sign failed")
		return
	}

	b := bundle.Bundle{
		BundleVersion: 1,
		IssuedAt:      s.now().UTC().Format(time.RFC3339),
		Device:        bundle.Device{Name: dev.DeviceName, OverlayIP: dev.OverlayIP, Groups: groups},
		Certificate:   string(certPEM),
		CABundle:      []string{string(s.cfg.CABundlePEM)},
		Firewall:      bundle.CompileFirewall(s.cfg.Policy, groups),
		Lighthouses:   s.lighthouses(ctx),
		NotAfter:      notAfter.UTC().Format(time.RFC3339),
	}
	bundleJWS, err := bundle.Sign(s.cfg.ConfigBackend, s.cfg.ConfigKeyID, b)
	if err != nil {
		wire.WriteError(w, wire.CodeInternal, "bundle sign failed")
		return
	}
	fp, _ := cert.Fingerprint()
	_, _ = s.cfg.Store.AppendAudit(ctx, "renew:"+dev.DeviceName, "cert-renewed", dev.DeviceName,
		fmt.Sprintf(`{"overlay_ip":%q,"fingerprint":%q}`, dev.OverlayIP, fp))

	wire.WriteJSON(w, http.StatusOK, wire.RenewResponse{ProtocolVersion: wire.ProtocolVersion, Bundle: bundleJWS})
}
