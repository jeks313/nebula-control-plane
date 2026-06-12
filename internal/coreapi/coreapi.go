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
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"gorm.io/gorm"
)

const maxBody = 16 << 10

// Config builds a Core API server.
type Config struct {
	Store         *store.Store
	Signer        *signer.Signer
	ConfigBackend signer.Backend
	ConfigKeyID   string
	CABundlePEM   []byte
	Lighthouses   []bundle.Lighthouse
	Pool          netip.Prefix
	CertLifetime  time.Duration
	Now           func() time.Time
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
	return mux
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
		Lighthouses:   s.cfg.Lighthouses,
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
