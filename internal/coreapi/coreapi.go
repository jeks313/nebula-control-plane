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
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Heartbeat is the latest reported state for a device (one row per overlay IP).
type Heartbeat struct {
	ID                      int64  `gorm:"column:id;primaryKey"`
	OverlayIP               string `gorm:"column:overlay_ip"`
	DeviceName              string `gorm:"column:device_name"`
	PilotVersion            string `gorm:"column:pilot_version"`
	NebulaVersion           string `gorm:"column:nebula_version"`
	CertNotAfter            int64  `gorm:"column:cert_not_after"`
	AppliedBundleVersion    int    `gorm:"column:applied_bundle_version"`
	AppliedBlocklistVersion int    `gorm:"column:applied_blocklist_version"`
	AppliedNebulaVersion    int    `gorm:"column:applied_nebula_version"`
	AppliedPilotVersion     int    `gorm:"column:applied_pilot_version"`
	ClockOffsetMs           int    `gorm:"column:clock_offset_ms"`
	Health                  string `gorm:"column:health"`
	LastSeen                int64  `gorm:"column:last_seen"`
}

// ReleaseSource is a binary-release registry Core consults to stamp a host's per-host
// release tuple and to map its reported running binary back to a generation for lane
// convergence — the nebula registry (1c) and the pilot registry (3c) both satisfy it.
// nil -> Core falls back to its static config for that binary.
type ReleaseSource interface {
	// Lookup returns the (version, sha256, url) for a generation AND the host's (goos, goarch)
	// — the artifact matching that platform (ADR 0003 per-arch URL support). ok=false when the
	// generation has no artifact for that arch, so Core leaves the host on its current binary
	// rather than serving a wrong-arch one. An empty (goos, goarch) resolves to the default.
	Lookup(ctx context.Context, gen int, goos, goarch string) (version, sha256, url string, ok bool)
	// GenForSHA maps the RUNNING binary's sha256 to a generation (0 if unknown). The
	// sha is the artifact's identity, so this is unambiguous across rebuilds sharing a
	// version string — and it reflects what the host is ACTUALLY running (the pilot
	// hashes the on-disk binary), so a failed swap that reverted to last-good reports
	// the prev gen and the lane correctly rolls back rather than false-converging.
	GenForSHA(ctx context.Context, sha256 string) int
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
	// BlocklistSource, if set, is consulted at bundle-build time so revocations
	// (7.1) propagate live into the renew bundle's pki.blocklist. A failed read
	// falls back to an empty blocklist rather than failing the renewal — peers
	// still enforce the blocklist from their own bundles (§4.7, fail-open on
	// availability / P3).
	BlocklistSource func(context.Context) ([]string, error)
	Policy          *policy.Policy // central firewall (M6); nil -> Pilot's local default
	// Rollout, if set, drives staged canary rollouts (6.6): heartbeats are fed to
	// the engine, in-wave hosts are commanded toward the target version, and the
	// renew bundle is stamped with the host's rollout version.
	Rollout *rollout.Engine
	// NebulaReleases, if set, makes the nebula version a per-host ROLLOUT target
	// (ADR 0003 Phase 1c): assembleBundle stamps the tuple for the host's nebula-lane
	// generation (in-wave -> target, else prev) instead of the static NebulaVersion,
	// and the heartbeat maps the host's running version back to a generation so the
	// nebula lane can converge + auto-roll-back. nil -> the static NebulaVersion.
	NebulaReleases ReleaseSource
	// PilotReleases is NebulaReleases for the PILOT binary (ADR 0003 Phase 3c): the
	// pilot version becomes a per-host rollout target on the pilot lane, stamped into
	// the bundle, and the pilot self-updates by re-exec/re-adopt. nil -> static config.
	PilotReleases ReleaseSource
	Pool          netip.Prefix
	// TunDev + ListenPort are this mesh's nebula TUN device name + UDP listen port,
	// stamped into renew + GET /v1/config bundles. MUST match enrollment.Config's, or a
	// renew/refresh would flip a device's tun/port. Empty/zero -> nebula1/4242.
	TunDev     string
	ListenPort int
	// NebulaVersion / NebulaSHA256 / NebulaURL distribute the data-plane binary
	// (ADR 0003 Phase 1) — stamped into every bundle so pilots converge on the
	// version Harbor chooses. MUST match enrollment.Config's. All empty -> hosts
	// keep their current nebula.
	NebulaVersion string
	NebulaSHA256  string
	NebulaURL     string
	// PilotVersion / PilotSHA256 / PilotURL are the static fallback for the pilot binary
	// (ADR 0003 Phase 3c), used when no pilot release/rollout is configured. Stamped into
	// the bundle; the pilot self-updates to it. All empty -> hosts keep their current pilot.
	PilotVersion string
	PilotSHA256  string
	PilotURL     string
	CertLifetime time.Duration
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
	mux.HandleFunc("GET /v1/config", s.handleConfig)
	mux.HandleFunc("POST /v1/heartbeat", s.handleHeartbeat)
	return mux
}

// bundleVersion returns the bundle version to stamp for a host: the rollout's
// per-host version (6.6) when a rollout governs it, else the baseline 1.
func (s *Server) bundleVersion(ctx context.Context, overlayIP string) int {
	if s.cfg.Rollout != nil {
		if v, ok := s.cfg.Rollout.VersionFor(ctx, overlayIP); ok {
			return v
		}
	}
	return 1
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

// blocklistVersion is the current blocklist-lane generation Core stamps on every
// bundle (7.1b), so a host can report back which blocklist generation it carries
// and the blocklist rollout can drive the healthy fleet to converge. 0 with no
// rollout engine or no blocklist rollout yet.
func (s *Server) blocklistVersion(ctx context.Context) int {
	if s.cfg.Rollout == nil {
		return 0
	}
	return s.cfg.Rollout.BlocklistVersion(ctx)
}

// blocklist returns the fleet's active revoked-cert fingerprints for a bundle
// (7.1) when a source is configured, else nil. A failed read falls back to an
// empty blocklist: a renewal must not fail because the revocation store is
// briefly unreadable, and peers still enforce their own blocklists (§4.7).
func (s *Server) blocklist(ctx context.Context) []string {
	if s.cfg.BlocklistSource == nil {
		return nil
	}
	fps, err := s.cfg.BlocklistSource(ctx)
	if err != nil {
		return nil
	}
	return fps
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
	// Map the host's reported running nebula binary (by sha — its artifact identity)
	// back to a registry generation so the nebula lane (1c) can judge convergence on
	// the same integer axis as the other lanes. 0 when unmanaged or the sha is unknown.
	appliedNebula := 0
	if s.cfg.NebulaReleases != nil {
		appliedNebula = s.cfg.NebulaReleases.GenForSHA(ctx, req.NebulaSHA256)
	}
	// Likewise for the PILOT lane (3c): map the running pilot binary's sha to a gen.
	appliedPilot := 0
	if s.cfg.PilotReleases != nil {
		appliedPilot = s.cfg.PilotReleases.GenForSHA(ctx, req.PilotSHA256)
	}
	hb := Heartbeat{
		OverlayIP: dev.OverlayIP, DeviceName: dev.DeviceName,
		PilotVersion: req.PilotVersion, NebulaVersion: req.NebulaVersion,
		CertNotAfter: certNotAfter, AppliedBundleVersion: req.AppliedBundleVersion,
		AppliedBlocklistVersion: req.AppliedBlocklistVersion, AppliedNebulaVersion: appliedNebula,
		AppliedPilotVersion: appliedPilot,
		ClockOffsetMs:       req.ClockOffsetMs, Health: req.Health, LastSeen: s.now().UnixNano(),
	}
	if err := s.cfg.Store.DB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "overlay_ip"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"device_name", "pilot_version", "nebula_version", "cert_not_after",
			"applied_bundle_version", "applied_blocklist_version", "applied_nebula_version",
			"applied_pilot_version", "clock_offset_ms", "health", "last_seen",
		}),
	}).Create(&hb).Error; err != nil {
		wire.WriteError(w, wire.CodeInternal, "persist heartbeat failed")
		return
	}

	// Per-arch release support: the pilot reports its runtime.GOOS/GOARCH each beat. Record it
	// on the enrollment row (where assembleBundle reads it) when it changed — this BACKFILLS the
	// arch for hosts enrolled before the feature (whose enrollment.goos/goarch is empty) on their
	// first heartbeat under an arch-reporting pilot. Best-effort: a failure here must not fail the
	// heartbeat (the host keeps its prior/empty arch, which resolves to the linux/amd64 default).
	if req.GOOS != "" && (req.GOOS != dev.GOOS || req.GOARCH != dev.GOARCH) {
		if err := s.cfg.Store.DB.WithContext(ctx).Model(&enrollment.Enrollment{}).Where("id = ?", dev.ID).
			Updates(map[string]any{"goos": req.GOOS, "goarch": req.GOARCH}).Error; err != nil {
			_, _ = s.cfg.Store.AppendAudit(ctx, "system", "host-arch-update-error", dev.OverlayIP, err.Error())
		}
	}

	// 6.6: each heartbeat drives the rollout state machine — convergence widens,
	// a failed/silent canary auto-rolls-back. A rollout error never fails the
	// heartbeat (the data plane must keep reporting).
	if s.cfg.Rollout != nil {
		if _, err := s.cfg.Rollout.Evaluate(ctx); err != nil {
			_, _ = s.cfg.Store.AppendAudit(ctx, "system", "rollout-eval-error", dev.OverlayIP, err.Error())
		}
	}

	wire.WriteJSON(w, http.StatusOK, wire.HeartbeatResponse{
		ProtocolVersion: wire.ProtocolVersion,
		Commands:        s.commandsFor(ctx, dev.OverlayIP, req.AppliedBundleVersion, req.AppliedBlocklistVersion, appliedNebula, appliedPilot, certNotAfter),
	})
}

// commandsFor decides the typed commands to return: the near-expiry renew
// backstop (4.6) plus, for 6.6, an apply_bundle that drives the host toward its
// rollout target version (or back to prev after a rollback).
func (s *Server) commandsFor(ctx context.Context, overlayIP string, appliedVersion, appliedBlocklist, appliedNebula, appliedPilot int, certNotAfter int64) []wire.Command {
	var cmds []wire.Command
	if s.cfg.RenewCommandThreshold > 0 && certNotAfter > 0 {
		if time.Unix(0, certNotAfter).Sub(s.now()) < s.cfg.RenewCommandThreshold {
			cmds = append(cmds, wire.Command{Type: wire.CmdRenew})
		}
	}
	if s.cfg.Rollout != nil {
		// A single apply_bundle refetches the host's CURRENT bundle (the latest of
		// every lane via GET /v1/config), so emit at most one even when several lanes
		// (policy, blocklist, nebula, pilot) want this host to converge.
		if cmd, ok := s.cfg.Rollout.CommandFor(ctx, overlayIP, appliedVersion); ok {
			cmds = append(cmds, cmd)
		} else if cmd, ok := s.cfg.Rollout.BlocklistCommandFor(ctx, overlayIP, appliedBlocklist); ok {
			cmds = append(cmds, cmd)
		} else if cmd, ok := s.cfg.Rollout.NebulaCommandFor(ctx, overlayIP, appliedNebula); ok {
			cmds = append(cmds, cmd)
		} else if cmd, ok := s.cfg.Rollout.PilotCommandFor(ctx, overlayIP, appliedPilot); ok {
			cmds = append(cmds, cmd)
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
	crt, certPEM, err := s.cfg.Signer.Issue(ctx, "renew:"+dev.DeviceName, signer.Template{
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

	b := s.assembleBundle(ctx, dev, groups, string(certPEM), notAfter)
	bundleJWS, err := bundle.Sign(s.cfg.ConfigBackend, s.cfg.ConfigKeyID, b)
	if err != nil {
		wire.WriteError(w, wire.CodeInternal, "bundle sign failed")
		return
	}
	fp, _ := crt.Fingerprint()
	// Track the host's CURRENT fingerprint: it rotates with the key on every
	// renewal, so a blocklist must target the live fingerprint (M7.1/7.3). Fail
	// closed if we can't persist it — delivering a renewed bundle whose fingerprint
	// Core never recorded would leave a blocklist blind spot (the device could not
	// be revoked by fingerprint).
	if err := s.cfg.Store.DB.WithContext(ctx).Model(&enrollment.Enrollment{}).
		Where("id = ?", dev.ID).Update("fingerprint", fp).Error; err != nil {
		wire.WriteError(w, wire.CodeInternal, "renew bookkeeping failed")
		return
	}
	_, _ = s.cfg.Store.AppendAudit(ctx, "renew:"+dev.DeviceName, "cert-renewed", dev.DeviceName,
		fmt.Sprintf(`{"overlay_ip":%q,"fingerprint":%q}`, dev.OverlayIP, fp))

	wire.WriteJSON(w, http.StatusOK, wire.RenewResponse{ProtocolVersion: wire.ProtocolVersion, Bundle: bundleJWS})
}

// assembleBundle builds the host's current signed-config bundle payload: its
// policy firewall, the live lighthouses + blocklist, and both lane versions. The
// caller supplies the leaf cert (a fresh one on renew; the stored one on a config
// refresh) and its expiry.
func (s *Server) assembleBundle(ctx context.Context, dev enrollment.Enrollment, groups []string, certPEM string, notAfter time.Time) bundle.Bundle {
	nebVer, nebSHA, nebURL := s.nebulaRelease(ctx, dev.OverlayIP, dev.GOOS, dev.GOARCH)
	pilotVer, pilotSHA, pilotURL := s.pilotRelease(ctx, dev.OverlayIP, dev.GOOS, dev.GOARCH)
	return bundle.Bundle{
		BundleVersion:    s.bundleVersion(ctx, dev.OverlayIP),
		BlocklistVersion: s.blocklistVersion(ctx),
		IssuedAt:         s.now().UTC().Format(time.RFC3339),
		Device:           bundle.Device{Name: dev.DeviceName, OverlayIP: dev.OverlayIP, Groups: groups},
		Certificate:      certPEM,
		CABundle:         []string{string(s.cfg.CABundlePEM)},
		Firewall:         bundle.CompileFirewall(s.cfg.Policy, groups),
		Lighthouses:      s.lighthouses(ctx),
		Blocklist:        s.blocklist(ctx),
		TunDev:           s.cfg.TunDev,
		ListenPort:       s.cfg.ListenPort,
		NebulaVersion:    nebVer,
		NebulaSHA256:     nebSHA,
		NebulaURL:        nebURL,
		PilotVersion:     pilotVer,
		PilotSHA256:      pilotSHA,
		PilotURL:         pilotURL,
		NotAfter:         notAfter.UTC().Format(time.RFC3339),
	}
}

// nebulaRelease returns the (version, sha256, url) nebula tuple to stamp for a host.
// When a nebula rollout governs the host (1c), it is the tuple for that host's
// staged generation (in-wave -> target, else prev; gen 0 -> unpinned, leave nebula
// alone). Otherwise it falls back to the static NebulaVersion config (Phase 1a/1b).
func (s *Server) nebulaRelease(ctx context.Context, overlayIP, goos, goarch string) (version, sha256, url string) {
	if s.cfg.Rollout != nil && s.cfg.NebulaReleases != nil {
		if gen, governed := s.cfg.Rollout.NebulaGenFor(ctx, overlayIP); governed {
			if gen == 0 {
				return "", "", "" // unpinned (e.g. prev of the first rollout / rolled back to none)
			}
			if v, sh, u, ok := s.cfg.NebulaReleases.Lookup(ctx, gen, goos, goarch); ok {
				return v, sh, u
			}
			// Either pinned to a gen the registry can't resolve (shouldn't happen) or the gen
			// has no artifact for this host's arch: leave the host's nebula ALONE (empty tuple)
			// rather than stamp a wrong-arch binary or the static config. The host stays on its
			// current nebula until the operator registers its arch for the staged generation.
			// Warn (not audit — this fires per bundle build): a stranded host never converges,
			// so the nebula rollout will eventually observe-window-rollback with a generic note;
			// this breadcrumb attributes that to the missing per-arch artifact.
			slog.Warn("coreapi: no nebula artifact for host arch in staged generation; leaving host on current binary",
				"lane", "nebula", "overlay_ip", overlayIP, "gen", gen, "goos", goos, "goarch", goarch)
			return "", "", ""
		}
	}
	return s.cfg.NebulaVersion, s.cfg.NebulaSHA256, s.cfg.NebulaURL
}

// pilotRelease is nebulaRelease for the PILOT binary (ADR 0003 Phase 3c): the staged
// pilot generation's tuple when a pilot rollout governs the host, else the static
// PilotVersion config.
func (s *Server) pilotRelease(ctx context.Context, overlayIP, goos, goarch string) (version, sha256, url string) {
	if s.cfg.Rollout != nil && s.cfg.PilotReleases != nil {
		if gen, governed := s.cfg.Rollout.PilotGenFor(ctx, overlayIP); governed {
			if gen == 0 {
				return "", "", "" // unpinned (prev of the first rollout / rolled back to none)
			}
			if v, sh, u, ok := s.cfg.PilotReleases.Lookup(ctx, gen, goos, goarch); ok {
				return v, sh, u
			}
			// Governed but no artifact for this host's arch (or a dangling gen): leave the
			// host's pilot ALONE rather than stamp a wrong-arch binary or the static config.
			// Warn (see nebulaRelease) so a stranded host + a later observe-window rollback can
			// be attributed to a missing per-arch artifact.
			slog.Warn("coreapi: no pilot artifact for host arch in staged generation; leaving host on current binary",
				"lane", "pilot", "overlay_ip", overlayIP, "gen", gen, "goos", goos, "goarch", goarch)
			return "", "", ""
		}
	}
	return s.cfg.PilotVersion, s.cfg.PilotSHA256, s.cfg.PilotURL
}

// handleConfig implements GET /v1/config (spec §9): return the host's CURRENT
// signed config bundle built from its EXISTING cert — no key rotation, no
// re-issue. This is the cheap refresh a Pilot does on an apply_bundle command so a
// blocklist/policy/lighthouse change propagates fast (7.1b) without loading the
// Signer or churning the cert/fingerprint.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()

	dev, ok := s.device(ctx, r)
	if !ok {
		wire.WriteError(w, wire.CodeAccountNotAllowed, "no enrolled device at this overlay address")
		return
	}
	if len(dev.CertPEM) == 0 {
		wire.WriteError(w, wire.CodeInternal, "device has no stored certificate")
		return
	}
	var groups []string
	_ = json.Unmarshal([]byte(dev.Groups), &groups)

	// NotAfter comes from the host's existing cert (we are not re-issuing it).
	notAfter := s.now().Add(s.cfg.CertLifetime)
	if c, _, err := cert.UnmarshalCertificateFromPEM(dev.CertPEM); err == nil {
		notAfter = c.NotAfter()
	}

	b := s.assembleBundle(ctx, dev, groups, string(dev.CertPEM), notAfter)
	bundleJWS, err := bundle.Sign(s.cfg.ConfigBackend, s.cfg.ConfigKeyID, b)
	if err != nil {
		wire.WriteError(w, wire.CodeInternal, "bundle sign failed")
		return
	}
	wire.WriteJSON(w, http.StatusOK, wire.ConfigResponse{ProtocolVersion: wire.ProtocolVersion, Bundle: bundleJWS})
}
