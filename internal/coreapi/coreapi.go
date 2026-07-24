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
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/configsign"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/revocation"
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
	TrustedCAs              string `gorm:"column:trusted_cas"` // JSON array of CA fingerprints this host reported trusting (from its applied ca_bundle, M8.1)
	TrustedConfigKeys       string `gorm:"column:trusted_config_keys"` // JSON array of config-signing key fingerprints this host trusts (applied config_signing_keys UNION pin, M8.5); CASE-SENSITIVE base64url
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
	// ConfigSigner, if set, is the HOT-SWAPPABLE config-signing key (M8.5): a config-key cut-over
	// re-points it with no restart, so every renew / GET /v1/config bundle is signed under the active
	// key. When set it supersedes ConfigBackend/ConfigKeyID (which stay the static fallback for tests).
	ConfigSigner *configsign.ConfigSigner
	CABundlePEM  []byte // static fallback for the bundle's ca_bundle
	// CABundleSource, if set, is consulted at bundle-build time so the CA rotation
	// registry (M8) drives every renew / GET /v1/config bundle's ca_bundle live: it returns
	// every NON-RETIRED CA (staged+active+draining), so a newly staged CA is trusted
	// fleet-wide before it ever signs ("trust before you sign", design §4.6). A failed or
	// empty read falls back to CABundlePEM (fail-open, like BlocklistSource/LighthouseSource).
	CABundleSource func(context.Context) ([]string, error)
	// ConfigKeyPEM is the current config-signing PUBLIC-key PEM: the static fallback for the
	// bundle's config_signing_keys trust set (M8.5), used when ConfigKeySource is unset or fails.
	ConfigKeyPEM []byte
	// ConfigKeySource, if set, is consulted at bundle-build time so the config-key rotation registry
	// (M8.5) drives every renew / GET /v1/config bundle's config_signing_keys live: it returns every
	// NON-RETIRED config-signing key (staged+active+draining), so a staged key is trusted fleet-wide
	// before it ever signs. A failed/empty read falls back to ConfigKeyPEM (fail-open on availability).
	ConfigKeySource func(context.Context) ([]string, error)
	// ConfigKeyVersionSource, if set, returns the config-key registry generation stamped into the
	// bundle as ConfigKeyVersion (M8.5 anti-rollback). 0 / unset -> no version pressure.
	ConfigKeyVersionSource func(context.Context) (int64, error)
	Lighthouses            []bundle.Lighthouse
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

	// Revocation + Allocator + Central back the heartbeat self-heal: a host presenting a VALID,
	// non-revoked, non-reserved cert whose device/heartbeat/IPAM rows were reclaimed (e.g. a reaper
	// false-positive or a hard-deleted enrollment) repairs itself on its next heartbeat instead of
	// 403-ing forever. Identity is taken STRICTLY from the surviving enrollment row keyed by the
	// authenticated source overlay IP — never from the request body. When Revocation or Allocator is
	// nil, self-heal is DISABLED and a missing device 403s exactly as before.
	Revocation *revocation.Registry
	Allocator  *ipam.Allocator
	Central    netip.Prefix

	// CADrain, if set, enables the M8.3c accelerated drain: a heartbeat from a host whose current
	// leaf still chains to a DRAINING CA under force-renew is answered with a `renew` command, in
	// deterministic widening waves, so the CA drains in ~a window instead of a full cert lifetime.
	// nil disables force-renew (natural renewal still drains). ca.Registry satisfies it.
	CADrain CADrainSource
}

// CADrainSource surfaces the M8.3c accelerated-drain state to the heartbeat path without coreapi
// importing the ca package. ca.Registry implements it.
type CADrainSource interface {
	// ActiveFingerprint is the current signing CA's fingerprint, or "" when none is active.
	ActiveFingerprint(ctx context.Context) (string, error)
	// DrainWave reports the force-renew window for the CA identified by caFingerprint; accelerated
	// is true only when that CA is draining AND under an active force-renew.
	DrainWave(ctx context.Context, caFingerprint string) (startedNS, windowNS int64, accelerated bool, err error)
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

// caBundle returns the fleet's trusted CA cert PEMs for a bundle: the live CA rotation
// registry (M8) when a source is set (every non-retired CA), else the static single CA. A
// failed or empty read falls back to CABundlePEM so a renew / config refresh never ships a
// bundle with no CA to trust (fail-open on availability, design §4.6).
func (s *Server) caBundle(ctx context.Context) []string {
	if s.cfg.CABundleSource != nil {
		if cas, err := s.cfg.CABundleSource(ctx); err == nil && len(cas) > 0 {
			return cas
		}
	}
	return []string{string(s.cfg.CABundlePEM)}
}

// configKeys returns the fleet's trusted config-signing PUBLIC-key PEMs for a bundle (M8.5): the
// live config-key rotation registry when a source is set (every non-retired key), else the static
// single key. A failed or empty read falls back to ConfigKeyPEM so a bundle never advertises an
// empty config-key trust set (fail-open on availability, like caBundle).
func (s *Server) configKeys(ctx context.Context) []string {
	if s.cfg.ConfigKeySource != nil {
		if ks, err := s.cfg.ConfigKeySource(ctx); err == nil && len(ks) > 0 {
			return ks
		}
	}
	if len(s.cfg.ConfigKeyPEM) > 0 {
		return []string{string(s.cfg.ConfigKeyPEM)}
	}
	return nil
}

// configKeyVersion returns the config-key registry generation for a bundle (M8.5 anti-rollback), or
// 0 when no source is wired (legacy bundles carry no version pressure).
func (s *Server) configKeyVersion(ctx context.Context) int64 {
	if s.cfg.ConfigKeyVersionSource != nil {
		if v, err := s.cfg.ConfigKeyVersionSource(ctx); err == nil {
			return v
		}
	}
	return 0
}

// signBundle signs b with the hot-swappable ConfigSigner (M8.5) when wired, else the static
// ConfigBackend/ConfigKeyID (tests / pre-M8.5). Routing all bundle signing through here is what lets
// a config-key cut-over hot-swap the signing key with no restart.
func (s *Server) signBundle(b bundle.Bundle) ([]byte, error) {
	if s.cfg.ConfigSigner != nil {
		return s.cfg.ConfigSigner.Sign(b)
	}
	return bundle.Sign(s.cfg.ConfigBackend, s.cfg.ConfigKeyID, b)
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

// revoked reports whether fingerprint is on the active blocklist. When the revocation
// registry is not wired (dev/test/read-only Core), it reports (false, nil) — the check is
// a no-op. A read error is surfaced so the caller can FAIL CLOSED: a cert-minting path
// (renew) must not proceed when we cannot confirm the host is un-revoked. dev.Fingerprint
// and ActiveFingerprints are both canonical lowercase hex, so this is an exact match.
func (s *Server) revoked(ctx context.Context, fingerprint string) (bool, error) {
	if s.cfg.Revocation == nil || fingerprint == "" {
		return false, nil
	}
	fps, err := s.cfg.Revocation.ActiveFingerprints(ctx)
	if err != nil {
		return false, err
	}
	for _, fp := range fps {
		if fp == fingerprint {
			return true, nil
		}
	}
	return false, nil
}

// allocationOwner returns the device NAME currently holding overlay IP ip in IPAM (overlay_ip is
// UNIQUE among live allocations, so at most one). Used by self-heal to fail closed when the IP was
// re-handed to a DIFFERENT device.
func (s *Server) allocationOwner(ctx context.Context, ip string) (string, bool) {
	var name string
	err := s.cfg.Store.DB.WithContext(ctx).Raw(
		"SELECT d.name FROM ip_allocations a JOIN devices d ON d.id = a.device_id WHERE a.ip = ?", ip).
		Scan(&name).Error
	if err != nil || name == "" {
		return "", false
	}
	return name, true
}

// trySelfHeal repairs the control-plane rows for a host that presents a VALID, non-revoked,
// non-reserved cert (authenticated by its source overlay IP) but whose device/heartbeat/IPAM state
// was reclaimed (a reaper false-positive, or a hard-deleted enrollment). Identity is taken STRICTLY
// from the surviving enrollment row keyed by the authenticated overlay IP — NEVER from the request
// body (a host must not assert its own name/groups/IP). Every guardrail fails CLOSED; on refusal the
// caller keeps the 403. Disabled (always false) unless Revocation + Allocator are wired.
func (s *Server) trySelfHeal(ctx context.Context, r *http.Request) (enrollment.Enrollment, bool) {
	if s.cfg.Revocation == nil || s.cfg.Allocator == nil {
		return enrollment.Enrollment{}, false
	}
	ip := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = h
	}
	refuse := func(reason string) (enrollment.Enrollment, bool) {
		// LOG, never audit: a persistently-refused host heartbeats every ~60s, so an audit-chain write
		// here (global mutex + advisory lock + serialized INSERT) would be an unbounded, lock-contending
		// DB write. The hash-chained audit records the SUCCESSFUL heal (a real state change) only.
		slog.Warn("heartbeat self-heal refused", "overlay_ip", ip, "reason", reason)
		return enrollment.Enrollment{}, false
	}

	// 1. Authoritative identity: the LATEST enrollment at this overlay IP, any status. No row at all
	//    means nothing to repair from — never fabricate identity from the body; keep the 403 silently
	//    (an unknown source IP is not worth an audit row on every beat).
	var e enrollment.Enrollment
	if err := s.cfg.Store.DB.WithContext(ctx).
		Where("overlay_ip = ?", ip).Order("id DESC").First(&e).Error; err != nil {
		return enrollment.Enrollment{}, false
	}

	// 2. Cert validity from the STORED cert — never the host-reported cert_not_after.
	c, _, perr := cert.UnmarshalCertificateFromPEM(e.CertPEM)
	if perr != nil || !c.NotAfter().After(s.now()) {
		return refuse(`{"reason":"cert-expired-or-unparseable"}`)
	}

	// 3. Revocation/blocklist — independent of expiry, a live DB read so a not-yet-propagated
	//    blocklisting still bars the heal. Fail closed if the read fails.
	if e.Fingerprint != "" {
		fps, ferr := s.cfg.Revocation.ActiveFingerprints(ctx)
		if ferr != nil {
			return refuse(`{"reason":"revocation-read-failed"}`)
		}
		for _, fp := range fps {
			if fp == e.Fingerprint {
				return refuse(fmt.Sprintf(`{"reason":"revoked","fingerprint":%q}`, e.Fingerprint))
			}
		}
	}

	// 4. Control-plane / reserved guard — never silently re-home a reserved-group or central-block
	//    identity off the heartbeat path (defense-in-depth; a CP host should never have been reaped).
	var groups []string
	_ = json.Unmarshal([]byte(e.Groups), &groups)
	if policy.GrantsReservedGroup(groups) {
		return refuse(`{"reason":"reserved-group"}`)
	}
	addr, aerr := netip.ParseAddr(ip)
	if aerr != nil {
		return refuse(`{"reason":"bad-overlay-ip"}`)
	}
	if s.cfg.Central.IsValid() && s.cfg.Central.Contains(addr) {
		return refuse(`{"reason":"central-netblock"}`)
	}

	// 5. Re-assert the EXACT overlay IP. ErrAddrTaken is ambiguous: already-healed (same device, ok),
	//    or the IP was re-handed to a DIFFERENT device — then FAIL CLOSED (two live certs must never
	//    share one overlay IP).
	switch err := s.cfg.Allocator.AllocateSpecific(ctx, e.DeviceName, addr, "self-heal"); {
	case err == nil:
	case errors.Is(err, ipam.ErrAddrTaken):
		if owner, ok := s.allocationOwner(ctx, ip); !ok || owner != e.DeviceName {
			return refuse(fmt.Sprintf(`{"reason":"ip-conflict","owner":%q}`, owner))
		}
	default:
		return refuse(fmt.Sprintf(`{"reason":"ipam-error","err":%q}`, err.Error()))
	}

	// 6. Re-mark the enrollment issued if it isn't (by id, idempotent — never INSERT a duplicate
	//    issued row, which would confuse device()'s id-DESC pick and the reaper's MAX(id) join).
	if e.Status != enrollment.StatusIssued {
		_ = s.cfg.Store.DB.WithContext(ctx).Model(&enrollment.Enrollment{}).
			Where("id = ? AND status != ?", e.ID, enrollment.StatusIssued).
			Update("status", enrollment.StatusIssued)
	}

	// 7. Clear the reaper soft-mark (CAS) so the next reaper pass doesn't see a live-but-flagged host.
	_ = s.cfg.Store.DB.WithContext(ctx).Exec(
		"UPDATE devices SET reaped_at = 0, reap_reason = '' WHERE name = ? AND reaped_at != 0", e.DeviceName)

	_, _ = s.cfg.Store.AppendAudit(ctx, "system", "heartbeat-self-heal", ip,
		fmt.Sprintf(`{"device":%q,"fingerprint":%q}`, e.DeviceName, e.Fingerprint))

	// 8. Re-resolve via the normal issued-only path; the caller's heartbeat UPSERT then recreates the
	//    heartbeats row, restoring fleet visibility.
	return s.device(ctx, r)
}

// reconcileAllocation re-asserts dev's overlay-IP allocation if it went missing — e.g. a reaper
// false-positive released it while the host stayed live with an 'issued' enrollment (so device()
// resolves it and the self-heal gate never fires). Runs on every heartbeat; the common case is one
// cheap indexed lookup (overlay_ip is UNIQUE among live allocations). Fail-CLOSED on a genuine
// conflict (a DIFFERENT device now holds the IP): never clobber — the data plane still works off the
// cert — but surface it. Logs, never audits: this is per-beat, so audit-chain writes would be
// unbounded. No-op (always) when the allocator is unwired.
func (s *Server) reconcileAllocation(ctx context.Context, dev enrollment.Enrollment) {
	if s.cfg.Allocator == nil || dev.OverlayIP == "" {
		return
	}
	if owner, ok := s.allocationOwner(ctx, dev.OverlayIP); ok {
		if owner != dev.DeviceName {
			slog.Warn("heartbeat: overlay IP held by a different device while a live host heartbeats on it",
				"overlay_ip", dev.OverlayIP, "current_owner", owner, "device", dev.DeviceName)
		}
		return // already allocated (to us, or — logged — to another device; never clobber)
	}
	addr, err := netip.ParseAddr(dev.OverlayIP)
	if err != nil {
		return
	}
	if err := s.cfg.Allocator.AllocateSpecific(ctx, dev.DeviceName, addr, "heartbeat-reconcile"); err != nil && !errors.Is(err, ipam.ErrAddrTaken) {
		slog.Warn("heartbeat: re-assert overlay IP allocation failed",
			"overlay_ip", dev.OverlayIP, "device", dev.DeviceName, "err", err)
	}
}

// handleHeartbeat implements POST /v1/heartbeat (4.6): persist the device's
// reported state (fleet visibility) and return the typed command channel.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()

	dev, ok := s.device(ctx, r)
	if !ok {
		// A host presenting a VALID, non-revoked cert (authenticated by its source overlay IP) whose
		// control-plane rows were reclaimed repairs itself here instead of 403-ing forever. Disabled
		// (always !ok) unless self-heal is wired; identity is taken strictly from the surviving
		// enrollment row, never the request body.
		if dev, ok = s.trySelfHeal(ctx, r); !ok {
			wire.WriteError(w, wire.CodeAccountNotAllowed, "no enrolled device at this overlay address")
			return
		}
	}
	// Reconcile the device's overlay-IP allocation on EVERY beat. A reaper false-positive (or any
	// reclaim) can release a live host's IP while its enrollment stays 'issued' — so device() still
	// resolves it and the self-heal gate above never fires, yet the freed IP could be re-handed to a
	// SECOND device. Re-assert it idempotently so one overlay IP can never back two live certs.
	s.reconcileAllocation(ctx, dev)
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
	// M8.1: normalize the host's reported trusted-CA set to a byte-stable JSON array so
	// ca.AdoptionStatus parses a uniform shape. A pre-M8.1 pilot omits the field (nil) ->
	// store "[]" (NOT json.Marshal(nil)'s "null"), correctly counting as not-adopted until
	// the pilot upgrades. Lower+trim matches ca_certs.fingerprint.
	trustedCAs := "[]"
	if len(req.TrustedCAFingerprints) > 0 {
		fps := append([]string(nil), req.TrustedCAFingerprints...)
		for i := range fps {
			fps[i] = strings.ToLower(strings.TrimSpace(fps[i]))
		}
		sort.Strings(fps)
		if b, err := json.Marshal(fps); err == nil {
			trustedCAs = string(b)
		}
	}
	// M8.5 config-key adoption: same shape as trusted_cas, but base64url wire.PubkeyHash fingerprints
	// are CASE-SENSITIVE, so trim+sort only (NEVER lowercase) — configkey.AdoptionStatus matches them
	// EXACTLY. Default "[]" so a pre-M8.5 pilot omitting the field reads as not-yet-adopted (fail-closed).
	trustedConfigKeys := "[]"
	if len(req.TrustedConfigKeyFingerprints) > 0 {
		fps := append([]string(nil), req.TrustedConfigKeyFingerprints...)
		for i := range fps {
			fps[i] = strings.TrimSpace(fps[i])
		}
		sort.Strings(fps)
		if b, err := json.Marshal(fps); err == nil {
			trustedConfigKeys = string(b)
		}
	}
	hb := Heartbeat{
		OverlayIP: dev.OverlayIP, DeviceName: dev.DeviceName,
		PilotVersion: req.PilotVersion, NebulaVersion: req.NebulaVersion,
		CertNotAfter: certNotAfter, AppliedBundleVersion: req.AppliedBundleVersion,
		AppliedBlocklistVersion: req.AppliedBlocklistVersion, AppliedNebulaVersion: appliedNebula,
		AppliedPilotVersion: appliedPilot,
		ClockOffsetMs:       req.ClockOffsetMs, Health: req.Health, LastSeen: s.now().UnixNano(),
		TrustedCAs:          trustedCAs,
		TrustedConfigKeys:   trustedConfigKeys,
	}
	if err := s.cfg.Store.DB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "overlay_ip"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"device_name", "pilot_version", "nebula_version", "cert_not_after",
			"applied_bundle_version", "applied_blocklist_version", "applied_nebula_version",
			"applied_pilot_version", "clock_offset_ms", "health", "last_seen",
			// CRITICAL (M8.1): without trusted_cas here the per-overlay_ip upsert writes it
			// only at INSERT and never updates it, so adoption freezes at each host's first
			// beat and never converges after a CA is staged — the gate would block forever.
			"trusted_cas",
			// CRITICAL (M8.5): same for trusted_config_keys — a config-key cut-over/drain gate
			// would freeze at each host's first beat without this.
			"trusted_config_keys",
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
		Commands:        s.commandsFor(ctx, dev.OverlayIP, dev.GOOS, dev.GOARCH, dev.CAFingerprint, req.AppliedBundleVersion, req.AppliedBlocklistVersion, appliedNebula, appliedPilot, certNotAfter, dev.GroupsGeneration, dev.IssuedGeneration),
	})
}

// commandsFor decides the typed commands to return: the near-expiry renew
// backstop (4.6) plus, for 6.6, an apply_bundle that drives the host toward its
// rollout target version (or back to prev after a rollback).
func (s *Server) commandsFor(ctx context.Context, overlayIP, goos, goarch, hostCAFp string, appliedVersion, appliedBlocklist, appliedNebula, appliedPilot int, certNotAfter, groupsGen, issuedGen int64) []wire.Command {
	var cmds []wire.Command
	// Renew backstop: near cert expiry (4.6) OR a pending group reassignment
	// (groups_generation > issued_generation — ADR 0002) OR an M8.3c accelerated drain of the
	// draining CA this host still chains to. One CmdRenew covers all (renew re-keys AND re-signs
	// from desired_groups under the ACTIVE CA), so emit at most one even if several fire. The
	// force-renew check does DB work, so it is only run when a cheaper trigger has not already fired.
	nearExpiry := s.cfg.RenewCommandThreshold > 0 && certNotAfter > 0 &&
		time.Unix(0, certNotAfter).Sub(s.now()) < s.cfg.RenewCommandThreshold
	renew := nearExpiry || groupsGen > issuedGen
	if !renew {
		renew = s.forceRenewStraggler(ctx, overlayIP, hostCAFp)
	}
	if renew {
		cmds = append(cmds, wire.Command{Type: wire.CmdRenew})
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
		} else if cmd, ok := s.floorReconcile(ctx, goos, goarch, appliedNebula, appliedPilot); ok {
			// Backstop for hosts that no active/completed rollout commands because they
			// were never in its member snapshot (enrolled/re-enrolled after Start, or
			// absent from it): drive any host running below the completed nebula/pilot
			// floor up to it. Gated on arch-servability so an unservable host doesn't
			// churn a no-op refetch every beat. See rollout.Engine.FloorCatchupGen.
			cmds = append(cmds, cmd)
		}
	}
	return cmds
}

// forceRenewStraggler reports whether this host should be force-renewed to accelerate a draining
// CA's drain (M8.3c): its current leaf chains to a NON-active CA that is under an active force-renew,
// and its deterministic wave bucket has opened. It PAUSES (returns false) while the signing breaker
// is open, so a force-drain never piles renewals onto a halted signer. Fail-safe: any read error
// returns false — the host simply keeps draining at its natural renewal cadence.
func (s *Server) forceRenewStraggler(ctx context.Context, overlayIP, hostCAFp string) bool {
	if s.cfg.CADrain == nil || hostCAFp == "" {
		return false
	}
	activeFp, err := s.cfg.CADrain.ActiveFingerprint(ctx)
	if err != nil || activeFp == "" || strings.EqualFold(hostCAFp, activeFp) {
		return false // no active CA known, or the host is already on it
	}
	// Only force-renew once THIS process's signer has actually cut over to the active CA. handleRenew
	// signs with the LOCAL signer's current identity (not the registry's active CA), so if this Core
	// has not swapped yet — the fail-safe states force-renew exists to rescue: -ca-cutover-interval=0,
	// a refused software swap, a stuck BackendFactory/KMS — a forced renewal would re-sign the
	// straggler under the SAME draining CA, leaving it a straggler that is force-renewed every beat
	// forever (an unbounded self-inflicted re-key storm that never drains).
	if s.cfg.Signer == nil || !strings.EqualFold(s.cfg.Signer.CurrentFingerprint(), activeFp) {
		return false
	}
	startedNS, windowNS, accelerated, err := s.cfg.CADrain.DrainWave(ctx, hostCAFp)
	if err != nil || !accelerated || !inDrainWave(overlayIP, startedNS, windowNS, s.now().UnixNano()) {
		return false
	}
	// Pause widening while signing is halted (breaker open) — don't add to a halted signer.
	if s.cfg.Signer != nil {
		if open, berr := s.cfg.Signer.BreakerOpen(ctx); berr == nil && open {
			return false
		}
	}
	return true
}

// inDrainWave reports whether overlayIP's deterministic bucket has opened in an accelerated drain
// that started startedNS ago and completes over windowNS (M8.3c). Buckets [0,100) open linearly
// with elapsed time, so renewals spread evenly across the window instead of storming at t0. Once
// the window has fully elapsed, every remaining straggler is admitted (the drain must still finish).
func inDrainWave(overlayIP string, startedNS, windowNS, nowNS int64) bool {
	if startedNS <= 0 || windowNS <= 0 {
		return false
	}
	elapsed := nowNS - startedNS
	if elapsed < 0 {
		return false // clock skew: not started yet
	}
	if elapsed >= windowNS {
		return true // window complete -> admit every remaining straggler
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(overlayIP))
	bucket := int64(h.Sum32() % 100)   // stable per-host in [0,99]
	admitted := elapsed * 100 / windowNS // grows 0..99 as the window elapses
	return bucket <= admitted
}

// floorReconcile returns a single apply_bundle when the host is running below the
// completed nebula- or pilot-lane floor AND the floor generation ships an artifact for
// the host's arch (so the refetched bundle actually carries a newer tuple). nebula is
// checked before pilot; one apply_bundle refreshes every lane, so at most one is emitted.
func (s *Server) floorReconcile(ctx context.Context, goos, goarch string, appliedNebula, appliedPilot int) (wire.Command, bool) {
	if s.cfg.NebulaReleases != nil {
		if gen, ok := s.cfg.Rollout.FloorCatchupGen(ctx, rollout.LaneNebula, appliedNebula); ok {
			if _, _, _, servable := s.cfg.NebulaReleases.Lookup(ctx, gen, goos, goarch); servable {
				return wire.Command{Type: wire.CmdApplyBundle, BundleVersion: gen}, true
			}
		}
	}
	if s.cfg.PilotReleases != nil {
		if gen, ok := s.cfg.Rollout.FloorCatchupGen(ctx, rollout.LanePilot, appliedPilot); ok {
			if _, _, _, servable := s.cfg.PilotReleases.Lookup(ctx, gen, goos, goarch); servable {
				return wire.Command{Type: wire.CmdApplyBundle, BundleVersion: gen}, true
			}
		}
	}
	return wire.Command{}, false
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

	// A revoked host must not be able to renew itself back to life (M7.1 durability).
	// `harbor blocklist add` only writes the revocations table — it does NOT flip the
	// enrollment status or release the IP — so without this gate a blocklisted host that
	// still has ANY path to Core (its established tunnel, or Core not-yet-having-applied
	// the block) would re-sign with a fresh key and land a NEW fingerprint the blocklist
	// does not cover, orphaning the operator's revocation. Checked against the host's
	// CURRENT persisted fingerprint. Fail CLOSED on a read error, mirroring trySelfHeal:
	// don't mint a fresh cert when we cannot confirm the host is not revoked.
	switch revoked, rerr := s.revoked(ctx, dev.Fingerprint); {
	case rerr != nil:
		_, _ = s.cfg.Store.AppendAudit(ctx, "system", "renew-revocation-check-error", dev.OverlayIP, rerr.Error())
		wire.WriteError(w, wire.CodeSigningUnavailable, "revocation status unavailable; retry")
		return
	case revoked:
		_, _ = s.cfg.Store.AppendAudit(ctx, "renew:"+dev.DeviceName, "renew-refused-revoked", dev.DeviceName,
			fmt.Sprintf(`{"overlay_ip":%q,"fingerprint":%q}`, dev.OverlayIP, dev.Fingerprint))
		wire.WriteError(w, wire.CodeAccountNotAllowed, "certificate revoked")
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

	// 4.3 — re-sign the SAME identity (IP), with the DESIRED groups (ADR 0002). The control
	// plane is the authority: the host supplies only a CSR, never groups. desired_groups is what
	// we sign; the existing `groups` column is what the LIVE cert carries (used for the reserved
	// guard + reduction detection below). capturedGen is the generation we are issuing for; the
	// write-back is guarded by it so a concurrent operator bump / racing renew can't clobber.
	capturedGen := dev.GroupsGeneration
	var issuedGroups, groups []string
	_ = json.Unmarshal([]byte(dev.Groups), &issuedGroups)
	_ = json.Unmarshal([]byte(dev.DesiredGroups), &groups)
	// CHOKEPOINT reserved-group guard (defense in depth, independent of the admin perimeter):
	// the signer is the only place groups become authority, so a reduction must NEVER strip a
	// reserved group (control-plane/lighthouse) off a node that holds it — that drops its
	// baseline-accept firewall and bricks the fleet. Re-add any reserved group the live cert
	// carries and alarm; the perimeter (P1.6) should have rejected it, this is the backstop.
	var keptReserved []string
	groups, keptReserved = keepReservedGroups(issuedGroups, groups)
	for _, g := range keptReserved {
		_, _ = s.cfg.Store.AppendAudit(ctx, "system", "renew-reserved-strip-refused", dev.DeviceName,
			fmt.Sprintf(`{"overlay_ip":%q,"kept_group":%q}`, dev.OverlayIP, g))
	}
	isReduction := groupsReduced(issuedGroups, groups) // a group the live cert carries is gone from the new set
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
	bundleJWS, err := s.signBundle(b)
	if err != nil {
		wire.WriteError(w, wire.CodeInternal, "bundle sign failed")
		return
	}
	fp, _ := crt.Fingerprint()
	// The CA that signed this renewed leaf (M8.3 drain tracking) — re-stamped on every
	// renewal so CA1 drains toward zero as hosts migrate to CA2 after a cut-over. Issuer()
	// is the exact CA this signature chained to (== ca_certs.fingerprint), TOCTOU-free.
	caFp := strings.ToLower(strings.TrimSpace(crt.Issuer()))
	// Track the host's CURRENT fingerprint: it rotates with the key on every
	// renewal, so a blocklist must target the live fingerprint (M7.1/7.3). Fail
	// closed if we can't persist it — delivering a renewed bundle whose fingerprint
	// Core never recorded would leave a blocklist blind spot (the device could not
	// be revoked by fingerprint). The ca_fingerprint rides the SAME fail-closed write.
	if err := s.cfg.Store.DB.WithContext(ctx).Model(&enrollment.Enrollment{}).
		Where("id = ?", dev.ID).Updates(map[string]any{"fingerprint": fp, "ca_fingerprint": caFp}).Error; err != nil {
		wire.WriteError(w, wire.CodeInternal, "renew bookkeeping failed")
		return
	}
	// Advance issued groups + generation to what we just signed, GUARDED by the captured
	// generation: a concurrent operator bump (newer desired) or a slower racing renew must not
	// clobber a newer issue nor mark a stale issue converged. A near-expiry renew with no pending
	// change has capturedGen == issued_generation, so this 0-row-matches (no-op; the fingerprint
	// write above is unconditional and already persisted). On a reduction, record the DURABLE
	// advisory flag + the OLD cert's expiry (the heartbeat still holds it here, pre-update below);
	// it is cleared in Phase 3 once the old cert is revoked. (AppendAuditTx for atomic write+audit
	// is plan item P1.4b, still TODO — this keeps today's write-then-append convention.)
	signedGroupsJSON, _ := json.Marshal(groups)
	upd := map[string]any{"groups": string(signedGroupsJSON), "issued_generation": capturedGen}
	if isReduction {
		var oldNotAfter int64
		_ = s.cfg.Store.DB.WithContext(ctx).Raw(
			"SELECT cert_not_after FROM heartbeats WHERE overlay_ip = ?", dev.OverlayIP).Scan(&oldNotAfter).Error
		upd["reduction_pending_enforcement"] = true
		upd["reduction_old_not_after"] = oldNotAfter
	}
	if err := s.cfg.Store.DB.WithContext(ctx).Model(&enrollment.Enrollment{}).
		Where("id = ? AND issued_generation < ?", dev.ID, capturedGen).Updates(upd).Error; err != nil {
		_, _ = s.cfg.Store.AppendAudit(ctx, "system", "renew-groups-writeback-error", dev.OverlayIP, err.Error())
	}
	// Advance the heartbeat row's recorded cert_not_after to the freshly-issued expiry so the reaper
	// sees the new validity immediately, instead of lagging (and possibly mis-judging the host
	// cert-expired) until the host's next heartbeat re-reports it. Best-effort: a host that has never
	// heartbeated has no row (RowsAffected 0 is fine), and a failure here must not fail the renew —
	// the next heartbeat reconciles it.
	if res := s.cfg.Store.DB.WithContext(ctx).Exec(
		"UPDATE heartbeats SET cert_not_after = ? WHERE overlay_ip = ?", notAfter.UnixNano(), dev.OverlayIP); res.Error != nil {
		_, _ = s.cfg.Store.AppendAudit(ctx, "system", "renew-heartbeat-cert-update-error", dev.OverlayIP, res.Error.Error())
	}
	// Authority audit: the cert-issue is where groups become authority, so record the groups
	// signed + the generation issued (groups is valid JSON — a string array — embedded raw).
	_, _ = s.cfg.Store.AppendAudit(ctx, "renew:"+dev.DeviceName, "cert-renewed", dev.DeviceName,
		fmt.Sprintf(`{"overlay_ip":%q,"fingerprint":%q,"groups":%s,"issued_generation":%d}`, dev.OverlayIP, fp, string(signedGroupsJSON), capturedGen))

	wire.WriteJSON(w, http.StatusOK, wire.RenewResponse{ProtocolVersion: wire.ProtocolVersion, Bundle: bundleJWS})
}

// containsGroup reports whether g is in gs.
func containsGroup(gs []string, g string) bool {
	for _, x := range gs {
		if x == g {
			return true
		}
	}
	return false
}

// keepReservedGroups is the renew CHOKEPOINT: the groups to actually sign are the desired set
// PLUS any reserved group (control-plane/lighthouse) the live cert holds that desired tried to
// drop — stripping one would brick a control-plane node by dropping its baseline-accept firewall.
// Returns the corrected set + the reserved groups it re-added (for the caller to audit/alarm).
func keepReservedGroups(issued, desired []string) (result, keptReserved []string) {
	result = desired
	if !policy.GrantsReservedGroup(issued) {
		return result, nil
	}
	for _, g := range issued {
		if policy.IsReservedGroup(g) && !containsGroup(result, g) {
			result = append(result, g)
			keptReserved = append(keptReserved, g)
		}
	}
	return result, keptReserved
}

// groupsReduced reports whether any group the live cert carries (oldSet) is absent from the
// newly-signed set (newSet) — i.e. the change is a reduction (soft until the old cert is revoked).
func groupsReduced(oldSet, newSet []string) bool {
	for _, o := range oldSet {
		if !containsGroup(newSet, o) {
			return true
		}
	}
	return false
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
		Certificate:       certPEM,
		CABundle:          s.caBundle(ctx),
		ConfigSigningKeys: s.configKeys(ctx),
		ConfigKeyVersion:  s.configKeyVersion(ctx),
		Firewall:          bundle.CompileFirewall(s.cfg.Policy, groups),
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
	bundleJWS, err := s.signBundle(b)
	if err != nil {
		wire.WriteError(w, wire.CodeInternal, "bundle sign failed")
		return
	}
	wire.WriteJSON(w, http.StatusOK, wire.ConfigResponse{ProtocolVersion: wire.ProtocolVersion, Bundle: bundleJWS})
}
