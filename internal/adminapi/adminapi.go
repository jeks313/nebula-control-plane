// Package adminapi is Harbor's admin HTTP API (UI Implementation Plan track A0):
// the single versioned `/admin/v1` surface the web console consumes — and, in
// time, the surface the `harbor` CLI is refactored onto, so "CLI-parity / no UI
// backdoor" is enforced rather than asserted.
//
// It is a strict, server-owns-the-truth surface: every "is this healthy / safe?"
// answer (notably the fleet-health rollup) is computed here, never in the client.
// This first slice is read-only (me, fleet health, devices, audit, lighthouses);
// mutating endpoints and the OpenAPI/CLI refactor land in later A0 slices.
//
// Auth is the dev-auth seam: until 2.11 (OIDC/MFA/RBAC) ships, an IdentityProvider
// resolves the calling admin. The DevHeaderProvider (env-gated, never in prod) lets
// the running console + dual-control be exercised against a seeded Harbor early.
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/fleet"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
)

// Identity is the authenticated admin principal.
type Identity struct {
	Principal string     `json:"principal"`
	Roles     []string   `json:"roles"`
	MFAAt     *time.Time `json:"mfa_satisfied_at,omitempty"`
}

// IdentityProvider resolves the admin identity from a request — the seam that the
// real OIDC session provider plugs into once 2.11 lands.
type IdentityProvider interface {
	Identify(r *http.Request) (Identity, bool)
}

// DevHeaderProvider trusts an `X-Harbor-Dev-Actor` header. It exists ONLY to
// dogfood the console before 2.11; it must never be wired in production (the
// harbor command gates it behind an explicit -dev-auth flag + a loud warning).
type DevHeaderProvider struct {
	Roles []string // roles granted to the dev actor (default ["admin"])
}

// Identify implements IdentityProvider.
func (d DevHeaderProvider) Identify(r *http.Request) (Identity, bool) {
	actor := r.Header.Get("X-Harbor-Dev-Actor")
	if actor == "" {
		return Identity{}, false
	}
	roles := d.Roles
	if len(roles) == 0 {
		roles = []string{"admin"}
	}
	return Identity{Principal: actor, Roles: roles}, true
}

// Config builds a Server.
type Config struct {
	Store       *store.Store
	Identity    IdentityProvider
	Rollout     *rollout.Engine      // optional; feeds the health rollup
	Lighthouses *lighthouse.Registry // optional; /lighthouses
	Thresholds  fleet.Thresholds     // health thresholds (sensible defaults if zero)
	Now         func() time.Time
	Logger      *slog.Logger // server-side error log (default slog.Default())
}

// Server is the admin API.
type Server struct{ cfg Config }

// New builds a Server, filling sensible defaults.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Thresholds.ExpiryWindow == 0 {
		cfg.Thresholds.ExpiryWindow = 7 * 24 * time.Hour
	}
	if cfg.Thresholds.StaleAfter == 0 {
		cfg.Thresholds.StaleAfter = 5 * time.Minute
	}
	if cfg.Thresholds.ClockSkewMs == 0 {
		cfg.Thresholds.ClockSkewMs = 5000
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{cfg: cfg}
}

// fail logs the real error server-side and returns a stable, generic detail to
// the client — internal DB/SQL/path strings must never leak (cf. coreapi, which
// uses the same static-message convention).
func (s *Server) fail(w http.ResponseWriter, r *http.Request, msg string, err error) {
	s.cfg.Logger.Error("adminapi: "+msg, "err", err, "path", r.URL.Path)
	writeProblem(w, http.StatusInternalServerError, "internal error", msg)
}

func (s *Server) now() time.Time { return s.cfg.Now() }

type ctxKey int

const identityKey ctxKey = 0

// Handler returns the routed, auth-wrapped admin API. Mesh-only: bind it to
// Core's overlay IP in production (never the public ENI).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/me", s.handleMe)
	mux.HandleFunc("GET /admin/v1/fleet/health", s.handleFleetHealth)
	mux.HandleFunc("GET /admin/v1/devices", s.handleDevices)
	mux.HandleFunc("GET /admin/v1/audit", s.handleAudit)
	mux.HandleFunc("GET /admin/v1/audit/verify", s.handleAuditVerify)
	mux.HandleFunc("GET /admin/v1/lighthouses", s.handleLighthouses)
	return s.authMiddleware(mux)
}

// authMiddleware resolves the admin identity (the dev-auth seam) and rejects
// unauthenticated requests with problem+json. The identity is stashed for handlers.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if s.cfg.Identity == nil {
			// No provider wired yet (pre-OIDC, no -dev-auth): every request is
			// unauthenticated (401), not "service down" (503) — matches the
			// startup message and the actual semantics.
			writeProblem(w, http.StatusUnauthorized, "unauthenticated", "no identity provider configured")
			return
		}
		id, ok := s.cfg.Identity.Identify(r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "unauthenticated", "no admin identity on the request")
			return
		}
		if id.Roles == nil {
			id.Roles = []string{} // contract: roles is always a JSON array
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
	})
}

func identityFrom(ctx context.Context) Identity {
	id, _ := ctx.Value(identityKey).(Identity)
	return id
}

// GET /admin/v1/me
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, identityFrom(r.Context()))
}

// FleetHealth is the /fleet/health response: the rollup plus the underlying counts
// the dashboard masthead/cards render.
type FleetHealth struct {
	fleet.Health
	Totals struct {
		Total       int `json:"total"`
		Expired     int `json:"expired"`
		Expiring    int `json:"expiring"`
		Stale       int `json:"stale"`
		ClockSkewed int `json:"clock_skewed"`
		Unhealthy   int `json:"unhealthy"`
	} `json:"totals"`
	RolloutState string `json:"rollout_state,omitempty"`
	AuditOK      bool   `json:"audit_ok"`
}

// GET /admin/v1/fleet/health — the server-computed health verdict (§3.2).
func (s *Server) handleFleetHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rep, err := fleet.Generate(ctx, s.cfg.Store, s.now(), s.cfg.Thresholds)
	if err != nil {
		s.fail(w, r, "fleet report failed", err)
		return
	}
	// Distinguish "chain is tampered" (critical) from "couldn't verify right now"
	// (degraded) — a transient DB error must not read as tampering.
	auditState, auditOK := fleet.AuditOK, true
	if _, averr := s.cfg.Store.VerifyAudit(ctx); averr != nil {
		auditOK = false
		if errors.Is(averr, store.ErrAuditTampered) {
			auditState = fleet.AuditTampered
		} else {
			auditState = fleet.AuditUnavailable
			s.cfg.Logger.Error("adminapi: audit verify unavailable", "err", averr)
		}
	}

	rolloutState := ""
	if s.cfg.Rollout != nil {
		if rr, _, rerr := s.cfg.Rollout.Status(ctx); rerr == nil {
			rolloutState = rr.State
		}
	}

	var resp FleetHealth
	resp.Health = fleet.Rollup(rep, auditState, rolloutState, s.cfg.Thresholds)
	resp.Totals.Total = rep.Total
	resp.Totals.Expired = rep.Expired
	resp.Totals.Expiring = rep.ExpiringSoon
	resp.Totals.Stale = rep.Stale
	resp.Totals.ClockSkewed = rep.ClockSkewed
	resp.Totals.Unhealthy = rep.Unhealthy
	resp.RolloutState = rolloutState
	resp.AuditOK = auditOK
	writeJSON(w, http.StatusOK, resp)
}

// deviceHB maps the heartbeats table (read-only view, like fleet/rollout).
type deviceHB struct {
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

func (deviceHB) TableName() string { return "heartbeats" }

// Device is the API device summary.
type Device struct {
	OverlayIP            string `json:"overlay_ip"`
	Name                 string `json:"name"`
	PilotVersion         string `json:"pilot_version,omitempty"`
	NebulaVersion        string `json:"nebula_version,omitempty"`
	CertNotAfter         string `json:"cert_not_after,omitempty"`
	AppliedBundleVersion int    `json:"applied_bundle_version"`
	ClockOffsetMs        int    `json:"clock_offset_ms"`
	Health               string `json:"health,omitempty"`
	LastSeen             string `json:"last_seen,omitempty"`
}

// GET /admin/v1/devices?limit=N&after=OVERLAY_IP — device inventory from
// heartbeats, keyset-paginated on overlay_ip (same cursor shape as /audit).
// `count` is the page size; `next_after` (when present) is the cursor for the
// next page — never assume `count` is the fleet total.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 200, 1, 2000)
	after := r.URL.Query().Get("after")
	q := s.cfg.Store.DB.WithContext(r.Context()).Order("overlay_ip ASC").Limit(limit)
	if after != "" {
		q = q.Where("overlay_ip > ?", after)
	}
	var rows []deviceHB
	if err := q.Find(&rows).Error; err != nil {
		s.fail(w, r, "list devices failed", err)
		return
	}
	out := make([]Device, len(rows))
	for i, h := range rows {
		out[i] = Device{
			OverlayIP: h.OverlayIP, Name: h.DeviceName,
			PilotVersion: h.PilotVersion, NebulaVersion: h.NebulaVersion,
			CertNotAfter: rfc3339(h.CertNotAfter), AppliedBundleVersion: h.AppliedBundleVersion,
			ClockOffsetMs: h.ClockOffsetMs, Health: h.Health, LastSeen: rfc3339(h.LastSeen),
		}
	}
	resp := map[string]any{"devices": out, "count": len(out)}
	if len(out) == limit {
		resp["next_after"] = out[len(out)-1].OverlayIP
	}
	writeJSON(w, http.StatusOK, resp)
}

// AuditRow is one audit-log entry in the API.
type AuditRow struct {
	Seq     int64  `json:"seq"`
	TS      string `json:"ts"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Target  string `json:"target,omitempty"`
	Details string `json:"details,omitempty"`
}

// GET /admin/v1/audit?limit=N&before=SEQ — newest-first, cursor-paginated.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50, 1, 500)
	before := queryInt(r, "before", 0, 0, 1<<62)
	q := s.cfg.Store.DB.WithContext(r.Context()).Model(&store.Audit{}).Order("seq DESC").Limit(limit)
	if before > 0 {
		q = q.Where("seq < ?", before)
	}
	var rows []store.Audit
	if err := q.Find(&rows).Error; err != nil {
		s.fail(w, r, "list audit failed", err)
		return
	}
	out := make([]AuditRow, len(rows))
	for i, a := range rows {
		out[i] = AuditRow{Seq: a.Seq, TS: rfc3339(a.TS), Actor: a.Actor, Action: a.Action, Target: a.Target, Details: a.Details}
	}
	resp := map[string]any{"entries": out, "count": len(out)}
	if len(out) == limit {
		resp["next_before"] = out[len(out)-1].Seq // cursor: rows older than the last seq
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /admin/v1/audit/verify — chain integrity, as three honest states:
// "verified" (clean), "tampered" (a genuine integrity failure), or — on an infra
// read error — 503 "unavailable" (we could not check; NOT a claim of tampering).
// NOTE: in-DB scope only; it cannot detect tail-truncation without the WORM
// anchor (impl 2.13).
const auditScope = "in-db (does not detect tail truncation until WORM anchoring is configured)"

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	n, err := s.cfg.Store.VerifyAudit(r.Context())
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"status": "verified", "ok": true, "verified_rows": n, "scope": auditScope})
	case errors.Is(err, store.ErrAuditTampered):
		// A real, returnable answer: the chain is bad. Detail is safe (no SQL/paths).
		writeJSON(w, http.StatusOK, map[string]any{"status": "tampered", "ok": false, "verified_rows": n, "scope": auditScope, "detail": "audit chain failed integrity verification"})
	default:
		s.cfg.Logger.Error("adminapi: audit verify read failed", "err", err, "path", r.URL.Path)
		writeProblem(w, http.StatusServiceUnavailable, "audit check unavailable", "could not read the audit log")
	}
}

// Lighthouse is the API view of a registry entry.
type Lighthouse struct {
	OverlayIP   string   `json:"overlay_ip"`
	Hostname    string   `json:"hostname,omitempty"`
	State       string   `json:"state"`
	PublicAddrs []string `json:"public_addrs"`
}

// GET /admin/v1/lighthouses — the discovery fleet.
func (s *Server) handleLighthouses(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Lighthouses == nil {
		writeJSON(w, http.StatusOK, map[string]any{"lighthouses": []Lighthouse{}, "count": 0})
		return
	}
	rows, err := s.cfg.Lighthouses.List(r.Context())
	if err != nil {
		s.fail(w, r, "list lighthouses failed", err)
		return
	}
	out := make([]Lighthouse, len(rows))
	for i, l := range rows {
		out[i] = Lighthouse{OverlayIP: l.OverlayIP, Hostname: l.Hostname, State: l.State, PublicAddrs: l.Addrs()}
	}
	writeJSON(w, http.StatusOK, map[string]any{"lighthouses": out, "count": len(out)})
}

// ── helpers ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeProblem emits an RFC 9457 problem+json error the UI renders inline.
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"title": title, "status": status, "detail": detail})
}

func rfc3339(unixNano int64) string {
	if unixNano == 0 {
		return ""
	}
	return time.Unix(0, unixNano).UTC().Format(time.RFC3339)
}

func queryInt(r *http.Request, key string, def, min, max int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min {
		return def
	}
	if n > max {
		return max
	}
	return n
}
