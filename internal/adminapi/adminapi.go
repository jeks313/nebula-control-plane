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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/config"
	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/fleet"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/nebularelease"
	"github.com/jeks313/nebula-control-plane/internal/netblock"
	"github.com/jeks313/nebula-control-plane/internal/pilotrelease"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/usertrust"
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

// ChainProvider tries each provider in order and returns the first identity that
// resolves — so machine tokens (Authorization: Bearer) and human sessions (cookie)
// can both authenticate the same admin API. Put the token provider first: it keys
// off a header the browser session never sets, so the two never collide.
type ChainProvider []IdentityProvider

// Identify implements IdentityProvider.
func (c ChainProvider) Identify(r *http.Request) (Identity, bool) {
	for _, p := range c {
		if p == nil {
			continue
		}
		if id, ok := p.Identify(r); ok {
			return id, true
		}
	}
	return Identity{}, false
}

// DevHeaderProvider trusts an `X-Harbor-Dev-Actor` header. It exists ONLY to
// dogfood the console before 2.11; it must never be wired in production (the
// harbor command gates it behind an explicit -dev-auth flag + a loud warning).
type DevHeaderProvider struct {
	Roles []string // roles granted to the dev actor (default ["admin"])
	MFA   bool     // assert fresh MFA (so the dev seam satisfies step-up enforcement)
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
	id := Identity{Principal: actor, Roles: roles}
	if d.MFA {
		now := time.Now()
		id.MFAAt = &now
	}
	return id, true
}

// Config builds a Server.
type Config struct {
	Store       *store.Store
	Identity    IdentityProvider
	Rollout     *rollout.Engine      // optional; feeds the health rollup
	Lighthouses *lighthouse.Registry // optional; /lighthouses
	// NebulaReleases / PilotReleases back the /releases view (ADR 0003 1c/3c): the
	// release registries the console lists + stages rollouts from. Optional; defaulted
	// from the store like Rollout.
	NebulaReleases *nebularelease.Store
	PilotReleases  *pilotrelease.Store
	// Enrollment drives the approval queue. A Store-only consumer (the default)
	// supports list + deny; a fully-configured one (CanIssue) also approves
	// (issues a cert). CanIssue gates the approve endpoint.
	Enrollment *enrollment.Consumer
	CanIssue   bool
	// Netblocks + Allocator back the IPAM admin surface (ADR 0010): the netblock
	// registry (CRUD + Suggest) and the allocator that reads allocations for
	// utilization/overlay + backs the registry's stranding guard. Optional — when
	// both are nil the IPAM endpoints behave as "not configured" (empty list, 503 on
	// mutate), mirroring the Lighthouses guard. Pool is the overlay CIDR used to
	// default the registry from the store when Netblocks is nil.
	Netblocks  *netblock.Registry
	Allocator  *ipam.Allocator
	Pool       netip.Prefix
	Thresholds fleet.Thresholds // health thresholds (sensible defaults if zero)
	// MFAFreshness gates the most privileged actions (dual-control approve, policy
	// publish) on recent MFA: the session's mfa_satisfied_at must be within this
	// window. Zero disables step-up enforcement (dev / no-IdP).
	MFAFreshness time.Duration
	Now          func() time.Time
	Logger       *slog.Logger // server-side error log (default slog.Default())
}

// Server is the admin API.
type Server struct {
	cfg         Config
	dc          *dualcontrol.Controller // dual-control workflow (approvals + privileged config commits + bulk-revoke)
	configStore *config.Store           // ADR 0011 Phase 1: the declarative config store (single source of truth)
}

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
	s := &Server{cfg: cfg}
	if cfg.Store != nil {
		audit := func(ctx context.Context, a, ac, t, d string) error {
			_, e := cfg.Store.AppendAudit(ctx, a, ac, t, d)
			return e
		}
		s.dc = dualcontrol.New(dualcontrol.Config{DB: cfg.Store.DB, Audit: audit})
		s.configStore = config.New(cfg.Store.DB, audit)
		// Default the fleet engines from the store so the mutation handlers always
		// have them (no 501 "not configured" path); a caller may still inject its own.
		if s.cfg.Rollout == nil {
			s.cfg.Rollout = rollout.New(cfg.Store.DB, audit)
		}
		if s.cfg.Lighthouses == nil {
			s.cfg.Lighthouses = lighthouse.New(cfg.Store.DB, audit)
		}
		if s.cfg.NebulaReleases == nil {
			s.cfg.NebulaReleases = nebularelease.New(cfg.Store.DB)
		}
		if s.cfg.PilotReleases == nil {
			s.cfg.PilotReleases = pilotrelease.New(cfg.Store.DB)
		}
		if s.cfg.Enrollment == nil {
			// Store-only: list + deny work; approve is gated by CanIssue (false here).
			s.cfg.Enrollment = enrollment.New(enrollment.Config{Store: cfg.Store})
		}
		// IPAM (ADR 0010): default the netblock registry + allocator from the store so
		// the IPAM admin endpoints always have them. The allocator backs the registry's
		// stranding guard (and the utilization/allocation reads); the registry is its
		// netblock resolver. A caller may still inject its own (e.g. one already wired
		// for enrollment). Requires a pool — default to the genesis convention if unset.
		if s.cfg.Allocator == nil || s.cfg.Netblocks == nil {
			pool := s.cfg.Pool
			if !pool.IsValid() {
				pool, _ = netip.ParsePrefix("100.64.0.0/16")
			}
			if alloc, aerr := ipam.NewAllocator(cfg.Store, ipam.Pool{Prefix: pool}); aerr == nil {
				reg := netblock.New(cfg.Store.DB, pool, nil, alloc, audit)
				alloc = alloc.WithResolver(reg)
				if s.cfg.Allocator == nil {
					s.cfg.Allocator = alloc
				}
				if s.cfg.Netblocks == nil {
					s.cfg.Netblocks = reg
				}
			}
		}
		// ADR 0011 Phase 1 (C5): the dual-control committers for the three config
		// kinds now WRITE THE CONFIG STORE on commit. A privileged change (routed
		// through the two-person flow by the PUT) re-validates AND lands in the SAME
		// store the single-operator PUT writes — both paths converge on the store, so
		// it is the single source of truth. Re-validating at commit is defense in
		// depth (the PUT already validated inline before proposing).
		registerConfigCommitter(s.dc, s.configStore, policy.PublishKind, func(b []byte) error {
			p, err := policy.Parse(string(b))
			if err != nil {
				return err
			}
			return policy.CheckInvariants(p)
		})
		registerConfigCommitter(s.dc, s.configStore, cloudtrust.PublishKind, func(b []byte) error {
			_, err := cloudtrust.Parse(b)
			return err
		})
		registerConfigCommitter(s.dc, s.configStore, usertrust.PublishKind, func(b []byte) error {
			_, err := usertrust.Parse(b)
			return err
		})
		// Bulk device re-group (ADR 0013): an elevating/large bulk routes through dual-control;
		// the committer re-resolves + applies the frozen entry set at approval time.
		s.dc.Register(regroupKind, s.commitDeviceRegroup)
	}
	return s
}

// registerConfigCommitter wires a dual-control committer for a config kind: on
// quorum it re-validates the change payload (defense in depth) and then writes it to
// the config store attributed to the proposer (ADR 0011 C5). Both the single-operator
// PUT and this two-person commit therefore converge on configStore.Set.
func registerConfigCommitter(dc *dualcontrol.Controller, cs *config.Store, kind string, validate func([]byte) error) {
	dc.Register(kind, func(ctx context.Context, ch dualcontrol.Change) error {
		if err := validate(ch.Payload); err != nil {
			return err
		}
		_, err := cs.Set(ctx, kind, ch.Payload, ch.Proposer)
		return err
	})
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

type route struct {
	Method, Path string
	h            http.HandlerFunc
}

// routes is the single source of truth for the admin surface — both the mux and
// the OpenAPI contract test (Routes) derive from it, so the spec can't silently
// drift from the implementation.
func (s *Server) routeTable() []route {
	return []route{
		{"GET", "/admin/v1/me", s.handleMe},
		{"GET", "/admin/v1/fleet/health", s.handleFleetHealth},
		{"GET", "/admin/v1/devices", s.handleDevices},
		{"PATCH", "/admin/v1/devices/{ip}/groups", s.handleDeviceGroupSet},
		{"POST", "/admin/v1/devices/regroup", s.handleDeviceRegroup},
		{"GET", "/admin/v1/devices/regroup/match", s.handleDeviceRegroupMatch},
		{"GET", "/admin/v1/audit", s.handleAudit},
		{"GET", "/admin/v1/audit/verify", s.handleAuditVerify},
		{"GET", "/admin/v1/lighthouses", s.handleLighthouses},
		// Dual-control approvals (generic) + policy publish (the showcase).
		{"GET", "/admin/v1/approvals", s.handleApprovals},
		{"GET", "/admin/v1/approvals/{id}", s.handleApproval},
		{"POST", "/admin/v1/approvals/{id}/approve", s.handleApprove},
		{"POST", "/admin/v1/approvals/{id}/deny", s.handleDeny},
		// ADR 0011 Phase 1: the declarative set/get config primitive. PUT sets the
		// ENTIRE config for a kind (validates inline, then routes privileged changes
		// two-person or writes the store directly); GET reads the store. The
		// per-kind /active GETs are the rich console views (also store-backed now).
		{"PUT", "/admin/v1/config/{kind}", s.handleConfigSet},
		{"GET", "/admin/v1/config/{kind}", s.handleConfigGet},
		{"GET", "/admin/v1/policy/active", s.handlePolicyActive},
		{"POST", "/admin/v1/policy/compile", s.handlePolicyCompile},
		{"POST", "/admin/v1/policy/reachability", s.handlePolicyReachability},
		{"POST", "/admin/v1/policy/matrix", s.handlePolicyMatrix},
		{"POST", "/admin/v1/policy/tests", s.handlePolicyTests},
		{"POST", "/admin/v1/policy/diff", s.handlePolicyDiff},
		// Cloud-attestation trust config (store-backed; privileged changes routed two-person via /approvals).
		{"GET", "/admin/v1/cloudtrust/active", s.handleCloudTrustActive},
		// SSO user-trust config (ADR 0004; store-backed; privileged changes routed two-person via /approvals).
		{"GET", "/admin/v1/usertrust/active", s.handleUserTrustActive},
		// A0.4 fleet-management mutations (pure-DB).
		{"POST", "/admin/v1/lighthouses", s.handleLighthouseAdd},
		{"PUT", "/admin/v1/lighthouses/{ip}", s.handleLighthouseReplace},
		{"DELETE", "/admin/v1/lighthouses/{ip}", s.handleLighthouseRemove},
		{"GET", "/admin/v1/rollouts/current", s.handleRolloutCurrent},
		{"POST", "/admin/v1/rollouts", s.handleRolloutStart},
		{"POST", "/admin/v1/rollouts/current/step", s.handleRolloutStep},
		{"POST", "/admin/v1/rollouts/current/abort", s.handleRolloutAbort},
		// Binary releases (nebula + pilot) — list the registries + each lane's rollout,
		// stage a fleet upgrade, abort it (ADR 0003 1c/3c).
		{"GET", "/admin/v1/releases", s.handleReleasesList},
		{"POST", "/admin/v1/releases/{kind}/rollouts", s.handleReleaseRolloutStart},
		{"POST", "/admin/v1/releases/{kind}/rollouts/current/abort", s.handleReleaseRolloutAbort},
		{"GET", "/admin/v1/joinkeys", s.handleJoinKeys},
		{"POST", "/admin/v1/joinkeys", s.handleJoinKeyCreate},
		{"PATCH", "/admin/v1/joinkeys/{name}", s.handleJoinKeyUpdate},
		{"POST", "/admin/v1/joinkeys/{name}/revoke", s.handleJoinKeyRevoke},
		// A0.5 enrollment approval queue.
		{"GET", "/admin/v1/enrollments", s.handleEnrollments},
		{"POST", "/admin/v1/enrollments/{id}/approve", s.handleEnrollApprove},
		{"POST", "/admin/v1/enrollments/{id}/deny", s.handleEnrollDeny},
		// IPAM netblocks (ADR 0010 Phase 3). The literal /netblocks/suggest is more
		// specific than /netblocks/{name}, so the 1.22 mux routes it first.
		{"GET", "/admin/v1/ipam/netblocks", s.handleNetblocks},
		{"POST", "/admin/v1/ipam/netblocks", s.handleNetblockCreate},
		{"GET", "/admin/v1/ipam/netblocks/suggest", s.handleNetblockSuggest},
		{"PATCH", "/admin/v1/ipam/netblocks/{name}", s.handleNetblockUpdate},
		{"DELETE", "/admin/v1/ipam/netblocks/{name}", s.handleNetblockRemove},
		{"GET", "/admin/v1/ipam/allocations", s.handleIPAMAllocations},
	}
}

// Routes returns "METHOD /path" for every admin endpoint — the contract test
// asserts this set equals the documented OpenAPI operations.
func (s *Server) Routes() []string {
	rt := s.routeTable()
	out := make([]string, len(rt))
	for i, r := range rt {
		out[i] = r.Method + " " + r.Path
	}
	return out
}

// Handler returns the routed, auth-wrapped admin API. Mesh-only: bind it to
// Core's overlay IP in production (never the public ENI). The OpenAPI document is
// served unauthenticated (it is the public contract, carries no fleet data).
func (s *Server) Handler() http.Handler {
	inner := http.NewServeMux()
	for _, r := range s.routeTable() {
		inner.HandleFunc(r.Method+" "+r.Path, r.h)
	}
	authed := s.authMiddleware(inner)

	top := http.NewServeMux()
	top.HandleFunc("GET /admin/v1/openapi.yaml", s.handleOpenAPI)
	top.Handle("/", authed)
	return top
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
	// Stale is true when the host has not heartbeated within Thresholds.StaleAfter — the
	// same definition the fleet dashboard and the `condition=stale` filter use. Health is
	// the host's LAST self-report, so a long-silent host would otherwise still read "ok";
	// Stale tells the UI that its reported health is no longer current.
	Stale                bool   `json:"stale,omitempty"`
	// Provenance — how the host joined, from its authoritative (latest issued)
	// enrollment. Cloud-attested hosts carry the attestation evidence; token-enrolled
	// hosts carry the join-key name. Groups are the groups the host was issued.
	AttestProvider  string   `json:"attest_provider,omitempty"`
	AttestAccount   string   `json:"attest_account,omitempty"`
	AttestPrincipal string   `json:"attest_principal,omitempty"`
	AttestRegion    string   `json:"attest_region,omitempty"`
	JoinKeyName     string   `json:"join_key_name,omitempty"`
	Groups          []string `json:"groups,omitempty"`
	// DesiredGroups / Pending / ReductionPendingEnforcement — post-enrollment group reassignment
	// (ADR 0002). DesiredGroups is the control-plane target set (equals Groups unless a change is
	// in flight). Pending is true while the host hasn't re-issued yet (groups_generation >
	// issued_generation), clearing on its next renew. ReductionPendingEnforcement marks a soft
	// group REMOVAL whose old, higher-privilege cert is still valid (advisory until revoked, Phase 3).
	DesiredGroups               []string `json:"desired_groups,omitempty"`
	Pending                     bool     `json:"pending,omitempty"`
	ReductionPendingEnforcement bool     `json:"reduction_pending_enforcement,omitempty"`
	// Ephemeral marks a host that joined via an ephemeral join key (shorter cert TTL;
	// foundation for the auto-reaping lifecycle, impl 2.12). From the authoritative enrollment.
	Ephemeral bool `json:"ephemeral,omitempty"`
	// ReapedAt / ReapReason expose the reaper soft-mark (impl 2.12) for completeness. The
	// reaper deletes a reaped host's heartbeat, so a reaped device normally drops out of
	// this heartbeat-driven list; these are populated only if a reaped device ever surfaces
	// (e.g. a future include-reaped view). From the devices table, keyed by name.
	ReapedAt   string `json:"reaped_at,omitempty"`
	ReapReason string `json:"reap_reason,omitempty"`
}

// GET /admin/v1/devices?limit=N&after=OVERLAY_IP — device inventory from
// heartbeats, keyset-paginated on overlay_ip (same cursor shape as /audit).
// `count` is the page size; `next_after` (when present) is the cursor for the
// next page — never assume `count` is the fleet total.
//
// Each row is enriched with provenance + issued groups from its authoritative
// (latest issued) enrollment. Optional filters narrow the list: scope filters
// (provider, attest_account, join_key) match how the host joined; the condition
// filter (expired|expiring|stale|clock_skewed|unhealthy) is the dashboard "why"
// drill-down, computed with the same thresholds/clock as /fleet/health so the
// count matches the verdict. Filters are applied in SQL before the limit, so the
// keyset cursor stays correct.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := queryInt(r, "limit", 200, 1, 2000)
	after := r.URL.Query().Get("after")
	provider := r.URL.Query().Get("provider")
	account := r.URL.Query().Get("attest_account")
	joinKey := r.URL.Query().Get("join_key")
	condition := r.URL.Query().Get("condition")
	namePattern := r.URL.Query().Get("name_pattern") // glob (*, ?) -> SQL LIKE, applied in SQL like `condition`
	scoped := provider != "" || account != "" || joinKey != ""

	var condSQL string
	var condArgs []any
	if condition != "" {
		ok := false
		// One s.now() for the whole request (the page is eventual-consistency anyway: a
		// later page request re-evaluates against a fresh clock — fine for a monitoring
		// list, and the keyset cursor guarantees no row is skipped or duplicated).
		if condSQL, condArgs, ok = fleet.ConditionSQL(condition, s.now(), s.cfg.Thresholds); !ok {
			writeProblem(w, http.StatusBadRequest, "bad condition",
				"condition must be one of: expired, expiring, stale, clock_skewed, unhealthy")
			return
		}
	}

	// Join-key id->name map, loaded at most once per request (for the join_key scope
	// filter and/or token-host provenance).
	var names map[int64]string
	ensureNames := func() error {
		if names == nil {
			m, err := s.joinKeyNameMap(ctx)
			if err != nil {
				return err
			}
			names = m
		}
		return nil
	}

	// Scope filter -> an allow-set of overlay IPs (the authoritative-enrollment match).
	var allow map[string]bool
	if scoped {
		if joinKey != "" {
			if err := ensureNames(); err != nil {
				s.fail(w, r, "join key lookup failed", err)
				return
			}
		}
		a, err := s.overlayIPsForScope(ctx, provider, account, joinKey, names)
		if err != nil {
			s.fail(w, r, "scope filter failed", err)
			return
		}
		if len(a) == 0 { // nothing matches the scope — short-circuit.
			writeJSON(w, http.StatusOK, map[string]any{"devices": []Device{}, "count": 0})
			return
		}
		allow = a
	}

	// Keyset-walk heartbeats in overlay_ip order, applying the condition predicate in
	// SQL and the scope allow-set in Go, until we have a page. Filtering scope in Go
	// (rather than a giant `overlay_ip IN (...)`) keeps each query's bind-parameter
	// count bounded by `limit` regardless of fleet size.
	var kept []deviceHB
	hitLimit := false
	cursor := after
	for {
		q := s.cfg.Store.DB.WithContext(ctx).Order("overlay_ip ASC").Limit(limit)
		if cursor != "" {
			q = q.Where("overlay_ip > ?", cursor)
		}
		if condSQL != "" {
			q = q.Where(condSQL, condArgs...)
		}
		if namePattern != "" {
			q = q.Where("device_name LIKE ? ESCAPE '\\'", globToLike(namePattern))
		}
		var rows []deviceHB
		if err := q.Find(&rows).Error; err != nil {
			s.fail(w, r, "list devices failed", err)
			return
		}
		if len(rows) == 0 {
			break
		}
		cursor = rows[len(rows)-1].OverlayIP
		for _, h := range rows {
			if scoped && !allow[h.OverlayIP] {
				continue
			}
			kept = append(kept, h)
			if len(kept) == limit {
				hitLimit = true
				break
			}
		}
		if hitLimit || len(rows) < limit {
			break
		}
	}

	prov, err := s.deviceProvenance(ctx, overlayIPs(kept))
	if err != nil {
		s.fail(w, r, "device provenance failed", err)
		return
	}
	for _, p := range prov {
		if p.JoinKeyID != 0 {
			if err := ensureNames(); err != nil {
				s.fail(w, r, "join key lookup failed", err)
				return
			}
			break
		}
	}

	// Reaper soft-marks (impl 2.12), keyed by device name. A reaped host's heartbeat is
	// deleted, so a reaped device rarely appears in this list — this enriches the field
	// for completeness / a future include-reaped view.
	reapMarks, err := s.deviceReapMarks(ctx, deviceNames(kept))
	if err != nil {
		s.fail(w, r, "device reap-mark lookup failed", err)
		return
	}

	// Stale per row, computed identically to fleet.ConditionSQL("stale") so the Devices
	// list, the dashboard count, and a `condition=stale` filter all agree.
	nowNs := s.now().UnixNano()
	staleNs := s.cfg.Thresholds.StaleAfter.Nanoseconds()
	out := make([]Device, len(kept))
	for i, h := range kept {
		d := Device{
			OverlayIP: h.OverlayIP, Name: h.DeviceName,
			PilotVersion: h.PilotVersion, NebulaVersion: h.NebulaVersion,
			CertNotAfter: rfc3339(h.CertNotAfter), AppliedBundleVersion: h.AppliedBundleVersion,
			ClockOffsetMs: h.ClockOffsetMs, Health: h.Health, LastSeen: rfc3339(h.LastSeen),
			Stale: staleNs > 0 && h.LastSeen < nowNs-staleNs,
		}
		if p, ok := prov[h.OverlayIP]; ok {
			d.Groups = p.Groups
			d.Ephemeral = p.Ephemeral
			d.DesiredGroups = p.DesiredGroups
			d.Pending = p.Pending
			d.ReductionPendingEnforcement = p.ReductionPendingEnforcement
			switch {
			case p.AttestProvider != "":
				d.AttestProvider, d.AttestAccount = p.AttestProvider, p.AttestAccount
				d.AttestPrincipal, d.AttestRegion = p.AttestPrincipal, p.AttestRegion
			case p.JoinKeyID != 0:
				d.JoinKeyName = names[p.JoinKeyID]
			}
		}
		if rm, ok := reapMarks[h.DeviceName]; ok {
			d.ReapedAt = rfc3339(rm.ReapedAt)
			d.ReapReason = rm.ReapReason
		}
		out[i] = d
	}

	resp := map[string]any{"devices": out, "count": len(out)}
	if hitLimit { // a full page — there may be more beyond the last kept row.
		resp["next_after"] = out[len(out)-1].OverlayIP
	}
	writeJSON(w, http.StatusOK, resp)
}

func overlayIPs(rows []deviceHB) []string {
	ips := make([]string, len(rows))
	for i, h := range rows {
		ips[i] = h.OverlayIP
	}
	return ips
}

func deviceNames(rows []deviceHB) []string {
	names := make([]string, len(rows))
	for i, h := range rows {
		names[i] = h.DeviceName
	}
	return names
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

// ── dual-control approvals + policy publish ─────────────────────────────────

// Change is the API view of a dual-control change.
type Change struct {
	ID         int64  `json:"id"`
	Kind       string `json:"kind"`
	Target     string `json:"target,omitempty"`
	State      string `json:"state"`
	Quorum     int    `json:"quorum"`
	Proposer   string `json:"proposer"`
	PayloadSHA string `json:"payload_sha256"`
	CreatedAt  string `json:"created_at"`
	DecidedAt  string `json:"decided_at,omitempty"`
	Payload    string `json:"payload,omitempty"` // included on detail, not in lists
}

// Signoff is the API view of one vote.
type Signoff struct {
	Actor     string `json:"actor"`
	Decision  string `json:"decision"`
	CreatedAt string `json:"created_at"`
}

func changeView(ch dualcontrol.Change, withPayload bool) Change {
	cv := Change{
		ID: ch.ID, Kind: ch.Kind, Target: ch.Target, State: ch.State, Quorum: ch.Quorum,
		Proposer: ch.Proposer, PayloadSHA: hex.EncodeToString(ch.PayloadHash),
		CreatedAt: rfc3339(ch.CreatedAt), DecidedAt: rfc3339(ch.DecidedAt),
	}
	if withPayload {
		cv.Payload = string(ch.Payload)
	}
	return cv
}

// GET /admin/v1/approvals?state=pending — the dual-control inbox (all kinds).
func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	changes, err := s.dc.List(r.Context(), dualcontrol.State(r.URL.Query().Get("state")))
	if err != nil {
		s.fail(w, r, "list approvals failed", err)
		return
	}
	out := make([]Change, len(changes))
	for i, c := range changes {
		out[i] = changeView(c, false)
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": out, "count": len(out)})
}

// GET /admin/v1/approvals/{id} — a change + its sign-offs (payload included).
func (s *Server) handleApproval(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ch, sigs, err := s.dc.Get(r.Context(), id)
	if err != nil {
		s.mapDCErr(w, r, err)
		return
	}
	out := make([]Signoff, len(sigs))
	for i, sg := range sigs {
		out[i] = Signoff{Actor: sg.Actor, Decision: sg.Decision, CreatedAt: rfc3339(sg.CreatedAt)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"change": changeView(ch, true), "signoffs": out})
}

// POST /admin/v1/approvals/{id}/approve — approve as the authenticated principal
// (never a body field). The dual-control engine enforces distinct-approver.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermApprovalDecide) {
		return
	}
	if !s.requireStepUp(w, id) { // approving grants authority → require fresh MFA
		return
	}
	cid, ok := pathID(w, r)
	if !ok {
		return
	}
	ch, err := s.dc.Approve(r.Context(), cid, id.Principal)
	if err != nil {
		s.mapDCErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, changeView(ch, true))
}

// POST /admin/v1/approvals/{id}/deny — a single deny vetoes (fail-closed).
func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermApprovalDecide) {
		return
	}
	cid, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ch, err := s.dc.Deny(r.Context(), cid, id.Principal, body.Reason)
	if err != nil {
		s.mapDCErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, changeView(ch, true))
}

// configKinds maps the {kind} path segment to the dual-control change kind, the
// :manage permission gating it, and the inline validate+marshal+privileged-detect
// logic the PUT runs. This is the single table the declarative API dispatches on.
type configKind struct {
	publishKind string
	perm        Permission
	// prepare validates the request body INLINE (ADR 0011 P1.1 — the load-bearing
	// carry-over: every validator that used to fire from the dualcontrol commit path
	// now fires here on EVERY write), returns the canonical payload bytes, and reports
	// whether the resulting config is PRIVILEGED (P1.2). A non-nil error is the 400.
	prepare func(body []byte) (payload []byte, privileged bool, err error)
}

func (s *Server) configKinds() map[string]configKind {
	return map[string]configKind{
		"policy": {
			publishKind: policy.PublishKind,
			perm:        PermPolicyManage,
			prepare: func(body []byte) ([]byte, bool, error) {
				// The policy body is the firewall-policy DSL carried as a JSON string
				// (the OpenAPI ConfigBody contract). Unwrap the JSON string to the raw
				// DSL; a body that is not a JSON string is treated as raw DSL directly so
				// CLI/curl callers can PUT a bare policy file too.
				dsl := string(body)
				var asString string
				if json.Unmarshal(body, &asString) == nil {
					dsl = asString
				}
				p, err := policy.Parse(dsl) // Parse runs Validate
				if err != nil {
					return nil, false, err
				}
				if err := policy.CheckInvariants(p); err != nil {
					return nil, false, err
				}
				// Store the canonical DSL bytes (the reader re-parses them).
				// ContainsReservedRef is always false here (a valid policy can't reference
				// a reserved group — CheckInvariants rejected it), so policy never routes
				// two-person; kept for the uniform rule.
				return []byte(dsl), policy.ContainsReservedRef(p), nil
			},
		},
		"cloudtrust": {
			publishKind: cloudtrust.PublishKind,
			perm:        PermCloudTrustManage,
			prepare: func(body []byte) ([]byte, bool, error) {
				cfg, err := cloudtrust.Parse(body) // Parse runs Validate
				if err != nil {
					return nil, false, err
				}
				payload, merr := json.Marshal(cfg) // store the canonical, validated form
				if merr != nil {
					return nil, false, merr
				}
				return payload, cloudtrust.ContainsPrivileged(cfg), nil
			},
		},
		"usertrust": {
			publishKind: usertrust.PublishKind,
			perm:        PermUserTrustManage,
			prepare: func(body []byte) ([]byte, bool, error) {
				// Parse runs Validate, which includes ErrAutoIssuePrivileged (S8): the
				// auto_issue+reserved combo 400s HERE and never reaches the privileged route.
				cfg, err := usertrust.Parse(body)
				if err != nil {
					return nil, false, err
				}
				payload, merr := json.Marshal(cfg)
				if merr != nil {
					return nil, false, merr
				}
				return payload, usertrust.ContainsPrivileged(cfg), nil
			},
		},
	}
}

// PUT /admin/v1/config/{kind} — the ADR-0011 Phase-1 declarative set primitive.
// kind ∈ policy|cloudtrust|usertrust. Gated on the per-kind :manage permission +
// step-up MFA (human console writes keep their MFA gate, C9). The body is the ENTIRE
// config for that kind. The handler validates INLINE (the load-bearing carry-over —
// every commit-time validator now fires here, P1.1), then ROUTES:
//   - PRIVILEGED resulting config (P1.2): does NOT write the store directly; opens a
//     dual-control change (distinct second approver via /approvals/{id}/approve) and
//     returns 202 + the Change. The registered committer writes the store on commit.
//   - non-privileged: writes the store directly (single operator) and returns 200.
func (s *Server) handleConfigSet(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	kindName := r.PathValue("kind")
	ck, ok := s.configKinds()[kindName]
	if !ok {
		writeProblem(w, http.StatusNotFound, "unknown config kind", "kind must be one of: policy, cloudtrust, usertrust")
		return
	}
	if !s.requirePerm(w, id, ck.perm) {
		return
	}
	if !s.requireStepUp(w, id) { // human console writes keep MFA (C9)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "bad request", "could not read body")
		return
	}
	if len(body) == 0 {
		writeProblem(w, http.StatusBadRequest, "config required", "the request body is empty")
		return
	}
	payload, privileged, perr := ck.prepare(body)
	if perr != nil {
		// THE load-bearing 400: ErrAutoIssuePrivileged, policy invariant violations,
		// cloudtrust/usertrust structural errors etc. all surface here with their exact text.
		writeProblem(w, http.StatusBadRequest, "invalid config", perr.Error())
		return
	}
	if privileged {
		// Route the privileged change through a distinct-second-approver dual-control
		// commit (P1.2). The PUT proposer is the first sign-off; a different operator
		// commits it via /approvals/{id}/approve, and the committer writes the store.
		ch, derr := s.dc.Propose(r.Context(), ck.publishKind,
			fmt.Sprintf("%s config (privileged — needs a distinct second approver)", kindName), payload, id.Principal)
		if derr != nil {
			s.fail(w, r, "propose privileged config failed", derr)
			return
		}
		writeJSON(w, http.StatusAccepted, changeView(ch, true))
		return
	}
	// Non-privileged: single-operator write straight to the store.
	row, serr := s.configStore.Set(r.Context(), ck.publishKind, payload, id.Principal)
	if serr != nil {
		s.fail(w, r, "write config failed", serr)
		return
	}
	writeJSON(w, http.StatusOK, configRowView(kindName, row))
}

// GET /admin/v1/config/{kind} — reads the config store (ADR 0011 Phase 1). Returns
// {set:false} when no config of that kind has been written yet.
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	kindName := r.PathValue("kind")
	ck, ok := s.configKinds()[kindName]
	if !ok {
		writeProblem(w, http.StatusNotFound, "unknown config kind", "kind must be one of: policy, cloudtrust, usertrust")
		return
	}
	row, err := s.configStore.Get(r.Context(), ck.publishKind)
	if err != nil {
		s.fail(w, r, "read config failed", err)
		return
	}
	if row == nil {
		writeJSON(w, http.StatusOK, map[string]any{"kind": kindName, "set": false})
		return
	}
	writeJSON(w, http.StatusOK, configRowView(kindName, row))
}

// configRowView is the API view of a stored config row.
func configRowView(kindName string, row *config.Row) map[string]any {
	return map[string]any{
		"kind":       kindName,
		"set":        true,
		"version":    row.Version,
		"payload":    string(row.Payload),
		"updated_at": rfc3339(row.UpdatedAt),
		"updated_by": row.UpdatedBy,
	}
}

// GET /admin/v1/policy/active — the active fleet policy (ADR 0011 Phase 1: read from
// the config store, the single source of truth). {published:false} when none is set.
func (s *Server) handlePolicyActive(w http.ResponseWriter, r *http.Request) {
	row, err := s.configStore.Get(r.Context(), policy.PublishKind)
	if err != nil {
		s.fail(w, r, "read active policy failed", err)
		return
	}
	if row == nil {
		writeJSON(w, http.StatusOK, map[string]any{"published": false})
		return
	}
	p, perr := policy.Parse(string(row.Payload))
	if perr != nil {
		s.fail(w, r, "active policy is unparseable", perr)
		return
	}
	rules := p.Rules
	if rules == nil {
		rules = []policy.Rule{} // contract: rules is always a JSON array
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"published": true, "version": row.Version, "hash": hex.EncodeToString(payloadHash(row.Payload)),
		"text": string(row.Payload), "rules": rules,
	})
}

// GET /admin/v1/cloudtrust/active — the active cloud-attestation trust config (ADR
// 0011 Phase 1: read from the config store). {published:false} when none is set.
func (s *Server) handleCloudTrustActive(w http.ResponseWriter, r *http.Request) {
	row, err := s.configStore.Get(r.Context(), cloudtrust.PublishKind)
	if err != nil {
		s.fail(w, r, "read active cloud-trust failed", err)
		return
	}
	if row == nil {
		writeJSON(w, http.StatusOK, map[string]any{"published": false})
		return
	}
	cfg, perr := cloudtrust.Parse(row.Payload)
	if perr != nil {
		s.fail(w, r, "active cloud-trust is unparseable", perr)
		return
	}
	dg := cfg.DefaultGroups
	if dg == nil {
		dg = []string{} // contract: always a JSON array
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"published": true, "version": row.Version, "hash": hex.EncodeToString(payloadHash(row.Payload)),
		"default_groups": dg, "aws": cfg.AWS,
	})
}

// GET /admin/v1/usertrust/active — the active SSO user-trust config (ADR 0004; ADR
// 0011 Phase 1: read from the config store, the seam SSO issuance reads).
// {published:false} when none is set.
func (s *Server) handleUserTrustActive(w http.ResponseWriter, r *http.Request) {
	row, err := s.configStore.Get(r.Context(), usertrust.PublishKind)
	if err != nil {
		s.fail(w, r, "read active user-trust failed", err)
		return
	}
	if row == nil {
		writeJSON(w, http.StatusOK, map[string]any{"published": false})
		return
	}
	cfg, perr := usertrust.Parse(row.Payload)
	if perr != nil {
		s.fail(w, r, "active user-trust is unparseable", perr)
		return
	}
	dg := cfg.DefaultGroups
	if dg == nil {
		dg = []string{} // contract: always a JSON array
	}
	entries := cfg.IDPEntries
	if entries == nil {
		entries = []usertrust.IDPEntry{} // contract: always a JSON array
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"published": true, "version": row.Version, "hash": hex.EncodeToString(payloadHash(row.Payload)),
		"default_groups": dg, "idp_entries": entries,
	})
}

// CompileResult is the analysis-rail response: validity, invariants, and the
// per-host compiled firewall — the server is the single source of "is it safe?".
type CompileResult struct {
	Valid        bool   `json:"valid"`
	Error        string `json:"error,omitempty"`
	InvariantsOK bool   `json:"invariants_ok"`
	Compiled     *struct {
		Inbound  []nebulaRule `json:"inbound"`
		Outbound []nebulaRule `json:"outbound"`
	} `json:"compiled,omitempty"`
}

type nebulaRule struct {
	Proto string `json:"proto"`
	Port  string `json:"port"`
	Host  string `json:"host,omitempty"`
	Group string `json:"group,omitempty"`
}

// POST /admin/v1/policy/compile — dry-run compile a draft for a host's groups
// (the designer's live analysis). Read-only (no mutation), so any authenticated
// admin may preview — not role-gated like the mutating endpoints. Returns 200 with
// a structured result even on a parse error (a live-lint surface), so the editor
// can render squiggles.
func (s *Server) handlePolicyCompile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Policy string   `json:"policy"`
		Groups []string `json:"groups"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	p, err := policy.Parse(body.Policy)
	if err != nil {
		writeJSON(w, http.StatusOK, CompileResult{Valid: false, Error: err.Error()})
		return
	}
	res := CompileResult{Valid: true, InvariantsOK: policy.CheckInvariants(p) == nil}
	c := policy.CompileHost(p, body.Groups)
	res.Compiled = &struct {
		Inbound  []nebulaRule `json:"inbound"`
		Outbound []nebulaRule `json:"outbound"`
	}{Inbound: toRules(c.Inbound), Outbound: toRules(c.Outbound)}
	writeJSON(w, http.StatusOK, res)
}

// POST /admin/v1/policy/reachability — read-only analysis (A1): does `from` reach `to`
// on proto/port under the draft policy + non-removable baseline? Returns the granting
// rule, or default-deny with the nearest miss. No perm/step-up (a dry-run, like compile).
func (s *Server) handlePolicyReachability(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Policy string `json:"policy"`
		From   string `json:"from"`
		To     string `json:"to"`
		Proto  string `json:"proto"`
		Port   string `json:"port"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	p, err := policy.Parse(body.Policy)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid policy", err.Error())
		return
	}
	from := strings.TrimPrefix(body.From, "group:")
	to := strings.TrimPrefix(body.To, "group:")
	if from == "" || to == "" {
		writeProblem(w, http.StatusBadRequest, "bad query", "from and to are required")
		return
	}
	proto := body.Proto
	if proto == "" {
		proto = "any"
	}
	port := body.Port
	if port == "" {
		port = "any"
	}
	if err := policy.ValidateQuery(proto, port); err != nil {
		writeProblem(w, http.StatusBadRequest, "bad query", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, policy.Reachable(p, from, to, proto, port))
}

// POST /admin/v1/policy/matrix — read-only analysis (A1): the all-pairs group x group
// reachability grid (policy-permitted flows; baseline flagged per cell).
func (s *Server) handlePolicyMatrix(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Policy string   `json:"policy"`
		Groups []string `json:"groups"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	// The matrix is O(groups^2 * rules); bound the caller-supplied set so an oversized
	// `groups` array can't pin a worker / blow up memory (the default path derives groups
	// from the policy and is bounded by the rule count).
	const maxMatrixGroups = 256
	if len(body.Groups) > maxMatrixGroups {
		writeProblem(w, http.StatusBadRequest, "too many groups", fmt.Sprintf("matrix supports at most %d groups", maxMatrixGroups))
		return
	}
	p, err := policy.Parse(body.Policy)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid policy", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, policy.Matrix(p, body.Groups))
}

// POST /admin/v1/policy/tests — read-only analysis (A1): evaluate reachability assertions
// against the policy (the test-authoring loop that gates publish).
func (s *Server) handlePolicyTests(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Policy string `json:"policy"`
		Tests  string `json:"tests"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	p, err := policy.Parse(body.Policy)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid policy", err.Error())
		return
	}
	asserts, terr := policy.ParseTests(body.Tests)
	if terr != nil {
		writeProblem(w, http.StatusBadRequest, "invalid tests", terr.Error())
		return
	}
	results := policy.RunTests(p, asserts)
	passed := 0
	for _, res := range results {
		if res.Pass {
			passed++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results": results, "passed": passed, "failed": len(results) - passed, "ok": passed == len(results),
	})
}

// POST /admin/v1/policy/diff — read-only analysis (A1.2): the user-rule flow delta
// between the active published policy and a draft, plus the blast radius (the real
// hosts whose compiled firewall changes). Dry-run; ungated like the other analysis
// endpoints (it is authenticated, like all of /admin/v1, but carries no perm/step-up).
func (s *Server) handlePolicyDiff(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Policy string `json:"policy"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	draft, err := policy.Parse(body.Policy)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid policy", err.Error())
		return
	}
	// Bound the draft: FlowDiff is O(distinct group-pairs) and the handler also scans the
	// fleet, so an enormous caller-supplied draft must not pin a worker (mirrors the matrix
	// group cap). The active policy is our own bounded committed state.
	const maxDraftRules = 4096
	if len(draft.Rules) > maxDraftRules {
		writeProblem(w, http.StatusBadRequest, "policy too large", fmt.Sprintf("diff supports at most %d rules", maxDraftRules))
		return
	}
	// A draft that violates the publish invariants (e.g. references a reserved group) can
	// be previewed, but it can never be committed — surface that as a non-fatal warning so
	// the preview is honest (the propose path hard-rejects it).
	warning := ""
	if cerr := policy.CheckInvariants(draft); cerr != nil {
		warning = cerr.Error()
	}
	// Active side = the config store (ADR 0011 Phase 1, the single source of truth).
	// Absent => empty policy (everything in the draft is "added"). A stored policy that
	// fails to parse is a 500, not a 400: the draft is the caller's input, the active
	// policy is our own stored state.
	active := policy.Policy{}
	activeInfo := map[string]any{"published": false}
	if row, lerr := s.configStore.Get(r.Context(), policy.PublishKind); lerr != nil {
		s.fail(w, r, "read active policy failed", lerr)
		return
	} else if row != nil {
		if active, err = policy.Parse(string(row.Payload)); err != nil {
			s.fail(w, r, "active policy is unparseable", err)
			return
		}
		activeInfo = map[string]any{"published": true, "version": row.Version, "hash": hex.EncodeToString(payloadHash(row.Payload))}
	}

	diff := policy.FlowDiff(active, draft)

	groupHosts, allHosts, gerr := s.fleetGroupMap(r.Context())
	if gerr != nil {
		s.fail(w, r, "fleet group map failed", gerr)
		return
	}
	blast := policy.BlastRadius(diff, groupHosts, allHosts)
	// Cap the host list in the response; `count` stays the true blast radius.
	const maxBlastHosts = 200
	hosts, truncated := blast.Hosts, false
	if len(hosts) > maxBlastHosts {
		hosts, truncated = hosts[:maxBlastHosts], true
	}
	resp := map[string]any{
		"active":  activeInfo,
		"added":   diff.Added,
		"removed": diff.Removed,
		"blast":   map[string]any{"count": blast.Count, "total": blast.Total, "hosts": hosts, "truncated": truncated},
	}
	if warning != "" {
		resp["warning"] = warning
	}
	writeJSON(w, http.StatusOK, resp)
}

func toRules(in []nebulaconfig.Rule) []nebulaRule {
	out := make([]nebulaRule, len(in))
	for i, r := range in {
		out[i] = nebulaRule{Proto: r.Proto, Port: r.Port, Host: r.Host, Group: r.Group}
	}
	return out
}

// mapDCErr maps dual-control sentinels to HTTP; unknown errors are 500 (logged).
func (s *Server) mapDCErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, dualcontrol.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "not found", "no such change")
	case errors.Is(err, dualcontrol.ErrSelfApproval):
		writeProblem(w, http.StatusConflict, "self-approval not allowed", "the proposer cannot approve their own change")
	case errors.Is(err, dualcontrol.ErrDuplicateActor):
		writeProblem(w, http.StatusConflict, "already signed", "this actor has already signed off")
	case errors.Is(err, dualcontrol.ErrNotPending):
		writeProblem(w, http.StatusConflict, "not pending", "the change is no longer pending")
	case errors.Is(err, dualcontrol.ErrCommit):
		// Quorum was reached but the effect was rejected at commit (business
		// failure) — the change is marked failed. Not an infra 500.
		writeProblem(w, http.StatusUnprocessableEntity, "change rejected at commit", "the approved change failed validation at commit and was not applied")
	default:
		s.fail(w, r, "dual-control operation failed", err)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// pathID parses the {id} path wildcard; writes a 400 and returns false if bad.
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeProblem(w, http.StatusBadRequest, "bad id", "id must be a positive integer")
		return 0, false
	}
	return id, true
}

// readJSON decodes a (size-limited) JSON body. An empty body is allowed (the
// target keeps its zero value) so optional-body endpoints work; malformed JSON or
// trailing data after the value is a 400.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	switch err := dec.Decode(v); {
	case errors.Is(err, io.EOF): // empty body → leave v as zero
		return true
	case err != nil:
		writeProblem(w, http.StatusBadRequest, "bad request", "invalid JSON body")
		return false
	}
	if dec.More() {
		writeProblem(w, http.StatusBadRequest, "bad request", "unexpected trailing data after JSON body")
		return false
	}
	return true
}

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

// payloadHash is the content hash surfaced by the /active reads. The config store
// (Phase 1) does not persist a hash column (deferred to Phase 2), so it is computed
// from the stored payload — matching how dualcontrol hashes a change payload.
func payloadHash(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return sum[:]
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
