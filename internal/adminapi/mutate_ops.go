package adminapi

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"gorm.io/gorm"
)

// This file holds the A0.4 fleet-management mutations: lighthouse registry,
// staged rollouts, and join keys. All are pure-DB (reuse the existing engines),
// bind to the authenticated principal for audit, and require the admin role.

// ── lighthouses ─────────────────────────────────────────────────────────────

func lighthouseView(r lighthouse.Row) Lighthouse {
	return Lighthouse{OverlayIP: r.OverlayIP, Hostname: r.Hostname, State: r.State, PublicAddrs: r.Addrs()}
}

func (s *Server) mapLighthouseErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, lighthouse.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "not found", "no such lighthouse")
	case errors.Is(err, lighthouse.ErrAlreadyExists):
		writeProblem(w, http.StatusConflict, "already exists", "a lighthouse with that overlay IP already exists")
	case errors.Is(err, lighthouse.ErrLastActive):
		writeProblem(w, http.StatusConflict, "last lighthouse", "refusing to remove the last active lighthouse (discovery would be lost)")
	case errors.Is(err, lighthouse.ErrNoAddrs), errors.Is(err, lighthouse.ErrNoOverlayIP):
		writeProblem(w, http.StatusBadRequest, "invalid lighthouse", err.Error())
	default:
		s.fail(w, r, "lighthouse operation failed", err)
	}
}

// POST /admin/v1/lighthouses — register a lighthouse.
func (s *Server) handleLighthouseAdd(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermLighthouseManage) {
		return
	}
	var b struct {
		OverlayIP   string   `json:"overlay_ip"`
		Hostname    string   `json:"hostname"`
		PublicAddrs []string `json:"public_addrs"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	row, err := s.cfg.Lighthouses.Add(r.Context(), b.OverlayIP, b.Hostname, b.PublicAddrs, id.Principal)
	if err != nil {
		s.mapLighthouseErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, lighthouseView(row))
}

// PUT /admin/v1/lighthouses/{ip} — re-address (and re-activate) a lighthouse.
func (s *Server) handleLighthouseReplace(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermLighthouseManage) {
		return
	}
	var b struct {
		PublicAddrs []string `json:"public_addrs"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	row, err := s.cfg.Lighthouses.Replace(r.Context(), r.PathValue("ip"), b.PublicAddrs, id.Principal)
	if err != nil {
		s.mapLighthouseErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, lighthouseView(row))
}

// DELETE /admin/v1/lighthouses/{ip} — retire a lighthouse (never the last active).
func (s *Server) handleLighthouseRemove(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermLighthouseManage) {
		return
	}
	ip := r.PathValue("ip")
	if err := s.cfg.Lighthouses.Remove(r.Context(), ip, id.Principal); err != nil {
		s.mapLighthouseErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"overlay_ip": ip, "removed": true})
}

// ── rollouts ────────────────────────────────────────────────────────────────

// RolloutView is the API view of a rollout.
type RolloutView struct {
	ID            int64  `json:"id"`
	Description   string `json:"description,omitempty"`
	TargetVersion int    `json:"target_version"`
	PrevVersion   int    `json:"prev_version"`
	State         string `json:"state"`
	ActiveWave    int    `json:"active_wave"`
	WaveSize      int    `json:"wave_size"`
	MinHealthy    int    `json:"min_healthy"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at,omitempty"`
	Note          string `json:"note,omitempty"`
}

// RolloutHostView is a host's wave assignment + status.
type RolloutHostView struct {
	OverlayIP string `json:"overlay_ip"`
	Wave      int    `json:"wave"`
	Status    string `json:"status"`
}

func rolloutView(r rollout.Rollout) RolloutView {
	return RolloutView{
		ID: r.ID, Description: r.Description, TargetVersion: r.TargetVersion, PrevVersion: r.PrevVersion,
		State: r.State, ActiveWave: r.ActiveWave, WaveSize: r.WaveSize, MinHealthy: r.MinHealthy,
		CreatedAt: rfc3339(r.CreatedAt), UpdatedAt: rfc3339(r.UpdatedAt), Note: r.Note,
	}
}

func rolloutStatus(r rollout.Rollout, hosts []rollout.Host) map[string]any {
	hv := make([]RolloutHostView, len(hosts))
	for i, h := range hosts {
		hv[i] = RolloutHostView{OverlayIP: h.OverlayIP, Wave: h.Wave, Status: h.Status}
	}
	// active reflects the actual lifecycle — a completed/rolledback rollout is the
	// "current" one (latest) but NOT in flight. Still return it so the UI sees the
	// final state.
	active := r.State == rollout.StateCanary || r.State == rollout.StateWidening
	return map[string]any{"active": active, "rollout": rolloutView(r), "hosts": hv}
}

func (s *Server) mapRolloutErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, rollout.ErrNoHosts):
		writeProblem(w, http.StatusBadRequest, "no hosts", "at least one host is required")
	case errors.Is(err, rollout.ErrActiveExists):
		writeProblem(w, http.StatusConflict, "rollout active", "a rollout is already active; finish or abort it first")
	case errors.Is(err, rollout.ErrNotActive):
		writeProblem(w, http.StatusConflict, "no active rollout", "there is no active rollout")
	default:
		s.fail(w, r, "rollout operation failed", err)
	}
}

// GET /admin/v1/rollouts/current — the current rollout + per-host wave status.
func (s *Server) handleRolloutCurrent(w http.ResponseWriter, r *http.Request) {
	rr, hosts, err := s.cfg.Rollout.Status(r.Context())
	if errors.Is(err, rollout.ErrNone) {
		writeJSON(w, http.StatusOK, map[string]any{"active": false, "hosts": []RolloutHostView{}})
		return
	}
	if err != nil {
		s.fail(w, r, "rollout status failed", err)
		return
	}
	writeJSON(w, http.StatusOK, rolloutStatus(rr, hosts))
}

// POST /admin/v1/rollouts — start a staged rollout.
func (s *Server) handleRolloutStart(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermRolloutControl) {
		return
	}
	var b struct {
		TargetVersion       int      `json:"target_version"`
		PrevVersion         int      `json:"prev_version"`
		Hosts               []string `json:"hosts"`
		CanarySize          int      `json:"canary_size"`
		WaveSize            int      `json:"wave_size"`
		MinHealthy          int      `json:"min_healthy"`
		ObserveSeconds      int      `json:"observe_seconds"`
		MissingAfterSeconds int      `json:"missing_after_seconds"`
		Description         string   `json:"description"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if b.TargetVersion == 0 {
		writeProblem(w, http.StatusBadRequest, "bad request", "target_version is required")
		return
	}
	observe := time.Duration(b.ObserveSeconds) * time.Second
	if observe == 0 {
		observe = 10 * time.Minute
	}
	missing := time.Duration(b.MissingAfterSeconds) * time.Second
	if missing == 0 {
		missing = 3 * time.Minute
	}
	rr, err := s.cfg.Rollout.Start(r.Context(), rollout.StartConfig{
		Description: b.Description, TargetVersion: b.TargetVersion, PrevVersion: b.PrevVersion, Hosts: b.Hosts,
		CanarySize: b.CanarySize, WaveSize: b.WaveSize, MinHealthy: b.MinHealthy,
		Observe: observe, MissingAfter: missing, Actor: id.Principal,
	})
	if err != nil {
		s.mapRolloutErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, rolloutView(rr))
}

// POST /admin/v1/rollouts/current/step — force one evaluation (cron/ops).
func (s *Server) handleRolloutStep(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermRolloutControl) {
		return
	}
	changed, err := s.cfg.Rollout.Evaluate(r.Context())
	if err != nil {
		s.fail(w, r, "rollout step failed", err)
		return
	}
	// Attribute the manual trigger to the caller (the engine's own transitions are
	// audited as "system").
	_, _ = s.cfg.Store.AppendAudit(r.Context(), id.Principal, "rollout-step", "rollout", fmt.Sprintf("manual step, changed=%v", changed))
	rr, hosts, serr := s.cfg.Rollout.Status(r.Context())
	if errors.Is(serr, rollout.ErrNone) {
		writeJSON(w, http.StatusOK, map[string]any{"changed": changed, "status": map[string]any{"active": false, "hosts": []RolloutHostView{}}})
		return
	}
	if serr != nil {
		s.fail(w, r, "rollout status failed", serr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changed": changed, "status": rolloutStatus(rr, hosts)})
}

// POST /admin/v1/rollouts/current/abort — cancel the active rollout.
func (s *Server) handleRolloutAbort(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermRolloutControl) {
		return
	}
	if err := s.cfg.Rollout.Abort(r.Context(), id.Principal); err != nil {
		s.mapRolloutErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aborted": true})
}

// ── join keys ───────────────────────────────────────────────────────────────

// JoinKeyView is the API view (never includes the secret — only its hash is stored).
type JoinKeyView struct {
	Name         string   `json:"name"`
	Groups       []string `json:"groups"`
	SubRange     string   `json:"sub_range,omitempty"`
	MaxUses      int      `json:"max_uses"`
	UsedCount    int      `json:"used_count"`
	AutoIssue    bool     `json:"auto_issue"`
	Ephemeral    bool     `json:"ephemeral"`
	QuotaPerHour int      `json:"quota_per_hour"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	State        string   `json:"state"`
	CreatedAt    string   `json:"created_at"`
}

func joinKeyView(k joinkey.JoinKey) JoinKeyView {
	g := k.GroupList()
	if g == nil {
		g = []string{}
	}
	return JoinKeyView{
		Name: k.Name, Groups: g, SubRange: k.SubRange, MaxUses: k.MaxUses, UsedCount: k.UsedCount,
		AutoIssue: k.AutoIssue, Ephemeral: k.Ephemeral, QuotaPerHour: k.QuotaPerHour,
		ExpiresAt: rfc3339(k.ExpiresAt), State: k.State, CreatedAt: rfc3339(k.CreatedAt),
	}
}

// GET /admin/v1/joinkeys — list keys (no secrets).
func (s *Server) handleJoinKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := joinkey.List(r.Context(), s.cfg.Store)
	if err != nil {
		s.fail(w, r, "list join keys failed", err)
		return
	}
	out := make([]JoinKeyView, len(keys))
	for i, k := range keys {
		out[i] = joinKeyView(k)
	}
	writeJSON(w, http.StatusOK, map[string]any{"joinkeys": out, "count": len(out)})
}

// POST /admin/v1/joinkeys — create a key; the secret is returned ONCE.
func (s *Server) handleJoinKeyCreate(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermJoinKeyManage) {
		return
	}
	var b struct {
		Name         string   `json:"name"`
		Groups       []string `json:"groups"`
		SubRange     string   `json:"sub_range"`
		MaxUses      int      `json:"max_uses"`
		TTLSeconds   int      `json:"ttl_seconds"`
		AutoIssue    bool     `json:"auto_issue"`
		Ephemeral    bool     `json:"ephemeral"`
		QuotaPerHour int      `json:"quota_per_hour"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if b.Name == "" {
		writeProblem(w, http.StatusBadRequest, "name required", "the 'name' field is empty")
		return
	}
	// A join key may not grant a reserved group (control-plane/lighthouse): those
	// identities bypass the fleet firewall and are revocation-immune, so they are minted
	// only by genesis / lighthouse-mint — never self-service via enrollment. Early 400
	// here (the enrollment issue() chokepoint is the load-bearing backstop).
	if policy.GrantsReservedGroup(b.Groups) {
		writeProblem(w, http.StatusBadRequest, "reserved group",
			"join keys may not grant a reserved group (control-plane/lighthouse)")
		return
	}
	secret, jk, err := joinkey.Create(r.Context(), s.cfg.Store, joinkey.Params{
		Name: b.Name, Groups: b.Groups, SubRange: b.SubRange, MaxUses: b.MaxUses,
		TTL: time.Duration(b.TTLSeconds) * time.Second, AutoIssue: b.AutoIssue,
		Ephemeral: b.Ephemeral, QuotaPerHour: b.QuotaPerHour,
	}, s.now())
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			writeProblem(w, http.StatusConflict, "duplicate name", "a join key with that name already exists")
			return
		}
		s.fail(w, r, "create join key failed", err)
		return
	}
	_, _ = s.cfg.Store.AppendAudit(r.Context(), id.Principal, "joinkey-create", b.Name,
		fmt.Sprintf("groups=%v auto_issue=%v max_uses=%d", jk.GroupList(), jk.AutoIssue, jk.MaxUses))
	writeJSON(w, http.StatusCreated, map[string]any{"secret": secret, "joinkey": joinKeyView(jk)})
}

// PATCH /admin/v1/joinkeys/{name} — edit an active key's config (groups, caps,
// auto-issue, etc.). Config-columns only: the secret, name, used_count, and state are
// never touched. Active-only (a revoked key 404s). All body fields are optional —
// absent means "leave unchanged"; pointers let auto_issue=false / max_uses=0 persist.
func (s *Server) handleJoinKeyUpdate(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermJoinKeyManage) {
		return
	}
	name := r.PathValue("name")
	var b struct {
		Groups       *[]string `json:"groups"`
		SubRange     *string   `json:"sub_range"`
		MaxUses      *int      `json:"max_uses"`
		QuotaPerHour *int      `json:"quota_per_hour"`
		AutoIssue    *bool     `json:"auto_issue"`
		Ephemeral    *bool     `json:"ephemeral"`
		TTLSeconds   *int      `json:"ttl_seconds"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	// Can't PATCH a key into granting a reserved group either (see handleJoinKeyCreate).
	if b.Groups != nil && policy.GrantsReservedGroup(*b.Groups) {
		writeProblem(w, http.StatusBadRequest, "reserved group",
			"join keys may not grant a reserved group (control-plane/lighthouse)")
		return
	}
	p := joinkey.UpdateParams{
		Groups: b.Groups, SubRange: b.SubRange, MaxUses: b.MaxUses,
		QuotaPerHour: b.QuotaPerHour, AutoIssue: b.AutoIssue, Ephemeral: b.Ephemeral,
	}
	if b.TTLSeconds != nil {
		ttl := time.Duration(*b.TTLSeconds) * time.Second
		p.TTL = &ttl
	}
	jk, err := joinkey.Update(r.Context(), s.cfg.Store, name, p, s.now())
	if err != nil {
		if errors.Is(err, joinkey.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not found", "no such active join key")
			return
		}
		s.fail(w, r, "update join key failed", err)
		return
	}
	_, _ = s.cfg.Store.AppendAudit(r.Context(), id.Principal, "joinkey-update", name,
		fmt.Sprintf("groups=%v auto_issue=%v max_uses=%d quota_per_hour=%d ephemeral=%v",
			jk.GroupList(), jk.AutoIssue, jk.MaxUses, jk.QuotaPerHour, jk.Ephemeral))
	writeJSON(w, http.StatusOK, joinKeyView(jk))
}

// POST /admin/v1/joinkeys/{name}/revoke — revoke a key by name.
func (s *Server) handleJoinKeyRevoke(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermJoinKeyManage) {
		return
	}
	name := r.PathValue("name")
	if err := joinkey.Revoke(r.Context(), s.cfg.Store, name); err != nil {
		if errors.Is(err, joinkey.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not found", "no such join key")
			return
		}
		s.fail(w, r, "revoke join key failed", err)
		return
	}
	_, _ = s.cfg.Store.AppendAudit(r.Context(), id.Principal, "joinkey-revoke", name, "")
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "revoked": true})
}
