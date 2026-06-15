package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/rollout"
)

// Binary-release endpoints (ADR 0003 1c/3c): the console lists the nebula + pilot
// release registries and stages / aborts a fleet upgrade. Binaries are added via the
// CLI (harbor nebula/pilot add) — there is no upload path here; Harbor stays a pointer
// registry. Staging reuses the rollout engine's canary lanes.

// ReleaseView is one registered release (nebula or pilot) for the console.
type ReleaseView struct {
	Gen       int64  `json:"gen"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	URL       string `json:"url"`
	Status    string `json:"status"` // candidate | current | superseded
	Note      string `json:"note,omitempty"`
	CreatedAt string `json:"created_at"`
}

// handleReleasesList implements GET /admin/v1/releases: both registries + each lane's
// current rollout, in one call.
func (s *Server) handleReleasesList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	writeJSON(w, http.StatusOK, map[string]any{
		"nebula": s.releaseLane(ctx, "nebula"),
		"pilot":  s.releaseLane(ctx, "pilot"),
	})
}

// releaseLane builds one kind's section: its registry rows (newest first), the live
// fleet-desired generation, and the current rollout status (nil when none).
func (s *Server) releaseLane(ctx context.Context, kind string) map[string]any {
	lane, _ := releaseLaneName(kind)
	curGen := s.currentGen(ctx, kind)
	views := []ReleaseView{}
	for _, r := range s.listReleases(ctx, kind) {
		status := r.Status
		if int(r.Gen) == curGen { // the registry status field is advisory; the lane decides "current"
			status = "current"
		}
		views = append(views, ReleaseView{
			Gen: r.Gen, Version: r.Version, SHA256: r.SHA256, URL: r.URL,
			Status: status, Note: r.Note, CreatedAt: rfc3339(r.CreatedAt),
		})
	}
	out := map[string]any{"releases": views, "current_gen": curGen, "rollout": nil}
	if rr, hosts, err := s.cfg.Rollout.StatusLane(ctx, lane); err == nil {
		out["rollout"] = rolloutStatus(rr, hosts)
	}
	return out
}

// releaseRow is the common shape across the two registries (their Release types are
// identical-by-field; this lets listReleases return one type).
type releaseRow struct {
	Gen                                int64
	Version, SHA256, URL, Status, Note string
	CreatedAt                          int64
}

func (s *Server) listReleases(ctx context.Context, kind string) []releaseRow {
	var out []releaseRow
	switch kind {
	case "nebula":
		rows, _ := s.cfg.NebulaReleases.List(ctx)
		for _, r := range rows {
			out = append(out, releaseRow{r.Gen, r.Version, r.SHA256, r.URL, r.Status, r.Note, r.CreatedAt})
		}
	case "pilot":
		rows, _ := s.cfg.PilotReleases.List(ctx)
		for _, r := range rows {
			out = append(out, releaseRow{r.Gen, r.Version, r.SHA256, r.URL, r.Status, r.Note, r.CreatedAt})
		}
	}
	return out
}

func (s *Server) currentGen(ctx context.Context, kind string) int {
	switch kind {
	case "nebula":
		return s.cfg.Rollout.CurrentNebulaGen(ctx)
	case "pilot":
		return s.cfg.Rollout.CurrentPilotGen(ctx)
	}
	return 0
}

// handleReleaseRolloutStart implements POST /admin/v1/releases/{kind}/rollouts — stage a
// fleet upgrade to a registered generation on the kind's canary lane.
func (s *Server) handleReleaseRolloutStart(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermRolloutControl) {
		return
	}
	kind := r.PathValue("kind")
	lane, ok := releaseLaneName(kind)
	if !ok {
		writeProblem(w, http.StatusNotFound, "unknown release kind", "kind must be nebula or pilot")
		return
	}
	var b struct {
		Gen                 int `json:"gen"`
		CanarySize          int `json:"canary_size"`
		WaveSize            int `json:"wave_size"`
		ObserveSeconds      int `json:"observe_seconds"`
		MissingAfterSeconds int `json:"missing_after_seconds"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if b.Gen == 0 {
		writeProblem(w, http.StatusBadRequest, "bad request", "gen is required")
		return
	}
	ctx := r.Context()
	version, prev, found := s.lookupRelease(ctx, kind, b.Gen)
	if !found {
		writeProblem(w, http.StatusBadRequest, "unknown release", fmt.Sprintf("no %s release at generation %d", kind, b.Gen))
		return
	}
	var ips []string
	if err := s.cfg.Store.DB.WithContext(ctx).Table("heartbeats").Order("overlay_ip ASC").Pluck("overlay_ip", &ips).Error; err != nil {
		s.fail(w, r, "read fleet failed", err)
		return
	}
	rr, err := s.cfg.Rollout.Start(ctx, rollout.StartConfig{
		Lane: lane, Description: fmt.Sprintf("%s %s (gen %d)", kind, version, b.Gen),
		TargetVersion: b.Gen, PrevVersion: prev, Hosts: ips,
		CanarySize: b.CanarySize, WaveSize: b.WaveSize,
		Observe: releaseDur(b.ObserveSeconds, 10*time.Minute), MissingAfter: releaseDur(b.MissingAfterSeconds, 3*time.Minute),
		Actor: id.Principal,
	})
	if err != nil {
		s.mapRolloutErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, rolloutView(rr))
}

// handleReleaseRolloutAbort implements POST /admin/v1/releases/{kind}/rollouts/current/abort.
func (s *Server) handleReleaseRolloutAbort(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermRolloutControl) {
		return
	}
	lane, ok := releaseLaneName(r.PathValue("kind"))
	if !ok {
		writeProblem(w, http.StatusNotFound, "unknown release kind", "kind must be nebula or pilot")
		return
	}
	if err := s.cfg.Rollout.AbortLane(r.Context(), lane, id.Principal); err != nil {
		s.mapRolloutErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aborted": true})
}

func releaseLaneName(kind string) (string, bool) {
	switch kind {
	case "nebula":
		return rollout.LaneNebula, true
	case "pilot":
		return rollout.LanePilot, true
	default:
		return "", false
	}
}

// lookupRelease returns the gen's version, the lane's current settled gen (the rollout
// prev), and whether the gen exists in the registry.
func (s *Server) lookupRelease(ctx context.Context, kind string, gen int) (version string, prev int, found bool) {
	switch kind {
	case "nebula":
		r, ok := s.cfg.NebulaReleases.Get(ctx, gen)
		return r.Version, s.cfg.Rollout.CurrentNebulaGen(ctx), ok
	case "pilot":
		r, ok := s.cfg.PilotReleases.Get(ctx, gen)
		return r.Version, s.cfg.Rollout.CurrentPilotGen(ctx), ok
	}
	return "", 0, false
}

func releaseDur(sec int, def time.Duration) time.Duration {
	if sec <= 0 {
		return def
	}
	return time.Duration(sec) * time.Second
}
