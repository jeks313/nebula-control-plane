package adminapi

import (
	"net/http"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/gatewayhealth"
	"github.com/jeks313/nebula-control-plane/internal/gatewayreg"
)

// gatewayDownAfter: a gateway with no successful collect cycle within this window is "down".
// It MUST stay comfortably larger than collect's healthHeartbeat (15s) AND the collect poll
// interval: a healthy gateway only re-stamps last_success_at on an ok/fail transition or every
// heartbeat (writes are throttled, not per-cycle), so too small a window would false-flap a
// healthy gateway to "down" between writes. 60s tolerates ~4 missed heartbeats — well past any
// transient blip, and exactly the silent state the 2026-06-28 TLS-wedge sat in unnoticed.
const gatewayDownAfter = 60 * time.Second

type gatewayView struct {
	Name                string `json:"name"`
	URL                 string `json:"url"`
	Status              string `json:"status"` // healthy | degraded | down | unknown
	LastSuccessAt       string `json:"last_success_at,omitempty"`
	SecondsSinceSuccess int64  `json:"seconds_since_success"` // -1 if never succeeded
	ConsecutiveFailures int64  `json:"consecutive_failures"`
	LastError           string `json:"last_error,omitempty"`
}

// handleGateways implements GET /admin/v1/gateways — the active pull-based enrollment
// gateways (ADR 0005 registry) joined with their collect-loop health, for the console's
// Gateways dashboard pane. Authenticated, no special permission (read-only, like
// /fleet/health). Health is recorded by harbor-collect; because both processes share the
// DB, a wedged gateway shows here as down even though the collect loop is what observed it.
func (s *Server) handleGateways(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := gatewayreg.New(s.cfg.Store.DB, nil).Active(ctx)
	if err != nil {
		s.fail(w, r, "list gateways failed", err)
		return
	}
	health, err := gatewayhealth.New(s.cfg.Store.DB).List(ctx)
	if err != nil {
		s.fail(w, r, "gateway health failed", err)
		return
	}
	now := s.now()
	out := make([]gatewayView, 0, len(rows))
	summary := map[string]int{"total": 0, "healthy": 0, "degraded": 0, "down": 0, "unknown": 0}
	for _, gw := range rows {
		v := gatewayView{Name: gw.Name, URL: gw.URL, Status: "unknown", SecondsSinceSuccess: -1}
		h, ok := health[gw.Name]
		switch {
		case ok && h.LastSuccessAt > 0:
			since := now.Sub(time.Unix(0, h.LastSuccessAt))
			v.SecondsSinceSuccess = int64(since.Seconds())
			v.LastSuccessAt = rfc3339(h.LastSuccessAt)
			v.ConsecutiveFailures = h.ConsecutiveFailures
			v.LastError = h.LastError
			switch {
			case since > gatewayDownAfter:
				v.Status = "down"
			case h.ConsecutiveFailures > 0:
				v.Status = "degraded"
			default:
				v.Status = "healthy"
			}
		case ok:
			// a health row exists but no successful cycle ever -> down (collect can't reach it)
			v.Status = "down"
			v.ConsecutiveFailures = h.ConsecutiveFailures
			v.LastError = h.LastError
		}
		// else: no health row at all -> "unknown" (harbor-collect hasn't recorded this gateway
		// yet, e.g. collect not running / never polled it).
		summary[v.Status]++
		summary["total"]++
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"gateways": out, "summary": summary})
}
