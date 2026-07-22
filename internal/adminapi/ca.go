package adminapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/ca"
)

// caView is one CA row for the console's CA Rotation dashboard (M8): its lifecycle state plus the
// derived rotation signals — whether it is the active signing CA, whether it is still trusted (in
// every signed bundle), its drain count, any accelerated-drain window, and any pending key deletion.
type caView struct {
	ID          int64            `json:"id"`
	Name        string           `json:"name"`
	State       string           `json:"state"` // staged | active | draining | retired
	Fingerprint string           `json:"fingerprint"`
	NotAfter    string           `json:"not_after,omitempty"`
	IsActive    bool             `json:"is_active"`       // the current signing CA
	Trusted     bool             `json:"trusted"`         // in the distributed trust bundle (non-retired)
	LiveDeps    int              `json:"live_dependents"` // leaf certs still chaining to it (-1 = read error)
	ForceRenew  *forceRenewView  `json:"force_renew,omitempty"`
	KeyDeletion *keyDeletionView `json:"key_deletion,omitempty"`
}

// forceRenewView is the M8.3c accelerated-drain window on a draining CA.
type forceRenewView struct {
	WindowSeconds int64  `json:"window_seconds"`
	StartedAt     string `json:"started_at"`
}

// keyDeletionView is the M8.4 pending key deletion on a retired CA.
type keyDeletionView struct {
	Date             string `json:"date"`
	SecondsRemaining int64  `json:"seconds_remaining"` // negative once the deletion date has passed
}

// handleCAs implements GET /admin/v1/ca — the M8 CA-rotation lifecycle for the console dashboard:
// every CA with its state and the derived rotation signals (active/trusted/drain/force-renew/key
// deletion). Read-only, authenticated, no special permission (like /gateways and /fleet/health).
func (s *Server) handleCAs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reg := ca.New(s.cfg.Store.DB, nil)
	rows, err := reg.List(ctx)
	if err != nil {
		s.fail(w, r, "list CAs failed", err)
		return
	}
	now := s.now()
	out := make([]caView, 0, len(rows))
	summary := map[string]int{"total": 0, "staged": 0, "active": 0, "draining": 0, "retired": 0}
	for _, c := range rows {
		v := caView{
			ID: c.ID, Name: c.Name, State: string(c.State), Fingerprint: c.Fingerprint,
			IsActive: c.State == ca.StateActive,
			Trusted:  c.State != ca.StateRetired,
		}
		if c.NotAfter != 0 {
			v.NotAfter = rfc3339(c.NotAfter)
		}
		if n, derr := reg.LiveDependents(ctx, c.Fingerprint); derr == nil {
			v.LiveDeps = n
		} else {
			v.LiveDeps = -1 // unknown — the UI shows "?" rather than a false 0
		}
		if c.ForceRenewStartedAt != 0 && c.ForceRenewWindowNS > 0 {
			v.ForceRenew = &forceRenewView{
				WindowSeconds: int64(time.Duration(c.ForceRenewWindowNS).Seconds()),
				StartedAt:     rfc3339(c.ForceRenewStartedAt),
			}
		}
		if c.KeyDeletionScheduledAt != 0 {
			v.KeyDeletion = &keyDeletionView{
				Date:             rfc3339(c.KeyDeletionDate),
				SecondsRemaining: int64(time.Duration(c.KeyDeletionDate - now.UnixNano()).Seconds()),
			}
		}
		summary[string(c.State)]++
		summary["total"]++
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"cas": out, "summary": summary})
}

// handleCAAdoption implements GET /admin/v1/ca/{id}/adoption — the trust-adoption progress for one
// CA (M8.1): how many LIVE hosts have confirmed via heartbeat that they trust it, which is the gate
// the CLI enforces before `ca activate` cuts signing over. Read-only, authenticated.
func (s *Server) handleCAAdoption(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "bad id", "id must be an integer")
		return
	}
	reg := ca.New(s.cfg.Store.DB, nil)
	target, err := reg.Get(ctx, id)
	if err != nil {
		if errors.Is(err, ca.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "no such CA", "no CA with that id")
			return
		}
		s.fail(w, r, "get CA failed", err)
		return
	}
	ad, err := reg.AdoptionStatus(ctx, target.Fingerprint, s.cfg.Thresholds.StaleAfter)
	if err != nil {
		s.fail(w, r, "CA adoption failed", err)
		return
	}
	pct := 100.0
	if ad.Live > 0 {
		pct = float64(ad.Adopted) / float64(ad.Live) * 100
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": target.ID, "name": target.Name, "fingerprint": target.Fingerprint, "state": string(target.State),
		"adopted": ad.Adopted, "live": ad.Live, "fully_adopted": ad.FullyAdopted(), "percent": pct,
		"laggards": ad.Laggards, "stale": ad.Stale,
	})
}
