package adminapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/configkey"
)

// configKeyView is one config-signing-key row for the console's Config-Key Rotation dashboard
// (M8.5): its lifecycle state plus the derived rotation signals — whether it is the active signing
// key, whether it is still trusted (in every signed bundle's config_signing_keys), whether it has a
// real signing backend (vs a trust-only import), and any pending key deletion. Unlike a CA a
// config-signing key has NO expiry and NO per-key drain count — drain is fleet-wide (the inverse of
// AdoptionStatus(active)), surfaced via the /adoption endpoint, not a per-row live-dependents count.
type configKeyView struct {
	ID          int64            `json:"id"`
	Name        string           `json:"name"`
	State       string           `json:"state"` // staged | active | draining | retired
	Fingerprint string           `json:"fingerprint"`
	IsActive    bool             `json:"is_active"`   // the current signing key
	Trusted     bool             `json:"trusted"`     // in the distributed trust bundle (non-retired == in TrustedKeys)
	HasBackend  bool             `json:"has_backend"` // kms_key_id set (a real signing backend, not a trust-only import)
	CreatedAt   string           `json:"created_at,omitempty"`
	KeyDeletion *keyDeletionView `json:"key_deletion,omitempty"` // reuses ca.go's keyDeletionView (identical shape)
}

// handleConfigKeys implements GET /admin/v1/config-key — the M8.5 config-signing-key rotation
// lifecycle for the console dashboard: every key with its state and the derived rotation signals
// (active/trusted/backend/key-deletion). Read-only, authenticated, no special permission (like /ca
// and /gateways).
func (s *Server) handleConfigKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reg := configkey.New(s.cfg.Store.DB, nil)
	rows, err := reg.List(ctx)
	if err != nil {
		s.fail(w, r, "list config keys failed", err)
		return
	}
	now := s.now()
	out := make([]configKeyView, 0, len(rows))
	summary := map[string]int{"total": 0, "staged": 0, "active": 0, "draining": 0, "retired": 0}
	for _, c := range rows {
		v := configKeyView{
			ID: c.ID, Name: c.Name, State: string(c.State), Fingerprint: c.Fingerprint,
			IsActive:   c.State == configkey.StateActive,
			Trusted:    c.State != configkey.StateRetired,
			HasBackend: c.KMSKeyID != "",
		}
		if c.CreatedAt != 0 {
			v.CreatedAt = rfc3339(c.CreatedAt)
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
	writeJSON(w, http.StatusOK, map[string]any{"config_keys": out, "summary": summary})
}

// handleConfigKeyAdoption implements GET /admin/v1/config-key/{id}/adoption — the trust-adoption
// progress for one config-signing key (M8.5): how many LIVE hosts have confirmed via heartbeat that
// they trust it, which is the gate the CLI enforces before `config-key activate` cuts signing over
// (and, for the active key, the inverse of the drain that gates retire). Read-only, authenticated.
func (s *Server) handleConfigKeyAdoption(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "bad id", "id must be an integer")
		return
	}
	reg := configkey.New(s.cfg.Store.DB, nil)
	target, err := reg.Get(ctx, id)
	if err != nil {
		if errors.Is(err, configkey.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "no such config key", "no config-signing key with that id")
			return
		}
		s.fail(w, r, "get config key failed", err)
		return
	}
	ad, err := reg.AdoptionStatus(ctx, target.Fingerprint, s.cfg.Thresholds.StaleAfter)
	if err != nil {
		s.fail(w, r, "config key adoption failed", err)
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
