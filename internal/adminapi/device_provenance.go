package adminapi

import (
	"context"
	"encoding/json"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
)

// Device provenance: each device's enrollment lineage — how it joined the mesh and
// the groups it was issued — derived from its AUTHORITATIVE enrollment, defined
// (exactly as coreapi.device()) as the latest issued enrollment for the device's
// overlay_ip. enrollments has multiple rows per overlay_ip (re-enrolls, denied
// attempts), so we always filter status='issued' and take the highest id.

// provRow is the resolved provenance for one device.
type provRow struct {
	AttestProvider  string
	AttestAccount   string
	AttestPrincipal string
	AttestRegion    string
	JoinKeyID       int64 // 0 for cloud-attested hosts
	Groups          []string
}

// enrollProv is a narrow read view of the enrollment columns provenance needs (no
// pubkey/cert blobs).
type enrollProv struct {
	OverlayIP       string `gorm:"column:overlay_ip"`
	JoinKeyID       int64  `gorm:"column:join_key_id"`
	Groups          string `gorm:"column:groups"`
	AttestProvider  string `gorm:"column:attest_provider"`
	AttestAccount   string `gorm:"column:attest_account"`
	AttestPrincipal string `gorm:"column:attest_principal"`
	AttestRegion    string `gorm:"column:attest_region"`
}

func (enrollProv) TableName() string { return "enrollments" }

const provSelect = "overlay_ip, join_key_id, groups, attest_provider, attest_account, attest_principal, attest_region"

// deviceProvenance resolves the authoritative enrollment for each overlay IP and
// returns it keyed by overlay_ip. A device with no issued enrollment (e.g. a legacy
// or seeded heartbeat) is simply absent from the map.
func (s *Server) deviceProvenance(ctx context.Context, ips []string) (map[string]provRow, error) {
	out := make(map[string]provRow, len(ips))
	if len(ips) == 0 {
		return out, nil
	}
	var rows []enrollProv
	if err := s.cfg.Store.DB.WithContext(ctx).
		Select(provSelect).
		Where("overlay_ip IN ? AND status = ?", ips, enrollment.StatusIssued).
		Order("id DESC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	// Globally id-DESC ordered: the first row seen for an overlay_ip is its latest
	// issued enrollment (the authoritative one).
	for _, r := range rows {
		if _, seen := out[r.OverlayIP]; seen {
			continue
		}
		var groups []string
		_ = json.Unmarshal([]byte(r.Groups), &groups)
		out[r.OverlayIP] = provRow{
			AttestProvider: r.AttestProvider, AttestAccount: r.AttestAccount,
			AttestPrincipal: r.AttestPrincipal, AttestRegion: r.AttestRegion,
			JoinKeyID: r.JoinKeyID, Groups: groups,
		}
	}
	return out, nil
}

// overlayIPsForScope returns the SET of overlay IPs whose AUTHORITATIVE (latest
// issued) enrollment matches the active scope filters, as an O(1)-lookup allow-set.
// Empty args are ignored; the result is the intersection of the active filters.
// Matching the latest issued enrollment (not merely any) keeps the filter consistent
// with the provenance the row shows — a host that re-enrolled out of a scope is
// excluded even if an older enrollment matched. `names` (join-key id->name) is only
// consulted for a join_key filter; pass nil when joinKey is empty.
func (s *Server) overlayIPsForScope(ctx context.Context, provider, account, joinKey string, names map[int64]string) (map[string]bool, error) {
	var rows []enrollProv
	if err := s.cfg.Store.DB.WithContext(ctx).
		Select("overlay_ip, join_key_id, attest_provider, attest_account").
		Where("status = ? AND overlay_ip <> ''", enrollment.StatusIssued).
		Order("id DESC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(rows))
	allow := map[string]bool{}
	for _, r := range rows {
		if seen[r.OverlayIP] {
			continue // only the latest issued enrollment per overlay_ip counts
		}
		seen[r.OverlayIP] = true
		if provider != "" && r.AttestProvider != provider {
			continue
		}
		if account != "" && r.AttestAccount != account {
			continue
		}
		if joinKey != "" && names[r.JoinKeyID] != joinKey {
			continue
		}
		allow[r.OverlayIP] = true
	}
	return allow, nil
}

// joinKeyNameMap returns join-key id -> name for ALL keys (including revoked ones,
// so a host enrolled via a since-revoked key still resolves its name).
func (s *Server) joinKeyNameMap(ctx context.Context) (map[int64]string, error) {
	keys, err := joinkey.List(ctx, s.cfg.Store)
	if err != nil {
		return nil, err
	}
	m := make(map[int64]string, len(keys))
	for _, k := range keys {
		m[k.ID] = k.Name
	}
	return m, nil
}
