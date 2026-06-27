package adminapi

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/policy"
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
	Ephemeral       bool // joined via an ephemeral join key (shorter cert TTL; impl 2.12 foundation)
	// Group-reassignment state (ADR 0002): DesiredGroups is the control-plane-authoritative
	// target; Pending = a re-issue is pending (groups_generation > issued_generation), clearing
	// on the host's next renew; ReductionPendingEnforcement = a soft removal whose old, higher-
	// privilege cert is still valid (advisory until revoked, Phase 3).
	DesiredGroups               []string
	Pending                     bool
	ReductionPendingEnforcement bool
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
	Ephemeral       bool   `gorm:"column:ephemeral"`

	DesiredGroups               string `gorm:"column:desired_groups"`
	GroupsGeneration            int64  `gorm:"column:groups_generation"`
	IssuedGeneration            int64  `gorm:"column:issued_generation"`
	ReductionPendingEnforcement bool   `gorm:"column:reduction_pending_enforcement"`
}

func (enrollProv) TableName() string { return "enrollments" }

const provSelect = "overlay_ip, join_key_id, groups, attest_provider, attest_account, attest_principal, attest_region, ephemeral, desired_groups, groups_generation, issued_generation, reduction_pending_enforcement"

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
		var groups, desired []string
		_ = json.Unmarshal([]byte(r.Groups), &groups)
		_ = json.Unmarshal([]byte(r.DesiredGroups), &desired)
		out[r.OverlayIP] = provRow{
			AttestProvider: r.AttestProvider, AttestAccount: r.AttestAccount,
			AttestPrincipal: r.AttestPrincipal, AttestRegion: r.AttestRegion,
			JoinKeyID: r.JoinKeyID, Groups: groups, Ephemeral: r.Ephemeral,
			DesiredGroups:               desired,
			Pending:                     r.GroupsGeneration > r.IssuedGeneration,
			ReductionPendingEnforcement: r.ReductionPendingEnforcement,
		}
	}
	return out, nil
}

// deviceReap is the reaper soft-mark for one device (impl 2.12), read from the
// devices table keyed by name. reaped_at = 0 means never reaped.
type deviceReap struct {
	Name       string `gorm:"column:name"`
	ReapedAt   int64  `gorm:"column:reaped_at"`   // unix ns; 0 = never reaped
	ReapReason string `gorm:"column:reap_reason"` // cert-expired | silent | ""
}

func (deviceReap) TableName() string { return "devices" }

// deviceReapMarks resolves the reaper soft-mark (reaped_at / reap_reason) for the
// given device names, keyed by name. Only reaped rows (reaped_at != 0) are returned —
// a live or never-reaped device is simply absent. The heartbeat-driven device list
// rarely contains a reaped host (its heartbeat is deleted at reap), so this is for
// completeness / a future include-reaped view (impl 2.12).
func (s *Server) deviceReapMarks(ctx context.Context, names []string) (map[string]deviceReap, error) {
	out := make(map[string]deviceReap, 0)
	if len(names) == 0 {
		return out, nil
	}
	var rows []deviceReap
	if err := s.cfg.Store.DB.WithContext(ctx).
		Select("name, reaped_at, reap_reason").
		Where("name IN ? AND reaped_at <> 0", names).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.Name] = r
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

// fleetGroupMap builds the fleet-wide group -> hosts membership (and the full issued
// host population) for blast-radius, from each host's AUTHORITATIVE (latest issued)
// enrollment groups — the same latest-issued-per-overlay_ip dedup as the provenance
// path. Reserved groups (control-plane/lighthouse) are excluded as keys (no user rule
// can change their reachability), but those hosts still count in allHosts (an `any`
// rule touches them). Issued — not heartbeats — is the right population: groups live
// on enrollments, and a policy change affects every cert-holder whether or not it has
// recently reported.
func (s *Server) fleetGroupMap(ctx context.Context) (groupHosts map[string][]string, allHosts []string, err error) {
	var rows []enrollProv
	if err = s.cfg.Store.DB.WithContext(ctx).
		Select(provSelect).
		Where("status = ? AND overlay_ip <> ''", enrollment.StatusIssued).
		Order("id DESC").
		Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	groupHosts = map[string][]string{}
	seen := make(map[string]bool, len(rows))
	for _, r := range rows {
		if seen[r.OverlayIP] {
			continue // only the latest issued enrollment per overlay_ip
		}
		seen[r.OverlayIP] = true
		allHosts = append(allHosts, r.OverlayIP)
		var groups []string
		_ = json.Unmarshal([]byte(r.Groups), &groups)
		for _, g := range groups {
			if g == policy.GroupControlPlane || g == policy.GroupLighthouse {
				continue
			}
			groupHosts[g] = append(groupHosts[g], r.OverlayIP)
		}
	}
	sort.Strings(allHosts)
	return groupHosts, allHosts, nil
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
