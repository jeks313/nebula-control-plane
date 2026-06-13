// Package lighthouse is Harbor's lighthouse fleet registry (implementation-plan
// 6.8). It is the single source of truth for the fleet's discovery topology:
// Core renders each host bundle's static_host_map / lighthouse.hosts from the
// active rows here, so adding, re-addressing, or removing a lighthouse
// propagates to every host via the next signed bundle (3.6/6.4) and is enforced
// on hosts by drift-revert (6.7).
//
// The discovery-never-lost invariant (6.3, design §P10): there must always be at
// least one active lighthouse — Remove refuses to retire the last one — so a
// lighthouse swap is done add-new-then-remove-old and members never see an empty
// static_host_map mid-change.
package lighthouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"gorm.io/gorm"
)

// State values.
const (
	StateActive  = "active"
	StateRemoved = "removed"
)

// Errors callers can branch on.
var (
	ErrNotFound      = errors.New("lighthouse: not found")
	ErrLastActive    = errors.New("lighthouse: refusing to remove the last active lighthouse — discovery would be lost (6.3 invariant)")
	ErrNoAddrs       = errors.New("lighthouse: at least one public address is required")
	ErrNoOverlayIP   = errors.New("lighthouse: overlay IP is required")
	ErrAlreadyExists = errors.New("lighthouse: an entry for that overlay IP already exists")
)

// Row is a registry record.
type Row struct {
	ID          int64  `gorm:"column:id;primaryKey"`
	OverlayIP   string `gorm:"column:overlay_ip"`
	PublicAddrs string `gorm:"column:public_addrs"` // JSON array of host:port
	Hostname    string `gorm:"column:hostname"`
	State       string `gorm:"column:state"`
	CreatedAt   int64  `gorm:"column:created_at"`
	UpdatedAt   int64  `gorm:"column:updated_at"`
}

// TableName pins the table.
func (Row) TableName() string { return "lighthouses" }

// Addrs decodes the JSON public-address list.
func (r Row) Addrs() []string {
	var out []string
	_ = json.Unmarshal([]byte(r.PublicAddrs), &out)
	return out
}

// AuditFunc appends one row to the hash-chained audit log.
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// Registry manages the lighthouse fleet.
type Registry struct {
	db    *gorm.DB
	audit AuditFunc
	now   func() time.Time
}

// New builds a Registry.
func New(db *gorm.DB, audit AuditFunc) *Registry {
	return &Registry{db: db, audit: audit, now: time.Now}
}

// Add registers a new active lighthouse.
func (r *Registry) Add(ctx context.Context, overlayIP, hostname string, addrs []string, actor string) (Row, error) {
	if overlayIP == "" {
		return Row{}, ErrNoOverlayIP
	}
	if len(addrs) == 0 {
		return Row{}, ErrNoAddrs
	}
	now := r.now().UTC().UnixNano()
	row := Row{
		OverlayIP: overlayIP, PublicAddrs: encodeAddrs(addrs), Hostname: hostname,
		State: StateActive, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return Row{}, ErrAlreadyExists
		}
		return Row{}, fmt.Errorf("lighthouse: add: %w", err)
	}
	r.recordAudit(ctx, actor, "lighthouse-add", overlayIP, fmt.Sprintf("addrs=%v", addrs))
	return row, nil
}

// Replace re-addresses an existing lighthouse in place (same overlay IP, new
// underlay address) and re-activates it if it was removed. This is the safe path
// when a lighthouse keeps its overlay identity but moves on the underlay.
func (r *Registry) Replace(ctx context.Context, overlayIP string, addrs []string, actor string) (Row, error) {
	if len(addrs) == 0 {
		return Row{}, ErrNoAddrs
	}
	var row Row
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&row, "overlay_ip = ?", overlayIP).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		now := r.now().UTC().UnixNano()
		return tx.Model(&Row{}).Where("overlay_ip = ?", overlayIP).Updates(map[string]any{
			"public_addrs": encodeAddrs(addrs), "state": StateActive, "updated_at": now,
		}).Error
	})
	if err != nil {
		return Row{}, err
	}
	r.recordAudit(ctx, actor, "lighthouse-replace", overlayIP, fmt.Sprintf("addrs=%v", addrs))
	return r.get(ctx, overlayIP)
}

// Remove retires a lighthouse so it is no longer advertised. It refuses to
// retire the last active one (the discovery-never-lost invariant) — to swap the
// final lighthouse, Add its replacement first.
func (r *Registry) Remove(ctx context.Context, overlayIP, actor string) error {
	changed := false
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row Row
		if err := tx.First(&row, "overlay_ip = ?", overlayIP).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if row.State == StateRemoved {
			return nil // idempotent: already removed, nothing to do
		}
		var activeCount int64
		if err := tx.Model(&Row{}).Where("state = ?", StateActive).Count(&activeCount).Error; err != nil {
			return err
		}
		if activeCount <= 1 {
			return ErrLastActive
		}
		changed = true
		return tx.Model(&Row{}).Where("overlay_ip = ?", overlayIP).
			Updates(map[string]any{"state": StateRemoved, "updated_at": r.now().UTC().UnixNano()}).Error
	})
	if err != nil {
		return err
	}
	if changed { // don't audit the idempotent no-op (already-removed) path
		r.recordAudit(ctx, actor, "lighthouse-remove", overlayIP, "")
	}
	return nil
}

// Active returns the active lighthouses as bundle entries, ordered by overlay IP
// for deterministic bundle output (so an unchanged fleet yields an unchanged
// bundle and never trips drift).
func (r *Registry) Active(ctx context.Context) ([]bundle.Lighthouse, error) {
	var rows []Row
	if err := r.db.WithContext(ctx).Where("state = ?", StateActive).
		Order("overlay_ip ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("lighthouse: active: %w", err)
	}
	out := make([]bundle.Lighthouse, len(rows))
	for i, row := range rows {
		out[i] = bundle.Lighthouse{OverlayIP: row.OverlayIP, PublicAddrs: row.Addrs()}
	}
	return out, nil
}

// List returns every registry row (including removed), newest first.
func (r *Registry) List(ctx context.Context) ([]Row, error) {
	var rows []Row
	if err := r.db.WithContext(ctx).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("lighthouse: list: %w", err)
	}
	return rows, nil
}

func (r *Registry) get(ctx context.Context, overlayIP string) (Row, error) {
	var row Row
	if err := r.db.WithContext(ctx).First(&row, "overlay_ip = ?", overlayIP).Error; err != nil {
		return Row{}, err
	}
	return row, nil
}

func (r *Registry) recordAudit(ctx context.Context, actor, action, target, details string) {
	if r.audit == nil {
		return
	}
	_ = r.audit(ctx, actor, action, target, details)
}

func encodeAddrs(addrs []string) string {
	b, _ := json.Marshal(addrs)
	return string(b)
}
