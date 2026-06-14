// Package revocation is Harbor's cert blocklist (implementation-plan 7.1, design
// §4.7/§8). It is the single source of truth for which Nebula cert fingerprints
// the fleet must refuse: Core renders every host bundle's pki.blocklist from the
// active rows here, so adding (or lifting) a revocation propagates to every host
// via the next signed bundle (3.6/6.4) and is enforced on hosts by drift-revert
// (6.7).
//
// The control is enforced PEER-SIDE: a compromised host's own Pilot may ignore an
// order to block itself, so correctness comes from every OTHER node refusing to
// handshake with a blocklisted fingerprint (§4.7). The SLO that matters is
// therefore propagation latency to the healthy fleet, not to the target.
//
// This package implements the basic, audited add/lift/list operations (single-host
// blocklist, RBAC-gated by the caller). The P10 "cannot blocklist
// control-plane/lighthouses" invariant and the bulk-revoke dual-control + rate
// limiting (7.2) layer on top of this registry; they are not enforced here.
package revocation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

// State values.
const (
	StateActive = "active"
	StateLifted = "lifted"
)

// Errors callers can branch on.
var (
	ErrNoFingerprint = errors.New("revocation: fingerprint is required")
	ErrAlreadyActive = errors.New("revocation: fingerprint is already blocklisted")
)

// Row is a registry record.
type Row struct {
	ID          int64  `gorm:"column:id;primaryKey"`
	Fingerprint string `gorm:"column:fingerprint"`
	Reason      string `gorm:"column:reason"`
	Bulk        bool   `gorm:"column:bulk"`
	State       string `gorm:"column:state"`
	CreatedBy   string `gorm:"column:created_by"`
	CreatedAt   int64  `gorm:"column:created_at"`
	UpdatedAt   int64  `gorm:"column:updated_at"`
}

// TableName pins the table.
func (Row) TableName() string { return "revocations" }

// AuditFunc appends one row to the hash-chained audit log.
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// Registry manages the cert blocklist.
type Registry struct {
	db    *gorm.DB
	audit AuditFunc
	now   func() time.Time
}

// New builds a Registry.
func New(db *gorm.DB, audit AuditFunc) *Registry {
	return &Registry{db: db, audit: audit, now: time.Now}
}

// normFingerprint canonicalizes a fingerprint to lowercase hex with no
// surrounding space, so the same cert always maps to one row (Nebula's
// Fingerprint() returns lowercase hex sha256).
func normFingerprint(fp string) string {
	return strings.ToLower(strings.TrimSpace(fp))
}

// Add blocklists a cert fingerprint. If a lifted row for the same fingerprint
// exists it is re-activated; an already-active fingerprint returns
// ErrAlreadyActive (idempotent-friendly: callers may treat it as success). The
// reserved-group / dual-control guards (7.2) are the caller's responsibility.
func (r *Registry) Add(ctx context.Context, fingerprint, reason, actor string) (Row, error) {
	fp := normFingerprint(fingerprint)
	if fp == "" {
		return Row{}, ErrNoFingerprint
	}
	now := r.now().UTC().UnixNano()
	var row Row
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		switch err := tx.First(&row, "fingerprint = ?", fp).Error; {
		case errors.Is(err, gorm.ErrRecordNotFound):
			row = Row{Fingerprint: fp, Reason: reason, State: StateActive, CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
			return tx.Create(&row).Error
		case err != nil:
			return err
		}
		if row.State == StateActive {
			return ErrAlreadyActive
		}
		// Re-activate a previously lifted revocation.
		row.State, row.Reason, row.CreatedBy, row.UpdatedAt = StateActive, reason, actor, now
		return tx.Model(&Row{}).Where("fingerprint = ?", fp).Updates(map[string]any{
			"state": StateActive, "reason": reason, "created_by": actor, "updated_at": now,
		}).Error
	})
	if err != nil {
		return Row{}, fmt.Errorf("revocation: add: %w", err)
	}
	r.recordAudit(ctx, actor, "revocation-add", fp, fmt.Sprintf("reason=%q", reason))
	return row, nil
}

// Lift removes a fingerprint from the active blocklist (kept as state='lifted'
// for audit/history). Idempotent: lifting an unknown or already-lifted
// fingerprint is a no-op (no audit row). Use with care — lifting un-revokes a
// host the fleet was refusing.
func (r *Registry) Lift(ctx context.Context, fingerprint, actor string) error {
	fp := normFingerprint(fingerprint)
	if fp == "" {
		return ErrNoFingerprint
	}
	changed := false
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row Row
		switch err := tx.First(&row, "fingerprint = ?", fp).Error; {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return nil // never blocklisted; nothing to lift
		case err != nil:
			return err
		}
		if row.State == StateLifted {
			return nil // already lifted
		}
		changed = true
		return tx.Model(&Row{}).Where("fingerprint = ?", fp).
			Updates(map[string]any{"state": StateLifted, "updated_at": r.now().UTC().UnixNano()}).Error
	})
	if err != nil {
		return fmt.Errorf("revocation: lift: %w", err)
	}
	if changed {
		r.recordAudit(ctx, actor, "revocation-lift", fp, "")
	}
	return nil
}

// ActiveFingerprints returns the active blocklist as a sorted slice of
// fingerprints — sorted so an unchanged blocklist yields a byte-identical bundle
// and never trips drift-revert (6.7/6.8). This is the BlocklistSource Core
// consults at bundle-build time.
func (r *Registry) ActiveFingerprints(ctx context.Context) ([]string, error) {
	var fps []string
	if err := r.db.WithContext(ctx).Model(&Row{}).
		Where("state = ?", StateActive).
		Order("fingerprint ASC").Pluck("fingerprint", &fps).Error; err != nil {
		return nil, fmt.Errorf("revocation: active: %w", err)
	}
	sort.Strings(fps) // belt-and-suspenders: guarantee deterministic order
	return fps, nil
}

// List returns every registry row (including lifted), newest first.
func (r *Registry) List(ctx context.Context) ([]Row, error) {
	var rows []Row
	if err := r.db.WithContext(ctx).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("revocation: list: %w", err)
	}
	return rows, nil
}

func (r *Registry) recordAudit(ctx context.Context, actor, action, target, details string) {
	if r.audit == nil {
		return
	}
	_ = r.audit(ctx, actor, action, target, details)
}
