// Package gatewayreg is Harbor's registry of pull-based enrollment gateways
// (ADR 0005), modeled on internal/lighthouse. It is the admin-managed list of
// gateways Harbor's collector polls over leaf-pinned mTLS: each row is a gateway's
// collect URL + its pinned self-signed server cert. Adding/removing a gateway is
// an audited admin action. Unlike lighthouses there is no "last active" invariant:
// a gateway is an off-mesh sink, so removing the last one only pauses public
// enrollment — it cannot sever the mesh.
package gatewayreg

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// State values.
const (
	StateActive  = "active"
	StateRemoved = "removed"
)

// Errors callers can branch on.
var (
	ErrNotFound      = errors.New("gatewayreg: not found")
	ErrNoName        = errors.New("gatewayreg: name is required")
	ErrNoURL         = errors.New("gatewayreg: url is required")
	ErrBadCert       = errors.New("gatewayreg: cert is not a valid CERTIFICATE PEM")
	ErrAlreadyExists = errors.New("gatewayreg: a gateway with that name already exists")
)

// Row is a registry record.
type Row struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	Name      string `gorm:"column:name"`
	URL       string `gorm:"column:url"`
	CertPEM   string `gorm:"column:cert_pem"`
	State     string `gorm:"column:state"`
	CreatedAt int64  `gorm:"column:created_at"`
	UpdatedAt int64  `gorm:"column:updated_at"`
}

// TableName pins the table.
func (Row) TableName() string { return "gateways" }

// AuditFunc appends one row to the hash-chained audit log.
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// Registry manages the gateway list.
type Registry struct {
	db    *gorm.DB
	audit AuditFunc
	now   func() time.Time
}

// New builds a Registry.
func New(db *gorm.DB, audit AuditFunc) *Registry {
	return &Registry{db: db, audit: audit, now: time.Now}
}

// validCertPEM confirms pemBytes is a single CERTIFICATE PEM that parses (so a
// fat-fingered paste can't enter the registry and silently break the mTLS dial).
func validCertPEM(pemBytes string) error {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil || block.Type != "CERTIFICATE" {
		return ErrBadCert
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("%w: %v", ErrBadCert, err)
	}
	return nil
}

// Add registers a gateway (or re-activates + re-addresses a previously removed one
// of the same name). certPEM is the gateway's self-signed server cert, whose leaf
// Harbor pins for the collect mTLS dial.
func (r *Registry) Add(ctx context.Context, name, url, certPEM, actor string) (Row, error) {
	name, url = strings.TrimSpace(name), strings.TrimSpace(url)
	if name == "" {
		return Row{}, ErrNoName
	}
	if url == "" {
		return Row{}, ErrNoURL
	}
	if err := validCertPEM(certPEM); err != nil {
		return Row{}, err
	}
	now := r.now().UTC().UnixNano()
	var row Row
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		switch err := tx.First(&row, "name = ?", name).Error; {
		case errors.Is(err, gorm.ErrRecordNotFound):
			row = Row{Name: name, URL: url, CertPEM: certPEM, State: StateActive, CreatedAt: now, UpdatedAt: now}
			return tx.Create(&row).Error
		case err != nil:
			return err
		}
		if row.State == StateActive {
			return ErrAlreadyExists
		}
		// Re-activate a previously removed gateway, re-addressing + re-pinning it.
		row.URL, row.CertPEM, row.State, row.UpdatedAt = url, certPEM, StateActive, now
		return tx.Model(&Row{}).Where("name = ?", name).Updates(map[string]any{
			"url": url, "cert_pem": certPEM, "state": StateActive, "updated_at": now,
		}).Error
	})
	if err != nil {
		return Row{}, fmt.Errorf("gatewayreg: add: %w", err)
	}
	r.recordAudit(ctx, actor, "gateway-add", name, fmt.Sprintf("url=%s", url))
	return row, nil
}

// Remove retires a gateway so the collector stops polling it (kept as
// state='removed' for audit/history). Idempotent: removing an unknown or
// already-removed gateway is a no-op (no audit row).
func (r *Registry) Remove(ctx context.Context, name, actor string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrNoName
	}
	changed := false
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row Row
		switch err := tx.First(&row, "name = ?", name).Error; {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return nil
		case err != nil:
			return err
		}
		if row.State == StateRemoved {
			return nil
		}
		changed = true
		return tx.Model(&Row{}).Where("name = ?", name).
			Updates(map[string]any{"state": StateRemoved, "updated_at": r.now().UTC().UnixNano()}).Error
	})
	if err != nil {
		return fmt.Errorf("gatewayreg: remove: %w", err)
	}
	if changed {
		r.recordAudit(ctx, actor, "gateway-remove", name, "")
	}
	return nil
}

// Active returns the active gateways, ordered by name (stable for the collector).
func (r *Registry) Active(ctx context.Context) ([]Row, error) {
	var rows []Row
	if err := r.db.WithContext(ctx).Where("state = ?", StateActive).
		Order("name ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("gatewayreg: active: %w", err)
	}
	return rows, nil
}

// List returns every registry row (including removed), newest first.
func (r *Registry) List(ctx context.Context) ([]Row, error) {
	var rows []Row
	if err := r.db.WithContext(ctx).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("gatewayreg: list: %w", err)
	}
	return rows, nil
}

func (r *Registry) recordAudit(ctx context.Context, actor, action, target, details string) {
	if r.audit == nil {
		return
	}
	_ = r.audit(ctx, actor, action, target, details)
}
