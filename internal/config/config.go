// Package config is Harbor's first-class declarative config store (ADR 0011 Phase 1,
// P1.0). It is the single source of truth for the three declarative singletons —
// the firewall policy, the cloud-trust config, and the SSO user-trust config — each
// keyed by its dual-control change kind ("policy.publish" / "cloudtrust.publish" /
// "usertrust.publish") so the same string identifies the config across the store,
// the enforcement readers, and the dual-control ledger.
//
// Before Phase 1 the "active config" of each kind was DERIVED — the latest committed
// dual-control change on the shared approvals ledger. Phase 1 makes the config
// first-class: enforcement reads this store, and BOTH write paths converge here —
// the single-operator declarative PUT (non-privileged changes) and the two-person
// dual-control commit (privileged changes). The store is the convergence point; the
// store is the truth.
//
// The package is deliberately LOW-LEVEL: it imports only gorm + std, validates
// nothing (the caller's Parse/Validate runs before Set — ADR 0011 P1.1), and depends
// on no domain package, so internal/adminapi and cmd/harbor can import it without an
// import cycle. Set writes the row + version bump in ONE transaction, then appends the
// audit row, mirroring internal/revocation's audited-write style (the hash-chained
// AppendAudit runs its own serialized tx, which cannot be nested inside the row tx on
// the single-writer SQLite connection).
package config

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// Audited action names written to the hash-chained audit log by Set.
const (
	// ActionSet is the audit action for a declarative config write (Store.Set).
	ActionSet = "config-set"
)

// ErrNoKind is returned when Get/Set is called with an empty kind.
var ErrNoKind = errors.New("config: a kind is required")

// Row is one stored config singleton. Payload is the canonical, validated bytes the
// kind's Parse accepts; Version is a monotonic counter bumped on every Set.
type Row struct {
	Kind      string `gorm:"column:kind;primaryKey"`
	Payload   []byte `gorm:"column:payload"`
	Version   int64  `gorm:"column:version"`
	UpdatedAt int64  `gorm:"column:updated_at"` // unix ns
	UpdatedBy string `gorm:"column:updated_by"`
}

// TableName pins the table.
func (Row) TableName() string { return "config" }

// AuditFunc appends one row to the hash-chained audit log (matches
// revocation.AuditFunc / netblock.AuditFunc so the same store wiring serves all).
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// Store reads and writes the config singletons.
type Store struct {
	db    *gorm.DB
	audit AuditFunc
	now   func() time.Time
}

// New builds a Store over db, with an optional audit hook (no-op if nil).
func New(db *gorm.DB, audit AuditFunc) *Store {
	return &Store{db: db, audit: audit, now: time.Now}
}

// Get returns the stored row for a kind, or (nil, nil) when none has been written
// yet (absent is not an error — a fresh fleet has no config).
func (s *Store) Get(ctx context.Context, kind string) (*Row, error) {
	if kind == "" {
		return nil, ErrNoKind
	}
	var row Row
	switch err := s.db.WithContext(ctx).First(&row, "kind = ?", kind).Error; {
	case err == nil:
		return &row, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	default:
		return nil, fmt.Errorf("config: get %s: %w", kind, err)
	}
}

// Set replaces the config for a kind with payload, attributing the write to actor.
// In ONE transaction it reads the current version, increments it (1 on first write,
// prev+1 thereafter), and upserts the row — so the version bump + the write are
// atomic (no torn read-modify-write under concurrency). The audit row is then
// appended right after the row commits, matching the established audited-write
// pattern in this codebase (internal/revocation, internal/netblock, internal/
// lighthouse): the AuditFunc (store.AppendAudit) runs its OWN serialized,
// hash-chained transaction, which on the single-writer SQLite connection cannot be
// nested inside the row tx (it would deadlock on the lone connection). The caller
// MUST have already validated payload (ADR 0011 P1.1 — the load-bearing inline
// validation lives in the PUT handler + the dual-control committer, not here).
// Returns the stored row.
func (s *Store) Set(ctx context.Context, kind string, payload []byte, actor string) (*Row, error) {
	if kind == "" {
		return nil, ErrNoKind
	}
	now := s.now().UTC().UnixNano()
	var out Row
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Read the current version (if any) under the tx so concurrent writers can't
		// race the bump. SQLite is single-writer; Postgres serializes on the row.
		var cur Row
		version := int64(1)
		switch err := tx.First(&cur, "kind = ?", kind).Error; {
		case err == nil:
			version = cur.Version + 1
		case errors.Is(err, gorm.ErrRecordNotFound):
			// first write of this kind — version 1
		default:
			return err
		}
		out = Row{Kind: kind, Payload: payload, Version: version, UpdatedAt: now, UpdatedBy: actor}
		// Upsert: insert on first write, overwrite payload/version/updated_* on update.
		if version == 1 {
			return tx.Create(&out).Error
		}
		return tx.Model(&Row{}).Where("kind = ?", kind).Updates(map[string]any{
			"payload": payload, "version": version, "updated_at": now, "updated_by": actor,
		}).Error
	})
	if err != nil {
		return nil, fmt.Errorf("config: set %s: %w", kind, err)
	}
	if s.audit != nil {
		if aerr := s.audit(ctx, actor, ActionSet, kind, fmt.Sprintf("version=%d bytes=%d", out.Version, len(payload))); aerr != nil {
			return nil, fmt.Errorf("config: set %s: audit: %w", kind, aerr)
		}
	}
	return &out, nil
}

// SeedIfEmpty writes the config for a kind ONLY if no row exists yet — the idempotent
// boot data-migration path (ADR 0011 P1, C8): it carries the live PoC's current
// committed config (the latest committed dual-control change) into the new store so
// nothing is lost on the cutover. It does NOT audit (the seed is a one-time carry,
// distinct from an operator-driven Set) and is a no-op (false, nil) when a row is
// already present, so repeated boots converge. Like Set, it does NOT validate —
// the seeded payload was already validated when it was committed.
func (s *Store) SeedIfEmpty(ctx context.Context, kind string, payload []byte, actor string) (bool, error) {
	if kind == "" {
		return false, ErrNoKind
	}
	now := s.now().UTC().UnixNano()
	seeded := false
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var cur Row
		switch err := tx.First(&cur, "kind = ?", kind).Error; {
		case err == nil:
			return nil // already present — no-op
		case errors.Is(err, gorm.ErrRecordNotFound):
			// fall through to insert
		default:
			return err
		}
		seeded = true
		return tx.Create(&Row{Kind: kind, Payload: payload, Version: 1, UpdatedAt: now, UpdatedBy: actor}).Error
	})
	if err != nil {
		return false, fmt.Errorf("config: seed %s: %w", kind, err)
	}
	return seeded, nil
}
