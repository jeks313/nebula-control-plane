// Package gatewayhealth persists the runtime health of each pull-based enrollment
// gateway (ADR 0005). harbor-collect's poll loop Records the outcome of every cycle
// (one row per gateway, keyed by name); admin-api Lists the rows to drive the console's
// Gateways dashboard pane. A wedged gateway — claim timing out, no successful cycle —
// surfaces as a stale LastSuccessAt + a climbing ConsecutiveFailures, which is exactly
// the signal that was invisible during the 2026-06-28 gateway TLS-wedge outage.
//
// Single-writer per gateway (the collect loop drains gateways sequentially), so the
// caller owns the consecutive-failure count and Record just upserts absolute values —
// no cross-dialect counter expression needed. last_success_at persists across a collect
// restart, so staleness detection survives even though the in-memory counter resets.
package gatewayhealth

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// errMax bounds the stored error string so a pathological error can't bloat the row.
const errMax = 500

// Health is one gateway's persisted runtime health (table gateway_health).
type Health struct {
	GatewayName         string `gorm:"column:gateway_name;primaryKey" json:"gateway_name"`
	LastAttemptAt       int64  `gorm:"column:last_attempt_at" json:"last_attempt_at"`
	LastSuccessAt       int64  `gorm:"column:last_success_at" json:"last_success_at"`
	LastError           string `gorm:"column:last_error" json:"last_error"`
	LastErrorAt         int64  `gorm:"column:last_error_at" json:"last_error_at"`
	ConsecutiveFailures int64  `gorm:"column:consecutive_failures" json:"consecutive_failures"`
	UpdatedAt           int64  `gorm:"column:updated_at" json:"updated_at"`
}

// TableName pins the table.
func (Health) TableName() string { return "gateway_health" }

// Store reads/writes gateway health.
type Store struct{ db *gorm.DB }

// New builds a Store.
func New(db *gorm.DB) *Store { return &Store{db: db} }

// Record upserts a gateway's health after a collect cycle. ok=true stamps last_success_at
// and clears the error; ok=false stamps the error. consecutiveFailures is the absolute
// count the caller maintains (0 on success).
func (s *Store) Record(ctx context.Context, gateway string, ok bool, lastErr string, consecutiveFailures int, at time.Time) error {
	now := at.UnixNano()
	if len(lastErr) > errMax {
		lastErr = lastErr[:errMax]
	}
	row := Health{GatewayName: gateway, LastAttemptAt: now, ConsecutiveFailures: int64(consecutiveFailures), UpdatedAt: now}
	assigns := map[string]any{"last_attempt_at": now, "consecutive_failures": int64(consecutiveFailures), "updated_at": now}
	if ok {
		row.LastSuccessAt = now
		assigns["last_success_at"] = now
		assigns["last_error"] = "" // clear the prior error so a recovered gateway shows clean
	} else {
		row.LastError, row.LastErrorAt = lastErr, now
		assigns["last_error"] = lastErr
		assigns["last_error_at"] = now
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "gateway_name"}},
		DoUpdates: clause.Assignments(assigns),
	}).Create(&row).Error
}

// List returns every gateway_health row keyed by gateway name.
func (s *Store) List(ctx context.Context) (map[string]Health, error) {
	var rows []Health
	if err := s.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]Health, len(rows))
	for _, r := range rows {
		out[r.GatewayName] = r
	}
	return out, nil
}
