package signer

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// advisoryClassBreaker namespaces the breaker's pg_advisory_xact_lock (classid) so it
// can't collide with other advisory-lock users (e.g. the audit chain). objid is derived
// from the lane, so distinct lanes don't serialize against each other.
const advisoryClassBreaker = 2

// breakerGCInterval bounds how often acquire sweeps issuance rows older than the window.
const breakerGCInterval = time.Minute

// signerBreakerRow is the per-lane open latch.
type signerBreakerRow struct {
	Lane     string `gorm:"column:lane;primaryKey"`
	Open     bool   `gorm:"column:open"`
	OpenedAt int64  `gorm:"column:opened_at"` // unix nanoseconds
}

func (signerBreakerRow) TableName() string { return "signer_breaker" }

// signerIssuance records one cert issuance for the rolling-window rate count.
type signerIssuance struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Lane string `gorm:"column:lane"`
	TS   int64  `gorm:"column:ts"` // unix nanoseconds
}

func (signerIssuance) TableName() string { return "signer_issuance" }

// SQLBreaker is a shared, DB-backed Breaker: every Core process counts issuances in one
// signer_issuance table and shares one signer_breaker latch row, so the rate ceiling is
// fleet-wide and a trip halts the whole fleet (until an operator resets). On Postgres the
// count→latch step is serialized by a transaction-scoped advisory lock; on SQLite the
// single-writer connection already serializes it.
type SQLBreaker struct {
	db     *gorm.DB
	lane   string
	max    int
	window time.Duration
	now    func() time.Time

	mu     sync.Mutex
	lastGC time.Time
}

// NewSQLBreaker returns a DB-backed breaker for lane (use LaneCA), allowing maxPerWindow
// issuances per window fleet-wide. A non-positive maxPerWindow means "no ceiling" — the
// breaker is a no-op and does no DB work. The signer_breaker/signer_issuance tables must
// already be migrated (internal/store/migrate).
func NewSQLBreaker(db *gorm.DB, lane string, maxPerWindow int, window time.Duration) *SQLBreaker {
	return &SQLBreaker{db: db, lane: lane, max: maxPerWindow, window: window, now: time.Now}
}

func (b *SQLBreaker) limit() int { return b.max }

func (b *SQLBreaker) acquire(ctx context.Context) (allowed, justTripped bool, err error) {
	if b.max <= 0 {
		return true, false, nil // no ceiling configured -> no DB work
	}
	b.maybeGC(ctx)
	txErr := b.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Serialize count→latch across Cores. Postgres: a txn-scoped advisory lock keyed
		// by the lane (auto-released at commit). SQLite: the single writer already does.
		if tx.Name() == "postgres" {
			if e := tx.Exec("SELECT pg_advisory_xact_lock(?, ?)", advisoryClassBreaker, laneKey(b.lane)).Error; e != nil {
				return e
			}
		}
		var row signerBreakerRow
		switch e := tx.Where("lane = ?", b.lane).First(&row).Error; {
		case errors.Is(e, gorm.ErrRecordNotFound):
			row = signerBreakerRow{Lane: b.lane}
		case e != nil:
			return e
		}
		if row.Open {
			allowed, justTripped = false, false
			return nil
		}
		now := b.now().UTC()
		cutoff := now.Add(-b.window).UnixNano()
		var n int64
		if e := tx.Model(&signerIssuance{}).Where("lane = ? AND ts > ?", b.lane, cutoff).Count(&n).Error; e != nil {
			return e
		}
		if n >= int64(b.max) {
			// Breach: latch open (the breaching attempt is rejected, not recorded).
			row.Open = true
			row.OpenedAt = now.UnixNano()
			if e := b.upsertLatch(tx, row); e != nil {
				return e
			}
			allowed, justTripped = false, true
			return nil
		}
		if e := tx.Create(&signerIssuance{Lane: b.lane, TS: now.UnixNano()}).Error; e != nil {
			return e
		}
		allowed, justTripped = true, false
		return nil
	})
	if txErr != nil {
		return false, false, txErr // fail closed
	}
	return allowed, justTripped, nil
}

func (b *SQLBreaker) reset(ctx context.Context) error {
	return b.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if e := tx.Where("lane = ?", b.lane).Delete(&signerIssuance{}).Error; e != nil {
			return e
		}
		return b.upsertLatch(tx, signerBreakerRow{Lane: b.lane, Open: false, OpenedAt: 0})
	})
}

func (b *SQLBreaker) upsertLatch(tx *gorm.DB, row signerBreakerRow) error {
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "lane"}},
		DoUpdates: clause.AssignmentColumns([]string{"open", "opened_at"}),
	}).Create(&row).Error
}

func (b *SQLBreaker) maybeGC(ctx context.Context) {
	b.mu.Lock()
	if !b.lastGC.IsZero() && b.now().Sub(b.lastGC) < breakerGCInterval {
		b.mu.Unlock()
		return
	}
	b.lastGC = b.now()
	b.mu.Unlock()
	cutoff := b.now().UTC().Add(-b.window).UnixNano()
	_ = b.db.WithContext(ctx).Where("lane = ? AND ts < ?", b.lane, cutoff).Delete(&signerIssuance{})
}

// laneKey hashes a lane to an int32 objid for pg_advisory_xact_lock(classid, objid).
func laneKey(lane string) int32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(lane))
	return int32(h.Sum32())
}
