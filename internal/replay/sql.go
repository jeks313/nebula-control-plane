package replay

import (
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// gcInterval bounds how often SQLStore.Observe sweeps expired rows, so a busy Core
// doesn't issue a DELETE on every enrollment.
const gcInterval = time.Minute

// nonceReplay is one recorded nonce. The PRIMARY KEY on nonce makes the insert the
// atomic check-and-record: a duplicate insert is a replay.
type nonceReplay struct {
	Nonce     string `gorm:"column:nonce;primaryKey"`
	ExpiresAt int64  `gorm:"column:expires_at"` // unix nanoseconds
}

func (nonceReplay) TableName() string { return "nonce_replays" }

// SQLStore is a shared, DB-backed Observer: an HA Harbor's Core processes all record
// nonces in one nonce_replays table, so single-use is enforced fleet-wide. It works on
// SQLite (dev) and Postgres (prod) alike — INSERT … ON CONFLICT DO NOTHING is the
// atomic check-and-record on both.
type SQLStore struct {
	db  *gorm.DB
	ttl time.Duration
	now func() time.Time

	mu     sync.Mutex
	lastGC time.Time
}

// NewSQLStore returns a DB-backed replay store remembering nonces for ttl. The
// nonce_replays table must already be migrated (internal/store/migrate).
func NewSQLStore(db *gorm.DB, ttl time.Duration) *SQLStore {
	return &SQLStore{db: db, ttl: ttl, now: time.Now}
}

// Observe atomically records the nonce and reports whether this is its first sighting.
// The unique-insert is the guard: 1 row affected => first time (true); a conflict =>
// replay (false). A DB error returns (false, err) so the caller retries rather than
// terminally rejecting a request whose single-use status we couldn't determine.
//
// Verify (freshness) runs before Observe, so an expired nonce never reaches here; a
// conflict therefore always means a genuine replay within the freshness window. Expired
// rows are swept lazily (at most once per gcInterval) only to bound table size.
func (s *SQLStore) Observe(nonce string) (firstTime bool, err error) {
	s.maybeGC()
	row := nonceReplay{Nonce: nonce, ExpiresAt: s.now().UTC().Add(s.ttl).UnixNano()}
	res := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// GC deletes expired rows and returns how many. Safe to call concurrently / on a
// schedule; Observe also calls it lazily.
func (s *SQLStore) GC() (int64, error) {
	res := s.db.Where("expires_at < ?", s.now().UTC().UnixNano()).Delete(&nonceReplay{})
	return res.RowsAffected, res.Error
}

func (s *SQLStore) maybeGC() {
	s.mu.Lock()
	if !s.lastGC.IsZero() && s.now().Sub(s.lastGC) < gcInterval {
		s.mu.Unlock()
		return
	}
	s.lastGC = s.now()
	s.mu.Unlock()
	_, _ = s.GC() // best-effort; a failed sweep just leaves expired rows for next time
}
