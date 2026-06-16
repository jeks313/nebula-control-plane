package replay

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newTestDB(t *testing.T, withTable bool) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if withTable {
		if err := db.Exec(`CREATE TABLE nonce_replays (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)`).Error; err != nil {
			t.Fatalf("create table: %v", err)
		}
	}
	return db
}

func TestSQLStoreDetectsReplay(t *testing.T) {
	s := NewSQLStore(newTestDB(t, true), time.Minute)
	if first, err := s.Observe("n1"); err != nil || !first {
		t.Fatalf("first Observe = (%v, %v), want (true, nil)", first, err)
	}
	if first, err := s.Observe("n1"); err != nil || first {
		t.Fatalf("replay Observe = (%v, %v), want (false, nil)", first, err)
	}
	if first, err := s.Observe("n2"); err != nil || !first {
		t.Fatalf("new nonce Observe = (%v, %v), want (true, nil)", first, err)
	}
}

func TestSQLStoreGC(t *testing.T) {
	s := NewSQLStore(newTestDB(t, true), time.Minute)
	now := time.Now()
	s.now = func() time.Time { return now }
	if _, err := s.Observe("n1"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.GC(); err != nil || n != 0 {
		t.Fatalf("GC before expiry = (%d, %v), want (0, nil)", n, err)
	}
	now = now.Add(2 * time.Minute) // past TTL
	if n, err := s.GC(); err != nil || n != 1 {
		t.Fatalf("GC after expiry = (%d, %v), want (1, nil)", n, err)
	}
	if first, err := s.Observe("n1"); err != nil || !first {
		t.Fatalf("post-GC Observe = (%v, %v), want (true, nil)", first, err)
	}
}

func TestSQLStoreFailsClosedOnError(t *testing.T) {
	// No table => the insert errors; Observe must return (false, err) so the caller
	// retries rather than treating an unrecorded nonce as first-time (which would
	// silently disable replay protection) or as a terminal replay.
	s := NewSQLStore(newTestDB(t, false), time.Minute)
	first, err := s.Observe("n1")
	if err == nil {
		t.Fatal("expected an error when the table is missing")
	}
	if first {
		t.Fatal("on error, firstTime must be false")
	}
}
