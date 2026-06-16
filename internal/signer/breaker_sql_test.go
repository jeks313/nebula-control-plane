package signer

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newBreakerDB(t *testing.T, withTables bool) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if withTables {
		for _, ddl := range []string{
			`CREATE TABLE signer_breaker (lane TEXT PRIMARY KEY, open INTEGER NOT NULL DEFAULT 0, opened_at INTEGER NOT NULL DEFAULT 0)`,
			`CREATE TABLE signer_issuance (id INTEGER PRIMARY KEY AUTOINCREMENT, lane TEXT NOT NULL, ts INTEGER NOT NULL)`,
		} {
			if err := db.Exec(ddl).Error; err != nil {
				t.Fatalf("ddl: %v", err)
			}
		}
	}
	return db
}

func TestSQLBreakerTripsAndResets(t *testing.T) {
	ctx := context.Background()
	b := NewSQLBreaker(newBreakerDB(t, true), LaneCA, 3, time.Hour)

	for i := 0; i < 3; i++ {
		allowed, tripped, err := b.acquire(ctx)
		if err != nil || !allowed || tripped {
			t.Fatalf("acquire %d = (%v,%v,%v), want (true,false,nil)", i, allowed, tripped, err)
		}
	}
	// The 4th breaches the ceiling: refused, and justTripped exactly once.
	allowed, tripped, err := b.acquire(ctx)
	if err != nil || allowed || !tripped {
		t.Fatalf("4th acquire = (%v,%v,%v), want (false,true,nil)", allowed, tripped, err)
	}
	// The 5th is still refused but must NOT re-trip (latched).
	allowed, tripped, err = b.acquire(ctx)
	if err != nil || allowed || tripped {
		t.Fatalf("5th acquire = (%v,%v,%v), want (false,false,nil)", allowed, tripped, err)
	}
	// Reset re-arms.
	if err := b.reset(ctx); err != nil {
		t.Fatalf("reset: %v", err)
	}
	allowed, tripped, err = b.acquire(ctx)
	if err != nil || !allowed || tripped {
		t.Fatalf("post-reset acquire = (%v,%v,%v), want (true,false,nil)", allowed, tripped, err)
	}
}

func TestSQLBreakerWindowExpiry(t *testing.T) {
	ctx := context.Background()
	b := NewSQLBreaker(newBreakerDB(t, true), LaneCA, 2, time.Hour)
	now := time.Now()
	b.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		if a, _, err := b.acquire(ctx); err != nil || !a {
			t.Fatalf("acquire %d: allowed=%v err=%v", i, a, err)
		}
	}
	// Past the window the old issuances no longer count, so it allows again (no trip).
	now = now.Add(2 * time.Hour)
	if a, tr, err := b.acquire(ctx); err != nil || !a || tr {
		t.Fatalf("post-window acquire = (%v,%v,%v), want (true,false,nil)", a, tr, err)
	}
}

func TestSQLBreakerNoLimit(t *testing.T) {
	// max<=0 means no ceiling and no DB work — must not error even with no tables.
	b := NewSQLBreaker(newBreakerDB(t, false), LaneCA, 0, time.Hour)
	if a, tr, err := b.acquire(context.Background()); err != nil || !a || tr {
		t.Fatalf("no-limit acquire = (%v,%v,%v), want (true,false,nil)", a, tr, err)
	}
}

func TestSQLBreakerFailsClosed(t *testing.T) {
	// A configured ceiling with missing tables must fail CLOSED (halt), not allow.
	b := NewSQLBreaker(newBreakerDB(t, false), LaneCA, 3, time.Hour)
	a, _, err := b.acquire(context.Background())
	if err == nil {
		t.Fatal("expected an error when tables are missing")
	}
	if a {
		t.Fatal("on error, allowed must be false (fail closed)")
	}
}
