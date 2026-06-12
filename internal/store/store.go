// Package store is Harbor's data layer (implementation-plan M2). It runs on
// SQLite for minimal-footprint local dev and Postgres for production from one
// codebase, via GORM with a one-line dialect swap. The pure-Go SQLite driver
// (glebarez/modernc) keeps Harbor a static, cgo-free binary.
//
// Schema is owned by versioned migrations (internal/store/migrate), not by
// GORM AutoMigrate — GORM here is data access only.
package store

import (
	"fmt"
	"sync"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Config selects the backend. Driver is "sqlite" or "postgres".
type Config struct {
	Driver string
	DSN    string
}

// DefaultSQLiteDSN returns a sensible local-dev DSN for a real on-disk file:
// foreign keys on, a busy timeout so brief write contention waits instead of
// erroring. Note: a plain path (no "file:" URI prefix) — the pure-Go driver
// treats some "file:…?…" forms as in-memory, which silently loses data across
// connections.
func DefaultSQLiteDSN(path string) string {
	return path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
}

// Store wraps the DB handle and serializes audit appends (the chain has a single
// logical writer; see AppendAudit).
type Store struct {
	DB *gorm.DB

	auditMu sync.Mutex
}

// Open connects using the configured dialect. The schema must already be
// migrated (see internal/store/migrate).
func Open(cfg Config) (*Store, error) {
	var dialector gorm.Dialector
	switch cfg.Driver {
	case "sqlite":
		dialector = sqlite.Open(cfg.DSN)
	case "postgres":
		dialector = postgres.Open(cfg.DSN)
	default:
		return nil, fmt.Errorf("store: unsupported driver %q (want sqlite|postgres)", cfg.Driver)
	}
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger:                 logger.Default.LogMode(logger.Silent),
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", cfg.Driver, err)
	}
	return &Store{DB: db}, nil
}

// Close releases the underlying connection pool.
func (s *Store) Close() error {
	sqlDB, err := s.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Key is a reference to a signing key. Private material lives in the backend
// (KMS/HSM), never here.
type Key struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	Name      string `gorm:"column:name"`
	Kind      string `gorm:"column:kind"`
	Backend   string `gorm:"column:backend"`
	URI       string `gorm:"column:uri"`
	Curve     string `gorm:"column:curve"`
	PublicKey []byte `gorm:"column:public_key"`
	State     string `gorm:"column:state"`
	CreatedAt int64  `gorm:"column:created_at"` // unix nanoseconds
}

// TableName pins the table name (GORM would otherwise pluralize to "keys"
// anyway, but be explicit).
func (Key) TableName() string { return "keys" }

// Audit is one hash-chained audit row. See audit.go for the chain semantics.
type Audit struct {
	Seq      int64  `gorm:"column:seq;primaryKey"`
	TS       int64  `gorm:"column:ts"` // unix nanoseconds
	Actor    string `gorm:"column:actor"`
	Action   string `gorm:"column:action"`
	Target   string `gorm:"column:target"`
	Details  string `gorm:"column:details"`
	PrevHash []byte `gorm:"column:prev_hash"`
	Hash     []byte `gorm:"column:hash"`
}

func (Audit) TableName() string { return "audit_log" }
