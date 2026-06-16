// Package store is Harbor's data layer (implementation-plan M2). It runs on
// SQLite for minimal-footprint local dev and Postgres for production from one
// codebase, via GORM with a one-line dialect swap. The pure-Go SQLite driver
// (glebarez/modernc) keeps Harbor a static, cgo-free binary.
//
// Schema is owned by versioned migrations (internal/store/migrate), not by
// GORM AutoMigrate — GORM here is data access only.
package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Config selects the backend. Driver is "sqlite" or "postgres".
type Config struct {
	Driver string
	DSN    string

	// Postgres connection-pool tuning (ignored on SQLite, which is pinned to a single
	// writer). Zero values fall back to sane Aurora-friendly defaults in Open. Set
	// MaxOpenConns so (Cores × MaxOpenConns) stays under Aurora's max_connections.
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration

	// Credentials, when set (postgres only), resolves the username+password at connection
	// time instead of reading them from the DSN. Open then uses a pgx connector that calls
	// it BEFORE EACH physical connection, so a rotated secret (e.g. Aurora's RDS-managed
	// master credential) is picked up automatically — no password ever sits in the DSN, on
	// argv, or on disk. With it set, DSN must carry only host/port/dbname/params (no userinfo).
	Credentials CredentialFunc
}

// CredentialFunc resolves the Postgres login (username, password) on demand. See
// Config.Credentials. It is called once per new physical connection, so implementations
// should cache with a short TTL to avoid hammering the secret store under connection storms.
type CredentialFunc func(ctx context.Context) (user, password string, err error)

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
	var (
		dialector gorm.Dialector
		err       error
	)
	switch cfg.Driver {
	case "sqlite":
		dialector = sqlite.Open(cfg.DSN)
	case "postgres":
		if cfg.Credentials != nil {
			// Resolve user/pass per-connection (rotating secret); password never in the DSN.
			if dialector, err = postgresRotating(cfg.DSN, cfg.Credentials); err != nil {
				return nil, err
			}
		} else {
			dialector = postgres.Open(cfg.DSN)
		}
	default:
		return nil, fmt.Errorf("store: unsupported driver %q (want sqlite|postgres)", cfg.Driver)
	}
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger:                 logger.Default.LogMode(logger.Silent),
		SkipDefaultTransaction: true,
		TranslateError:         true, // surfaces gorm.ErrDuplicatedKey portably (IPAM relies on it)
	})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", cfg.Driver, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	switch cfg.Driver {
	case "sqlite":
		// SQLite is a single-writer engine; one connection avoids spurious
		// "database is locked" under concurrent writers (the IPAM allocator
		// still exercises real INSERT contention via the UNIQUE(ip) guard).
		sqlDB.SetMaxOpenConns(1)
	case "postgres":
		// Production Postgres (Aurora). Bound the pool so (Cores × MaxOpenConns)
		// stays under Aurora's max_connections, keep a few idle connections warm to
		// avoid per-request dial latency, and CAP CONNECTION LIFETIME so connections
		// to a demoted writer are recycled after an Aurora failover (the cluster
		// endpoint re-resolves to the new writer on the next dial).
		maxOpen := cfg.MaxOpenConns
		if maxOpen <= 0 {
			maxOpen = 20
		}
		maxIdle := cfg.MaxIdleConns
		if maxIdle <= 0 {
			maxIdle = 5
		}
		if maxIdle > maxOpen {
			maxIdle = maxOpen
		}
		life := cfg.ConnMaxLifetime
		if life <= 0 {
			life = 30 * time.Minute
		}
		sqlDB.SetMaxOpenConns(maxOpen)
		sqlDB.SetMaxIdleConns(maxIdle)
		sqlDB.SetConnMaxLifetime(life)
	}
	return &Store{DB: db}, nil
}

// postgresRotating builds a GORM Postgres dialector whose connections resolve their
// credentials from cred BEFORE EACH physical connect (pgx BeforeConnect hook). A rotated
// password is therefore picked up on the next new connection (bounded by ConnMaxLifetime)
// without a restart, and the password never lives in the DSN string. dsn must carry only
// host/port/dbname/params — any userinfo in it is overridden by cred.
func postgresRotating(dsn string, cred CredentialFunc) (gorm.Dialector, error) {
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse postgres dsn: %w", err)
	}
	sqlDB := stdlib.OpenDB(*connConfig, stdlib.OptionBeforeConnect(func(ctx context.Context, cc *pgx.ConnConfig) error {
		user, password, err := cred(ctx)
		if err != nil {
			return fmt.Errorf("store: resolve postgres credentials: %w", err)
		}
		cc.User = user
		cc.Password = password
		return nil
	}))
	return postgres.New(postgres.Config{Conn: sqlDB}), nil
}

// IsPostgres reports whether db is backed by Postgres (vs SQLite). It gates the
// Postgres-only HA coordination primitives (advisory locks, SELECT … FOR UPDATE):
// on SQLite the single-writer connection (SetMaxOpenConns(1) above) already
// serializes all writers, so those primitives are unnecessary — and FOR UPDATE
// isn't valid SQLite syntax, so they must not be emitted there.
func IsPostgres(db *gorm.DB) bool { return db.Name() == "postgres" }

// Ping verifies the DB connection is alive — the readiness (/readyz) probe.
func (s *Store) Ping(ctx context.Context) error {
	sqlDB, err := s.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
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
