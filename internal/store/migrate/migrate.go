// Package migrate runs Harbor's versioned schema migrations (implementation-plan
// M2.1) over the single GORM connection, so it works on SQLite (local,
// minimal-footprint dev) and Postgres (prod) without pulling a second SQLite
// driver. Up and Down both work, so "migrations apply/rollback cleanly" is
// testable in CI.
//
// We use gormigrate (rides the GORM connection) rather than golang-migrate: the
// latter's sqlite driver blank-imports modernc.org/sqlite, which collides with
// the pure-Go GORM sqlite driver (both register the "sqlite" name). Each
// migration's SQL still lives in dialect-specific files, selected at run time by
// the connection's dialect.
package migrate

import (
	"embed"
	"fmt"
	"strings"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

//go:embed sql
var files embed.FS

// migrations is the ordered list. Add new entries with a new ID; never edit a
// shipped one.
var migrations = []*gormigrate.Migration{
	sqlMigration("000001_init"),
}

// Up applies all pending migrations.
func Up(db *gorm.DB) error {
	m := gormigrate.New(db, gormigrate.DefaultOptions, migrations)
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// Down rolls every migration back, latest first (the M2.1 rollback path).
func Down(db *gorm.DB) error {
	m := gormigrate.New(db, gormigrate.DefaultOptions, migrations)
	for i := len(migrations) - 1; i >= 0; i-- {
		if err := m.RollbackMigration(migrations[i]); err != nil {
			return fmt.Errorf("migrate down %s: %w", migrations[i].ID, err)
		}
	}
	return nil
}

// sqlMigration builds a migration whose up/down SQL is read from the embedded
// per-dialect files at run time.
func sqlMigration(id string) *gormigrate.Migration {
	return &gormigrate.Migration{
		ID:       id,
		Migrate:  func(tx *gorm.DB) error { return execSQL(tx, id, "up") },
		Rollback: func(tx *gorm.DB) error { return execSQL(tx, id, "down") },
	}
}

func execSQL(tx *gorm.DB, id, dir string) error {
	name := fmt.Sprintf("sql/%s/%s.%s.sql", tx.Dialector.Name(), id, dir)
	b, err := files.ReadFile(name)
	if err != nil {
		return fmt.Errorf("no migration %s: %w", name, err)
	}
	for _, stmt := range strings.Split(string(b), ";") {
		if isBlank(stmt) {
			continue
		}
		if err := tx.Exec(stmt).Error; err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// isBlank reports whether a statement is only whitespace and/or -- comments.
func isBlank(stmt string) bool {
	for _, line := range strings.Split(stmt, "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "--") {
			return false
		}
	}
	return true
}
