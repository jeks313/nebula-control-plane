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
	sqlMigration("000002_ipam"),
	sqlMigration("000003_enroll"),
	sqlMigration("000004_joinkey_quota"),
	sqlMigration("000005_heartbeats"),
	sqlMigration("000006_approvals"),
	sqlMigration("000007_lighthouses"),
	sqlMigration("000008_rollouts"),
	sqlMigration("000009_sessions"),
	sqlMigration("000010_admin_tokens"),
	sqlMigration("000011_enroll_evidence"),
	sqlMigration("000012_enroll_overlay_index"),
	sqlMigration("000013_revocations"),
	sqlMigration("000014_blocklist_propagation"),
	sqlMigration("000015_gateways"),
	sqlMigration("000016_nebula_releases"),
	sqlMigration("000017_pilot_releases"),
	sqlMigration("000018_nonce_replays"),
	sqlMigration("000019_signer_breaker"),
	sqlMigration("000020_release_per_arch"),
	sqlMigration("000021_host_arch"),
	sqlMigration("000022_ipam_netblocks"),
	sqlMigration("000023_ip_allocation_provenance"),
	sqlMigration("000024_heartbeats_lastseen_index"),
	sqlMigration("000025_enroll_ephemeral"),
	sqlMigration("000026_device_reaped"),
	sqlMigration("000027_config_store"),
	sqlMigration("000028_lighthouse_rotation_status"),
	sqlMigration("000029_enrollment_sub_range"),
	sqlMigration("000030_group_reassignment"),
	sqlMigration("000031_gateway_health"),
	sqlMigration("000032_ca_certs"),
	sqlMigration("000033_heartbeat_trusted_cas"),
	sqlMigration("000034_enrollment_ca_fingerprint"),
	sqlMigration("000035_ca_force_renew"),
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
	name := fmt.Sprintf("sql/%s/%s.%s.sql", tx.Name(), id, dir)
	b, err := files.ReadFile(name)
	if err != nil {
		return fmt.Errorf("no migration %s: %w", name, err)
	}
	// Strip line comments first, so a semicolon inside a `-- comment` can't
	// split a statement in two.
	for _, stmt := range strings.Split(stripLineComments(string(b)), ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if err := tx.Exec(stmt).Error; err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func stripLineComments(sql string) string {
	var sb strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String()
}
