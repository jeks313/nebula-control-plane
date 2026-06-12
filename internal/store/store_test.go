package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// newTestStore migrates a fresh temp SQLite DB and opens a Store on it.
func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "harbor.db")
	dsn := DefaultSQLiteDSN(path)
	s, err := Open(Config{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := migrate.Up(s.DB); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dsn
}

// TestMigrateUpDown is the M2.1 acceptance: migrations apply and roll back
// cleanly. After Up the tables accept writes; after Down they're gone.
func TestMigrateUpDown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "harbor.db")
	dsn := DefaultSQLiteDSN(path)
	s, err := Open(Config{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := migrate.Up(s.DB); err != nil {
		t.Fatalf("up: %v", err)
	}
	if err := s.DB.Create(&Key{Name: "ca", Kind: "ca", Backend: "softhsm", CreatedAt: 1}).Error; err != nil {
		t.Fatalf("insert into migrated schema failed: %v", err)
	}
	s.Close()

	// Reopen a *fresh* connection to prove the migration persisted to the file
	// (guards against accidentally opening an in-memory DB).
	s2, err := Open(Config{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	var got Key
	if err := s2.DB.First(&got, "name = ?", "ca").Error; err != nil {
		t.Fatalf("migrated row not visible on a fresh connection (in-memory DB?): %v", err)
	}

	if err := migrate.Down(s2.DB); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := s2.DB.Create(&Key{Name: "x", Kind: "ca", Backend: "softhsm", CreatedAt: 1}).Error; err == nil {
		t.Fatal("expected insert to fail after Down (table should be gone)")
	}
	s2.Close()
}

// TestAuditChainVerifies is part of M2.2: a well-formed chain verifies.
func TestAuditChainVerifies(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	first, err := s.AppendAudit(ctx, "alice", "issue-cert", "device-1", `{"ip":"100.64.0.5"}`)
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq != 1 {
		t.Fatalf("first seq = %d, want 1", first.Seq)
	}
	for i := 0; i < 4; i++ {
		if _, err := s.AppendAudit(ctx, "bob", "rotate", "key-ca", ""); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.VerifyAudit(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 5 {
		t.Fatalf("verified %d rows, want 5", n)
	}
}

// TestAuditTamperDetected is the M2.2 acceptance: mutating a row breaks
// verification.
func TestAuditTamperDetected(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := s.AppendAudit(ctx, "alice", "action", "t", "ok"); err != nil {
			t.Fatal(err)
		}
	}

	// Mutate row 2's content directly, behind the chain's back.
	if err := s.DB.Exec("UPDATE audit_log SET actor = ? WHERE seq = ?", "mallory", 2).Error; err != nil {
		t.Fatal(err)
	}

	n, err := s.VerifyAudit(ctx)
	if err == nil {
		t.Fatal("expected verification to fail after tampering")
	}
	if n != 1 {
		t.Fatalf("verified %d rows before detecting tamper, want 1", n)
	}
}

// TestAuditDeletionDetected: removing a row leaves a sequence gap the verifier
// catches (truncating the *latest* rows is only catchable against the WORM
// anchor, M2.13 — documented, not tested here).
func TestAuditDeletionDetected(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := s.AppendAudit(ctx, "a", "x", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DB.Exec("DELETE FROM audit_log WHERE seq = ?", 2).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAudit(ctx); err == nil {
		t.Fatal("expected verification to fail after deleting a middle row")
	}
}
