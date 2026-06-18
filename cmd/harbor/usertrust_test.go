package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/ssoassert"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/jeks313/nebula-control-plane/internal/usertrust"
)

func utTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "ut.db"))})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestUserTrustActiveGetterLive: the (cf).userTrustActive getter, wired with
// -usertrust-db, reads the dual-control-published config LIVE — it returns nil before any
// publish (fail closed), then the committed config after, all WITHOUT rebuilding the
// getter (mirroring how a long-running consumer reads it per enrollment).
func TestUserTrustActiveGetterLive(t *testing.T) {
	s := utTestStore(t)

	// Build the getter the consumer would carry, with -usertrust-db on.
	fs := flag.NewFlagSet("core", flag.ContinueOnError)
	cf := addCoreFlags(fs)
	if err := fs.Set("usertrust-db", "true"); err != nil {
		t.Fatal(err)
	}
	getter := cf.userTrustActive(s)
	if getter == nil {
		t.Fatal("userTrustActive should be non-nil with -usertrust-db set")
	}

	// Live read BEFORE any publish: nil => SSO not configured (fail closed).
	if got := getter(); got != nil {
		t.Fatalf("getter should return nil before any publish, got %+v", got)
	}

	cfg := usertrust.Config{
		DefaultGroups: []string{"fleet"},
		IDPEntries: []usertrust.IDPEntry{
			{Realm: "corp", DirectoryGroup: "corp-eng", MeshGroups: []string{"eng"}, AutoIssue: false},
		},
	}
	if _, err := publishUserTrust(s, cfg, "alice", "bob", "test user-trust"); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// The SAME getter now sees the committed config (read live, no rebuild).
	got := getter()
	if got == nil {
		t.Fatal("getter should return the published config after commit")
	}
	if len(got.IDPEntries) != 1 || got.IDPEntries[0].DirectoryGroup != "corp-eng" {
		t.Fatalf("active user-trust = %+v", got)
	}

	// And activeUserTrust agrees (the reader the getter is built on).
	if _, ok := activeUserTrust(context.Background(), s); !ok {
		t.Fatal("activeUserTrust returned not-found after a committed publish")
	}

	// Same operator proposing + approving must be rejected (two-person control).
	if _, err := publishUserTrust(s, cfg, "carol", "carol", "x"); err == nil {
		t.Fatal("expected same-operator publish to be rejected")
	}
}

// TestPublishUserTrust: the `harbor usertrust publish` core — two distinct operators
// commit a config that the active reader AND the -usertrust-db getter then see (closing
// B2: once published, SSO can reach issuance); a same-operator publish is rejected (no
// single-actor bypass). Mirrors TestPublishCloudTrust.
func TestPublishUserTrust(t *testing.T) {
	s := utTestStore(t)
	cfg := usertrust.Config{
		DefaultGroups: []string{"fleet"},
		IDPEntries: []usertrust.IDPEntry{
			{Realm: "corp", DirectoryGroup: "corp-eng", MeshGroups: []string{"eng"}, AutoIssue: true, Netblock: "eng-block"},
		},
	}

	ch, err := publishUserTrust(s, cfg, "alice", "bob", "test config")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if ch.State != "committed" {
		t.Fatalf("change state = %s, want committed", ch.State)
	}

	got, ok := activeUserTrust(context.Background(), s)
	if !ok {
		t.Fatal("activeUserTrust returned not-found after a committed publish")
	}
	if len(got.IDPEntries) != 1 || got.IDPEntries[0].DirectoryGroup != "corp-eng" || !got.IDPEntries[0].AutoIssue {
		t.Fatalf("active config = %+v", got)
	}
	if len(got.DefaultGroups) != 1 || got.DefaultGroups[0] != "fleet" {
		t.Fatalf("active default groups = %v", got.DefaultGroups)
	}

	// The -usertrust-db getter — the seam SSO issuance reads (enrollment.Config
	// .UserTrustActive) — now returns the published config (B2 closed).
	fs := flag.NewFlagSet("core", flag.ContinueOnError)
	cf := addCoreFlags(fs)
	if err := fs.Set("usertrust-db", "true"); err != nil {
		t.Fatal(err)
	}
	if live := cf.userTrustActive(s)(); live == nil || len(live.IDPEntries) != 1 {
		t.Fatalf("UserTrustActive getter = %+v after publish, want the committed config", live)
	}

	// Same operator proposing and approving must be rejected (two-person control).
	if _, err := publishUserTrust(s, cfg, "carol", "carol", "x"); err == nil {
		t.Fatal("expected same-operator publish to be rejected (no self-approve)")
	}

	// A config with a DUPLICATE (realm, directory_group) is rejected by the committer's
	// Validate (S3 AD-group uniqueness) — it never commits.
	dup := usertrust.Config{
		DefaultGroups: []string{"fleet"},
		IDPEntries: []usertrust.IDPEntry{
			{Realm: "corp", DirectoryGroup: "corp-eng", MeshGroups: []string{"eng"}},
			{Realm: "corp", DirectoryGroup: "corp-eng", MeshGroups: []string{"ops"}},
		},
	}
	if _, err := publishUserTrust(s, dup, "alice", "bob", "dup"); err == nil {
		t.Fatal("expected a duplicate (realm, directory_group) publish to be rejected by Validate")
	}
}

// TestActiveUserTrustResilientOnDBError is the FIX A acceptance (security-review final
// hardening): activeUserTrust is the LIVE per-enrollment read on a long-running harbor
// process, so a transient DB error must NOT exit the process — it must return not-found so
// SSO fails closed (ErrSSONotConfigured) rather than crashing the control plane. Closing the
// store's connection pool forces a LatestCommitted DB error; the getter must return nil, not
// os.Exit. (If it still called fatalf, this test would terminate the test binary.)
func TestActiveUserTrustResilientOnDBError(t *testing.T) {
	s := utTestStore(t)
	// Force a transient DB error on the next read by closing the connection pool.
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	if _, ok := activeUserTrust(context.Background(), s); ok {
		t.Fatal("activeUserTrust should report not-found on a DB error (fail closed), not ok")
	}

	// The live getter built on top of it must also degrade to nil, not exit.
	fs := flag.NewFlagSet("core", flag.ContinueOnError)
	cf := addCoreFlags(fs)
	if err := fs.Set("usertrust-db", "true"); err != nil {
		t.Fatal(err)
	}
	if got := cf.userTrustActive(s)(); got != nil {
		t.Fatalf("getter should return nil on a DB error (fail closed), got %+v", got)
	}
}

// TestUserTrustActiveDisabledWithoutFlag: without -usertrust-db, the getter is nil (SSO
// disabled at this consumer regardless of what is published) — fail closed.
func TestUserTrustActiveDisabledWithoutFlag(t *testing.T) {
	s := utTestStore(t)
	fs := flag.NewFlagSet("core", flag.ContinueOnError)
	cf := addCoreFlags(fs)
	if getter := cf.userTrustActive(s); getter != nil {
		t.Fatal("userTrustActive should be nil without -usertrust-db")
	}
}

// TestAssertionVerifyKeyPinned: -sso-assert-pub PEM (genesis sso-assert.pub) parses into
// the pinned public key the consumer pins; unset -> nil (SSO denied, fail closed).
func TestAssertionVerifyKeyPinned(t *testing.T) {
	// Unset -> nil.
	fs := flag.NewFlagSet("core", flag.ContinueOnError)
	cf := addCoreFlags(fs)
	if cf.assertionVerifyKey() != nil {
		t.Fatal("assertionVerifyKey should be nil when -sso-assert-pub is unset")
	}

	// A genesis-shaped public PEM parses and round-trips to the same key.
	priv, err := ssoassert.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := ssoassert.MarshalPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sso-assert.pub")
	if err := os.WriteFile(path, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	fs2 := flag.NewFlagSet("core", flag.ContinueOnError)
	cf2 := addCoreFlags(fs2)
	if err := fs2.Set("sso-assert-pub", path); err != nil {
		t.Fatal(err)
	}
	pub := cf2.assertionVerifyKey()
	if pub == nil {
		t.Fatal("assertionVerifyKey should be non-nil with -sso-assert-pub set")
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Fatal("pinned key does not match the generated key")
	}
}
