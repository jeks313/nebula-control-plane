package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
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

// publishUserTrust commits a user-trust config via dual-control (propose as opA, approve
// as the distinct opB), mirroring publishCloudTrust. The committer re-parses at commit.
func publishUserTrust(s *store.Store, cfg usertrust.Config, opA, opB string) (dualcontrol.Change, error) {
	ctx := context.Background()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	dc := dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit})
	usertrust.RegisterCommitter(dc)
	payload, _ := json.Marshal(cfg)
	ch, err := dc.Propose(ctx, usertrust.PublishKind, "test user-trust", payload, opA)
	if err != nil {
		return dualcontrol.Change{}, err
	}
	return dc.Approve(ctx, ch.ID, opB)
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
	if _, err := publishUserTrust(s, cfg, "alice", "bob"); err != nil {
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
	if _, err := publishUserTrust(s, cfg, "carol", "carol"); err == nil {
		t.Fatal("expected same-operator publish to be rejected")
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
