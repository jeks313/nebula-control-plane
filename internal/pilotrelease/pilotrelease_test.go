package pilotrelease_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/pilotrelease"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func newStore(t *testing.T) *pilotrelease.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/p.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	return pilotrelease.New(s.DB)
}

const sha1 = "99ac335caeb69d02a6b6b00a3d4b5d0a36ec3971df480a1cc50e6db378342955"
const sha2 = "1111111111111111111111111111111111111111111111111111111111111111"

func TestAddListGenForSHA(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	r1, err := s.Add(ctx, "2.0.0", sha1, "https://art/pilot/2.0.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if r1.Status != pilotrelease.StatusCandidate {
		t.Fatalf("new release should be a candidate, got %q", r1.Status)
	}
	r2, _ := s.Add(ctx, "2.1.0", sha2, "https://art/pilot/2.1.0", "")
	if list, _ := s.List(ctx); len(list) != 2 || list[0].Gen != r2.Gen {
		t.Fatalf("List must be newest-first: %+v", list)
	}

	ver, sha, url, ok := s.Lookup(ctx, int(r1.Gen))
	if !ok || ver != "2.0.0" || sha != sha1 || url != "https://art/pilot/2.0.0" {
		t.Fatalf("Lookup mismatch: %s %s %s %v", ver, sha, url, ok)
	}
	// GenForSHA is the convergence key: exact, case-insensitive, 0 for unknown.
	if got := s.GenForSHA(ctx, strings.ToUpper(sha1)); got != int(r1.Gen) {
		t.Fatalf("GenForSHA(sha1)=%d, want %d", got, r1.Gen)
	}
	if got := s.GenForSHA(ctx, "deadbeef"); got != 0 {
		t.Fatalf("unknown sha must map to 0, got %d", got)
	}
}

func TestAddValidates(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, bad := range []struct{ v, sha, url string }{
		{"", sha1, "u"}, {"1", "", "u"}, {"1", sha1, ""}, {"1", "deadbeef", "u"},
	} {
		if _, err := s.Add(ctx, bad.v, bad.sha, bad.url, ""); err == nil {
			t.Fatalf("expected ErrInvalid for %+v", bad)
		}
	}
}
