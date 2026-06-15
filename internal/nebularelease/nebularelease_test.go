package nebularelease_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/nebularelease"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func newStore(t *testing.T) *nebularelease.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/n.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	return nebularelease.New(s.DB)
}

const sha1 = "99ac335caeb69d02a6b6b00a3d4b5d0a36ec3971df480a1cc50e6db378342955"
const sha2 = "1111111111111111111111111111111111111111111111111111111111111111"

func TestAddAssignsMonotonicGenAndListsNewestFirst(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	r1, err := s.Add(ctx, "1.10.0", sha1, "https://art/1.10.0", "")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Add(ctx, "1.10.3", sha2, "https://art/1.10.3", "security fix")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Gen <= r1.Gen {
		t.Fatalf("gen must be monotonic: r1=%d r2=%d", r1.Gen, r2.Gen)
	}
	if r1.Status != nebularelease.StatusCandidate {
		t.Fatalf("new release should be a candidate, got %q", r1.Status)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Gen != r2.Gen || list[1].Gen != r1.Gen {
		t.Fatalf("List must be newest-first: %+v", list)
	}
}

func TestAddNormalizesAndValidates(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Uppercase sha + surrounding whitespace are normalized.
	r, err := s.Add(ctx, "  1.10.3 ", "  "+strings.ToUpper(sha1)+"  ", " https://art/x ", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.SHA256 != sha1 || r.Version != "1.10.3" || r.URL != "https://art/x" {
		t.Fatalf("not normalized: %+v", r)
	}

	for _, bad := range []struct{ v, sha, url string }{
		{"", sha1, "u"},                     // missing version
		{"1", "", "u"},                      // missing sha
		{"1", sha1, ""},                     // missing url
		{"1", "deadbeef", "u"},              // sha too short
		{"1", strings.Repeat("z", 64), "u"}, // non-hex sha
	} {
		if _, err := s.Add(ctx, bad.v, bad.sha, bad.url, ""); err == nil {
			t.Fatalf("expected ErrInvalid for %+v", bad)
		}
	}
}

func TestLookupAndGenForVersion(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	r, _ := s.Add(ctx, "1.10.3", sha1, "https://art/1.10.3", "")

	ver, sha, url, ok := s.Lookup(ctx, int(r.Gen))
	if !ok || ver != "1.10.3" || sha != sha1 || url != "https://art/1.10.3" {
		t.Fatalf("Lookup mismatch: %s %s %s %v", ver, sha, url, ok)
	}
	if _, _, _, ok := s.Lookup(ctx, 9999); ok {
		t.Fatal("Lookup of an unknown gen must be ok=false")
	}

	if got := s.GenForVersion(ctx, "1.10.3"); got != int(r.Gen) {
		t.Fatalf("GenForVersion=%d, want %d", got, r.Gen)
	}
	if got := s.GenForVersion(ctx, "0.0.0"); got != 0 {
		t.Fatalf("unknown version must map to gen 0, got %d", got)
	}
}

// A re-release of the same version string (new gen) is what a host should converge
// to: GenForVersion returns the newest gen.
func TestGenForVersionNewestWins(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, _ = s.Add(ctx, "1.10.3", sha1, "https://art/a", "")
	r2, _ := s.Add(ctx, "1.10.3", sha2, "https://art/b", "rebuild")
	if got := s.GenForVersion(ctx, "1.10.3"); got != int(r2.Gen) {
		t.Fatalf("GenForVersion must return newest gen %d, got %d", r2.Gen, got)
	}
}

func TestMarkCurrentSupersedes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	r1, _ := s.Add(ctx, "1.10.0", sha1, "https://art/0", "")
	r2, _ := s.Add(ctx, "1.10.3", sha2, "https://art/3", "")

	if err := s.MarkCurrent(ctx, int(r1.Gen)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, int(r1.Gen)); got.Status != nebularelease.StatusCurrent {
		t.Fatalf("r1 should be current, got %q", got.Status)
	}
	// Promoting r2 supersedes r1.
	if err := s.MarkCurrent(ctx, int(r2.Gen)); err != nil {
		t.Fatal(err)
	}
	got1, _ := s.Get(ctx, int(r1.Gen))
	got2, _ := s.Get(ctx, int(r2.Gen))
	if got2.Status != nebularelease.StatusCurrent || got1.Status != nebularelease.StatusSuperseded {
		t.Fatalf("after promote r2: r1=%q r2=%q", got1.Status, got2.Status)
	}
}
