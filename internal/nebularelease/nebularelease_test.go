package nebularelease_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
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
const sha3 = "2222222222222222222222222222222222222222222222222222222222222222"

func TestAddAssignsMonotonicGenAndListsNewestFirst(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	r1, err := s.Add(ctx, "1.10.0", "", "", sha1, "https://art/1.10.0", "")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Add(ctx, "1.10.3", "", "", sha2, "https://art/1.10.3", "security fix")
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

	// Uppercase sha + surrounding whitespace are normalized; empty arch normalizes
	// to the default platform (the row IS the default artifact).
	r, err := s.Add(ctx, "  1.10.3 ", "", "", "  "+strings.ToUpper(sha1)+"  ", " https://art/x ", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.SHA256 != sha1 || r.Version != "1.10.3" || r.URL != "https://art/x" {
		t.Fatalf("not normalized: %+v", r)
	}
	if r.GOOS != nebularelease.DefaultGOOS || r.GOARCH != nebularelease.DefaultGOARCH {
		t.Fatalf("empty arch must normalize to %s/%s, got %s/%s", nebularelease.DefaultGOOS, nebularelease.DefaultGOARCH, r.GOOS, r.GOARCH)
	}

	for _, bad := range []struct{ v, sha, url string }{
		{"", sha1, "u"},                     // missing version
		{"1", "", "u"},                      // missing sha
		{"1", sha1, ""},                     // missing url
		{"1", "deadbeef", "u"},              // sha too short
		{"1", strings.Repeat("z", 64), "u"}, // non-hex sha
	} {
		if _, err := s.Add(ctx, bad.v, "", "", bad.sha, bad.url, ""); err == nil {
			t.Fatalf("expected ErrInvalid for %+v", bad)
		}
	}
}

func TestLookupAndGenForVersion(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	r, _ := s.Add(ctx, "1.10.3", "", "", sha1, "https://art/1.10.3", "")

	ver, sha, url, ok := s.Lookup(ctx, int(r.Gen), "", "")
	if !ok || ver != "1.10.3" || sha != sha1 || url != "https://art/1.10.3" {
		t.Fatalf("Lookup mismatch: %s %s %s %v", ver, sha, url, ok)
	}
	if _, _, _, ok := s.Lookup(ctx, 9999, "", ""); ok {
		t.Fatal("Lookup of an unknown gen must be ok=false")
	}

	if got := s.GenForVersion(ctx, "1.10.3"); got != int(r.Gen) {
		t.Fatalf("GenForVersion=%d, want %d", got, r.Gen)
	}
	if got := s.GenForVersion(ctx, "0.0.0"); got != 0 {
		t.Fatalf("unknown version must map to gen 0, got %d", got)
	}

	// GenForSHA is the convergence key: exact, case-insensitive, 0 for unknown.
	if got := s.GenForSHA(ctx, sha1); got != int(r.Gen) {
		t.Fatalf("GenForSHA=%d, want %d", got, r.Gen)
	}
	if got := s.GenForSHA(ctx, strings.ToUpper(sha1)); got != int(r.Gen) {
		t.Fatalf("GenForSHA must be case-insensitive, got %d", got)
	}
	if got := s.GenForSHA(ctx, sha2); got != 0 {
		t.Fatalf("unknown sha must map to gen 0, got %d", got)
	}
}

// TestGenForSHADisambiguatesSameVersion is the fix for the review's version-string
// ambiguity: two generations sharing a version string are told apart by their sha,
// so a host running gen 1's binary maps to gen 1 (not the newest gen with that
// version) — the convergence key reflects the actual artifact.
func TestGenForSHADisambiguatesSameVersion(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	g1, _ := s.Add(ctx, "1.10.3", "", "", sha1, "https://art/a", "")
	g2, _ := s.Add(ctx, "1.10.3", "", "", sha2, "https://art/b", "rebuild") // same version, different artifact
	if got := s.GenForSHA(ctx, sha1); got != int(g1.Gen) {
		t.Fatalf("sha1 must map to gen %d, got %d", g1.Gen, got)
	}
	if got := s.GenForSHA(ctx, sha2); got != int(g2.Gen) {
		t.Fatalf("sha2 must map to gen %d, got %d", g2.Gen, got)
	}
	// The version string alone is ambiguous (newest wins) — which is why convergence
	// keys on the sha, not this.
	if got := s.GenForVersion(ctx, "1.10.3"); got != int(g2.Gen) {
		t.Fatalf("GenForVersion ambiguous case = %d, want newest %d", got, g2.Gen)
	}
}

// A re-release of the same version string (new gen) is what a host should converge
// to: GenForVersion returns the newest gen.
func TestGenForVersionNewestWins(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, _ = s.Add(ctx, "1.10.3", "", "", sha1, "https://art/a", "")
	r2, _ := s.Add(ctx, "1.10.3", "", "", sha2, "https://art/b", "rebuild")
	if got := s.GenForVersion(ctx, "1.10.3"); got != int(r2.Gen) {
		t.Fatalf("GenForVersion must return newest gen %d, got %d", r2.Gen, got)
	}
}

func TestMarkCurrentSupersedes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	r1, _ := s.Add(ctx, "1.10.0", "", "", sha1, "https://art/0", "")
	r2, _ := s.Add(ctx, "1.10.3", "", "", sha2, "https://art/3", "")

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

// TestAddArtifactAndPerArchLookup covers the per-arch override path (ADR 0003): a
// generation's parent Release is its default (linux/amd64) artifact, and AddArtifact
// registers additional binaries for other platforms. Lookup resolves a host's reported
// (goos, goarch) to the right artifact — the child's sha/url but the PARENT's version,
// since a per-arch binary is the same generation/version built for another platform.
func TestAddArtifactAndPerArchLookup(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Parent row is the default linux/amd64 artifact for this generation.
	r, err := s.Add(ctx, "1.10.3", "", "", sha1, "https://art/linux-amd64", "")
	if err != nil {
		t.Fatal(err)
	}
	gen := int(r.Gen)

	// (1) AddArtifact happy path, then Lookup for that arch returns the child's
	// sha/url with the parent's version.
	a, err := s.AddArtifact(ctx, gen, "darwin", "arm64", sha2, "https://art/darwin-arm64")
	if err != nil {
		t.Fatalf("AddArtifact darwin/arm64: %v", err)
	}
	if a.VersionID != int64(gen) || a.GOOS != "darwin" || a.GOARCH != "arm64" || a.SHA256 != sha2 {
		t.Fatalf("unexpected artifact: %+v", a)
	}
	ver, sha, url, ok := s.Lookup(ctx, gen, "darwin", "arm64")
	if !ok || ver != "1.10.3" || sha != sha2 || url != "https://art/darwin-arm64" {
		t.Fatalf("per-arch Lookup mismatch: ver=%q sha=%q url=%q ok=%v (want parent version + child sha/url)", ver, sha, url, ok)
	}

	// Artifacts lists the override rows (not the parent default).
	as, err := s.Artifacts(ctx, gen)
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 || as[0].GOOS != "darwin" || as[0].GOARCH != "arm64" {
		t.Fatalf("Artifacts must list only the override row: %+v", as)
	}

	// (2) Lookup with the default platform — both explicit linux/amd64 and empty
	// strings — returns the parent row.
	for _, c := range []struct{ goos, goarch string }{
		{nebularelease.DefaultGOOS, nebularelease.DefaultGOARCH},
		{"", ""},
	} {
		ver, sha, url, ok := s.Lookup(ctx, gen, c.goos, c.goarch)
		if !ok || ver != "1.10.3" || sha != sha1 || url != "https://art/linux-amd64" {
			t.Fatalf("default-platform Lookup(%q,%q) mismatch: ver=%q sha=%q url=%q ok=%v", c.goos, c.goarch, ver, sha, url, ok)
		}
	}

	// (3) Lookup for an arch with no registered artifact returns ok=false, so the
	// caller leaves the host alone rather than serving a wrong-arch binary.
	if _, _, _, ok := s.Lookup(ctx, gen, "windows", "amd64"); ok {
		t.Fatal("Lookup of an arch with no artifact must be ok=false")
	}

	// (4) AddArtifact rejects (goos, goarch) equal to the generation's default
	// platform — that artifact is the parent Release row.
	if _, err := s.AddArtifact(ctx, gen, nebularelease.DefaultGOOS, nebularelease.DefaultGOARCH, sha3, "https://art/dup-default"); !errors.Is(err, nebularelease.ErrInvalid) {
		t.Fatalf("AddArtifact of the default platform must be ErrInvalid, got %v", err)
	}
	// Empty strings normalize to the default platform too — same rejection.
	if _, err := s.AddArtifact(ctx, gen, "", "", sha3, "https://art/dup-default"); !errors.Is(err, nebularelease.ErrInvalid) {
		t.Fatalf("AddArtifact of empty (=> default) platform must be ErrInvalid, got %v", err)
	}

	// (5) AddArtifact rejects a duplicate (gen, goos, goarch) — enforced by the
	// unique index, so this surfaces as a (wrapped) store error rather than ErrInvalid.
	if _, err := s.AddArtifact(ctx, gen, "darwin", "arm64", sha3, "https://art/darwin-arm64-dup"); err == nil {
		t.Fatal("duplicate (gen,goos,goarch) AddArtifact must error")
	}

	// AddArtifact for a non-existent generation is rejected.
	if _, err := s.AddArtifact(ctx, 9999, "darwin", "arm64", sha3, "https://art/x"); !errors.Is(err, nebularelease.ErrInvalid) {
		t.Fatalf("AddArtifact for unknown gen must be ErrInvalid, got %v", err)
	}

	// (6) GenForSHA resolves both the parent sha and the child-artifact sha to this gen.
	if got := s.GenForSHA(ctx, sha1); got != gen {
		t.Fatalf("GenForSHA(parent sha)=%d, want %d", got, gen)
	}
	if got := s.GenForSHA(ctx, sha2); got != gen {
		t.Fatalf("GenForSHA(child artifact sha)=%d, want %d", got, gen)
	}
	// Case-insensitive for the child sha too.
	if got := s.GenForSHA(ctx, strings.ToUpper(sha2)); got != gen {
		t.Fatalf("GenForSHA must be case-insensitive for child sha, got %d", got)
	}
}

func TestServableFleet(t *testing.T) {
	st, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/sf.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := migrate.Up(st.DB); err != nil {
		t.Fatal(err)
	}
	s := nebularelease.New(st.DB)
	ctx := context.Background()

	g, err := s.Add(ctx, "1.0.0", "linux", "amd64", sha1, "https://art/linux-amd64", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddArtifact(ctx, int(g.Gen), "darwin", "arm64", sha2, "https://art/darwin-arm64"); err != nil {
		t.Fatal(err)
	}

	// Seed each host's arch via its (issued) enrollment row.
	enrollAt := func(enrollID, ip, goos, goarch string, createdAt int64) {
		t.Helper()
		e := enrollment.Enrollment{
			EnrollmentID: enrollID, DeviceName: enrollID, PubkeyHash: enrollID, Pubkey: []byte{1},
			Method: "joinkey", Status: "issued", OverlayIP: ip, CreatedAt: createdAt,
			GOOS: goos, GOARCH: goarch,
		}
		if err := st.DB.Create(&e).Error; err != nil {
			t.Fatalf("seed enrollment %s: %v", enrollID, err)
		}
	}
	enroll := func(ip, goos, goarch string) { enrollAt(ip, ip, goos, goarch, 1) }

	enroll("10.0.0.1", "linux", "amd64")   // default platform -> servable
	enroll("10.0.0.2", "darwin", "arm64")  // per-arch artifact -> servable
	enroll("10.0.0.3", "windows", "amd64") // no artifact -> excluded
	enroll("10.0.0.4", "", "")             // empty arch -> linux/amd64 default -> servable
	// 10.0.0.5 has NO issued enrollment -> resolves to the default platform -> servable
	// 10.0.0.6 has TWO issued rows: the LATER (higher-id) row is windows/amd64 (unshipped) but
	// carries an EARLIER created_at than the older linux/amd64 row. Only id-DESC (the resolver Core
	// uses) selects the true-latest row, so the host must be EXCLUDED; a created_at-ASC resolver
	// would wrongly pick linux/amd64 and stage it (the convergence/auto-rollback hazard).
	enrollAt("e6-old", "10.0.0.6", "linux", "amd64", 100) // lower id, later created_at
	enrollAt("e6-new", "10.0.0.6", "windows", "amd64", 1) // higher id, earlier created_at -> latest

	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	servable, excluded, err := s.ServableFleet(ctx, int(g.Gen), ips)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.4", "10.0.0.5"}; strings.Join(servable, ",") != strings.Join(want, ",") {
		t.Errorf("servable = %v, want %v", servable, want)
	}
	if len(excluded) != 2 ||
		excluded[0].OverlayIP != "10.0.0.3" || excluded[0].GOOS != "windows" ||
		excluded[1].OverlayIP != "10.0.0.6" || excluded[1].GOOS != "windows" {
		t.Errorf("excluded = %+v, want [{10.0.0.3 windows amd64} {10.0.0.6 windows amd64}]", excluded)
	}

	if _, _, err := s.ServableFleet(ctx, 9999, ips); err == nil {
		t.Error("ServableFleet on an unknown generation should error")
	}
}
