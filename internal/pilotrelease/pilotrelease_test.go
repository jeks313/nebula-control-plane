package pilotrelease_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
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
const sha3 = "2222222222222222222222222222222222222222222222222222222222222222"
const sha4 = "3333333333333333333333333333333333333333333333333333333333333333"

func TestAddListGenForSHA(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Empty goos/goarch normalize to the default platform (linux/amd64).
	r1, err := s.Add(ctx, "2.0.0", "", "", sha1, "https://art/pilot/2.0.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if r1.Status != pilotrelease.StatusCandidate {
		t.Fatalf("new release should be a candidate, got %q", r1.Status)
	}
	if r1.GOOS != pilotrelease.DefaultGOOS || r1.GOARCH != pilotrelease.DefaultGOARCH {
		t.Fatalf("empty arch must normalize to %s/%s, got %s/%s",
			pilotrelease.DefaultGOOS, pilotrelease.DefaultGOARCH, r1.GOOS, r1.GOARCH)
	}
	r2, _ := s.Add(ctx, "2.1.0", "", "", sha2, "https://art/pilot/2.1.0", "")
	if list, _ := s.List(ctx); len(list) != 2 || list[0].Gen != r2.Gen {
		t.Fatalf("List must be newest-first: %+v", list)
	}

	// The default-platform lookup returns the parent row.
	ver, sha, url, ok := s.Lookup(ctx, int(r1.Gen), "", "")
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
		if _, err := s.Add(ctx, bad.v, "", "", bad.sha, bad.url, ""); err == nil {
			t.Fatalf("expected ErrInvalid for %+v", bad)
		}
	}
}

// --- per-arch artifact coverage (ADR 0003 per-arch release URLs) ---

// TestAddArtifactRegistersOtherPlatform: a per-arch child binary is registered for an
// existing generation, normalizes its arch, and is reported by Artifacts (which lists only
// the children, not the parent default), ordered by goos,goarch.
func TestAddArtifactRegistersOtherPlatform(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	r, err := s.Add(ctx, "2.0.0", "", "", sha1, "https://art/pilot/2.0.0/linux-amd64", "")
	if err != nil {
		t.Fatal(err)
	}

	// Uppercase sha + whitespace are normalized like Add.
	a, err := s.AddArtifact(ctx, int(r.Gen), "DARWIN", " arm64 ", "  "+strings.ToUpper(sha2)+"  ", " https://art/pilot/2.0.0/darwin-arm64 ")
	if err != nil {
		t.Fatal(err)
	}
	if a.VersionID != r.Gen || a.GOOS != "darwin" || a.GOARCH != "arm64" ||
		a.SHA256 != sha2 || a.URL != "https://art/pilot/2.0.0/darwin-arm64" {
		t.Fatalf("artifact not normalized/linked: %+v", a)
	}

	// A second platform, registered out of sort order, to prove Artifacts orders by goos,goarch.
	if _, err := s.AddArtifact(ctx, int(r.Gen), "linux", "arm64", sha3, "https://art/pilot/2.0.0/linux-arm64"); err != nil {
		t.Fatal(err)
	}
	arts, err := s.Artifacts(ctx, int(r.Gen))
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 2 {
		t.Fatalf("Artifacts must list only the children (not the parent default), got %d: %+v", len(arts), arts)
	}
	if arts[0].GOOS != "darwin" || arts[0].GOARCH != "arm64" || arts[1].GOOS != "linux" || arts[1].GOARCH != "arm64" {
		t.Fatalf("Artifacts must be ordered by goos,goarch: %+v", arts)
	}
}

// TestAddArtifactValidates: AddArtifact wraps ErrInvalid for a bad sha, a missing generation,
// a (goos,goarch) equal to the generation's default platform, and a duplicate per-arch row.
func TestAddArtifactValidates(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	r, err := s.Add(ctx, "2.0.0", "", "", sha1, "https://art/pilot/2.0.0", "")
	if err != nil {
		t.Fatal(err)
	}

	// Bad sha (not 64 hex).
	if _, err := s.AddArtifact(ctx, int(r.Gen), "darwin", "arm64", "deadbeef", "u"); !errors.Is(err, pilotrelease.ErrInvalid) {
		t.Fatalf("short sha must wrap ErrInvalid, got %v", err)
	}
	// Non-existent generation.
	if _, err := s.AddArtifact(ctx, 9999, "darwin", "arm64", sha2, "u"); !errors.Is(err, pilotrelease.ErrInvalid) {
		t.Fatalf("missing generation must wrap ErrInvalid, got %v", err)
	}
	// (goos,goarch) equal to the gen's DEFAULT platform — empty normalizes to linux/amd64,
	// which is exactly the parent's platform.
	if _, err := s.AddArtifact(ctx, int(r.Gen), "", "", sha2, "u"); !errors.Is(err, pilotrelease.ErrInvalid) {
		t.Fatalf("default-platform artifact must wrap ErrInvalid, got %v", err)
	}
	if _, err := s.AddArtifact(ctx, int(r.Gen), "linux", "amd64", sha2, "u"); !errors.Is(err, pilotrelease.ErrInvalid) {
		t.Fatalf("explicit default-platform artifact must wrap ErrInvalid, got %v", err)
	}
	// Duplicate (gen, goos, goarch).
	if _, err := s.AddArtifact(ctx, int(r.Gen), "darwin", "arm64", sha2, "https://art/d-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddArtifact(ctx, int(r.Gen), "darwin", "arm64", sha3, "https://art/d-a-2"); err == nil {
		t.Fatal("duplicate (gen,goos,goarch) must error")
	}
}

// TestLookupDefaultPlatform: the default-arch lookup (and the empty/legacy arch that
// normalizes to it) resolves to the PARENT release's (version, sha256, url).
func TestLookupDefaultPlatform(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	r, _ := s.Add(ctx, "2.0.0", "linux", "amd64", sha1, "https://art/pilot/2.0.0/linux-amd64", "")
	// A darwin/arm64 child exists, but it must not be returned for the default platform.
	if _, err := s.AddArtifact(ctx, int(r.Gen), "darwin", "arm64", sha2, "https://art/pilot/2.0.0/darwin-arm64"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ goos, goarch string }{
		{"linux", "amd64"}, // explicit default
		{"", ""},           // legacy/empty host -> normalizes to default
		{"LINUX", "AMD64"}, // case-insensitive
	} {
		ver, sha, url, ok := s.Lookup(ctx, int(r.Gen), tc.goos, tc.goarch)
		if !ok || ver != "2.0.0" || sha != sha1 || url != "https://art/pilot/2.0.0/linux-amd64" {
			t.Fatalf("default lookup for %q/%q = %s %s %s %v, want the parent row", tc.goos, tc.goarch, ver, sha, url, ok)
		}
	}
}

// TestLookupChildArtifact: a non-default arch with a registered child returns the PARENT's
// version but the CHILD's (sha256, url) — one staged generation, per-arch binaries.
func TestLookupChildArtifact(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	r, _ := s.Add(ctx, "2.0.0", "", "", sha1, "https://art/pilot/2.0.0/linux-amd64", "")
	if _, err := s.AddArtifact(ctx, int(r.Gen), "darwin", "arm64", sha2, "https://art/pilot/2.0.0/darwin-arm64"); err != nil {
		t.Fatal(err)
	}

	ver, sha, url, ok := s.Lookup(ctx, int(r.Gen), "darwin", "arm64")
	if !ok || ver != "2.0.0" || sha != sha2 || url != "https://art/pilot/2.0.0/darwin-arm64" {
		t.Fatalf("child lookup = %s %s %s %v, want parent version + child sha/url", ver, sha, url, ok)
	}
}

// TestLookupMissingArch: an arch with NO registered artifact in this generation returns
// ok=false (so coreapi leaves the host on its current binary rather than serving a wrong
// arch), even though the generation exists for the default platform.
func TestLookupMissingArch(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	r, _ := s.Add(ctx, "2.0.0", "", "", sha1, "https://art/pilot/2.0.0", "")

	if _, _, _, ok := s.Lookup(ctx, int(r.Gen), "windows", "arm64"); ok {
		t.Fatal("Lookup of an unregistered arch in an existing generation must be ok=false")
	}
	// And an unknown generation is still ok=false for any arch.
	if _, _, _, ok := s.Lookup(ctx, 9999, "darwin", "arm64"); ok {
		t.Fatal("Lookup of an unknown generation must be ok=false")
	}
}

// TestGenForSHAMatchesChildArtifact: GenForSHA maps both the default (parent) sha and a
// per-arch CHILD sha back to the same generation axis; newest gen wins on collision.
func TestGenForSHAMatchesChildArtifact(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	g1, _ := s.Add(ctx, "2.0.0", "", "", sha1, "https://art/pilot/2.0.0", "")
	if _, err := s.AddArtifact(ctx, int(g1.Gen), "darwin", "arm64", sha2, "https://art/pilot/2.0.0/darwin-arm64"); err != nil {
		t.Fatal(err)
	}

	if got := s.GenForSHA(ctx, sha1); got != int(g1.Gen) {
		t.Fatalf("parent sha must map to gen %d, got %d", g1.Gen, got)
	}
	// A child artifact's sha maps to its parent generation.
	if got := s.GenForSHA(ctx, strings.ToUpper(sha2)); got != int(g1.Gen) {
		t.Fatalf("child sha must map to its parent gen %d (case-insensitive), got %d", g1.Gen, got)
	}

	// Newest gen wins when a sha is reused as a child of a later generation.
	g2, _ := s.Add(ctx, "2.1.0", "", "", sha3, "https://art/pilot/2.1.0", "")
	if _, err := s.AddArtifact(ctx, int(g2.Gen), "linux", "arm64", sha4, "https://art/pilot/2.1.0/linux-arm64"); err != nil {
		t.Fatal(err)
	}
	if got := s.GenForSHA(ctx, sha4); got != int(g2.Gen) {
		t.Fatalf("child sha of newest gen must map to gen %d, got %d", g2.Gen, got)
	}
	if got := s.GenForSHA(ctx, sha2); got != int(g1.Gen) {
		t.Fatalf("earlier child sha must still map to gen %d, got %d", g1.Gen, got)
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
	s := pilotrelease.New(st.DB)
	ctx := context.Background()

	g, err := s.Add(ctx, "1.0.0", "linux", "amd64", sha1, "https://art/linux-amd64", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddArtifact(ctx, int(g.Gen), "darwin", "arm64", sha2, "https://art/darwin-arm64"); err != nil {
		t.Fatal(err)
	}

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
