// Package nebularelease is Harbor's registry of nebula (data-plane) releases it
// can distribute (ADR 0003 Phase 1c). Each release has a monotonic GENERATION
// (gen) — the row id — that the rollout engine's "nebula" lane stages across the
// fleet exactly like a bundle version. The (version, sha256, url) tuple is stamped
// per-host into the signed bundle; a pilot fetches the artifact, verifies it
// against sha256 (the integrity anchor — the url/CDN need not be trusted), and
// atomically swaps the binary (Phase 1b).
//
// The registry is the catalog a console lists and an operator manages. It owns
// only the catalog; the staging/convergence/rollback state lives on the rollout
// engine's nebula lane, and which generation a given host should run is decided
// there (rollout.Engine.NebulaGenFor) — not here.
package nebularelease

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Release lifecycle status. The registry is a catalog; these reflect where a
// release sits relative to the live fleet, set as nebula rollouts settle.
const (
	StatusCandidate  = "candidate"  // registered; never (successfully) rolled out
	StatusCurrent    = "current"    // the live fleet-desired release (at most one)
	StatusSuperseded = "superseded" // a former current
)

// Default platform: the parent Release row IS the artifact for this (goos, goarch), and a
// host whose reported arch is empty/unknown is resolved as if it were this platform — so
// pre-arch enrollments and legacy pilots keep getting the default artifact (no behavior
// change). Other platforms for a generation live in the Artifact child table.
const (
	DefaultGOOS   = "linux"
	DefaultGOARCH = "amd64"
)

// Release is one registered nebula version. Gen (the row id) is the generation the nebula
// rollout lane stages. GOOS/GOARCH are the platform of the row's own (SHA256, URL) — the
// DEFAULT artifact; additional platforms for this generation are Artifact rows.
type Release struct {
	Gen       int64  `gorm:"column:id;primaryKey"`
	Version   string `gorm:"column:version"`
	SHA256    string `gorm:"column:sha256"`
	URL       string `gorm:"column:url"`
	GOOS      string `gorm:"column:goos"`
	GOARCH    string `gorm:"column:goarch"`
	Status    string `gorm:"column:status"`
	Note      string `gorm:"column:note"`
	CreatedAt int64  `gorm:"column:created_at"`
}

// TableName pins the table.
func (Release) TableName() string { return "nebula_versions" }

// Artifact is a per-arch binary for a generation other than the parent Release's default
// platform: same generation + version, a different (goos, goarch) → (sha256, url). The pilot
// fetches the one matching its own runtime.GOOS/GOARCH.
type Artifact struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	VersionID int64  `gorm:"column:version_id"` // the generation (nebula_versions.id) this belongs to
	GOOS      string `gorm:"column:goos"`
	GOARCH    string `gorm:"column:goarch"`
	SHA256    string `gorm:"column:sha256"`
	URL       string `gorm:"column:url"`
	CreatedAt int64  `gorm:"column:created_at"`
}

// TableName pins the table.
func (Artifact) TableName() string { return "nebula_artifacts" }

// normArch lower-cases + trims a (goos, goarch) and maps an empty pair component to the
// historical default, so an unknown/legacy host resolves to the linux/amd64 default artifact.
func normArch(goos, goarch string) (string, string) {
	goos = strings.ToLower(strings.TrimSpace(goos))
	goarch = strings.ToLower(strings.TrimSpace(goarch))
	if goos == "" {
		goos = DefaultGOOS
	}
	if goarch == "" {
		goarch = DefaultGOARCH
	}
	return goos, goarch
}

// ErrInvalid is returned by Add for a malformed release.
var ErrInvalid = errors.New("nebularelease: invalid release")

// Store is the registry over the DB.
type Store struct {
	db  *gorm.DB
	now func() time.Time
}

// New builds a Store.
func New(db *gorm.DB) *Store { return &Store{db: db, now: time.Now} }

// SetClock overrides the clock (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// Add registers a release and returns it with its assigned generation. version, sha256 and
// url are all required; sha256 is normalized to lowercase and must be 64 hex chars (a full
// SHA-256), since it is the integrity anchor the pilot enforces before swapping the binary.
// goos/goarch are the platform of this (sha256, url) — the generation's DEFAULT artifact;
// empty -> linux/amd64 (the historical default). Register additional platforms for the same
// generation with AddArtifact.
func (s *Store) Add(ctx context.Context, version, goos, goarch, sha256, url, note string) (Release, error) {
	version = strings.TrimSpace(version)
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	url = strings.TrimSpace(url)
	goos, goarch = normArch(goos, goarch)
	switch {
	case version == "" || sha256 == "" || url == "":
		return Release{}, fmt.Errorf("%w: version, sha256 and url are all required", ErrInvalid)
	case len(sha256) != 64 || !isHex(sha256):
		return Release{}, fmt.Errorf("%w: sha256 must be 64 hex chars, got %q", ErrInvalid, sha256)
	}
	r := Release{
		Version: version, SHA256: sha256, URL: url, GOOS: goos, GOARCH: goarch,
		Status: StatusCandidate, Note: note, CreatedAt: s.now().UTC().UnixNano(),
	}
	if err := s.db.WithContext(ctx).Create(&r).Error; err != nil {
		return Release{}, fmt.Errorf("nebularelease: add: %w", err)
	}
	return r, nil
}

// AddArtifact registers an ADDITIONAL per-arch binary for an existing generation: same gen
// (and version), a different (goos, goarch). It refuses a (goos, goarch) that equals the
// generation's default platform (that artifact is the parent Release row) and refuses a
// duplicate (goos, goarch) for the gen (enforced by a unique index too). sha256 is validated
// like Add's.
func (s *Store) AddArtifact(ctx context.Context, gen int, goos, goarch, sha256, url string) (Artifact, error) {
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	url = strings.TrimSpace(url)
	goos, goarch = normArch(goos, goarch)
	switch {
	case sha256 == "" || url == "":
		return Artifact{}, fmt.Errorf("%w: sha256 and url are required", ErrInvalid)
	case len(sha256) != 64 || !isHex(sha256):
		return Artifact{}, fmt.Errorf("%w: sha256 must be 64 hex chars, got %q", ErrInvalid, sha256)
	}
	r, found := s.Get(ctx, gen)
	if !found {
		return Artifact{}, fmt.Errorf("%w: no such generation %d", ErrInvalid, gen)
	}
	if dgoos, dgoarch := normArch(r.GOOS, r.GOARCH); goos == dgoos && goarch == dgoarch {
		return Artifact{}, fmt.Errorf("%w: %s/%s is the default artifact for generation %d (registered with `add`)", ErrInvalid, goos, goarch, gen)
	}
	a := Artifact{
		VersionID: int64(gen), GOOS: goos, GOARCH: goarch, SHA256: sha256, URL: url,
		CreatedAt: s.now().UTC().UnixNano(),
	}
	if err := s.db.WithContext(ctx).Create(&a).Error; err != nil {
		return Artifact{}, fmt.Errorf("nebularelease: add-artifact: %w", err)
	}
	return a, nil
}

// Artifacts returns the per-arch override artifacts for a generation (NOT the parent default),
// oldest first. Use Get for the default artifact (the parent Release's own goos/goarch).
func (s *Store) Artifacts(ctx context.Context, gen int) ([]Artifact, error) {
	var as []Artifact
	if err := s.db.WithContext(ctx).Where("version_id = ?", gen).Order("goos, goarch").Find(&as).Error; err != nil {
		return nil, fmt.Errorf("nebularelease: artifacts: %w", err)
	}
	return as, nil
}

// ExcludedHost is a fleet host left out of a rollout because the generation does not ship its
// architecture (the arch the host reported on its enrollment row).
type ExcludedHost struct {
	OverlayIP string
	GOOS      string
	GOARCH    string
}

// ServableFleet partitions fleet overlay IPs into the hosts this generation can serve and the
// hosts it cannot, BY ARCH (ADR 0003 per-arch URL support): a host is servable when its recorded
// platform matches the generation's default platform or one of its per-arch artifacts. A host with
// no recorded arch (empty — e.g. a pre-arch enrollment) resolves to the linux/amd64 default. The
// release-rollout entry points call this to apply ARCH AFFINITY before wave assignment, so a host
// whose arch the generation does not ship is never staged — which would otherwise strand the
// rollout and trip its observe-window auto-rollback. Input `ips` order is preserved in servable.
//
// Host arch lives on the enrollment row; this reads it directly (a single query, latest enrollment
// at an overlay IP wins) to keep the catalog the one place that knows per-arch servability.
func (s *Store) ServableFleet(ctx context.Context, gen int, ips []string) (servable []string, excluded []ExcludedHost, err error) {
	r, found := s.Get(ctx, gen)
	if !found {
		return nil, nil, fmt.Errorf("nebularelease: servable fleet: no such generation %d", gen)
	}
	set := map[[2]string]bool{}
	dgoos, dgoarch := normArch(r.GOOS, r.GOARCH)
	set[[2]string{dgoos, dgoarch}] = true
	arts, err := s.Artifacts(ctx, gen)
	if err != nil {
		return nil, nil, err
	}
	for _, a := range arts {
		g, h := normArch(a.GOOS, a.GOARCH)
		set[[2]string{g, h}] = true
	}
	archOf := map[string][2]string{}
	if len(ips) > 0 {
		var rows []struct {
			OverlayIP string `gorm:"column:overlay_ip"`
			GOOS      string `gorm:"column:goos"`
			GOARCH    string `gorm:"column:goarch"`
		}
		// Authoritative arch = the host's LATEST issued enrollment, resolved the SAME way Core
		// resolves a device (coreapi.device(): status='issued', id DESC, first row). id is the
		// monotonic AUTOINCREMENT, so id-DESC + first-wins is clock-skew-proof and picks the exact
		// row whose goos/goarch Core stamps into the bundle — created_at is app wall-clock and not
		// guaranteed monotonic across re-enrolls. (overlay_ip is NOT unique: a re-enroll adds a row.)
		if e := s.db.WithContext(ctx).Table("enrollments").Select("overlay_ip, goos, goarch").
			Where("overlay_ip IN ? AND status = ?", ips, "issued").Order("id DESC").Scan(&rows).Error; e != nil {
			return nil, nil, fmt.Errorf("nebularelease: servable fleet: read host arch: %w", e)
		}
		for _, rw := range rows { // id DESC => the FIRST row seen per IP is its latest issued enrollment
			if _, seen := archOf[rw.OverlayIP]; seen {
				continue
			}
			g, h := normArch(rw.GOOS, rw.GOARCH)
			archOf[rw.OverlayIP] = [2]string{g, h}
		}
	}
	dflt := [2]string{DefaultGOOS, DefaultGOARCH}
	for _, ip := range ips {
		a, ok := archOf[ip]
		if !ok {
			a = dflt // a live host with no enrollment arch (legacy / pre-feature) => default platform
		}
		if set[a] {
			servable = append(servable, ip)
		} else {
			excluded = append(excluded, ExcludedHost{OverlayIP: ip, GOOS: a[0], GOARCH: a[1]})
		}
	}
	return servable, excluded, nil
}

// List returns all releases, newest generation first.
func (s *Store) List(ctx context.Context) ([]Release, error) {
	var rs []Release
	if err := s.db.WithContext(ctx).Order("id DESC").Find(&rs).Error; err != nil {
		return nil, fmt.Errorf("nebularelease: list: %w", err)
	}
	return rs, nil
}

// Get returns the release at a generation.
func (s *Store) Get(ctx context.Context, gen int) (Release, bool) {
	var r Release
	if err := s.db.WithContext(ctx).Where("id = ?", gen).First(&r).Error; err != nil {
		return Release{}, false
	}
	return r, true
}

// Lookup is the coreapi NebulaReleaseSource hook: the (version, sha256, url) tuple to stamp
// for a generation AND a host's (goos, goarch). It returns the matching ARTIFACT — the parent
// Release when the arch is the generation's default platform, else the per-arch Artifact row.
// ok=false for an unknown generation OR an arch with no registered artifact in this generation
// (so the caller leaves the host on its current binary rather than serving a wrong-arch one).
// An empty/unknown (goos, goarch) resolves to the linux/amd64 default (normArch).
func (s *Store) Lookup(ctx context.Context, gen int, goos, goarch string) (version, sha256, url string, ok bool) {
	r, found := s.Get(ctx, gen)
	if !found {
		return "", "", "", false
	}
	goos, goarch = normArch(goos, goarch)
	if dgoos, dgoarch := normArch(r.GOOS, r.GOARCH); goos == dgoos && goarch == dgoarch {
		return r.Version, r.SHA256, r.URL, true // the default artifact (the parent row)
	}
	var a Artifact
	if err := s.db.WithContext(ctx).Where("version_id = ? AND goos = ? AND goarch = ?", gen, goos, goarch).First(&a).Error; err != nil {
		return "", "", "", false // no artifact for this arch in this generation
	}
	return r.Version, a.SHA256, a.URL, true
}

// GenForSHA maps a running binary's SHA-256 back to a generation (0 if unknown). The sha is
// the artifact's identity, so this is unambiguous even across rebuilds that share a version
// string — the convergence key the rollout engine uses (1c). A sha may be a generation's
// default artifact (a nebula_versions row) OR a per-arch one (a nebula_artifacts row); both
// map to the same generation axis. When several gens share a sha, the newest wins.
func (s *Store) GenForSHA(ctx context.Context, sha256 string) int {
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if sha256 == "" {
		return 0
	}
	gen := 0
	var r Release
	if err := s.db.WithContext(ctx).Where("sha256 = ?", sha256).Order("id DESC").First(&r).Error; err == nil {
		gen = int(r.Gen)
	}
	var a Artifact
	if err := s.db.WithContext(ctx).Where("sha256 = ?", sha256).Order("version_id DESC").First(&a).Error; err == nil {
		if int(a.VersionID) > gen {
			gen = int(a.VersionID)
		}
	}
	return gen
}

// GenForVersion maps a running version STRING back to a generation (0 if unknown).
// Display/diagnostic use only — version strings are NOT unique across rebuilds, so
// convergence keys on the sha (GenForSHA) instead. When several gens share a version
// string, the newest (highest gen) wins.
func (s *Store) GenForVersion(ctx context.Context, version string) int {
	version = strings.TrimSpace(version)
	if version == "" {
		return 0
	}
	var r Release
	if err := s.db.WithContext(ctx).Where("version = ?", version).Order("id DESC").First(&r).Error; err != nil {
		return 0
	}
	return int(r.Gen)
}

// MarkCurrent flips gen to 'current' and any prior 'current' to 'superseded'. It is
// called when a nebula rollout completes, so the catalog reflects the live fleet.
func (s *Store) MarkCurrent(ctx context.Context, gen int) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Release{}).Where("status = ? AND id <> ?", StatusCurrent, gen).
			Update("status", StatusSuperseded).Error; err != nil {
			return err
		}
		return tx.Model(&Release{}).Where("id = ?", gen).Update("status", StatusCurrent).Error
	})
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
