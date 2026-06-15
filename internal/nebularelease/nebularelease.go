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

// Release is one registered nebula version. Gen (the row id) is the generation
// the nebula rollout lane stages.
type Release struct {
	Gen       int64  `gorm:"column:id;primaryKey"`
	Version   string `gorm:"column:version"`
	SHA256    string `gorm:"column:sha256"`
	URL       string `gorm:"column:url"`
	Status    string `gorm:"column:status"`
	Note      string `gorm:"column:note"`
	CreatedAt int64  `gorm:"column:created_at"`
}

// TableName pins the table.
func (Release) TableName() string { return "nebula_versions" }

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

// Add registers a release and returns it with its assigned generation. version,
// sha256 and url are all required; sha256 is normalized to lowercase and must be
// 64 hex chars (a full SHA-256), since it is the integrity anchor the pilot
// enforces before swapping the binary.
func (s *Store) Add(ctx context.Context, version, sha256, url, note string) (Release, error) {
	version = strings.TrimSpace(version)
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	url = strings.TrimSpace(url)
	switch {
	case version == "" || sha256 == "" || url == "":
		return Release{}, fmt.Errorf("%w: version, sha256 and url are all required", ErrInvalid)
	case len(sha256) != 64 || !isHex(sha256):
		return Release{}, fmt.Errorf("%w: sha256 must be 64 hex chars, got %q", ErrInvalid, sha256)
	}
	r := Release{
		Version: version, SHA256: sha256, URL: url,
		Status: StatusCandidate, Note: note, CreatedAt: s.now().UTC().UnixNano(),
	}
	if err := s.db.WithContext(ctx).Create(&r).Error; err != nil {
		return Release{}, fmt.Errorf("nebularelease: add: %w", err)
	}
	return r, nil
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

// Lookup is the coreapi NebulaReleaseSource hook: the (version, sha256, url) tuple
// to stamp for a generation. ok=false for an unknown generation.
func (s *Store) Lookup(ctx context.Context, gen int) (version, sha256, url string, ok bool) {
	r, found := s.Get(ctx, gen)
	if !found {
		return "", "", "", false
	}
	return r.Version, r.SHA256, r.URL, true
}

// GenForVersion maps a running version STRING back to a generation so the rollout
// engine can judge nebula-lane convergence (0 if unknown). When several gens share
// a version string, the newest (highest gen) wins.
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
