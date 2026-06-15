// Package pilotrelease is Harbor's registry of pilot (agent) releases it can
// distribute (ADR 0003 Phase 3c) — the mirror of internal/nebularelease for the pilot
// binary. Each release has a monotonic GENERATION (the row id) the rollout engine's
// "pilot" lane canary-stages across the fleet; the (version, sha256, url) tuple is
// stamped per-host into the signed bundle, and a pilot fetches+verifies (against
// sha256, the integrity anchor)+re-execs into it (Phase 3b).
//
// (Intentionally parallel to nebularelease rather than a shared generic, to keep the
// tested nebula path untouched; a future DRY pass could unify them.)
package pilotrelease

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Release lifecycle status.
const (
	StatusCandidate  = "candidate"  // registered; never (successfully) rolled out
	StatusCurrent    = "current"    // the live fleet-desired release (at most one)
	StatusSuperseded = "superseded" // a former current
)

// Release is one registered pilot version. Gen (the row id) is the generation the
// pilot rollout lane stages.
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
func (Release) TableName() string { return "pilot_versions" }

// ErrInvalid is returned by Add for a malformed release.
var ErrInvalid = errors.New("pilotrelease: invalid release")

// Store is the registry over the DB.
type Store struct {
	db  *gorm.DB
	now func() time.Time
}

// New builds a Store.
func New(db *gorm.DB) *Store { return &Store{db: db, now: time.Now} }

// SetClock overrides the clock (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// Add registers a release and returns it with its assigned generation. version, sha256
// and url are all required; sha256 is normalized to lowercase and must be 64 hex chars
// (the integrity anchor the pilot enforces before swapping its own binary).
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
		return Release{}, fmt.Errorf("pilotrelease: add: %w", err)
	}
	return r, nil
}

// List returns all releases, newest generation first.
func (s *Store) List(ctx context.Context) ([]Release, error) {
	var rs []Release
	if err := s.db.WithContext(ctx).Order("id DESC").Find(&rs).Error; err != nil {
		return nil, fmt.Errorf("pilotrelease: list: %w", err)
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

// Lookup is the coreapi ReleaseSource hook: the (version, sha256, url) tuple to stamp
// for a generation. ok=false for an unknown generation.
func (s *Store) Lookup(ctx context.Context, gen int) (version, sha256, url string, ok bool) {
	r, found := s.Get(ctx, gen)
	if !found {
		return "", "", "", false
	}
	return r.Version, r.SHA256, r.URL, true
}

// GenForSHA maps a running binary's SHA-256 back to a generation (0 if unknown) — the
// convergence key (the artifact's identity, unambiguous across rebuilds).
func (s *Store) GenForSHA(ctx context.Context, sha256 string) int {
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if sha256 == "" {
		return 0
	}
	var r Release
	if err := s.db.WithContext(ctx).Where("sha256 = ?", sha256).Order("id DESC").First(&r).Error; err != nil {
		return 0
	}
	return int(r.Gen)
}

// MarkCurrent flips gen to 'current' and any prior 'current' to 'superseded'.
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
