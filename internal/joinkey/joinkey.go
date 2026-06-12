// Package joinkey manages join keys — the off-cloud / non-attested enrollment
// credential (design §4.1c, implementation-plan 3.4a). A join key is a bearer
// secret, so it is stored only as a SHA-256 hash, is scoped (groups, sub-range),
// capped (max_uses), expiring, and revocable. auto_issue defaults to false, so a
// join via the key requires manual approval (3.9) unless explicitly opted out.
package joinkey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"gorm.io/gorm"
)

const secretPrefix = "njk_" // nebula join key

// Validation errors.
var (
	ErrNotFound  = errors.New("joinkey: no matching active key")
	ErrExpired   = errors.New("joinkey: key expired")
	ErrExhausted = errors.New("joinkey: key use limit reached")
)

// JoinKey is a stored join key (secret held only as a hash).
type JoinKey struct {
	ID           int64  `gorm:"column:id;primaryKey"`
	Name         string `gorm:"column:name"`
	SecretHash   []byte `gorm:"column:secret_hash"`
	Groups       string `gorm:"column:groups"` // JSON array
	SubRange     string `gorm:"column:sub_range"`
	MaxUses      int    `gorm:"column:max_uses"` // 0 = unlimited
	UsedCount    int    `gorm:"column:used_count"`
	ExpiresAt    int64  `gorm:"column:expires_at"` // unix ns; 0 = none
	AutoIssue    bool   `gorm:"column:auto_issue"`
	Ephemeral    bool   `gorm:"column:ephemeral"`
	QuotaPerHour int    `gorm:"column:quota_per_hour"` // 0 = no rate quota
	State        string `gorm:"column:state"`
	CreatedAt    int64  `gorm:"column:created_at"`
}

func (JoinKey) TableName() string { return "join_keys" }

// GroupList decodes the JSON groups field.
func (k JoinKey) GroupList() []string {
	var g []string
	_ = json.Unmarshal([]byte(k.Groups), &g)
	return g
}

// Params configures a new join key.
type Params struct {
	Name         string
	Groups       []string
	SubRange     string
	MaxUses      int // 0 = unlimited
	TTL          time.Duration
	AutoIssue    bool
	Ephemeral    bool
	QuotaPerHour int // 0 = no rate quota
}

// Create generates a key, stores its hash, and returns the secret ONCE (it
// cannot be recovered later).
func Create(ctx context.Context, s *store.Store, p Params, now time.Time) (secret string, jk JoinKey, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", JoinKey{}, err
	}
	secret = secretPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	groups, _ := json.Marshal(p.Groups)
	var exp int64
	if p.TTL > 0 {
		exp = now.Add(p.TTL).UnixNano()
	}
	jk = JoinKey{
		Name: p.Name, SecretHash: sum[:], Groups: string(groups), SubRange: p.SubRange,
		MaxUses: p.MaxUses, ExpiresAt: exp, AutoIssue: p.AutoIssue, Ephemeral: p.Ephemeral,
		QuotaPerHour: p.QuotaPerHour, State: "active", CreatedAt: now.UnixNano(),
	}
	if err = s.DB.WithContext(ctx).Create(&jk).Error; err != nil {
		return "", JoinKey{}, fmt.Errorf("joinkey: create: %w", err)
	}
	return secret, jk, nil
}

// List returns all join keys (without secrets — only hashes are stored).
func List(ctx context.Context, s *store.Store) ([]JoinKey, error) {
	var keys []JoinKey
	if err := s.DB.WithContext(ctx).Order("id").Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("joinkey: list: %w", err)
	}
	return keys, nil
}

// Revoke marks a key revoked (stops further use; issued certs are unaffected).
func Revoke(ctx context.Context, s *store.Store, name string) error {
	res := s.DB.WithContext(ctx).Model(&JoinKey{}).
		Where("name = ? AND state = ?", name, "active").
		Update("state", "revoked")
	if res.Error != nil {
		return fmt.Errorf("joinkey: revoke: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Lookup validates a presented secret (active, not expired, uses remaining)
// WITHOUT consuming a use — so callers can apply a rate quota (3.10) before
// committing a use.
func Lookup(ctx context.Context, s *store.Store, secret string, now time.Time) (JoinKey, error) {
	sum := sha256.Sum256([]byte(secret))
	var jk JoinKey
	err := s.DB.WithContext(ctx).Where("secret_hash = ? AND state = ?", sum[:], "active").First(&jk).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return JoinKey{}, ErrNotFound
	}
	if err != nil {
		return JoinKey{}, fmt.Errorf("joinkey: lookup: %w", err)
	}
	if jk.ExpiresAt != 0 && now.UnixNano() >= jk.ExpiresAt {
		return JoinKey{}, ErrExpired
	}
	if jk.MaxUses > 0 && jk.UsedCount >= jk.MaxUses {
		return JoinKey{}, ErrExhausted
	}
	return jk, nil
}

// Consume atomically takes one use of a key. The conditional UPDATE makes
// concurrent consumption safe: only one of N racing callers can take the last use.
func Consume(ctx context.Context, s *store.Store, jk JoinKey) error {
	q := s.DB.WithContext(ctx).Model(&JoinKey{}).Where("id = ? AND state = ?", jk.ID, "active")
	if jk.MaxUses > 0 {
		q = q.Where("used_count < ?", jk.MaxUses)
	}
	res := q.UpdateColumn("used_count", gorm.Expr("used_count + 1"))
	if res.Error != nil {
		return fmt.Errorf("joinkey: consume: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrExhausted
	}
	return nil
}

// ValidateAndConsume looks up an active key and atomically consumes one use.
func ValidateAndConsume(ctx context.Context, s *store.Store, secret string, now time.Time) (JoinKey, error) {
	jk, err := Lookup(ctx, s, secret, now)
	if err != nil {
		return JoinKey{}, err
	}
	if err := Consume(ctx, s, jk); err != nil {
		return JoinKey{}, err
	}
	jk.UsedCount++
	return jk, nil
}
