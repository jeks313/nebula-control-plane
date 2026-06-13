package adminauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"gorm.io/gorm"
)

// tokenPrefix marks Harbor admin tokens so secret scanners can spot a leak.
const tokenPrefix = "harbor_"

// ErrNoToken means the bearer token is absent, unknown, expired, or revoked.
var ErrNoToken = errors.New("adminauth: no valid admin token")

// AdminToken is a non-interactive machine credential for the admin API. The raw
// token is never stored; ID is hex(sha256(token)).
type AdminToken struct {
	ID         string `gorm:"column:id;primaryKey"`
	Name       string `gorm:"column:name"`
	Principal  string `gorm:"column:principal"`
	Roles      string `gorm:"column:roles"` // JSON array
	CreatedBy  string `gorm:"column:created_by"`
	CreatedAt  int64  `gorm:"column:created_at"`
	ExpiresAt  int64  `gorm:"column:expires_at"`   // 0 = never
	LastUsedAt int64  `gorm:"column:last_used_at"` // 0 = never used
	RevokedAt  int64  `gorm:"column:revoked_at"`   // 0 = active
}

// TableName pins the GORM table.
func (AdminToken) TableName() string { return "admin_tokens" }

// TokenStore mints, resolves, lists, and revokes admin tokens.
type TokenStore struct {
	db  *gorm.DB
	now func() time.Time
}

// NewTokenStore builds a token store over the shared GORM connection.
func NewTokenStore(db *gorm.DB, now func() time.Time) *TokenStore {
	if now == nil {
		now = time.Now
	}
	return &TokenStore{db: db, now: now}
}

// Mint creates a token and returns the raw secret (shown ONCE). roles scope what
// the token can do; ttl == 0 means it never expires. principal defaults to
// "token:<name>" so the audit trail shows a token acted.
func (s *TokenStore) Mint(ctx context.Context, name, principal string, roles []string, createdBy string, ttl time.Duration) (string, AdminToken, error) {
	if strings.TrimSpace(name) == "" {
		return "", AdminToken{}, errors.New("adminauth: token name is required")
	}
	secret, err := randToken()
	if err != nil {
		return "", AdminToken{}, err
	}
	token := tokenPrefix + secret
	if principal == "" {
		principal = "token:" + name
	}
	rolesJSON, err := json.Marshal(nonNil(roles))
	if err != nil {
		return "", AdminToken{}, fmt.Errorf("adminauth: marshal roles: %w", err)
	}
	now := s.now()
	var exp int64
	if ttl > 0 {
		exp = now.Add(ttl).UnixNano()
	}
	row := AdminToken{
		ID: hashToken(token), Name: name, Principal: principal, Roles: string(rolesJSON),
		CreatedBy: createdBy, CreatedAt: now.UnixNano(), ExpiresAt: exp,
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return "", AdminToken{}, fmt.Errorf("adminauth: create token: %w", err)
	}
	return token, row, nil
}

// Lookup resolves a raw bearer token to its (active, unexpired) row and bumps
// last_used (throttled, best-effort). Returns ErrNoToken otherwise.
func (s *TokenStore) Lookup(ctx context.Context, token string) (AdminToken, error) {
	if token == "" {
		return AdminToken{}, ErrNoToken
	}
	var row AdminToken
	err := s.db.WithContext(ctx).Where("id = ?", hashToken(token)).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AdminToken{}, ErrNoToken
	}
	if err != nil {
		return AdminToken{}, fmt.Errorf("adminauth: lookup token: %w", err)
	}
	now := s.now().UnixNano()
	if row.RevokedAt != 0 || (row.ExpiresAt != 0 && now >= row.ExpiresAt) {
		return AdminToken{}, ErrNoToken
	}
	// Throttle last_used writes so high-QPS automation doesn't hammer the row.
	if now-row.LastUsedAt > int64(time.Minute) {
		_ = s.db.WithContext(ctx).Model(&AdminToken{}).Where("id = ?", row.ID).
			Update("last_used_at", now).Error // best-effort; never fail auth on this
	}
	return row, nil
}

// List returns all tokens (active and revoked) newest-first, for `admin-token list`.
func (s *TokenStore) List(ctx context.Context) ([]AdminToken, error) {
	var rows []AdminToken
	if err := s.db.WithContext(ctx).Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("adminauth: list tokens: %w", err)
	}
	return rows, nil
}

// Revoke marks every ACTIVE token of the given name revoked and returns the count.
func (s *TokenStore) Revoke(ctx context.Context, name string) (int64, error) {
	res := s.db.WithContext(ctx).Model(&AdminToken{}).
		Where("name = ? AND revoked_at = 0", name).
		Update("revoked_at", s.now().UnixNano())
	if res.Error != nil {
		return 0, fmt.Errorf("adminauth: revoke token: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// Active reports whether the token row is currently usable (helper for views).
func (t AdminToken) Active(now time.Time) bool {
	return t.RevokedAt == 0 && (t.ExpiresAt == 0 || now.UnixNano() < t.ExpiresAt)
}

func (t AdminToken) RoleList() []string {
	var roles []string
	_ = json.Unmarshal([]byte(t.Roles), &roles)
	return nonNil(roles)
}

// TokenProvider authenticates admin API requests from an `Authorization: Bearer`
// token. It implements adminapi.IdentityProvider. A token never carries MFA, so
// MFAAt is always nil — tokens cannot satisfy step-up MFA (no machine approval of
// dual-control changes).
type TokenProvider struct {
	store *TokenStore
}

// NewTokenProvider builds the bearer-token IdentityProvider.
func NewTokenProvider(store *TokenStore) *TokenProvider { return &TokenProvider{store: store} }

// Identify implements adminapi.IdentityProvider.
func (p *TokenProvider) Identify(r *http.Request) (adminapi.Identity, bool) {
	tok := bearerToken(r)
	if tok == "" {
		return adminapi.Identity{}, false
	}
	row, err := p.store.Lookup(r.Context(), tok)
	if err != nil {
		return adminapi.Identity{}, false
	}
	return adminapi.Identity{Principal: row.Principal, Roles: row.RoleList(), MFAAt: nil}, true
}

// bearerToken extracts a "Bearer <token>" value from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// compile-time: TokenProvider satisfies the admin API seam.
var _ adminapi.IdentityProvider = (*TokenProvider)(nil)
