// Package adminauth is Harbor's admin authentication layer (implementation-plan
// 2.11 "admin SSO"). It turns any external IdP login into one of Harbor's own
// server-side sessions and resolves that session back to an adminapi.Identity on
// every request — so the admin API stays a thin consumer of the existing
// IdentityProvider seam and never learns which protocol authenticated the human.
//
// The design is deliberately protocol-agnostic (bring-your-own-IdP). An
// Authenticator plugin runs ONLY at login; OIDC, GitHub OAuth, the in-process
// mock IdP, and SAML (later) all reduce a login to a Subject, which Harbor maps to
// roles and stores as a Session. Per-request auth is then just a cookie lookup.
//
// Security posture: the cookie carries a high-entropy random token; the store
// keeps only its SHA-256, so a database read never yields a usable cookie. The
// cookie is httpOnly + SameSite (+ Secure in prod); mutations additionally carry a
// double-submit CSRF token (see CSRF). The UI holds no authority (P-UI-1): roles,
// MFA state, and every decision live server-side.
package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// Cookie names. The session cookie is httpOnly (JS can't read it); the CSRF cookie
// is intentionally readable so the SPA can echo it in the X-CSRF-Token header
// (double-submit). Neither is the IdP's token — both are Harbor's.
const (
	SessionCookie = "harbor_session"
	CSRFCookie    = "harbor_csrf"
)

// ErrNoSession means no valid (present, unexpired) session for the token.
var ErrNoSession = errors.New("adminauth: no valid session")

// Session is one authenticated admin session. The cookie value is never stored;
// ID is hex(sha256(token)).
type Session struct {
	ID        string `gorm:"column:id;primaryKey"`
	Principal string `gorm:"column:principal"`
	Roles     string `gorm:"column:roles"` // JSON array
	IdP       string `gorm:"column:idp"`
	Subject   string `gorm:"column:subject"`
	Email     string `gorm:"column:email"`
	Name      string `gorm:"column:name"`
	CSRFToken string `gorm:"column:csrf_token"`
	MFAAt     int64  `gorm:"column:mfa_at"`     // unix ns, 0 = none
	CreatedAt int64  `gorm:"column:created_at"` // unix ns
	ExpiresAt int64  `gorm:"column:expires_at"` // unix ns
}

// TableName pins the GORM table.
func (Session) TableName() string { return "sessions" }

// SessionStore persists admin sessions.
type SessionStore struct {
	db  *gorm.DB
	now func() time.Time
}

// NewSessionStore builds a session store over the shared GORM connection.
func NewSessionStore(db *gorm.DB, now func() time.Time) *SessionStore {
	if now == nil {
		now = time.Now
	}
	return &SessionStore{db: db, now: now}
}

// hashToken maps a cookie token to its storage key. A DB read therefore never
// discloses a usable cookie (the token is the secret, the hash is the lookup key).
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// randToken returns a 256-bit URL-safe random secret.
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("adminauth: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Mint creates a session for an authenticated subject + resolved roles and returns
// the (token, csrf) the caller sets as cookies. The token is shown ONCE.
func (s *SessionStore) Mint(ctx context.Context, subj Subject, idp string, roles []string, ttl time.Duration) (token, csrf string, err error) {
	token, err = randToken()
	if err != nil {
		return "", "", err
	}
	csrf, err = randToken()
	if err != nil {
		return "", "", err
	}
	rolesJSON, err := json.Marshal(nonNil(roles))
	if err != nil {
		return "", "", fmt.Errorf("adminauth: marshal roles: %w", err)
	}
	now := s.now()
	row := Session{
		ID:        hashToken(token),
		Principal: subj.Principal(),
		Roles:     string(rolesJSON),
		IdP:       idp,
		Subject:   subj.ID,
		Email:     subj.Email,
		Name:      subj.Name,
		CSRFToken: csrf,
		MFAAt:     unixNano(subj.MFAAt),
		CreatedAt: now.UnixNano(),
		ExpiresAt: now.Add(ttl).UnixNano(),
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return "", "", fmt.Errorf("adminauth: create session: %w", err)
	}
	return token, csrf, nil
}

// Lookup resolves a cookie token to its (unexpired) session. Returns ErrNoSession
// for an absent or expired session (an expired row is best-effort reaped).
func (s *SessionStore) Lookup(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, ErrNoSession
	}
	var row Session
	err := s.db.WithContext(ctx).Where("id = ?", hashToken(token)).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("adminauth: lookup session: %w", err)
	}
	if s.now().UnixNano() >= row.ExpiresAt {
		_ = s.revokeID(ctx, row.ID)
		return Session{}, ErrNoSession
	}
	return row, nil
}

// Revoke deletes the session for a cookie token (logout). Absent is not an error.
func (s *SessionStore) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.revokeID(ctx, hashToken(token))
}

func (s *SessionStore) revokeID(ctx context.Context, id string) error {
	if err := s.db.WithContext(ctx).Where("id = ?", id).Delete(&Session{}).Error; err != nil {
		return fmt.Errorf("adminauth: revoke session: %w", err)
	}
	return nil
}

// GC deletes expired sessions and returns how many were removed.
func (s *SessionStore) GC(ctx context.Context) (int64, error) {
	res := s.db.WithContext(ctx).Where("expires_at <= ?", s.now().UnixNano()).Delete(&Session{})
	if res.Error != nil {
		return 0, fmt.Errorf("adminauth: gc sessions: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// roleList decodes the stored JSON role array (always non-nil).
func (sess Session) roleList() []string {
	var roles []string
	_ = json.Unmarshal([]byte(sess.Roles), &roles)
	return nonNil(roles)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func unixNano(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.UnixNano()
}
