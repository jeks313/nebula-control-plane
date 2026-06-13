package adminauth

import (
	"crypto/subtle"
	"net/http"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
)

// SessionProvider authenticates each admin API request from the session cookie.
// It implements adminapi.IdentityProvider, so the admin API is unchanged: it asks
// "who is this?" and the answer now comes from a real (IdP-minted) session instead
// of the dev header. Roles + MFA state come straight from the stored session;
// the client gets no say (P-UI-1).
type SessionProvider struct {
	store *SessionStore
}

// Identify resolves the session cookie to an Identity, or (zero,false) if there is
// no valid session (the admin API then answers 401).
func (p *SessionProvider) Identify(r *http.Request) (adminapi.Identity, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return adminapi.Identity{}, false
	}
	sess, err := p.store.Lookup(r.Context(), c.Value)
	if err != nil {
		return adminapi.Identity{}, false
	}
	return adminapi.Identity{
		Principal: sess.Principal,
		Roles:     sess.roleList(),
		MFAAt:     mfaPtr(sess.MFAAt),
	}, true
}

// CSRF guards state-changing requests with a SESSION-BOUND double-submit: the
// X-CSRF-Token header must equal the secret stored in the caller's session (which
// the SPA reads from the JS-readable harbor_csrf cookie set at login and echoes in
// the header). Binding to the session — not merely cookie==header — means a
// cookie-injection attacker who can set harbor_csrf still cannot forge a match
// without the server-side session secret. Safe methods are exempt; the
// unauthenticated /auth routes are mounted outside this wrapper. Fails closed: no
// session or a mismatched/absent token → 403 (docs §6: "mutations stay on fetch+CSRF").
func (s *Service) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		header := r.Header.Get("X-CSRF-Token")
		c, err := r.Cookie(SessionCookie)
		if header == "" || err != nil {
			problem(w, http.StatusForbidden, "csrf", "missing session or CSRF token")
			return
		}
		sess, err := s.cfg.Store.Lookup(r.Context(), c.Value)
		if err != nil {
			problem(w, http.StatusForbidden, "csrf", "no valid session")
			return
		}
		if subtle.ConstantTimeCompare([]byte(header), []byte(sess.CSRFToken)) != 1 {
			problem(w, http.StatusForbidden, "csrf", "invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
