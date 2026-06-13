package adminapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
)

// fakeProvider authenticates iff the request carries header h; it returns an
// identity whose principal is its name, so the test can tell which one fired.
type fakeProvider struct{ name, h string }

func (p fakeProvider) Identify(r *http.Request) (adminapi.Identity, bool) {
	if r.Header.Get(p.h) == "" {
		return adminapi.Identity{}, false
	}
	return adminapi.Identity{Principal: p.name, Roles: []string{"admin"}}, true
}

// TestChainProvider: the chain returns the first provider that resolves, skips
// nils, and reports false when none match.
func TestChainProvider(t *testing.T) {
	chain := adminapi.ChainProvider{
		nil, // a nil secondary (e.g. no session configured) must be skipped
		fakeProvider{name: "token", h: "Authorization"},
		fakeProvider{name: "session", h: "Cookie"},
	}

	// Bearer present → the token provider wins (it's first).
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer t")
	if id, ok := chain.Identify(req); !ok || id.Principal != "token" {
		t.Fatalf("bearer → %v ok=%v, want token", id, ok)
	}
	// Only a cookie → the session provider resolves it.
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Cookie", "harbor_session=s")
	if id, ok := chain.Identify(req); !ok || id.Principal != "session" {
		t.Fatalf("cookie → %v ok=%v, want session", id, ok)
	}
	// Neither → unauthenticated.
	if _, ok := chain.Identify(httptest.NewRequest(http.MethodGet, "/x", nil)); ok {
		t.Fatal("no credentials should not authenticate")
	}
}
