package adminauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/adminauth"
)

// TestTokenStore covers mint → lookup → expiry → revoke.
func TestTokenStore(t *testing.T) {
	st := newStore(t)
	now := time.Unix(1_700_000_000, 0)
	ts := adminauth.NewTokenStore(st.DB, func() time.Time { return now })

	token, row, err := ts.Mint(context.Background(), "ci-deploy", "", []string{"operator"}, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "harbor_") {
		t.Fatalf("token lacks scanner-friendly prefix: %q", token)
	}
	if row.Principal != "token:ci-deploy" {
		t.Fatalf("principal = %q, want token:ci-deploy", row.Principal)
	}
	got, err := ts.Lookup(context.Background(), token)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(got.RoleList()) != 1 || got.RoleList()[0] != "operator" {
		t.Fatalf("roles = %v", got.RoleList())
	}
	// A bogus / empty token never resolves.
	if _, err := ts.Lookup(context.Background(), "harbor_nope"); !errors.Is(err, adminauth.ErrNoToken) {
		t.Fatalf("bogus token err = %v, want ErrNoToken", err)
	}
	// Past expiry → ErrNoToken.
	now = now.Add(2 * time.Hour)
	if _, err := ts.Lookup(context.Background(), token); !errors.Is(err, adminauth.ErrNoToken) {
		t.Fatalf("expired token err = %v, want ErrNoToken", err)
	}
	// Revoke (a never-expiring token) → ErrNoToken.
	now = time.Unix(1_700_000_000, 0)
	tok2, _, _ := ts.Mint(context.Background(), "perm", "", []string{"operator"}, "alice", 0)
	if n, err := ts.Revoke(context.Background(), "perm"); err != nil || n != 1 {
		t.Fatalf("revoke = %d, %v; want 1, nil", n, err)
	}
	if _, err := ts.Lookup(context.Background(), tok2); !errors.Is(err, adminauth.ErrNoToken) {
		t.Fatalf("revoked token err = %v, want ErrNoToken", err)
	}
}

// TestTokenProvider: a bearer token resolves to an Identity with the token's roles
// and NO MFA (machine tokens can never satisfy step-up).
func TestTokenProvider(t *testing.T) {
	st := newStore(t)
	ts := adminauth.NewTokenStore(st.DB, nil)
	token, _, _ := ts.Mint(context.Background(), "ci", "", []string{"operator"}, "alice", 0)
	p := adminauth.NewTokenProvider(ts)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	id, ok := p.Identify(req)
	if !ok {
		t.Fatal("valid bearer token did not authenticate")
	}
	if id.Principal != "token:ci" || !contains(id.Roles, "operator") {
		t.Fatalf("identity = %+v", id)
	}
	if id.MFAAt != nil {
		t.Fatal("a machine token must never carry MFA")
	}
	// No header / wrong scheme / unknown token → not authenticated.
	if _, ok := p.Identify(httptest.NewRequest(http.MethodGet, "/x", nil)); ok {
		t.Fatal("missing Authorization should not authenticate")
	}
	bad := httptest.NewRequest(http.MethodGet, "/x", nil)
	bad.Header.Set("Authorization", "Bearer harbor_wrong")
	if _, ok := p.Identify(bad); ok {
		t.Fatal("unknown token should not authenticate")
	}
}

// TestTokenCannotStepUp is the A0.8 security showcase: a token (even admin-scoped)
// can run operator ops over HTTP, but is refused the step-up-gated dual-control
// actions because it carries no MFA.
func TestTokenCannotStepUp(t *testing.T) {
	st := newStore(t)
	ts := adminauth.NewTokenStore(st.DB, nil)
	token, _, _ := ts.Mint(context.Background(), "admin-bot", "", []string{adminapi.RoleAdmin}, "alice", 0)
	api := adminapi.New(adminapi.Config{
		Store: st, Identity: adminauth.NewTokenProvider(ts), MFAFreshness: 15 * time.Minute,
	})
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	bearer := func(method, path string, body any) (int, map[string]any) {
		var rdr = bytes.NewReader(nil)
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rdr)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}

	// Operator op (admin has the perm; not step-up-gated) → allowed.
	if code, _ := bearer("POST", "/admin/v1/lighthouses",
		map[string]any{"overlay_ip": "10.44.0.1", "public_addrs": []string{"1.2.3.4:4242"}}); code != http.StatusCreated {
		t.Fatalf("token lighthouse add = %d, want 201", code)
	}
	// Step-up-gated action (the declarative config PUT) → blocked, distinguishable code.
	code, body := bearer("PUT", "/admin/v1/config/policy", "allow web -> db tcp 5432\n")
	if code != http.StatusForbidden || body["code"] != "step_up_required" {
		t.Fatalf("token config PUT = %d code=%v, want 403 step_up_required", code, body["code"])
	}
	// /me reflects no MFA.
	_, me := bearer("GET", "/admin/v1/me", nil)
	if _, present := me["mfa_satisfied_at"]; present {
		t.Fatalf("token /me must not carry mfa_satisfied_at: %v", me)
	}
}
