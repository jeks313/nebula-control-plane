package adminauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCOptions configures a generic OIDC authenticator (the priority real IdP:
// Entra ID, AD FS, Okta, Google, Keycloak — and the in-process mock all speak it).
type OIDCOptions struct {
	Name         string // provider key (default "oidc")
	Issuer       string // discovery base; {Issuer}/.well-known/openid-configuration
	ClientID     string
	ClientSecret string
	RedirectURL  string // {BaseURL}/admin/v1/auth/callback
	ExtraScopes  []string
	GroupsClaim  string // ID-token claim carrying group membership (default "groups")
}

// OIDCAuthenticator is the Authorization-Code + PKCE OIDC login. Identity and
// groups come from the verified ID token; no token ever reaches the browser.
type OIDCAuthenticator struct {
	name        string
	oauth       oauth2.Config
	verifier    *oidc.IDTokenVerifier
	groupsClaim string
}

// NewOIDC performs OIDC discovery against the issuer and builds the authenticator.
func NewOIDC(ctx context.Context, opts OIDCOptions) (*OIDCAuthenticator, error) {
	provider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("adminauth: oidc discovery (%s): %w", opts.Issuer, err)
	}
	scopes := append([]string{oidc.ScopeOpenID, "profile", "email"}, opts.ExtraScopes...)
	return &OIDCAuthenticator{
		name: orDefault(opts.Name, "oidc"),
		oauth: oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  opts.RedirectURL,
			Scopes:       scopes,
		},
		verifier:    provider.Verifier(&oidc.Config{ClientID: opts.ClientID}),
		groupsClaim: orDefault(opts.GroupsClaim, "groups"),
	}, nil
}

// Name implements Authenticator.
func (a *OIDCAuthenticator) Name() string { return a.name }

// AuthURL builds the authorize redirect with a PKCE S256 challenge + nonce.
func (a *OIDCAuthenticator) AuthURL(state, nonce, verifier string) string {
	return a.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
}

// Exchange swaps the code (with the PKCE verifier) for tokens, verifies the ID
// token (signature, audience, expiry) and its nonce, and extracts the Subject.
func (a *OIDCAuthenticator) Exchange(ctx context.Context, code, nonce, verifier string) (Subject, error) {
	tok, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Subject{}, fmt.Errorf("adminauth: oidc exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Subject{}, errors.New("adminauth: oidc: no id_token in token response")
	}
	idt, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		return Subject{}, fmt.Errorf("adminauth: oidc verify: %w", err)
	}
	if idt.Nonce != nonce {
		return Subject{}, errors.New("adminauth: oidc: nonce mismatch")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Subject{}, fmt.Errorf("adminauth: oidc claims: %w", err)
	}
	return Subject{
		ID:     idt.Subject,
		Email:  stringClaim(claims, "email"),
		Name:   stringClaim(claims, "name"),
		Groups: stringSliceClaim(claims, a.groupsClaim),
		MFAAt:  mfaFromClaims(claims, idt.IssuedAt),
	}, nil
}

// mfaFromClaims reports MFA satisfaction conservatively: only when the IdP asserts
// it via the `amr` (auth methods) claim. We do NOT infer MFA from a bare login.
func mfaFromClaims(claims map[string]any, issuedAt time.Time) *time.Time {
	amr := stringSliceClaim(claims, "amr")
	mfa := false
	for _, m := range amr {
		switch m {
		case "mfa", "otp", "hwk", "swk", "pop", "fpt", "face", "iris":
			mfa = true
		}
	}
	if !mfa {
		return nil
	}
	if at, ok := claims["auth_time"].(float64); ok && at > 0 {
		t := time.Unix(int64(at), 0).UTC()
		return &t
	}
	if !issuedAt.IsZero() {
		t := issuedAt.UTC()
		return &t
	}
	return nil
}

func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func stringSliceClaim(claims map[string]any, key string) []string {
	switch v := claims[key].(type) {
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
