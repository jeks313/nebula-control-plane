package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/adminauth"
	"github.com/jeks313/nebula-control-plane/internal/adminauth/mockidp"
	"gorm.io/gorm"
)

// adminAuthFlags are the admin-api authentication flags. Auth is bring-your-own-
// IdP: configure any of OIDC / GitHub / the in-process mock and the admin API
// authenticates against real, IdP-minted sessions. (-dev-auth header seam stays
// for quick local dogfooding and is mutually exclusive with real auth.)
type adminAuthFlags struct {
	oidcIssuer, oidcClientID, oidcClientSecret, oidcGroupsClaim *string
	ghClientID, ghClientSecret                                  *string
	mockIdP                                                     *bool
	mockAddr                                                    *string
	baseURL                                                     *string
	secure                                                      *bool
	roleMap                                                     *string
	defaultRoles                                                *string
	sessionTTL                                                  *time.Duration
}

func addAdminAuthFlags(fs *flag.FlagSet) adminAuthFlags {
	return adminAuthFlags{
		oidcIssuer:       fs.String("oidc-issuer", "", "OIDC issuer URL (enables OIDC login: Entra/AD FS/Okta/Google/Keycloak)"),
		oidcClientID:     fs.String("oidc-client-id", "", "OIDC client id"),
		oidcClientSecret: fs.String("oidc-client-secret", "", "OIDC client secret"),
		oidcGroupsClaim:  fs.String("oidc-groups-claim", "groups", "ID-token claim carrying group membership"),
		ghClientID:       fs.String("github-client-id", "", "GitHub OAuth client id (enables GitHub login)"),
		ghClientSecret:   fs.String("github-client-secret", "", "GitHub OAuth client secret"),
		mockIdP:          fs.Bool("mock-idp", false, "DEV ONLY: run an in-process mock OIDC IdP and log in against it"),
		mockAddr:         fs.String("mock-idp-addr", "127.0.0.1:8446", "listen address for the -mock-idp provider"),
		baseURL:          fs.String("base-url", "", "external base URL for OAuth redirect URIs (default derived from -addr; use https in prod)"),
		secure:           fs.Bool("auth-secure", false, "set Secure on session cookies (enable in prod / behind https)"),
		roleMap:          fs.String("role-map", "", "group=role mappings, e.g. \"harbor-admins=admin;acme/ops=operator\""),
		defaultRoles:     fs.String("default-roles", "viewer", "roles granted to any authenticated user (CSV)"),
		sessionTTL:       fs.Duration("session-ttl", 12*time.Hour, "absolute admin session lifetime"),
	}
}

// buildAdminAuth wires the configured authenticators into an auth Service and
// returns the per-request IdentityProvider, the (unauthenticated) auth-route
// handler to mount, whether the API should be CSRF-wrapped, and a cleanup func.
// Returns (nil, nil, false, noop) when no real auth is configured (the caller
// falls back to -dev-auth / 401).
func buildAdminAuth(ctx context.Context, af adminAuthFlags, addr string, db *gorm.DB) (adminapi.IdentityProvider, http.Handler, func(http.Handler) http.Handler, func()) {
	noop := func() {}
	base := *af.baseURL
	if base == "" {
		base = deriveBaseURL(addr)
	}
	redirect := base + "/admin/v1/auth/callback"

	// The mock IdP is a passwordless dev login; it must never sit alongside real
	// auth (a stray -mock-idp in a prod invocation would be a live admin bypass).
	// Fail closed, mirroring how -dev-auth is neutralized when real auth is present.
	if *af.mockIdP && (*af.oidcIssuer != "" || *af.ghClientID != "") {
		fatalf("admin-api: -mock-idp (DEV ONLY) cannot be combined with real auth (-oidc-issuer/-github-client-id)")
	}

	var auths []adminauth.Authenticator
	var cleanups []func()

	if *af.mockIdP {
		ln, err := net.Listen("tcp", *af.mockAddr)
		if err != nil {
			fatalf("admin-api: mock-idp listen: %v", err)
		}
		issuer := "http://" + ln.Addr().String()
		mp, err := mockidp.New(mockidp.DefaultUsers(), nil)
		if err != nil {
			fatalf("admin-api: mock-idp: %v", err)
		}
		mp.SetIssuer(issuer)
		ms := &http.Server{Handler: mp, ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = ms.Serve(ln) }()
		cleanups = append(cleanups, func() { _ = ms.Close() })
		oidc, err := adminauth.NewOIDC(ctx, adminauth.OIDCOptions{
			Name: "mock", Issuer: issuer, ClientID: "harbor", ClientSecret: "mock",
			RedirectURL: redirect,
		})
		if err != nil {
			fatalf("admin-api: mock-idp oidc: %v", err)
		}
		auths = append(auths, oidc)
		fmt.Fprintf(os.Stderr, "harbor admin-api: WARNING mock IdP at %s — DEV ONLY (never in production)\n", issuer)
	}

	if *af.oidcIssuer != "" {
		oidc, err := adminauth.NewOIDC(ctx, adminauth.OIDCOptions{
			Issuer: *af.oidcIssuer, ClientID: *af.oidcClientID, ClientSecret: *af.oidcClientSecret,
			RedirectURL: redirect, GroupsClaim: *af.oidcGroupsClaim,
		})
		if err != nil {
			fatalf("admin-api: oidc: %v", err)
		}
		auths = append(auths, oidc)
		fmt.Fprintf(os.Stderr, "harbor admin-api: OIDC login via %s\n", *af.oidcIssuer)
	}

	if *af.ghClientID != "" {
		auths = append(auths, adminauth.NewGitHub(adminauth.GitHubOptions{
			ClientID: *af.ghClientID, ClientSecret: *af.ghClientSecret, RedirectURL: redirect,
		}))
		fmt.Fprintln(os.Stderr, "harbor admin-api: GitHub login enabled")
	}

	if len(auths) == 0 {
		return nil, nil, nil, noop
	}

	mapper := &adminauth.RoleMapper{
		GroupRoles:   parseRoleMap(*af.roleMap),
		DefaultRoles: parseCSV(*af.defaultRoles),
	}
	// Convenience: a bare -mock-idp with no role map gets the seeded mock mapping
	// so admin/operator/viewer work out of the box.
	if *af.mockIdP && *af.roleMap == "" {
		mapper.GroupRoles = map[string][]string{
			"harbor-admins":    {adminapi.RoleAdmin},
			"harbor-operators": {adminapi.RoleOperator},
			"harbor-viewers":   {adminapi.RoleViewer},
		}
	}
	if !*af.secure {
		fmt.Fprintln(os.Stderr, "harbor admin-api: WARNING cookies are not Secure (-auth-secure off) — only for local http")
	}
	svc := adminauth.New(adminauth.Config{
		Store:          adminauth.NewSessionStore(db, nil),
		Authenticators: auths,
		RoleMapper:     mapper,
		SessionTTL:     *af.sessionTTL,
		Secure:         *af.secure,
	})
	return svc.Provider(), svc.Handler(), svc.CSRF, func() {
		for _, c := range cleanups {
			c()
		}
	}
}

// deriveBaseURL turns a listen address (":8445", "127.0.0.1:8445") into a dev base
// URL. Production must pass -base-url with the real (https) external origin.
func deriveBaseURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://localhost:8445"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

// parseRoleMap parses "group=role;group2=role2,role3" into a group→roles map.
func parseRoleMap(s string) map[string][]string {
	out := map[string][]string{}
	for _, pair := range strings.Split(s, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		group, roles, ok := strings.Cut(pair, "=")
		if !ok {
			fatalf("admin-api: bad -role-map entry %q (want group=role[,role])", pair)
		}
		out[strings.TrimSpace(group)] = parseCSV(roles)
	}
	return out
}
