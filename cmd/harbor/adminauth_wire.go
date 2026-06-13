package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"

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
	samlMetadataURL, samlMetadataFile                           *string
	samlSPCert, samlSPKey, samlEntityID, samlGroupsAttr         *string
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
		samlMetadataURL:  fs.String("saml-idp-metadata-url", "", "SAML IdP metadata URL (enables SAML login: AD FS / Entra / Okta)"),
		samlMetadataFile: fs.String("saml-idp-metadata-file", "", "SAML IdP metadata XML file (alternative to -saml-idp-metadata-url)"),
		samlSPCert:       fs.String("saml-sp-cert", "", "SP signing cert PEM (ephemeral self-signed if unset)"),
		samlSPKey:        fs.String("saml-sp-key", "", "SP signing key PEM"),
		samlEntityID:     fs.String("saml-entity-id", "", "SP entity id (default the SP metadata URL)"),
		samlGroupsAttr:   fs.String("saml-groups-attr", "groups", "assertion attribute carrying group/role membership"),
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

	samlOn := *af.samlMetadataURL != "" || *af.samlMetadataFile != ""
	// The mock IdP is a passwordless dev login; it must never sit alongside real
	// auth (a stray -mock-idp in a prod invocation would be a live admin bypass).
	// Fail closed, mirroring how -dev-auth is neutralized when real auth is present.
	if *af.mockIdP && (*af.oidcIssuer != "" || *af.ghClientID != "" || samlOn) {
		fatalf("admin-api: -mock-idp (DEV ONLY) cannot be combined with real auth (-oidc-issuer/-github-client-id/-saml-idp-metadata-*)")
	}

	var auths []adminauth.Authenticator
	var flows []adminauth.FlowAuthenticator
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

	if samlOn {
		idpMeta := loadIdPMetadata(ctx, *af.samlMetadataURL, *af.samlMetadataFile)
		spKey, spCert := loadOrGenSPKeypair(*af.samlSPKey, *af.samlSPCert)
		sa, err := adminauth.NewSAML(adminauth.SAMLOptions{
			BaseURL: base, EntityID: *af.samlEntityID, IDPMetadata: idpMeta,
			Key: spKey, Certificate: spCert, GroupsAttr: *af.samlGroupsAttr, Secure: *af.secure,
		})
		if err != nil {
			fatalf("admin-api: saml: %v", err)
		}
		flows = append(flows, sa)
		fmt.Fprintf(os.Stderr, "harbor admin-api: SAML login enabled (SP metadata at %s/admin/v1/auth/saml/metadata)\n", base)
	}

	if len(auths) == 0 && len(flows) == 0 {
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
		Store:              adminauth.NewSessionStore(db, nil),
		Authenticators:     auths,
		FlowAuthenticators: flows,
		RoleMapper:         mapper,
		SessionTTL:         *af.sessionTTL,
		Secure:             *af.secure,
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

// loadIdPMetadata fetches (URL) or reads (file) the SAML IdP metadata — the IdP
// signing cert in it is the trust anchor for assertion verification.
func loadIdPMetadata(ctx context.Context, metaURL, metaFile string) *saml.EntityDescriptor {
	var data []byte
	if metaFile != "" {
		b, err := os.ReadFile(metaFile)
		if err != nil {
			fatalf("admin-api: read SAML IdP metadata: %v", err)
		}
		data = b
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
		if err != nil {
			fatalf("admin-api: bad -saml-idp-metadata-url: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fatalf("admin-api: fetch SAML IdP metadata: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			fatalf("admin-api: fetch SAML IdP metadata: status %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			fatalf("admin-api: read SAML IdP metadata: %v", err)
		}
		data = b
	}
	md, err := parseIdPMetadata(data)
	if err != nil {
		fatalf("admin-api: parse SAML IdP metadata: %v", err)
	}
	return md
}

// parseIdPMetadata parses an <EntityDescriptor> or an <EntitiesDescriptor> wrapper
// (IdP metadata comes both ways), validating the XML round-trips first to defeat
// XML-canonicalization attacks. (A faithful local copy of samlsp.ParseMetadata, so
// the SP code does not drag in samlsp's session/JWT machinery.)
func parseIdPMetadata(data []byte) (*saml.EntityDescriptor, error) {
	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}
	entity := &saml.EntityDescriptor{}
	err := xml.Unmarshal(data, entity)
	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}
		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				return &entities.EntityDescriptors[i], nil
			}
		}
		return nil, errors.New("no entity with an IDPSSODescriptor in metadata")
	}
	if err != nil {
		return nil, err
	}
	return entity, nil
}

// loadOrGenSPKeypair loads the SP signing keypair from PEM, or generates an
// ephemeral self-signed one (dev) with a warning — the SP key signs AuthnRequests
// and backs the SP metadata; a stable one is wanted in production.
func loadOrGenSPKeypair(keyPath, certPath string) (*rsa.PrivateKey, *x509.Certificate) {
	if keyPath != "" && certPath != "" {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			fatalf("admin-api: load SAML SP keypair: %v", err)
		}
		key, ok := pair.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			fatalf("admin-api: SAML SP key must be RSA")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			fatalf("admin-api: parse SAML SP cert: %v", err)
		}
		return key, leaf
	}
	fmt.Fprintln(os.Stderr, "harbor admin-api: WARNING SAML SP using an ephemeral self-signed cert (set -saml-sp-cert/-saml-sp-key for a stable SP identity)")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("admin-api: gen SAML SP key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "harbor-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		fatalf("admin-api: gen SAML SP cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		fatalf("admin-api: parse SAML SP cert: %v", err)
	}
	return key, leaf
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
