// Package samlmock is a minimal but REAL SAML 2.0 Identity Provider for tests. It
// serves IdP metadata + an SSO endpoint and signs genuine SAML assertions (real
// XML-dsig via crewjam/saml) for a selected seeded user — so Harbor's SAML SP
// (internal/adminauth) is exercised end-to-end (AuthnRequest → signed assertion →
// ACS validation) with no external IdP. It is NOT a security component: it signs
// for whoever passes ?login_as=. Test/dev use only.
package samlmock

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
)

// User is a seeded mock identity selectable via ?login_as=<key>.
type User struct {
	Email  string
	Name   string
	Groups []string
}

// IdP is the mock SAML identity provider (an http.Handler at /sso and /metadata).
type IdP struct {
	idp        *saml.IdentityProvider
	users      map[string]User
	spMetadata *saml.EntityDescriptor
	now        func() time.Time
}

// New builds the mock IdP rooted at baseURL (the test server URL). Call SetSP with
// the SP's metadata once the SP exists so the IdP can validate + target it.
func New(baseURL string, key *rsa.PrivateKey, cert *x509.Certificate, users map[string]User, now func() time.Time) (*IdP, error) {
	if now == nil {
		now = time.Now
	}
	ssoURL, err := url.Parse(baseURL + "/sso")
	if err != nil {
		return nil, err
	}
	metaURL, err := url.Parse(baseURL + "/metadata")
	if err != nil {
		return nil, err
	}
	m := &IdP{users: users, now: now}
	m.idp = &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             *metaURL,
		SSOURL:                  *ssoURL,
		ServiceProviderProvider: spProvider{m},
		SessionProvider:         sessionProvider{m},
	}
	return m, nil
}

// SetSP registers the SP metadata the IdP will issue assertions for.
func (m *IdP) SetSP(md *saml.EntityDescriptor) { m.spMetadata = md }

// Metadata is the IdP metadata the SP is configured with.
func (m *IdP) Metadata() *saml.EntityDescriptor { return m.idp.Metadata() }

// Handler routes the IdP endpoints.
func (m *IdP) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metadata", m.idp.ServeMetadata)
	mux.HandleFunc("GET /sso", m.idp.ServeSSO)
	mux.HandleFunc("POST /sso", m.idp.ServeSSO)
	return mux
}

// ServeHTTP lets the IdP be used directly as a handler.
func (m *IdP) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.Handler().ServeHTTP(w, r) }

type spProvider struct{ m *IdP }

func (p spProvider) GetServiceProvider(r *http.Request, spID string) (*saml.EntityDescriptor, error) {
	if p.m.spMetadata == nil {
		return nil, errors.New("samlmock: SP metadata not registered (call SetSP)")
	}
	return p.m.spMetadata, nil
}

type sessionProvider struct{ m *IdP }

// GetSession picks the seeded user named by ?login_as= and returns a session whose
// assertion carries NameID=email + a "groups" attribute (mapped to roles by the SP).
func (p sessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	u, ok := p.m.users[r.URL.Query().Get("login_as")]
	if !ok {
		http.Error(w, "samlmock: unknown or missing login_as", http.StatusBadRequest)
		return nil
	}
	now := p.m.now()
	return &saml.Session{
		ID: "sess-" + u.Email, Index: "idx-" + u.Email,
		CreateTime: now, ExpireTime: now.Add(time.Hour),
		NameID: u.Email, NameIDFormat: string(saml.EmailAddressNameIDFormat),
		UserEmail: u.Email, UserName: u.Name,
		CustomAttributes: []saml.Attribute{
			{FriendlyName: "groups", Name: "groups", Values: attrVals(u.Groups)},
			{FriendlyName: "displayName", Name: "displayName", Values: attrVals([]string{u.Name})},
		},
	}
}

func attrVals(vals []string) []saml.AttributeValue {
	out := make([]saml.AttributeValue, 0, len(vals))
	for _, v := range vals {
		out = append(out, saml.AttributeValue{Type: "xs:string", Value: v})
	}
	return out
}
