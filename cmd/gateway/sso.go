package main

// SSO enrollment portal wiring (ADR 0004 + decisions S5/S7/S9/B9). The portal is
// OPTIONAL: when none of the SSO flags/env are set, gateway.Config.SSO stays nil, the
// portal routes answer 404 "SSO not enabled", and the rest of the gateway is
// unaffected (it never gains a CA either way — ADR 0009). When SSO IS requested we
// FAIL CLOSED on partial config: a half-configured portal is a misconfiguration, not a
// silent disable.
//
// Construction mirrors admin-api's SAML login (cmd/harbor/adminauth_wire.go): we reuse
// adminauth.NewSAML so all SAML crypto stays in one place (decision B13), declaring the
// portal's own /v1/sso/acs as the SP's ACS via SAMLOptions.ACSPath so the IdP
// auto-POSTs there and crewjam's Destination/Recipient checks line up. The gateway
// signs assertions with its DEDICATED ECDSA P-256 private key (S6, distinct from any
// CA), the public half of which Core pins.

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"

	"github.com/jeks313/nebula-control-plane/internal/adminauth"
	"github.com/jeks313/nebula-control-plane/internal/gateway"
	"github.com/jeks313/nebula-control-plane/internal/ssoassert"
)

// Secret-material env vars (ADR 0006), mirroring the gateway's other key/cert vars: a
// shell-less distroless container reads its SSO assertion-signing key and SP keypair
// straight from Secrets-Manager-injected vars. Each PEM var holds the literal PEM and
// takes precedence over its matching -flag <file>.
const (
	envSSOAssertKey = "NCP_GW_SSO_ASSERT_KEY_PEM" // gateway assertion-signing private key (S6)
	envSSOSPCert    = "NCP_GW_SSO_SP_CERT_PEM"    // SAML SP signing cert
	envSSOSPKey     = "NCP_GW_SSO_SP_KEY_PEM"     // SAML SP signing key
	envSSOIdPMeta   = "NCP_GW_SSO_IDP_METADATA"   // SAML IdP metadata XML (alternative to the file/URL)
	// Non-secret operator knobs, also env-injectable so a shell-less distroless container
	// (Fargate) can be flipped on purely by populating its Secrets-Manager config — no
	// terraform `command` change. Each env var, when set, takes precedence over its
	// matching -flag. envSSOACSURL is the SSO TRIGGER (presence enables the portal).
	envSSOACSURL     = "NCP_GW_SSO_ACS_URL"     // public ACS URL — presence ENABLES SSO
	envSSOEntityID   = "NCP_GW_SSO_ENTITY_ID"   // SAML SP entity id
	envSSOIssuer     = "NCP_GW_SSO_ISSUER"      // assertion realm (iss)
	envSSOGroupsAttr = "NCP_GW_SSO_GROUPS_ATTR" // SAML group-claim attribute
)

// envOr returns the env var if set, else the flag value. Used for the non-secret SSO
// knobs (ACS URL / entity id / issuer / groups attr) so the Fargate task can supply them
// from its config secret (env-first, mirroring the PEM material precedence) rather than
// from a terraform-static `command`.
func envOr(env, flagVal string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return flagVal
}

// ssoFlags are the gateway's SSO enrollment-portal flags. SSO is enabled iff -sso-acs-url
// is set; the rest are then required (fail closed on partial config).
type ssoFlags struct {
	acsURL       *string // public ACS URL, e.g. https://gw.example.com/v1/sso/acs (presence = SSO requested)
	idpMetaURL   *string // SAML IdP metadata URL
	idpMetaFile  *string // SAML IdP metadata XML file (alternative to the URL or $NCP_GW_SSO_IDP_METADATA)
	entityID     *string // SP entity id (default the SP metadata URL adminauth derives)
	groupsAttr   *string // assertion attribute carrying directory-group membership
	spCert       *string // SP signing cert PEM (or $NCP_GW_SSO_SP_CERT_PEM)
	spKey        *string // SP signing key PEM (or $NCP_GW_SSO_SP_KEY_PEM)
	assertKey    *string // gateway assertion-signing PRIVATE key PEM (S6) (or $NCP_GW_SSO_ASSERT_KEY_PEM)
	issuer       *string // realm stamped into the assertion's iss (fed to Core usertrust.Match); empty -> SAML provider name
	assertionTTL *time.Duration
	sessionTTL   *time.Duration
}

func addSSOFlags(fs flagSet) *ssoFlags {
	return &ssoFlags{
		acsURL:       fs.String("sso-acs-url", "", "PUBLIC ACS URL for the SSO enrollment portal, e.g. https://<gateway>/v1/sso/acs — presence ENABLES SSO (ADR 0004; or $"+envSSOACSURL+"); the IdP POSTs the SAML response here"),
		idpMetaURL:   fs.String("sso-idp-metadata-url", "", "SAML IdP metadata URL (SSO; alternative to -sso-idp-metadata-file or $"+envSSOIdPMeta+")"),
		idpMetaFile:  fs.String("sso-idp-metadata-file", "", "SAML IdP metadata XML file (SSO; alternative to -sso-idp-metadata-url or $"+envSSOIdPMeta+")"),
		entityID:     fs.String("sso-entity-id", "", "SAML SP entity id (SSO; default the SP metadata URL; or $"+envSSOEntityID+")"),
		groupsAttr:   fs.String("sso-groups-attr", "groups", "SAML assertion attribute carrying directory-group membership (SSO; or $"+envSSOGroupsAttr+")"),
		spCert:       fs.String("sso-sp-cert", "", "SAML SP signing cert PEM (SSO; or $"+envSSOSPCert+")"),
		spKey:        fs.String("sso-sp-key", "", "SAML SP signing key PEM (SSO; or $"+envSSOSPKey+")"),
		assertKey:    fs.String("sso-assert-key", "", "gateway assertion-signing PRIVATE key PEM (SSO; ECDSA P-256, decision S6 — from genesis sso-assert.key; or $"+envSSOAssertKey+")"),
		issuer:       fs.String("sso-issuer", "", "realm stamped into the assertion's iss (SSO; fed to Core's usertrust.Match; empty -> the SAML provider name; or $"+envSSOIssuer+")"),
		assertionTTL: fs.Duration("sso-assertion-ttl", 0, "validity window of signed SSO assertions (SSO; <=0 -> default 3m, decision B12)"),
		sessionTTL:   fs.Duration("sso-session-ttl", 0, "how long a started SSO session may await the ACS POST (SSO; <=0 -> default 5m)"),
	}
}

// flagSet is the subset of *flag.FlagSet ssoFlags uses, so the builder is testable
// against a real flag.FlagSet without dragging in os.Args.
type flagSet interface {
	String(name, value, usage string) *string
	Duration(name string, value time.Duration, usage string) *time.Duration
}

// requested reports whether the operator asked for SSO at all (the trigger is set, via
// either -sso-acs-url or $NCP_GW_SSO_ACS_URL). When neither is set the portal stays
// disabled and the gateway is byte-for-behavior unchanged.
func (f *ssoFlags) requested() bool { return envOr(envSSOACSURL, *f.acsURL) != "" }

// build assembles gateway.Config.SSO from the flags/env. It returns nil when SSO is not
// requested (the trigger flag -sso-acs-url is unset). When SSO IS requested it FAILS
// CLOSED on any missing piece (a partial portal config is a misconfiguration), returning
// a clear error naming the missing flag/env. The caller turns an error into a fatal exit.
func (f *ssoFlags) build() (*gateway.SSOConfig, error) {
	if !f.requested() {
		return nil, nil // SSO not requested — portal disabled, gateway unaffected
	}

	// Assertion-signing private key (S6) — env-first, then file. Required.
	assertKeyPEM, err := materialString(envSSOAssertKey, *f.assertKey)
	if err != nil {
		return nil, err
	}
	if assertKeyPEM == "" {
		return nil, fmt.Errorf("-sso-acs-url enables SSO but the assertion-signing key is missing (-sso-assert-key or $%s) — the gateway needs its private half of the genesis sso-assert keypair", envSSOAssertKey)
	}
	signingKey, err := ssoassert.ParsePrivateKeyPEM([]byte(assertKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("SSO assertion-signing key: %w", err)
	}

	// SAML SP signing keypair (signs AuthnRequests, backs SP metadata) — env-first.
	// Both halves required together; unlike admin-api we do NOT silently generate an
	// ephemeral pair (the gateway is a public, restartable surface — a stable SP
	// identity the IdP trusts is mandatory).
	spCertPEM, err := materialString(envSSOSPCert, *f.spCert)
	if err != nil {
		return nil, err
	}
	spKeyPEM, err := materialString(envSSOSPKey, *f.spKey)
	if err != nil {
		return nil, err
	}
	if spCertPEM == "" || spKeyPEM == "" {
		return nil, fmt.Errorf("-sso-acs-url enables SSO but the SAML SP keypair is incomplete (need -sso-sp-cert/-sso-sp-key or $%s/$%s)", envSSOSPCert, envSSOSPKey)
	}
	spKey, spCert, err := parseSPKeypair([]byte(spCertPEM), []byte(spKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("SSO SAML SP keypair: %w", err)
	}

	// IdP metadata (the IdP signing cert in it is the trust anchor for assertion
	// verification) — env-first, then file, then URL. Required.
	idpMeta, err := f.loadIdPMetadata()
	if err != nil {
		return nil, err
	}

	// Derive the SP BaseURL + ACSPath from the public ACS URL so adminauth declares the
	// portal's own /v1/sso/acs as the SP's ACS (the IdP auto-POSTs there; crewjam's
	// Destination/Recipient checks line up). e.g. https://gw/v1/sso/acs ->
	// BaseURL=https://gw, ACSPath=/v1/sso/acs. ACS URL / entity id / groups attr resolve
	// env-first (so the Fargate task can supply them from its config secret).
	base, acsPath, err := splitACSURL(envOr(envSSOACSURL, *f.acsURL))
	if err != nil {
		return nil, fmt.Errorf("-sso-acs-url: %w", err)
	}
	sa, err := adminauth.NewSAML(adminauth.SAMLOptions{
		Name:        "sso",
		BaseURL:     base,
		EntityID:    envOr(envSSOEntityID, *f.entityID),
		IDPMetadata: idpMeta,
		Key:         spKey,
		Certificate: spCert,
		GroupsAttr:  envOr(envSSOGroupsAttr, *f.groupsAttr),
		ACSPath:     acsPath,
		// MetadataPath left default; the portal does not serve SP metadata itself —
		// the operator registers the SP out of band. Secure stays false: the cookie
		// helpers are unused by the portal (it owns state server-side, B10/B13).
	})
	if err != nil {
		return nil, fmt.Errorf("SSO SAML SP: %w", err)
	}

	return &gateway.SSOConfig{
		SAML:         sa,
		SigningKey:   signingKey,
		Issuer:       envOr(envSSOIssuer, *f.issuer),
		SessionTTL:   *f.sessionTTL,
		AssertionTTL: *f.assertionTTL,
	}, nil
}

// loadIdPMetadata fetches (URL) or reads (env/file) + parses the SAML IdP metadata.
// Precedence mirrors the gateway's other secret material: env, then file, then URL.
func (f *ssoFlags) loadIdPMetadata() (*saml.EntityDescriptor, error) {
	if v := os.Getenv(envSSOIdPMeta); v != "" {
		return parseIdPMetadata([]byte(v))
	}
	if *f.idpMetaFile != "" {
		b, err := os.ReadFile(*f.idpMetaFile)
		if err != nil {
			return nil, fmt.Errorf("read -sso-idp-metadata-file: %w", err)
		}
		return parseIdPMetadata(b)
	}
	if *f.idpMetaURL == "" {
		return nil, fmt.Errorf("-sso-acs-url enables SSO but no IdP metadata was provided (-sso-idp-metadata-url, -sso-idp-metadata-file, or $%s)", envSSOIdPMeta)
	}
	resp, err := http.Get(*f.idpMetaURL) //nolint:gosec,noctx // operator-supplied bootstrap URL; gateway has no request ctx here
	if err != nil {
		return nil, fmt.Errorf("fetch -sso-idp-metadata-url: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fetch -sso-idp-metadata-url: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read -sso-idp-metadata-url: %w", err)
	}
	return parseIdPMetadata(b)
}

// splitACSURL splits the public ACS URL into the SP BaseURL (scheme://host[:port]) and
// the ACS path. adminauth joins BaseURL+ACSPath to declare the SP's ACS, so the IdP
// auto-POSTs there and crewjam's Destination/Recipient checks match. The URL must be
// absolute (have a scheme + host) and carry a path (where the IdP POSTs the response).
func splitACSURL(raw string) (base, path string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("must be an absolute URL (scheme://host/path), e.g. https://gateway.example.com/v1/sso/acs")
	}
	if u.Path == "" || u.Path == "/" {
		return "", "", fmt.Errorf("must include the ACS path, e.g. https://gateway.example.com/v1/sso/acs")
	}
	base = u.Scheme + "://" + u.Host
	path = u.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base, path, nil
}

// parseSPKeypair parses an RSA SP signing keypair from PEM (adminauth's SAML SP requires
// RSA). A faithful, self-contained equivalent of admin-api's loadOrGenSPKeypair load arm.
func parseSPKeypair(certPEM, keyPEM []byte) (*rsa.PrivateKey, *x509.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load keypair: %w", err)
	}
	key, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("SP key must be RSA (crewjam SAML signs AuthnRequests with RSA)")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse cert: %w", err)
	}
	return key, leaf, nil
}

// parseIdPMetadata parses an <EntityDescriptor> or an <EntitiesDescriptor> wrapper (IdP
// metadata comes both ways), validating the XML round-trips first to defeat
// XML-canonicalization attacks. A faithful copy of cmd/harbor's parseIdPMetadata (the
// two binaries can't share a cmd-package helper, so the small parser is duplicated).
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
		return nil, errors.New("no entity with an IDPSSODescriptor in IdP metadata")
	}
	if err != nil {
		return nil, err
	}
	return entity, nil
}
