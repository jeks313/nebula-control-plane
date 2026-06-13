package adminauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
)

// SAMLOptions configures the SAML 2.0 Service Provider (the enterprise AD path:
// AD FS / Entra ID / Okta). Identity comes from the assertion's NameID; roles from
// an attribute statement (AD FS/Entra emit a Role/groups claim) mapped through the
// shared RoleMapper. The SP key/cert sign AuthnRequests and back the SP metadata.
type SAMLOptions struct {
	Name        string
	BaseURL     string                 // {BaseURL}/admin/v1/auth/<name>/{acs,metadata}
	EntityID    string                 // SP entity id (default the metadata URL)
	IDPMetadata *saml.EntityDescriptor // parsed IdP metadata (SSO URL + signing cert)
	Key         *rsa.PrivateKey        // SP signing key
	Certificate *x509.Certificate      // SP signing cert (in SP metadata)
	GroupsAttr  string                 // assertion attribute carrying roles/groups
	Secure      bool                   // Secure flag on the login cookie
}

// SAMLAuthenticator is a SAML 2.0 SP login provider. It implements
// FlowAuthenticator: it owns the AuthnRequest redirect and the HTTP-POST ACS.
type SAMLAuthenticator struct {
	name       string
	sp         *saml.ServiceProvider
	groupsAttr string
	secure     bool
	signer     cookieSigner // signs the login-state cookie (tamper-evident)
}

// NewSAML builds the SAML authenticator. IDPMetadata, Key, and Certificate are
// required (the IdP signing cert is the trust anchor for assertion verification).
func NewSAML(opts SAMLOptions) (*SAMLAuthenticator, error) {
	if opts.IDPMetadata == nil {
		return nil, fmt.Errorf("adminauth: saml: IdP metadata is required")
	}
	if opts.Key == nil || opts.Certificate == nil {
		return nil, fmt.Errorf("adminauth: saml: SP key + certificate are required")
	}
	name := orDefault(opts.Name, "saml")
	base := strings.TrimRight(opts.BaseURL, "/")
	acs, err := url.Parse(base + "/admin/v1/auth/" + name + "/acs")
	if err != nil {
		return nil, fmt.Errorf("adminauth: saml: acs url: %w", err)
	}
	meta, err := url.Parse(base + "/admin/v1/auth/" + name + "/metadata")
	if err != nil {
		return nil, fmt.Errorf("adminauth: saml: metadata url: %w", err)
	}
	sp := &saml.ServiceProvider{
		EntityID:          orDefault(opts.EntityID, meta.String()),
		Key:               opts.Key,
		Certificate:       opts.Certificate,
		MetadataURL:       *meta,
		AcsURL:            *acs,
		IDPMetadata:       opts.IDPMetadata,
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
		AllowIDPInitiated: false, // SP-initiated only: every assertion must answer one of our AuthnRequests
	}
	signer, err := newCookieSigner()
	if err != nil {
		return nil, err
	}
	return &SAMLAuthenticator{name: name, sp: sp, groupsAttr: orDefault(opts.GroupsAttr, "groups"), secure: opts.Secure, signer: signer}, nil
}

// Name implements FlowAuthenticator.
func (a *SAMLAuthenticator) Name() string { return a.name }

// SPMetadata returns the SP's SAML metadata (entity id, ACS endpoint, signing
// cert) — what an IdP admin registers, and what the test mock IdP consumes.
func (a *SAMLAuthenticator) SPMetadata() *saml.EntityDescriptor { return a.sp.Metadata() }

// samlLoginState is the per-attempt state for a SAML login: the AuthnRequest ID
// (verified as InResponseTo on the assertion), the RelayState (echoed back by the
// IdP, matched to defeat cross-login injection), and where to return after login.
type samlLoginState struct {
	RequestID  string `json:"id"`
	RelayState string `json:"rs"`
	ReturnTo   string `json:"r"`
}

func (a *SAMLAuthenticator) cookieName() string { return "harbor_saml_login_" + a.name }

// StartLogin issues an AuthnRequest (HTTP-Redirect binding) and stores the state.
// When forceReauth is set (step-up MFA), it marks the request ForceAuthn so the
// IdP re-authenticates the user (re-applying its MFA policy) rather than SSO-ing.
func (a *SAMLAuthenticator) StartLogin(w http.ResponseWriter, r *http.Request, returnTo string, forceReauth bool) {
	authReq, err := a.sp.MakeAuthenticationRequest(
		a.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		problem(w, http.StatusInternalServerError, "saml", "could not build authentication request")
		return
	}
	if forceReauth {
		yes := true
		authReq.ForceAuthn = &yes
	}
	relay, err := randToken()
	if err != nil {
		problem(w, http.StatusInternalServerError, "saml", "could not start login")
		return
	}
	a.setCookie(w, samlLoginState{RequestID: authReq.ID, RelayState: relay, ReturnTo: returnTo})
	redirect, err := authReq.Redirect(relay, a.sp)
	if err != nil {
		problem(w, http.StatusInternalServerError, "saml", "could not build redirect")
		return
	}
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// Register mounts the ACS (assertion consumer) + SP metadata routes.
func (a *SAMLAuthenticator) Register(mux *http.ServeMux, complete CompleteFunc) {
	mux.Handle("POST /admin/v1/auth/"+a.name+"/acs", a.acs(complete))
	mux.HandleFunc("GET /admin/v1/auth/"+a.name+"/metadata", a.metadata)
}

// acs consumes the IdP's signed SAMLResponse: crewjam validates the signature,
// conditions (NotBefore/NotOnOrAfter), audience (== SP entity id), and InResponseTo
// (== our AuthnRequest ID). We additionally bind RelayState to our cookie.
func (a *SAMLAuthenticator) acs(complete CompleteFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ls, ok := a.readCookie(r)
		a.clearCookie(w)
		if !ok || ls.RequestID == "" {
			// No (valid, signed) login state, or no request id to bind the assertion
			// to. An empty RequestID would make crewjam accept an unsolicited
			// assertion (InResponseTo == ""); reject it. Fail closed.
			problem(w, http.StatusBadRequest, "no login in progress", "missing or invalid SAML login state")
			return
		}
		if err := r.ParseForm(); err != nil {
			problem(w, http.StatusBadRequest, "bad request", "could not parse SAML response")
			return
		}
		if rs := r.FormValue("RelayState"); rs == "" || rs != ls.RelayState {
			problem(w, http.StatusBadRequest, "bad relaystate", "SAML RelayState mismatch")
			return
		}
		assertion, err := a.sp.ParseResponse(r, []string{ls.RequestID})
		if err != nil {
			problem(w, http.StatusUnauthorized, "login failed", "the SAML assertion did not verify")
			return
		}
		complete(w, r, a.name, a.subjectFrom(assertion), ls.ReturnTo)
	}
}

// metadata serves the SP metadata XML so the IdP admin can register Harbor.
func (a *SAMLAuthenticator) metadata(w http.ResponseWriter, r *http.Request) {
	md := a.sp.Metadata()
	out, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		problem(w, http.StatusInternalServerError, "saml", "could not render metadata")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(out)
}

// subjectFrom extracts identity + groups + MFA state from a verified assertion.
func (a *SAMLAuthenticator) subjectFrom(as *saml.Assertion) Subject {
	var subj Subject
	if as.Subject != nil && as.Subject.NameID != nil {
		subj.ID = as.Subject.NameID.Value
	}
	for _, st := range as.AttributeStatements {
		for _, attr := range st.Attributes {
			vals := attrValues(attr)
			switch {
			case attr.Name == a.groupsAttr || attr.FriendlyName == a.groupsAttr:
				subj.Groups = append(subj.Groups, vals...)
			case isEmailAttr(attr) && subj.Email == "" && len(vals) > 0:
				subj.Email = vals[0]
			case isNameAttr(attr) && subj.Name == "" && len(vals) > 0:
				subj.Name = vals[0]
			}
		}
	}
	if subj.Email == "" && strings.Contains(subj.ID, "@") {
		subj.Email = subj.ID // NameID is commonly the email
	}
	subj.MFAAt = samlMFA(as)
	return subj
}

func attrValues(attr saml.Attribute) []string {
	out := make([]string, 0, len(attr.Values))
	for _, v := range attr.Values {
		if v.Value != "" {
			out = append(out, v.Value)
		}
	}
	return out
}

func isEmailAttr(attr saml.Attribute) bool {
	return matchAttr(attr, "email", "emailaddress", "mail")
}

func isNameAttr(attr saml.Attribute) bool {
	return matchAttr(attr, "name", "displayname", "givenname", "cn")
}

func matchAttr(attr saml.Attribute, names ...string) bool {
	n := strings.ToLower(attr.Name)
	fn := strings.ToLower(attr.FriendlyName)
	for _, want := range names {
		if fn == want || n == want || strings.HasSuffix(n, "/"+want) || strings.HasSuffix(n, ":"+want) {
			return true
		}
	}
	return false
}

// samlMFA reports MFA satisfaction when the assertion's AuthnContextClassRef
// signals multi-factor (AD FS multipleauthn, SAML MultiFactor/MobileTwoFactor).
func samlMFA(as *saml.Assertion) *time.Time {
	for _, st := range as.AuthnStatements {
		ref := st.AuthnContext.AuthnContextClassRef
		if ref == nil {
			continue
		}
		v := strings.ToLower(ref.Value)
		if strings.Contains(v, "multifactor") || strings.Contains(v, "multipleauthn") || strings.Contains(v, "mobiletwofactor") {
			t := st.AuthnInstant.UTC()
			return &t
		}
	}
	return nil
}

// ── cookie helpers (SameSite=None so the cross-site IdP POST to the ACS carries
// it; that requires Secure, hence SP-initiated SAML needs https — the OIDC mock
// covers local http dev) ──────────────────────────────────────────────────────

func (a *SAMLAuthenticator) sameSite() http.SameSite {
	if a.secure {
		return http.SameSiteNoneMode
	}
	return http.SameSiteLaxMode
}

func (a *SAMLAuthenticator) setCookie(w http.ResponseWriter, ls samlLoginState) {
	val, err := a.signer.encode(ls) // signed: RequestID/RelayState must not be forgeable
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName(), Value: val,
		Path: "/admin/v1/auth/", MaxAge: 600,
		HttpOnly: true, Secure: a.secure, SameSite: a.sameSite(),
	})
}

func (a *SAMLAuthenticator) readCookie(r *http.Request) (samlLoginState, bool) {
	c, err := r.Cookie(a.cookieName())
	if err != nil {
		return samlLoginState{}, false
	}
	var ls samlLoginState
	if !a.signer.decode(c.Value, &ls) {
		return samlLoginState{}, false
	}
	return ls, true
}

func (a *SAMLAuthenticator) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName(), Value: "", Path: "/admin/v1/auth/", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: a.sameSite(),
	})
}
