package adminauth

import (
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func attr(name string, vals ...string) saml.Attribute {
	a := saml.Attribute{Name: name, FriendlyName: name}
	for _, v := range vals {
		a.Values = append(a.Values, saml.AttributeValue{Value: v})
	}
	return a
}

// TestSAMLSubjectFrom checks identity + group extraction from an assertion.
func TestSAMLSubjectFrom(t *testing.T) {
	a := &SAMLAuthenticator{groupsAttr: "groups"}
	as := &saml.Assertion{
		Subject: &saml.Subject{NameID: &saml.NameID{Value: "ada@harbor.test"}},
		AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{
			attr("groups", "harbor-admins", "harbor-operators"),
			attr("displayName", "Ada Admin"),
		}}},
	}
	subj := a.subjectFrom(as)
	if subj.ID != "ada@harbor.test" || subj.Email != "ada@harbor.test" {
		t.Fatalf("identity = %+v", subj)
	}
	if subj.Name != "Ada Admin" {
		t.Fatalf("name = %q", subj.Name)
	}
	if len(subj.Groups) != 2 || subj.Groups[0] != "harbor-admins" {
		t.Fatalf("groups = %v", subj.Groups)
	}
}

// TestSAMLMFA checks the AuthnContextClassRef → MFA mapping.
func TestSAMLMFA(t *testing.T) {
	withClassRef := func(ref string) *saml.Assertion {
		return &saml.Assertion{AuthnStatements: []saml.AuthnStatement{{
			AuthnInstant: time.Unix(1_700_000_000, 0),
			AuthnContext: saml.AuthnContext{AuthnContextClassRef: &saml.AuthnContextClassRef{Value: ref}},
		}}}
	}
	// AD FS multi-factor + SAML MultiFactor class refs are recognized.
	if samlMFA(withClassRef("http://schemas.microsoft.com/claims/multipleauthn")) == nil {
		t.Error("AD FS multipleauthn should count as MFA")
	}
	if samlMFA(withClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract")) == nil {
		t.Error("MobileTwoFactorContract should count as MFA")
	}
	// Plain password is NOT MFA.
	if samlMFA(withClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")) != nil {
		t.Error("PasswordProtectedTransport must not count as MFA")
	}
}

// TestSAMLMFAFromAMR: Entra leaves AuthnContextClassRef as plain Password even after MFA and
// records the multi-factor signal in the authnmethodsreferences (amr) attribute instead — the real
// live shape (MFA via Duo). samlMFA must honor it, else step-up can never be satisfied.
func TestSAMLMFAFromAMR(t *testing.T) {
	withAMR := func(vals ...string) *saml.Assertion {
		return &saml.Assertion{
			IssueInstant: time.Unix(1_700_000_000, 0),
			AuthnStatements: []saml.AuthnStatement{{
				AuthnInstant: time.Unix(1_700_000_000, 0),
				AuthnContext: saml.AuthnContext{AuthnContextClassRef: &saml.AuthnContextClassRef{
					Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"}},
			}},
			AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{
				attr("http://schemas.microsoft.com/claims/authnmethodsreferences", vals...),
			}}},
		}
	}
	// password + multipleauthn (the live Entra+Duo shape) -> MFA even though the class-ref is Password.
	if samlMFA(withAMR(
		"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
		"http://schemas.microsoft.com/claims/multipleauthn",
	)) == nil {
		t.Error("amr containing multipleauthn must count as MFA")
	}
	// password only (no second factor) -> NOT MFA.
	if samlMFA(withAMR("http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password")) != nil {
		t.Error("amr with only password must NOT count as MFA")
	}
}
