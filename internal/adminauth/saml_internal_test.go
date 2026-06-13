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
