package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminauth/samlmock"
	"github.com/jeks313/nebula-control-plane/internal/ssoassert"
)

// ssoFixture mints the on-disk material the SSO flags point at: the gateway's
// assertion-signing private key (genesis sso-assert.key), a SAML SP signing keypair, and
// IdP metadata (from an in-process mock IdP), exactly the shapes a real deploy threads in.
type ssoFixture struct {
	assertKeyPath string
	spCertPath    string
	spKeyPath     string
	idpMetaPath   string
}

func newSSOFixture(t *testing.T) ssoFixture {
	t.Helper()
	dir := t.TempDir()

	// Assertion-signing private key (the gateway's half of the genesis keypair, S6).
	priv, err := ssoassert.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	assertPEM, err := ssoassert.MarshalPrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	assertKeyPath := filepath.Join(dir, "sso-assert.key")
	writeFile(t, assertKeyPath, assertPEM)

	// SAML SP signing keypair (RSA — crewjam signs AuthnRequests with RSA).
	spKey, spCertDER := genRSACert(t)
	spCertPath := filepath.Join(dir, "sp.crt")
	spKeyPath := filepath.Join(dir, "sp.key")
	writeFile(t, spCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: spCertDER}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(spKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, spKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	// IdP metadata, via the same mock IdP the portal round-trip test uses.
	idpKey, idpCertDER := genRSACert(t)
	idpCert, err := x509.ParseCertificate(idpCertDER)
	if err != nil {
		t.Fatal(err)
	}
	mock, err := samlmock.New("https://idp.example.test", idpKey, idpCert, map[string]samlmock.User{
		"engineer": {Email: "dev@corp.test", Name: "Dev Eng", Groups: []string{"corp-eng"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	metaXML, err := xml.MarshalIndent(mock.Metadata(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	idpMetaPath := filepath.Join(dir, "idp-metadata.xml")
	writeFile(t, idpMetaPath, metaXML)

	return ssoFixture{assertKeyPath: assertKeyPath, spCertPath: spCertPath, spKeyPath: spKeyPath, idpMetaPath: idpMetaPath}
}

func genRSACert(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSSOFlagsDisabledWhenAbsent: with no SSO flags set, build() returns (nil, nil) —
// the portal is disabled and the gateway is unaffected.
func TestSSOFlagsDisabledWhenAbsent(t *testing.T) {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	f := addSSOFlags(fs)
	if f.requested() {
		t.Fatal("SSO should not be requested with no flags set")
	}
	cfg, err := f.build()
	if err != nil {
		t.Fatalf("build with no SSO flags: unexpected error %v", err)
	}
	if cfg != nil {
		t.Fatalf("Config.SSO should be nil when no SSO flags are set, got %+v", cfg)
	}
}

// TestSSOFlagsBuildWhenPresent: with the full set of SSO flags, build() returns a
// configured, enabled SSOConfig (SAML SP + signing key both present).
func TestSSOFlagsBuildWhenPresent(t *testing.T) {
	fx := newSSOFixture(t)
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	f := addSSOFlags(fs)
	mustSet(t, fs, map[string]string{
		"sso-acs-url":           "https://gateway.example.test/v1/sso/acs",
		"sso-idp-metadata-file": fx.idpMetaPath,
		"sso-sp-cert":           fx.spCertPath,
		"sso-sp-key":            fx.spKeyPath,
		"sso-assert-key":        fx.assertKeyPath,
		"sso-issuer":            "corp",
	})
	cfg, err := f.build()
	if err != nil {
		t.Fatalf("build with full SSO flags: %v", err)
	}
	if cfg == nil {
		t.Fatal("Config.SSO should be non-nil when the SSO flags are set")
	}
	if cfg.SAML == nil || cfg.SigningKey == nil {
		t.Fatalf("SSOConfig missing SAML (%v) or SigningKey (%v)", cfg.SAML == nil, cfg.SigningKey == nil)
	}
	if cfg.Issuer != "corp" {
		t.Fatalf("Issuer = %q, want corp", cfg.Issuer)
	}
}

// TestSSOFlagsFailClosedOnPartial: with SSO requested (-sso-acs-url set) but a required
// piece missing, build() FAILS rather than silently disabling the portal.
func TestSSOFlagsFailClosedOnPartial(t *testing.T) {
	fx := newSSOFixture(t)
	cases := map[string]map[string]string{
		"missing assert key": {
			"sso-acs-url":           "https://gateway.example.test/v1/sso/acs",
			"sso-idp-metadata-file": fx.idpMetaPath,
			"sso-sp-cert":           fx.spCertPath,
			"sso-sp-key":            fx.spKeyPath,
			// sso-assert-key omitted
		},
		"missing SP keypair": {
			"sso-acs-url":           "https://gateway.example.test/v1/sso/acs",
			"sso-idp-metadata-file": fx.idpMetaPath,
			"sso-assert-key":        fx.assertKeyPath,
			// sso-sp-cert / sso-sp-key omitted
		},
		"missing IdP metadata": {
			"sso-acs-url":    "https://gateway.example.test/v1/sso/acs",
			"sso-sp-cert":    fx.spCertPath,
			"sso-sp-key":     fx.spKeyPath,
			"sso-assert-key": fx.assertKeyPath,
			// no -sso-idp-metadata-*
		},
		"acs url not absolute": {
			"sso-acs-url":           "/v1/sso/acs",
			"sso-idp-metadata-file": fx.idpMetaPath,
			"sso-sp-cert":           fx.spCertPath,
			"sso-sp-key":            fx.spKeyPath,
			"sso-assert-key":        fx.assertKeyPath,
		},
	}
	for name, flags := range cases {
		t.Run(name, func(t *testing.T) {
			fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
			f := addSSOFlags(fs)
			mustSet(t, fs, flags)
			if _, err := f.build(); err == nil {
				t.Fatal("expected build() to fail closed on partial SSO config, got nil error")
			}
		})
	}
}

func mustSet(t *testing.T, fs *flag.FlagSet, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		if err := fs.Set(k, v); err != nil {
			t.Fatalf("set -%s: %v", k, err)
		}
	}
}
