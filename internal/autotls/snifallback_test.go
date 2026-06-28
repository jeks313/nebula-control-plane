package autotls

import (
	"crypto/tls"
	"errors"
	"testing"
)

// TestWithSNIFallback: a missing or unknown SNI falls back to the primary domain's cert (so a
// no-SNI load-balancer health check can handshake), while a known SNI is served directly.
func TestWithSNIFallback(t *testing.T) {
	primaryCert := &tls.Certificate{}
	// base serves a cert only for the exact primary ServerName, else errors (certmagic's behavior
	// on an unknown SNI — no on-demand issuance configured).
	base := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "gw.example.com" {
			return primaryCert, nil
		}
		return nil, errors.New("no certificate for " + h.ServerName)
	}
	wrapped := withSNIFallback(base, "gw.example.com")

	cases := map[string]string{
		"known SNI":   "gw.example.com",
		"empty SNI":   "",            // an NLB HTTPS health check sends none
		"unknown SNI": "10.99.2.30",  // or it connects by IP
		"other host":  "evil.example",
	}
	for name, sni := range cases {
		cert, err := wrapped(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil || cert != primaryCert {
			t.Errorf("%s (ServerName=%q): cert=%v err=%v, want the primary cert and no error", name, sni, cert, err)
		}
	}
}

// TestWithSNIFallback_PropagatesWhenPrimaryMissing: if even the primary cert can't be served
// (e.g. not yet issued), the error propagates rather than looping.
func TestWithSNIFallback_PropagatesWhenPrimaryMissing(t *testing.T) {
	base := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("not ready") }
	if _, err := withSNIFallback(base, "gw.example.com")(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("want error to propagate when the primary cert is unavailable")
	}
}
