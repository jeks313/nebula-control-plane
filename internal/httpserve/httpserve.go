// Package httpserve runs Harbor's HTTP servers with optional TLS. Even the
// mesh-only admin/Core APIs benefit from HTTPS (Secure cookies, HSTS, HTTP/2 for
// SSE, defense-in-depth on top of the Nebula overlay); the public enrollment
// gateway needs it outright. TLS material comes from either a preconfigured
// srv.TLSConfig (e.g. autotls/ACME, which sources + renews certs itself) or a
// cert/key file pair; with neither, the server falls back to plain HTTP (local dev).
package httpserve

import (
	"crypto/tls"
	"net/http"
)

// Serve runs srv with TLS when it can, plaintext only as a last resort:
//   - if srv.TLSConfig already provides certificates (an autotls/ACME config, or
//     preloaded Certificates), serve HTTPS via it — ListenAndServeTLS("", "") sources
//     the cert from the config rather than from files;
//   - else if certFile+keyFile are set, serve HTTPS from those files;
//   - else plain HTTP.
//
// Under TLS, net/http negotiates HTTP/2 automatically and TLS 1.2+ is enforced.
func Serve(srv *http.Server, certFile, keyFile string) error {
	if hasTLSConfig(srv) {
		return srv.ListenAndServeTLS("", "")
	}
	if certFile != "" && keyFile != "" {
		if srv.TLSConfig == nil {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
	return srv.ListenAndServe()
}

// Scheme reports the URL scheme a (cert,key) pair implies, for log/redirect lines.
func Scheme(certFile, keyFile string) string {
	if certFile != "" && keyFile != "" {
		return "https"
	}
	return "http"
}

// SchemeFor is Scheme but also reports "https" when srv carries a preconfigured
// TLSConfig (autotls/ACME) even without cert/key files.
func SchemeFor(srv *http.Server, certFile, keyFile string) string {
	if hasTLSConfig(srv) {
		return "https"
	}
	return Scheme(certFile, keyFile)
}

// hasTLSConfig reports whether srv.TLSConfig can already source certificates (so
// ListenAndServeTLS needs no cert/key files).
func hasTLSConfig(srv *http.Server) bool {
	c := srv.TLSConfig
	return c != nil && (c.GetCertificate != nil || len(c.Certificates) > 0)
}
