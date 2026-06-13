// Package httpserve runs Harbor's HTTP servers with optional TLS. Even the
// mesh-only admin/Core APIs benefit from HTTPS (Secure cookies, HSTS, HTTP/2 for
// SSE, defense-in-depth on top of the Nebula overlay); the public enrollment
// gateway needs it outright. A server without a cert/key falls back to plain HTTP
// (local dev / mesh-encrypted-only deployments).
package httpserve

import (
	"crypto/tls"
	"net/http"
)

// Serve runs srv with TLS when both certFile and keyFile are set, else plain HTTP.
// Under TLS, net/http negotiates HTTP/2 automatically and TLS 1.2+ is enforced.
func Serve(srv *http.Server, certFile, keyFile string) error {
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
