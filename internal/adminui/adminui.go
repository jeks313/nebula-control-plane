// Package adminui serves Harbor's web console (the React SPA) over the mesh from
// the admin API. The built bundle is embedded into the Core binary via go:embed
// under the `ui` build tag (single artifact, lockstep UI↔API versioning); a default
// build (no `-tags ui`, e.g. CI without Node) compiles a small "not built" stub, so
// `go build ./...` never needs the SPA.
//
// Build a UI-enabled binary with:
//
//	npm --prefix ui run build && go build -tags ui ./cmd/harbor
package adminui

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"strings"
)

// Config configures the served console.
type Config struct {
	// Environment is the deployment posture the SPA tints its banner on (the server
	// is the source of truth; the client must not infer it). Anything other than
	// "production" is treated by the SPA as non-production (fail-closed).
	Environment string
	// InstallerBaseURL is the public base URL of the artifact bucket the per-method
	// installer scripts live under (e.g. https://<bucket>.s3.<region>.amazonaws.com).
	// The console renders the node "Copy install command" widgets from it. Empty =
	// the widgets fall back to a generic, copy-the-URL-yourself hint.
	InstallerBaseURL string
}

// spaHandler serves the embedded SPA: real files by path, with a fallback to
// index.html for client-side routes (so deep links like /devices load the app).
// index.html is patched ONCE with the server-provided environment.
func spaHandler(dist fs.FS, cfg Config) http.Handler {
	raw, _ := fs.ReadFile(dist, "index.html")
	// ReplaceAll (not the first match): the tokens may appear more than once (e.g. in
	// a comment), and every occurrence must reflect the real value. Both substitutions
	// land inside the inline runtime-config <script>, so each value is sanitized to a
	// benign token before injection (the CSP sha256 is computed AFTER, but a value that
	// broke out of the JS string would still execute — sanitize, don't rely on the pin).
	s := strings.ReplaceAll(string(raw), "__HARBOR_ENV__", safeEnv(cfg.Environment))
	s = strings.ReplaceAll(s, "__HARBOR_INSTALLER_BASE__", safeURL(cfg.InstallerBaseURL))
	index := []byte(s)
	// The CSP must authorize the one inline runtime-config <script> we ship. Pin it by
	// the sha256 of its post-injection body (the env is already substituted), so it runs
	// without granting scripts 'unsafe-inline' — injected <script> still can't execute.
	csp := contentSecurityPolicy(index)
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, r, csp)
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean != "" && clean != "index.html" {
			if f, err := dist.Open(clean); err == nil {
				_ = f.Close()
				if strings.HasPrefix(clean, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable") // hashed → immutable
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		serveIndex(w, index) // patched index for "/", "/index.html", and SPA client routes
	})
}

// safeEnv constrains the injected environment to a benign token (operator-set, but
// it lands inside an inline script — never let it carry arbitrary characters).
func safeEnv(env string) string {
	if env == "" {
		return "development"
	}
	for _, r := range env {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return "development"
		}
	}
	return env
}

// safeURL constrains the injected installer base URL to a benign token: it lands
// inside the inline runtime-config script, so reject anything that could break out of
// the JS string literal or open a tag. Allow only the characters a plain https URL
// origin needs ([A-Za-z0-9._:/-]); anything else → "" (the SPA falls back to a generic
// hint). Empty in / empty out (the common dev + no-bucket case).
func safeURL(u string) string {
	if u == "" {
		return ""
	}
	for _, r := range u {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == ':' || r == '/' || r == '-'
		if !ok {
			return ""
		}
	}
	return u
}

func serveIndex(w http.ResponseWriter, index []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(index)
}

// contentSecurityPolicy builds the console CSP, pinning the inline runtime-config
// script by its sha256 so it executes without granting scripts 'unsafe-inline'.
// (style-src still allows 'unsafe-inline' for now — a later UI-0 hardening increment.)
func contentSecurityPolicy(index []byte) string {
	scriptSrc := "'self'"
	if h, ok := inlineScriptSHA256(index); ok {
		scriptSrc += " 'sha256-" + h + "'"
	}
	return "default-src 'self'; script-src " + scriptSrc + "; img-src 'self' data:; " +
		"style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; " +
		"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
}

// inlineScriptSHA256 returns the base64 sha256 of the single attribute-less inline
// <script> body (the runtime config). External module scripts use
// <script type="module" src=…> and are covered by 'self', so they're skipped.
func inlineScriptSHA256(html []byte) (string, bool) {
	open, closing := []byte("<script>"), []byte("</script>")
	i := bytes.Index(html, open)
	if i < 0 {
		return "", false
	}
	start := i + len(open)
	n := bytes.Index(html[start:], closing)
	if n < 0 {
		return "", false
	}
	sum := sha256.Sum256(html[start : start+n])
	return base64.StdEncoding.EncodeToString(sum[:]), true
}

// setSecurityHeaders applies the CSP + hardening to console responses. HSTS is sent
// only over TLS (r.TLS != nil) so it isn't emitted on plain-HTTP local dev.
func setSecurityHeaders(w http.ResponseWriter, r *http.Request, csp string) {
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

// notBuilt is served when the binary was compiled without -tags ui.
func notBuilt() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>Harbor</title>` +
			`<body style="font:14px system-ui;background:#0a0b0d;color:#e7eaf0;margin:3rem auto;max-width:40rem">` +
			`<h1>Harbor console not bundled</h1>` +
			`<p>This binary was built without the web console. Rebuild with the UI embedded:</p>` +
			`<pre style="background:#151820;border:1px solid #232733;border-radius:6px;padding:1rem">` +
			`npm --prefix ui run build &amp;&amp; go build -tags ui ./cmd/harbor</pre>` +
			`<p style="color:#5c6675">The JSON API at /admin/v1 is unaffected.</p>`))
	})
}
