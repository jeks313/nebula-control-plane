package adminui

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

const idx = `<!doctype html><html><head>` +
	`<script>window.__HARBOR__ = { environment: "__HARBOR_ENV__" };</script>` +
	`</head><body><div id="root"></div></body></html>`

func newSPA(env string) http.Handler {
	return spaHandler(fstest.MapFS{
		"index.html":           {Data: []byte(idx)},
		"assets/app-abc123.js": {Data: []byte("console.log(1)")},
	}, Config{Environment: env})
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestEnvInjection: the server injects its environment into index.html (the SPA
// must not infer it). Served on "/", "/index.html", and SPA client routes.
func TestEnvInjection(t *testing.T) {
	h := newSPA("production")
	for _, p := range []string{"/", "/index.html", "/devices"} {
		body := get(t, h, p).Body.String()
		if strings.Contains(body, "__HARBOR_ENV__") {
			t.Errorf("%s: placeholder not replaced: %s", p, body)
		}
		if !strings.Contains(body, `environment: "production"`) {
			t.Errorf("%s: environment not injected: %s", p, body)
		}
	}
}

// TestEnvSanitized: a hostile environment value can't break out of the script.
func TestEnvSanitized(t *testing.T) {
	body := get(t, newSPA(`"};alert(1);//`), "/").Body.String()
	if strings.Contains(body, "alert(1)") {
		t.Fatalf("injection not sanitized: %s", body)
	}
	if !strings.Contains(body, `environment: "development"`) {
		t.Fatalf("unsafe env should fall back to development: %s", body)
	}
}

// TestAssetVsSPAFallback: real files serve as-is; unknown paths fall back to index.
func TestSPAFallback(t *testing.T) {
	h := newSPA("development")
	if asset := get(t, h, "/assets/app-abc123.js"); !strings.Contains(asset.Body.String(), "console.log") {
		t.Fatalf("asset not served: %s", asset.Body.String())
	}
	if asset := get(t, h, "/assets/app-abc123.js"); !strings.Contains(asset.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("hashed asset should be cached immutable")
	}
	// A path that doesn't exist → SPA fallback (index), not 404.
	if fb := get(t, h, "/some/client/route"); !strings.Contains(fb.Body.String(), "id=\"root\"") {
		t.Fatalf("client route should fall back to index: %s", fb.Body.String())
	}
}

// TestCSPAllowsInlineScript: the served CSP must authorize the inline runtime-config
// script (else the browser blocks it and the injected environment never loads). The
// CSP carries a sha256 of the served inline body and never grants scripts unsafe-inline.
func TestCSPAllowsInlineScript(t *testing.T) {
	rec := get(t, newSPA("production"), "/")
	body := rec.Body.String()
	csp := rec.Header().Get("Content-Security-Policy")

	// Extract the served inline <script> body and hash it as a browser would.
	const open, closing = "<script>", "</script>"
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("no inline script in served index: %s", body)
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, closing)
	if j < 0 {
		t.Fatalf("unterminated inline script: %s", body)
	}
	sum := sha256.Sum256([]byte(rest[:j]))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"

	if !strings.Contains(csp, "script-src") {
		t.Fatalf("CSP has no script-src directive: %q", csp)
	}
	if !strings.Contains(csp, want) {
		t.Fatalf("CSP does not authorize the served inline script\n  want hash: %s\n  csp: %q", want, csp)
	}
	// The whole point: scripts must NOT be allowed via unsafe-inline.
	if strings.Contains(csp, "script-src") {
		scriptDir := csp[strings.Index(csp, "script-src"):]
		if end := strings.Index(scriptDir, ";"); end >= 0 {
			scriptDir = scriptDir[:end]
		}
		if strings.Contains(scriptDir, "'unsafe-inline'") {
			t.Fatalf("script-src must not grant 'unsafe-inline': %q", scriptDir)
		}
	}
}

// TestHSTSOnlyOverTLS: HSTS is emitted on TLS requests and withheld on plain HTTP.
func TestHSTSOnlyOverTLS(t *testing.T) {
	h := newSPA("production")

	plain := httptest.NewRecorder()
	h.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := plain.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS must not be sent over plain HTTP, got %q", got)
	}

	secure := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	h.ServeHTTP(secure, req)
	if got := secure.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatal("HSTS must be sent over TLS")
	}
}

// TestNoTraversal: a traversal attempt cannot escape the FS; it falls back to index.
func TestNoTraversal(t *testing.T) {
	body := get(t, newSPA("development"), "/../adminui.go").Body.String()
	if strings.Contains(body, "package adminui") {
		t.Fatal("path traversal escaped the embedded FS")
	}
}
