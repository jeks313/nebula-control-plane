package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveReleaseArgs(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "nebula")
	data := []byte("a pretend nebula binary")
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	wantHex := hex.EncodeToString(want[:])

	// -file derives the sha + substitutes {version} in the url.
	sha, url, err := resolveReleaseArgs(bin, "1.10.3", "", "https://cdn/nebula-{version}.bin")
	if err != nil {
		t.Fatal(err)
	}
	if sha != wantHex {
		t.Fatalf("sha = %s, want %s", sha, wantHex)
	}
	if url != "https://cdn/nebula-1.10.3.bin" {
		t.Fatalf("url = %s, want the {version}-substituted url", url)
	}

	// Without -file, the supplied sha passes through (+ {version} still substituted).
	sha, url, err = resolveReleaseArgs("", "2.0.0", "deadbeef", "https://cdn/x-{version}")
	if err != nil || sha != "deadbeef" || url != "https://cdn/x-2.0.0" {
		t.Fatalf("passthrough: sha=%s url=%s err=%v", sha, url, err)
	}

	// -file and -sha256 are mutually exclusive.
	if _, _, err := resolveReleaseArgs(bin, "1", "deadbeef", "u"); err == nil {
		t.Fatal("expected an error when both -file and -sha256 are given")
	}

	// A missing -file is a clear error (not a silent empty sha).
	if _, _, err := resolveReleaseArgs(filepath.Join(dir, "absent"), "1", "", "u"); err == nil {
		t.Fatal("expected an error for a missing -file")
	}
}

func TestCheckReleaseURL(t *testing.T) {
	body := []byte("the artifact bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body) // sets Content-Length for the HEAD too
	}))
	defer srv.Close()
	ctx := context.Background()

	// Reachable + matching size -> ok.
	if msg, ok := checkReleaseURL(ctx, srv.URL+"/ok", int64(len(body))); !ok {
		t.Fatalf("reachable+matching should be ok, got %q", msg)
	}
	// Reachable but size mismatch -> warn.
	if _, ok := checkReleaseURL(ctx, srv.URL+"/ok", int64(len(body)+10)); ok {
		t.Fatal("a size mismatch must warn (ok=false)")
	}
	// 404 -> warn.
	if _, ok := checkReleaseURL(ctx, srv.URL+"/missing", 0); ok {
		t.Fatal("a 404 must warn (ok=false)")
	}
	// Unreachable -> warn (not a panic).
	if _, ok := checkReleaseURL(ctx, "http://127.0.0.1:1/x", 0); ok {
		t.Fatal("an unreachable url must warn (ok=false)")
	}
}
