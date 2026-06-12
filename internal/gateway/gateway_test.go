package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

func testServer(t *testing.T) http.Handler {
	t.Helper()
	k := make([]byte, 32)
	ring, err := nonce.NewKeyring([][]byte{k}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return New(ring).Handler()
}

func TestNonceHappyPath(t *testing.T) {
	h := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/nonce?binding=abc123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	var resp wire.NonceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ProtocolVersion != wire.ProtocolVersion || resp.Nonce == "" || resp.ExpiresAt == "" {
		t.Fatalf("bad response: %+v", resp)
	}

	// The minted nonce verifies for the same binding.
	ring, _ := nonce.NewKeyring([][]byte{make([]byte, 32)}, 0, 0)
	if err := ring.Verify(resp.Nonce, []byte("abc123")); err != nil {
		t.Fatalf("minted nonce failed verify: %v", err)
	}
}

func TestNonceMissingBinding(t *testing.T) {
	h := testServer(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/nonce", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var body struct {
		Error wire.Error `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != wire.CodeInvalidRequest {
		t.Fatalf("code = %q, want %q", body.Error.Code, wire.CodeInvalidRequest)
	}
}

func TestNonceMethodNotAllowed(t *testing.T) {
	h := testServer(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/nonce", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
