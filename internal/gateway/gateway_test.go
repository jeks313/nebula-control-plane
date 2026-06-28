package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

func newTest(t *testing.T) (http.Handler, *nonce.Keyring, *queue.Memory) {
	t.Helper()
	ring, err := nonce.NewKeyring([][]byte{make([]byte, 32)}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := queue.NewMemory()
	h := New(Config{Nonces: ring, Queue: q}).Handler() // no limiter in tests
	return h, ring, q
}

// --- healthz endpoint (NLB self-heal probe) ---

func TestHealthz(t *testing.T) {
	h, _, _ := newTest(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	if got := rec.Body.String(); got != "ok\n" {
		t.Fatalf("body = %q, want %q", got, "ok\n")
	}
}

// --- nonce endpoint ---

func TestNonceHappyPath(t *testing.T) {
	h, ring, _ := newTest(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/nonce?binding=abc123", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("missing no-store")
	}
	var resp wire.NonceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Nonce == "" || ring.Verify(resp.Nonce, []byte("abc123")) != nil {
		t.Fatalf("minted nonce did not verify: %+v", resp)
	}
}

func TestNonceMissingBinding(t *testing.T) {
	h, _, _ := newTest(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/nonce", nil))
	if rec.Code != http.StatusBadRequest || gotCode(t, rec) != wire.CodeInvalidRequest {
		t.Fatalf("status=%d code=%s", rec.Code, gotCode(t, rec))
	}
}

func TestNonceMethodNotAllowed(t *testing.T) {
	h, _, _ := newTest(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/nonce", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// --- enroll endpoint ---

type enrollFixture struct {
	priv       *ecdsa.PrivateKey
	pubBytes   []byte
	pubkeyHash string
}

func newFixture(t *testing.T) enrollFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	pb := ek.Bytes()
	return enrollFixture{priv: priv, pubBytes: pb, pubkeyHash: wire.PubkeyHash(pb)}
}

// signedEnroll builds a valid request, then applies mutate to the payload before
// signing (mutate may be nil).
func (f enrollFixture) body(t *testing.T, ring *nonce.Keyring, mutate func(*wire.EnrollRequest)) []byte {
	t.Helper()
	n, _ := ring.Mint([]byte(f.pubkeyHash))
	req := wire.EnrollRequest{
		ProtocolVersion: wire.ProtocolVersion,
		Type:            "enroll",
		IssuedAt:        time.Now().UTC().Format(time.RFC3339),
		Nonce:           n,
		Method:          wire.MethodToken,
		Credential:      json.RawMessage(`{"token":"t"}`),
	}
	req.CSR = wire.CSR{Curve: "P256", PublicKey: base64.RawURLEncoding.EncodeToString(f.pubBytes), RequestedName: "web-1"}
	req.Client.SupportedProtocolVersions = []int{1}
	if mutate != nil {
		mutate(&req)
	}
	payload, _ := json.Marshal(req)
	env, err := jws.SignES256(f.priv, jws.Header{Typ: wire.TypEnrollRequest, Ver: 1, Kid: f.pubkeyHash}, payload)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	return body
}

func post(t *testing.T, h http.Handler, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(string(body))))
	return rec
}

func gotCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct {
		Error wire.Error `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	return b.Error.Code
}

func TestEnrollHappyPath(t *testing.T) {
	h, ring, q := newTest(t)
	f := newFixture(t)
	rec := post(t, h, f.body(t, ring, nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rec.Code, rec.Body)
	}
	var acc wire.EnrollAccepted
	if err := json.Unmarshal(rec.Body.Bytes(), &acc); err != nil {
		t.Fatal(err)
	}
	if acc.EnrollmentID == "" || acc.RetrievalSecret == "" {
		t.Fatalf("ticket incomplete: %+v", acc)
	}
	cands := q.Drain()
	if len(cands) != 1 || cands[0].PubkeyHash != f.pubkeyHash || cands[0].EnrollmentID != acc.EnrollmentID {
		t.Fatalf("candidate not queued correctly: %+v", cands)
	}
}

func TestEnrollBadSignature(t *testing.T) {
	h, ring, q := newTest(t)
	f := newFixture(t)
	body := f.body(t, ring, nil)
	// Flip a byte in the signature field of the JWS JSON.
	var env jws.Flattened
	_ = json.Unmarshal(body, &env)
	sig, _ := base64.RawURLEncoding.DecodeString(env.Signature)
	sig[0] ^= 0xff
	env.Signature = base64.RawURLEncoding.EncodeToString(sig)
	tampered, _ := json.Marshal(env)

	rec := post(t, h, tampered)
	if rec.Code != http.StatusUnauthorized || gotCode(t, rec) != wire.CodeInvalidSignature {
		t.Fatalf("status=%d code=%s", rec.Code, gotCode(t, rec))
	}
	if q.Len() != 0 {
		t.Fatal("bad-signature request must not be queued")
	}
}

func TestEnrollWrongNonceBinding(t *testing.T) {
	h, ring, _ := newTest(t)
	f := newFixture(t)
	// Mint a nonce bound to a different identity, splice it in.
	otherNonce, _ := ring.Mint([]byte("someone-else"))
	body := f.body(t, ring, func(r *wire.EnrollRequest) { r.Nonce = otherNonce })
	rec := post(t, h, body)
	if rec.Code != http.StatusUnauthorized || gotCode(t, rec) != wire.CodeInvalidNonce {
		t.Fatalf("status=%d code=%s", rec.Code, gotCode(t, rec))
	}
}

func TestEnrollMissingNonce(t *testing.T) {
	h, ring, _ := newTest(t)
	f := newFixture(t)
	body := f.body(t, ring, func(r *wire.EnrollRequest) { r.Nonce = "" })
	rec := post(t, h, body)
	if rec.Code != http.StatusBadRequest || gotCode(t, rec) != wire.CodeInvalidRequest {
		t.Fatalf("status=%d code=%s", rec.Code, gotCode(t, rec))
	}
}

func TestEnrollUnknownMethod(t *testing.T) {
	h, ring, _ := newTest(t)
	f := newFixture(t)
	body := f.body(t, ring, func(r *wire.EnrollRequest) { r.Method = "bogus" })
	rec := post(t, h, body)
	if rec.Code != http.StatusBadRequest || gotCode(t, rec) != wire.CodeInvalidRequest {
		t.Fatalf("status=%d code=%s", rec.Code, gotCode(t, rec))
	}
}

func TestEnrollOversizedRejected(t *testing.T) {
	h := New(Config{
		Nonces: mustRing(t), Queue: queue.NewMemory(), MaxBodyBytes: 512,
	}).Handler()
	big := strings.Repeat("A", 4096)
	rec := post(t, h, []byte(`{"protected":"`+big+`"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for oversized body", rec.Code)
	}
}

func mustRing(t *testing.T) *nonce.Keyring {
	t.Helper()
	r, err := nonce.NewKeyring([][]byte{make([]byte, 32)}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
