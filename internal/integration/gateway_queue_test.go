package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/gateway"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

// TestEnrollEndToEndPollBundle is the M3.6/3.6a acceptance: a host enrolls via
// the gateway, Core drains the queue and issues, and the host polls and gets a
// bundle JWS that verifies against the pinned config-signing key — and the cert
// inside verifies against the CA.
func TestEnrollEndToEndPollBundle(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()

	// Gateway shares the durable store for both publish (queue) and poll (results).
	gw := gateway.New(gateway.Config{Nonces: e.ring, Queue: e.d, Results: e.d}).Handler()
	secret, _, _ := joinkey.Create(ctx, e.store, joinkey.Params{Name: "q", Groups: []string{"web"}, MaxUses: 0, AutoIssue: true}, time.Now())

	// Submit.
	priv, _, n := e.fresh(t)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(string(signBody(t, priv, n, secret, "host-q")))))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enroll = %d; %s", rec.Code, rec.Body)
	}
	var acc wire.EnrollAccepted
	json.Unmarshal(rec.Body.Bytes(), &acc)

	// Before processing, polling shows... nothing yet recorded -> not_found.
	if code := poll(t, gw, acc.EnrollmentID, acc.RetrievalSecret).Code; code != http.StatusNotFound {
		t.Fatalf("pre-drain poll = %d, want 404", code)
	}

	// Core drains -> issues -> writes the bundle result.
	if _, err := e.cons.Drain(ctx, e.d, 10, time.Minute); err != nil {
		t.Fatal(err)
	}

	// Poll returns the issued bundle.
	pr := poll(t, gw, acc.EnrollmentID, acc.RetrievalSecret)
	if pr.Code != http.StatusOK {
		t.Fatalf("poll = %d; %s", pr.Code, pr.Body)
	}
	var resp wire.PollResponse
	json.Unmarshal(pr.Body.Bytes(), &resp)
	if resp.Status != "issued" || len(resp.Bundle) == 0 {
		t.Fatalf("poll resp = %+v", resp)
	}

	// The bundle JWS verifies against the PINNED config-signing key.
	b, err := bundle.Verify(resp.Bundle, e.pinned)
	if err != nil {
		t.Fatalf("bundle verify: %v", err)
	}
	if b.Device.Groups[0] != "web" || len(b.Lighthouses) != 1 {
		t.Fatalf("bundle device/lighthouses wrong: %+v", b)
	}
	// M6.4: the signed bundle carries the central-policy firewall for this host.
	if b.Firewall == nil {
		t.Fatal("bundle should carry the central firewall")
	}
	var has443 bool
	for _, r := range b.Firewall.Inbound {
		if r.Proto == "tcp" && r.Port == "443" {
			has443 = true
		}
	}
	if !has443 {
		t.Fatalf("web host firewall should allow inbound tcp/443: %+v", b.Firewall.Inbound)
	}
	// And the cert inside verifies against the CA.
	pool, _ := cert.NewCAPoolFromPEM([]byte(b.CABundle[0]))
	c, _, _ := cert.UnmarshalCertificateFromPEM([]byte(b.Certificate))
	if _, err := pool.VerifyCertificate(time.Now(), c); err != nil {
		t.Fatalf("bundle cert does not verify: %v", err)
	}

	// One-time read: a second poll of the issued bundle is gone.
	if code := poll(t, gw, acc.EnrollmentID, acc.RetrievalSecret).Code; code != http.StatusGone {
		t.Fatalf("second poll = %d, want 410 (one-time read)", code)
	}
	// Wrong secret never reveals anything.
	if code := poll(t, gw, acc.EnrollmentID, "njk_wrong").Code; code != http.StatusNotFound {
		t.Fatalf("wrong-secret poll = %d, want 404", code)
	}
}

func poll(t *testing.T, h http.Handler, id, secret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/enroll/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
