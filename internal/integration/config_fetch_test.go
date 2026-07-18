package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/enrollclient"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// TestFetchConfigHostBindingAndAntiRollback (M4 fix): the GET /v1/config apply path
// (enrollclient.FetchConfig, wired to the apply_bundle command) must (a) refuse a bundle
// bound to a DIFFERENT host — cross-device replay — and (b) refuse a bundle whose
// blocklist-lane version is LOWER than the one already applied — a replay/downgrade that
// would DROP a revoked fingerprint from pki.blocklist. Forward progress still applies.
func TestFetchConfigHostBindingAndAntiRollback(t *testing.T) {
	e := setupEnroll(t)
	ctx := context.Background()

	ip, certPEM := enrolledHost(t, e, "host-fc")

	// Lay down the host's cert so FetchConfig can read its (stable) overlay IP.
	layout := paths.New(t.TempDir())
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.HostCert(), []byte(certPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	mkBundle := func(devIP string, blVer int, blocklist []string) []byte {
		b := bundle.Bundle{
			BundleVersion: 1, BlocklistVersion: blVer,
			IssuedAt:    time.Now().UTC().Format(time.RFC3339),
			Device:      bundle.Device{Name: "host-fc", OverlayIP: devIP, Groups: []string{"web"}},
			Certificate: certPEM, CABundle: []string{string(e.caPEM)},
			Lighthouses: []bundle.Lighthouse{}, Blocklist: blocklist,
			NotAfter: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		}
		jw, err := bundle.Sign(e.cfgB, e.configKeyID, b)
		if err != nil {
			t.Fatal(err)
		}
		return jw
	}

	var serve []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		wire.WriteJSON(w, http.StatusOK, wire.ConfigResponse{ProtocolVersion: wire.ProtocolVersion, Bundle: serve})
	}))
	defer srv.Close()
	rp := enrollclient.RenewParams{CoreURL: srv.URL, Layout: layout, PinnedConfigPub: e.pinned}

	// 1. Correct host + blocklist v2 (revokes fp "a…") -> applied.
	serve = mkBundle(ip, 2, []string{strings.Repeat("a", 64)})
	if _, err := enrollclient.FetchConfig(ctx, rp); err != nil {
		t.Fatalf("valid fetch (blocklist v2) should apply: %v", err)
	}

	// 2. Cross-device replay: a validly-signed bundle bound to a DIFFERENT overlay IP -> refused.
	serve = mkBundle("100.64.9.9", 3, nil)
	if _, err := enrollclient.FetchConfig(ctx, rp); err == nil {
		t.Fatal("expected refusal for a config bundle bound to a different host")
	}

	// 3. Rollback replay: an OLD signed bundle (blocklist v1 < applied v2) that DROPS the
	//    revoked fingerprint -> refused (would otherwise un-revoke the peer on this host).
	serve = mkBundle(ip, 1, nil)
	if _, err := enrollclient.FetchConfig(ctx, rp); err == nil {
		t.Fatal("expected refusal for a blocklist-version rollback (replay/downgrade)")
	}

	// 4. Forward progress: blocklist v3 (adds another fp) -> applied.
	serve = mkBundle(ip, 3, []string{strings.Repeat("a", 64), strings.Repeat("b", 64)})
	if _, err := enrollclient.FetchConfig(ctx, rp); err != nil {
		t.Fatalf("forward fetch (blocklist v3) should apply: %v", err)
	}
}
