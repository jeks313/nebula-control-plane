package heartbeat

import (
	"crypto/ecdsa"
	"path/filepath"
	"testing"

	"github.com/slackhq/nebula/cert"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

func mkPub(t *testing.T) (pub *ecdsa.PublicKey, pem, fp string) {
	t.Helper()
	b, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := b.PublicKey()
	k, err := jws.ParseP256PublicPoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k, string(cert.MarshalSigningPublicKeyToPEM(cert.Curve_P256, raw)), wire.PubkeyHash(raw)
}

// TestConfigKeyReportFromTrustFileNotBundle is the regression for the M8.5 adversarial-review defect:
// the heartbeat must report the config-signing keys it will actually VERIFY with (pin UNION the trust
// FILE) — never the keys merely advertised in the last applied bundle. Reporting an advertised-but-
// not-yet-persisted key would OVER-report adoption and let a cut-over gate pass while the host can't
// verify the new key -> stranded. A lagging trust file must therefore make the host UNDER-report.
func TestConfigKeyReportFromTrustFileNotBundle(t *testing.T) {
	k1, pem1, fp1 := mkPub(t)
	_, pem2, fp2 := mkPub(t) // "K2": a bundle might advertise it, but it isn't in the trust file yet
	trustPath := filepath.Join(t.TempDir(), "config-signing-trust.json")

	// Trust file lags: it holds ONLY K1 (as if bundle.json already advertised [K1,K2] but PersistTrustFile
	// hadn't caught up). The report must be exactly {K1} — NOT K2.
	if err := bundle.PersistTrustFile(trustPath, 5, []string{pem1}); err != nil {
		t.Fatal(err)
	}
	got := trustedConfigKeyFingerprints([]*ecdsa.PublicKey{k1}, trustPath)
	if len(got) != 1 || got[0] != fp1 {
		t.Fatalf("report = %v, want just [%s] (trust-file source); must NOT include the un-persisted K2 %s", got, fp1, fp2)
	}

	// Once the trust file genuinely learns K2, the report includes both (adoption can then converge).
	if err := bundle.PersistTrustFile(trustPath, 6, []string{pem1, pem2}); err != nil {
		t.Fatal(err)
	}
	got = trustedConfigKeyFingerprints([]*ecdsa.PublicKey{k1}, trustPath)
	if len(got) != 2 {
		t.Fatalf("report after learning K2 = %v, want 2 (K1+K2)", got)
	}
	set := map[string]bool{got[0]: true, got[1]: true}
	if !set[fp1] || !set[fp2] {
		t.Fatalf("report = %v, want {K1=%s, K2=%s}", got, fp1, fp2)
	}

	// No trust file at all -> report only the pin (fail-safe, never empty/over-report).
	if got := trustedConfigKeyFingerprints([]*ecdsa.PublicKey{k1}, filepath.Join(t.TempDir(), "absent.json")); len(got) != 1 || got[0] != fp1 {
		t.Fatalf("no-trust-file report = %v, want just the pin [%s]", got, fp1)
	}
}
