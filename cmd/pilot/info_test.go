package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/slackhq/nebula/cert"
)

// TestReadMeshState lays a real enrolled mesh on disk (cert + ca + config.yml +
// service.env + a signed/pinned bundle.json) and confirms readMeshState surfaces every
// field — the same local reads `pilot status` does, plus the richer info fields.
func TestReadMeshState(t *testing.T) {
	base := t.TempDir()
	// A real host cert in 10.44.0.0/16 (reuses main_test's writeMeshCert via the shared
	// package, but that writes to <root>/<mesh>; here we want files directly in base).
	overlay := netip.MustParsePrefix("10.44.0.7/16")
	writeMeshCert(t, filepath.Dir(base), filepath.Base(base), overlay)

	// config.yml with two lighthouses.
	cfg := `static_host_map:
  "10.44.0.1": ["198.51.100.1:4242"]
  "10.44.0.2": ["198.51.100.2:4242"]
lighthouse:
  hosts:
    - "10.44.0.1"
    - "10.44.0.2"
`
	if err := os.WriteFile(paths.New(base).Config(), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	// service.env with the core URL.
	if err := os.WriteFile(filepath.Join(base, "service.env"),
		[]byte("# header\nNCP_CORE_URL=https://core.mesh.internal:8443\nNCP_NEBULA=/usr/local/bin/nebula\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	// A signed bundle + its pin (so readBundleVersion verifies + reports the version).
	writeSignedBundle(t, base, 42)

	mi := readMeshState(base)

	if mi.OverlayIP != "10.44.0.7" {
		t.Fatalf("overlay ip = %q, want 10.44.0.7", mi.OverlayIP)
	}
	if mi.CommonName != "host" {
		t.Fatalf("common name = %q, want host", mi.CommonName)
	}
	if len(mi.Groups) != 1 || mi.Groups[0] != "g" {
		t.Fatalf("groups = %v, want [g]", mi.Groups)
	}
	if mi.NotAfter == "" || mi.TimeToExpiry == "" || mi.Expired {
		t.Fatalf("validity not populated / wrongly expired: %+v", mi)
	}
	if !strings.HasPrefix(mi.TimeToExpiry, "in ") {
		t.Fatalf("time-to-expiry = %q, want a future 'in ...'", mi.TimeToExpiry)
	}
	if mi.CertFP == "" || mi.CAFP == "" {
		t.Fatalf("fingerprints not populated: cert=%q ca=%q", mi.CertFP, mi.CAFP)
	}
	wantLH := []string{"10.44.0.1", "10.44.0.2"}
	if strings.Join(mi.Lighthouses, ",") != strings.Join(wantLH, ",") {
		t.Fatalf("lighthouses = %v, want %v", mi.Lighthouses, wantLH)
	}
	if mi.CoreURL != "https://core.mesh.internal:8443" {
		t.Fatalf("core url = %q", mi.CoreURL)
	}
	if mi.BundleVer != 42 {
		t.Fatalf("bundle version = %d, want 42", mi.BundleVer)
	}
}

// TestReadMeshStateNotEnrolled: an empty state dir yields a mostly-empty MeshInfo (no
// panic, no error) — the "not joined / not enrolled" path.
func TestReadMeshStateNotEnrolled(t *testing.T) {
	mi := readMeshState(t.TempDir())
	if mi.OverlayIP != "" || mi.CommonName != "" || mi.CertFP != "" || mi.BundleVer != 0 {
		t.Fatalf("empty dir should yield empty identity: %+v", mi)
	}
}

// TestReadBundleVersionUnverified: a bundle signed by a key OTHER than the on-disk pin
// must NOT have its version trusted (returns 0) — info never reports an unverified
// bundle's contents.
func TestReadBundleVersionUnverified(t *testing.T) {
	base := t.TempDir()
	// Pin one key...
	good, _ := signer.NewSoftwareBackend()
	pub, _ := good.PublicKey()
	pin := cert.MarshalSigningPublicKeyToPEM(cert.Curve_P256, pub)
	if err := os.WriteFile(filepath.Join(base, "config-signing.pub"), pin, 0o644); err != nil {
		t.Fatal(err)
	}
	// ...but sign the bundle with a different key.
	other, _ := signer.NewSoftwareBackend()
	signed, err := bundle.Sign(other, "k", bundle.Bundle{
		BundleVersion: 99, Device: bundle.Device{Name: "h"},
		Certificate: "c", CABundle: []string{"ca"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.New(base).Bundle(), signed, 0o644); err != nil {
		t.Fatal(err)
	}
	if v := readBundleVersion(base, paths.New(base).Bundle()); v != 0 {
		t.Fatalf("unverified bundle version = %d, want 0 (must not trust it)", v)
	}
}

// TestReadCoreURL covers the service.env parse incl. comments + whitespace.
func TestReadCoreURL(t *testing.T) {
	base := t.TempDir()
	if got := readCoreURL(base); got != "" {
		t.Fatalf("missing service.env should yield empty, got %q", got)
	}
	if err := os.WriteFile(filepath.Join(base, "service.env"),
		[]byte("# a comment\n\nNCP_NEBULA=/x\n  NCP_CORE_URL=https://h:8443 \n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := readCoreURL(base); got != "https://h:8443" {
		t.Fatalf("core url = %q, want https://h:8443", got)
	}
}

// TestProbeHarborReachable: a 200 on /healthz is reported reachable with a latency.
func TestProbeHarborReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	h := probeHarbor(context.Background(), srv.URL)
	if h == nil || !h.Reachable || h.Endpoint != "/healthz" || h.StatusCode != 200 {
		t.Fatalf("probe = %+v, want reachable /healthz 200", h)
	}
}

// TestProbeHarborFallsThroughToReadyz: /healthz 404 but /readyz 200 -> reachable via
// /readyz.
func TestProbeHarborFallsThroughToReadyz(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	h := probeHarbor(context.Background(), srv.URL)
	if h == nil || !h.Reachable || h.Endpoint != "/readyz" {
		t.Fatalf("probe = %+v, want reachable via /readyz", h)
	}
}

// TestProbeHarborUnreachable: a dead address reports unreachable with an error, never
// panicking — a down Harbor must not fail `pilot info`.
func TestProbeHarborUnreachable(t *testing.T) {
	h := probeHarbor(context.Background(), "http://127.0.0.1:1")
	if h == nil || h.Reachable || h.Error == "" {
		t.Fatalf("probe = %+v, want unreachable + error", h)
	}
}

// TestHumanDur spot-checks the coarse expiry rendering.
func TestHumanDur(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{50 * time.Hour, "2d 2h"},
		{3*time.Hour + 30*time.Minute, "3h 30m"},
		{45 * time.Minute, "45m"},
		{20 * time.Second, "20s"},
		{-50 * time.Hour, "2d 2h"}, // sign-insensitive (used for "expired N ago")
	}
	for _, c := range cases {
		if got := humanDur(c.d); got != c.want {
			t.Fatalf("humanDur(%s) = %q, want %q", c.d, got, c.want)
		}
	}
}

// TestPrintInfoOffCloudNoMesh: the human render of a laptop (no mesh, no cloud) shows the
// "not joined" + "no cloud metadata" lines and never errors.
func TestPrintInfoOffCloudNoMesh(t *testing.T) {
	info := nodeInfo{
		Node:  NodeSection{Hostname: "laptop", OS: "darwin", Arch: "arm64", PilotVersion: "dev"},
		Cloud: CloudSection{Provider: "none"},
	}
	out := renderToString(t, info)
	for _, want := range []string{"node", "not joined to any mesh.", "no cloud instance metadata detected"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

// TestPrintInfoAWSCloudtrustHint: the AWS render includes the account + ARN pattern lines
// an operator pastes into Harbor's cloudtrust config.
func TestPrintInfoAWSCloudtrustHint(t *testing.T) {
	info := nodeInfo{
		Node: NodeSection{Hostname: "ec2", OS: "linux", Arch: "amd64", PilotVersion: "1.2.3"},
		Cloud: CloudSection{Provider: "aws", AWS: &AWSMeta{
			AccountID: "123456789012", Region: "us-east-1", InstanceID: "i-0abc",
			Roles:                []string{"edge-fleet"},
			AssumedRoleARN:       AssumedRoleARN("123456789012", "edge-fleet", "i-0abc"),
			CloudtrustARNPattern: CloudtrustARNPattern("123456789012", "edge-fleet"),
		}},
	}
	out := renderToString(t, info)
	for _, want := range []string{
		"AWS (EC2 IMDSv2)",
		"account id:     123456789012",
		"iam role(s):    edge-fleet",
		"attests as:     arn:aws:sts::123456789012:assumed-role/edge-fleet/i-0abc",
		"cloudtrust onboarding hint",
		"arn pattern:  arn:aws:sts::123456789012:assumed-role/edge-fleet/*",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("AWS output missing %q:\n%s", want, out)
		}
	}
}

// TestPrintInfoAzureInformationalNote: the Azure render carries the explicit
// "not yet supported by Harbor" note.
func TestPrintInfoAzureInformationalNote(t *testing.T) {
	info := nodeInfo{
		Node: NodeSection{Hostname: "vm", OS: "linux", Arch: "amd64", PilotVersion: "1.2.3"},
		Cloud: CloudSection{Provider: "azure", Azure: &AzureMeta{
			SubscriptionID: "sub", ResourceGroup: "rg", VMName: "vm-1", VMID: "vid", Location: "eastus",
		}},
	}
	out := renderToString(t, info)
	if !strings.Contains(out, "Azure attestation is not yet supported by Harbor (AWS sigv4 only)") {
		t.Fatalf("Azure output missing the informational note:\n%s", out)
	}
}

// renderToString runs printInfo against a temp file and returns the captured output.
func renderToString(t *testing.T, info nodeInfo) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	printInfo(f, info)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeSignedBundle writes a config bundle signed by a fresh config-signing key plus
// that key's pin (config-signing.pub) into base, so readBundleVersion verifies it.
func writeSignedBundle(t *testing.T, base string, ver int) {
	t.Helper()
	be, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := be.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pin := cert.MarshalSigningPublicKeyToPEM(cert.Curve_P256, pub)
	if err := os.WriteFile(filepath.Join(base, "config-signing.pub"), pin, 0o644); err != nil {
		t.Fatal(err)
	}
	signed, err := bundle.Sign(be, "kid", bundle.Bundle{
		BundleVersion: ver, Device: bundle.Device{Name: "host", OverlayIP: "10.44.0.7"},
		Certificate: "CERT", CABundle: []string{"CA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.New(base).Bundle(), signed, 0o644); err != nil {
		t.Fatal(err)
	}
}
