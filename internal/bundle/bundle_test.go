package bundle

import (
	"strings"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/signer"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	b, err := signer.NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := b.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pubBytes)

	in := Bundle{
		BundleVersion: 1,
		Device:        Device{Name: "web-1", OverlayIP: "100.64.0.5", Groups: []string{"web"}},
		Certificate:   "CERT-PEM",
		CABundle:      []string{"CA-PEM"},
		Lighthouses:   []Lighthouse{{OverlayIP: "100.64.0.1", PublicAddrs: []string{"x:4242"}}},
		NotAfter:      "2026-07-12T00:00:00Z",
	}
	jwsBytes, err := Sign(b, "kid-1", in)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := Verify(jwsBytes, pinned)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if out.Type != Type || out.Device.Name != "web-1" || out.Device.Groups[0] != "web" || out.CABundle[0] != "CA-PEM" {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

// TestSignedFirewallTamperRefused is the M6.4 acceptance: the firewall rides
// inside the signed bundle, so tampering with it is refused by Verify.
func TestSignedFirewallTamperRefused(t *testing.T) {
	b, _ := signer.NewSoftwareBackend()
	pubBytes, _ := b.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pubBytes)

	in := Bundle{
		Device:      Device{Name: "web-1", OverlayIP: "100.64.0.5", Groups: []string{"web"}},
		Certificate: "CERT", CABundle: []string{"CA"},
		Firewall: &Firewall{
			Inbound:  []nebulaconfig.Rule{{Proto: "tcp", Port: "443", Host: "any"}},
			Outbound: []nebulaconfig.Rule{{Proto: "tcp", Port: "5432", Group: "db"}},
		},
	}
	jwsBytes, err := Sign(b, "k", in)
	if err != nil {
		t.Fatal(err)
	}

	// Verifies intact, firewall present.
	out, err := Verify(jwsBytes, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if out.Firewall == nil || out.Firewall.Inbound[0].Port != "443" {
		t.Fatalf("firewall not carried: %+v", out.Firewall)
	}

	// Tamper any byte -> refused (the firewall is signed).
	tampered := make([]byte, len(jwsBytes))
	copy(tampered, jwsBytes)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := Verify(tampered, pinned); err == nil {
		t.Fatal("tampered bundle (incl. firewall) must be refused")
	}
}

// TestSignedBlocklistTamperRefused is the M7.1 acceptance: the cert blocklist
// rides inside the signed bundle (so a host trusts it only after Verify), and
// tampering with it is refused.
func TestSignedBlocklistTamperRefused(t *testing.T) {
	b, _ := signer.NewSoftwareBackend()
	pubBytes, _ := b.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pubBytes)

	in := Bundle{
		Device:      Device{Name: "web-1", OverlayIP: "100.64.0.5", Groups: []string{"web"}},
		Certificate: "CERT", CABundle: []string{"CA"},
		Blocklist: []string{"aa11", "bb22"},
	}
	jwsBytes, err := Sign(b, "k", in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Verify(jwsBytes, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Blocklist) != 2 || out.Blocklist[0] != "aa11" || out.Blocklist[1] != "bb22" {
		t.Fatalf("blocklist not carried: %+v", out.Blocklist)
	}

	tampered := make([]byte, len(jwsBytes))
	copy(tampered, jwsBytes)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := Verify(tampered, pinned); err == nil {
		t.Fatal("tampered bundle (incl. blocklist) must be refused")
	}
}

// TestRenderNebulaConfigBlocklist proves the bundle's blocklist threads into
// nebula's pki.blocklist, and that an empty blocklist renders no key at all.
func TestRenderNebulaConfigBlocklist(t *testing.T) {
	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	b := Bundle{
		Device:      Device{Name: "web-1", OverlayIP: "100.64.0.5"},
		Lighthouses: []Lighthouse{{OverlayIP: "100.64.0.1", PublicAddrs: []string{"198.51.100.1:4242"}}},
		Blocklist:   []string{fp},
	}
	out, err := RenderNebulaConfig(b, "/ca.crt", "/host.crt", "/host.key")
	if err != nil {
		t.Fatal(err)
	}
	if s := string(out); !strings.Contains(s, "blocklist:") || !strings.Contains(s, fp) {
		t.Fatalf("rendered config missing pki.blocklist %s:\n%s", fp, s)
	}

	// An empty blocklist must not emit a blocklist key (keeps configs byte-stable).
	b.Blocklist = nil
	out2, err := RenderNebulaConfig(b, "/ca.crt", "/host.crt", "/host.key")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out2), "blocklist:") {
		t.Fatalf("empty blocklist must render no blocklist key:\n%s", out2)
	}
}

// TestRenderNebulaConfigTunDevPort proves the mesh-wide TUN device + listen port
// thread from the signed bundle into the rendered config (so a multi-mesh host gets
// distinct values per mesh), and that an empty/zero bundle keeps the nebula1/4242
// defaults (backward compatible for legacy bundles).
func TestRenderNebulaConfigTunDevPort(t *testing.T) {
	b := Bundle{
		Device:     Device{Name: "gitlab", OverlayIP: "10.45.0.7"},
		TunDev:     "nebula-prod",
		ListenPort: 4243,
	}
	out, err := RenderNebulaConfig(b, "/ca.crt", "/host.crt", "/host.key")
	if err != nil {
		t.Fatal(err)
	}
	if s := string(out); !strings.Contains(s, "nebula-prod") || !strings.Contains(s, "4243") {
		t.Fatalf("rendered config missing mesh tun/port (nebula-prod / 4243):\n%s", s)
	}

	// Unset -> the renderer's nebula1/4242 defaults (legacy/single-mesh bundles).
	b.TunDev, b.ListenPort = "", 0
	out2, err := RenderNebulaConfig(b, "/ca.crt", "/host.crt", "/host.key")
	if err != nil {
		t.Fatal(err)
	}
	if s := string(out2); !strings.Contains(s, "nebula1") || !strings.Contains(s, "4242") {
		t.Fatalf("unset tun/port must default to nebula1/4242:\n%s", s)
	}
}

func TestVerifyWrongKeyFails(t *testing.T) {
	signing, _ := signer.NewSoftwareBackend()
	other, _ := signer.NewSoftwareBackend()
	jwsBytes, _ := Sign(signing, "k", Bundle{Device: Device{Name: "x"}, Certificate: "c", CABundle: []string{"ca"}})

	otherPub, _ := other.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(otherPub)
	if _, err := Verify(jwsBytes, pinned); err == nil {
		t.Fatal("verify against the wrong pinned key must fail")
	}
}

func TestVerifyTamperedFails(t *testing.T) {
	b, _ := signer.NewSoftwareBackend()
	pubBytes, _ := b.PublicKey()
	pinned, _ := jws.ParseP256PublicPoint(pubBytes)
	jwsBytes, _ := Sign(b, "k", Bundle{Device: Device{Name: "x"}, Certificate: "c", CABundle: []string{"ca"}})

	// Flip a byte in the middle (hits the base64 payload/signature).
	tampered := make([]byte, len(jwsBytes))
	copy(tampered, jwsBytes)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := Verify(tampered, pinned); err == nil {
		t.Fatal("tampered bundle must fail verification")
	}
}
