package bundle

import (
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
