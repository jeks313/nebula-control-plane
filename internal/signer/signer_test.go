package signer

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// testCA builds a self-signed P256 CA from the backend and returns its PEM.
func testCA(t *testing.T, b Backend) []byte {
	t.Helper()
	pub, err := b.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      "test-ca",
		IsCA:      true,
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		PublicKey: pub,
		Curve:     cert.Curve_P256,
	}
	ca, err := SignTBS(b, tbs, nil)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	pem, err := ca.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// hostPub returns a fresh P256 key-agreement public key (65-byte point).
func hostPub(t *testing.T) []byte {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

type recordingAudit struct{ actions []string }

func (r *recordingAudit) fn(_ context.Context, _, action, _, _ string) error {
	r.actions = append(r.actions, action)
	return nil
}

func (r *recordingAudit) has(action string) bool {
	for _, a := range r.actions {
		if a == action {
			return true
		}
	}
	return false
}

func newSigner(t *testing.T, max int, audit *recordingAudit) *Signer {
	t.Helper()
	b, err := NewSoftwareBackend()
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		CACertPEM: testCA(t, b),
		Backend:   b,
		Policy: IssuePolicy{
			AllowedNetwork: netip.MustParsePrefix("100.64.0.0/16"),
			AllowedGroups:  map[string]bool{"web": true, "db": true},
			MaxLifetime:    90 * 24 * time.Hour,
		},
		MaxCertsPerHour: max,
		Audit:           audit.fn,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func goodTemplate(t *testing.T) Template {
	return Template{
		Name:      "host-1",
		Networks:  []netip.Prefix{netip.MustParsePrefix("100.64.0.5/16")},
		Groups:    []string{"web"},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
		PublicKey: hostPub(t),
	}
}

// TestIssueAndVerify is the M2.3 acceptance: a signed leaf verifies against the
// CA, and the issuance is audited.
func TestIssueAndVerify(t *testing.T) {
	audit := &recordingAudit{}
	s := newSigner(t, 100, audit)
	caPEM, err := s.CACert().MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}

	c, pemBytes, err := s.Issue(context.Background(), "alice", goodTemplate(t))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(pemBytes) == 0 {
		t.Fatal("empty PEM")
	}
	if c.Name() != "host-1" {
		t.Errorf("name = %q", c.Name())
	}

	pool, err := cert.NewCAPoolFromPEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.VerifyCertificate(time.Now(), c); err != nil {
		t.Fatalf("issued cert does not verify against CA: %v", err)
	}
	if !audit.has("issue-cert") {
		t.Errorf("expected issue-cert audit, got %v", audit.actions)
	}
}

func TestValidationRules(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Template)
		want   error
	}{
		{"empty name", func(tp *Template) { tp.Name = "" }, ErrEmptyName},
		{"bad pubkey", func(tp *Template) { tp.PublicKey = []byte{1, 2, 3} }, ErrBadPublicKey},
		{"no networks", func(tp *Template) { tp.Networks = nil }, ErrNoNetworks},
		{"ip out of allocation", func(tp *Template) {
			tp.Networks = []netip.Prefix{netip.MustParsePrefix("10.0.0.5/16")}
		}, ErrIPOutOfAllocation},
		{"group not allowed", func(tp *Template) { tp.Groups = []string{"admin"} }, ErrGroupNotAllowed},
		{"invalid validity", func(tp *Template) {
			tp.NotBefore = time.Now().Add(time.Hour)
			tp.NotAfter = time.Now()
		}, ErrInvalidValidity},
		{"lifetime too long", func(tp *Template) {
			tp.NotBefore = time.Now()
			tp.NotAfter = time.Now().Add(200 * 24 * time.Hour)
		}, ErrLifetimeTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audit := &recordingAudit{}
			s := newSigner(t, 100, audit)
			tp := goodTemplate(t)
			tc.mutate(&tp)
			_, _, err := s.Issue(context.Background(), "alice", tp)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if !audit.has("issue-cert-rejected") {
				t.Errorf("rejection should be audited, got %v", audit.actions)
			}
		})
	}
}

// TestCircuitBreaker is the M2.5 acceptance: exceeding the ceiling halts signing,
// alarms once, and stays halted until reset.
func TestCircuitBreaker(t *testing.T) {
	audit := &recordingAudit{}
	s := newSigner(t, 3, audit)
	alarms := 0
	s.onAlarm = func(int) { alarms++ }

	for i := 0; i < 3; i++ {
		if _, _, err := s.Issue(context.Background(), "alice", goodTemplate(t)); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	// 4th trips the breaker.
	if _, _, err := s.Issue(context.Background(), "alice", goodTemplate(t)); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("4th issue err = %v, want ErrCircuitOpen", err)
	}
	// 5th is still refused, but must NOT alarm again.
	if _, _, err := s.Issue(context.Background(), "alice", goodTemplate(t)); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("5th issue err = %v, want ErrCircuitOpen", err)
	}
	if alarms != 1 {
		t.Fatalf("alarms = %d, want exactly 1", alarms)
	}
	if !audit.has("signing-circuit-tripped") {
		t.Errorf("trip should be audited, got %v", audit.actions)
	}

	if err := s.ResetBreaker(context.Background()); err != nil {
		t.Fatalf("reset breaker: %v", err)
	}
	if _, _, err := s.Issue(context.Background(), "alice", goodTemplate(t)); err != nil {
		t.Fatalf("issue after reset: %v", err)
	}
}

func TestBackendMustMatchCA(t *testing.T) {
	a, _ := NewSoftwareBackend()
	b, _ := NewSoftwareBackend()
	// CA cert built from backend a, but New given backend b.
	_, err := New(Config{
		CACertPEM: testCA(t, a),
		Backend:   b,
		Audit:     (&recordingAudit{}).fn,
	})
	if err == nil {
		t.Fatal("New should reject a backend whose key != CA cert")
	}
}
