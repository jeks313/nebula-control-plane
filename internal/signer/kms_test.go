package signer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/slackhq/nebula/cert"
)

// fakeKMS implements kmsAPI over a real in-process P256 key, so the SPKI->point
// conversion and the DER signature passthrough are exercised against real crypto
// without touching AWS.
type fakeKMS struct {
	key       *ecdsa.PrivateKey
	keySpec   types.KeySpec      // "" -> ECC_NIST_P256
	keyUsage  types.KeyUsageType // "" -> SIGN_VERIFY
	signErr   error
	getCalls  int
	signCalls int
	lastSign  *kms.SignInput
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKMS{key: k}
}

func (f *fakeKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.getCalls++
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		return nil, err
	}
	spec := f.keySpec
	if spec == "" {
		spec = types.KeySpecEccNistP256
	}
	usage := f.keyUsage
	if usage == "" {
		usage = types.KeyUsageTypeSignVerify
	}
	return &kms.GetPublicKeyOutput{KeyId: in.KeyId, PublicKey: der, KeySpec: spec, KeyUsage: usage}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signCalls++
	f.lastSign = in
	if f.signErr != nil {
		return nil, f.signErr
	}
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, in.Message) // DER, as KMS returns
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}

func TestKMSBackendPublicKey(t *testing.T) {
	f := newFakeKMS(t)
	b := newKMSBackend(f, "alias/ca", 0)

	pub, err := b.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	want, _ := f.key.PublicKey.ECDH()
	if !bytes.Equal(pub, want.Bytes()) {
		t.Fatal("PublicKey did not match the KMS key's uncompressed point")
	}
	if len(pub) != 65 {
		t.Fatalf("PublicKey len = %d, want 65", len(pub))
	}
	// Cached: a second call must not re-hit KMS.
	if _, err := b.PublicKey(); err != nil {
		t.Fatal(err)
	}
	if f.getCalls != 1 {
		t.Fatalf("GetPublicKey called %d times, want 1 (cached)", f.getCalls)
	}
	// The returned slice is a copy — mutating it must not corrupt the cache.
	pub[0] ^= 0xff
	again, _ := b.PublicKey()
	if !bytes.Equal(again, want.Bytes()) {
		t.Fatal("PublicKey cache was corrupted by a caller mutating the returned slice")
	}
}

func TestKMSBackendWrongKeySpec(t *testing.T) {
	f := newFakeKMS(t)
	f.keySpec = types.KeySpecRsa2048 // not a P256 signing key
	b := newKMSBackend(f, "alias/ca", 0)
	if _, err := b.PublicKey(); err == nil {
		t.Fatal("PublicKey must reject a non-P256 KMS key spec")
	}
}

func TestKMSBackendWrongKeyUsage(t *testing.T) {
	f := newFakeKMS(t)
	f.keyUsage = types.KeyUsageTypeKeyAgreement // P256 but ECDH, not signing
	b := newKMSBackend(f, "alias/ca", 0)
	if _, err := b.PublicKey(); err == nil {
		t.Fatal("PublicKey must reject a P256 KEY_AGREEMENT key (not SIGN_VERIFY)")
	}
}

func TestKMSBackendSignDigest(t *testing.T) {
	f := newFakeKMS(t)
	b := newKMSBackend(f, "alias/ca", 0)

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	sig, err := b.SignDigest(digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	// KMS was asked to sign the digest with the right algorithm + message type.
	if f.lastSign.MessageType != types.MessageTypeDigest {
		t.Fatalf("MessageType = %s, want DIGEST", f.lastSign.MessageType)
	}
	if f.lastSign.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 {
		t.Fatalf("SigningAlgorithm = %s, want ECDSA_SHA_256", f.lastSign.SigningAlgorithm)
	}
	if f.lastSign.KeyId == nil || *f.lastSign.KeyId != "alias/ca" {
		t.Fatalf("KeyId = %v, want alias/ca", f.lastSign.KeyId)
	}
	// The DER signature verifies against the key (proves the passthrough is correct).
	if !ecdsa.VerifyASN1(&f.key.PublicKey, digest, sig) {
		t.Fatal("the KMS DER signature did not verify against the public key")
	}

	// Guards: a non-32-byte digest is refused without ever calling KMS.
	before := f.signCalls
	if _, err := b.SignDigest(make([]byte, 31)); err == nil {
		t.Fatal("SignDigest must reject a non-32-byte digest")
	}
	if f.signCalls != before {
		t.Fatal("a bad-length digest must not reach KMS")
	}
	// A KMS error propagates.
	f.signErr = errors.New("kms unavailable")
	if _, err := b.SignDigest(digest); err == nil {
		t.Fatal("a KMS Sign error must propagate")
	}
}

// TestKMSBackendThroughSigner proves the KMS backend is a drop-in for the whole signer
// path: self-sign a CA from the KMS key, build a Signer (which verifies the backend pubkey
// matches the CA cert), and issue + verify a leaf.
func TestKMSBackendThroughSigner(t *testing.T) {
	f := newFakeKMS(t)
	b := newKMSBackend(f, "alias/ca", 0)

	now := time.Now()
	_, caPEM, err := SelfSignCA(b, CATemplate{Name: "kms-ca", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("SelfSignCA: %v", err)
	}
	audit := &recordingAudit{}
	s, err := New(Config{CACertPEM: caPEM, Backend: b, MaxCertsPerHour: 10, Audit: audit.fn, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("signer.New (backend pubkey must match the CA cert): %v", err)
	}
	c, _, err := s.Issue(context.Background(), "alice", Template{
		Name: "h1", Networks: []netip.Prefix{netip.MustParsePrefix("100.64.0.5/16")},
		NotBefore: now, NotAfter: now.Add(12 * time.Hour), PublicKey: hostPub(t),
	})
	if err != nil {
		t.Fatalf("Issue via KMS backend: %v", err)
	}
	pool, err := cert.NewCAPoolFromPEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.VerifyCertificate(now, c); err != nil {
		t.Fatalf("leaf signed via KMS does not verify against the CA: %v", err)
	}
	if !audit.has("issue-cert") {
		t.Fatal("expected an issue-cert audit row")
	}
}
