package ssoassert

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func sample(now time.Time) Assertion {
	return Assertion{
		Subject:    "user-123",
		Email:      "alice@corp.example",
		Issuer:     "https://idp.corp.example",
		IdPGroups:  []string{"eng-web", "eng-db"},
		PubkeyHash: "abc123def456",
		Nonce:      "bm9uY2U",
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(5 * time.Minute).Unix(),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	now := time.Now()
	a := sample(now)

	token, err := Sign(priv, a)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Verify(&priv.PublicKey, token, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !reflect.DeepEqual(got, a) {
		t.Fatalf("round-trip mismatch:\n in=%+v\nout=%+v", a, got)
	}
}

func TestVerifyTampered(t *testing.T) {
	priv, _ := GenerateKey()
	now := time.Now()
	token, err := Sign(priv, sample(now))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Flip a byte in the payload segment (middle of the token) -> signature fails.
	tampered := make([]byte, len(token))
	copy(tampered, token)
	mid := len(tampered) / 2
	tampered[mid] ^= 0x01
	if _, err := Verify(&priv.PublicKey, tampered, now); err == nil {
		t.Fatal("tampered token verified")
	} else if !errors.Is(err, ErrSignature) && !errors.Is(err, ErrMalformed) {
		// A base64-valid flip yields ErrSignature; an invalid-char flip yields ErrMalformed.
		t.Fatalf("tampered: want ErrSignature/ErrMalformed, got %v", err)
	}
}

func TestVerifySignatureFlip(t *testing.T) {
	priv, _ := GenerateKey()
	now := time.Now()
	a := sample(now)
	token, _ := Sign(priv, a)
	// Swap in a syntactically valid (64-byte) but wrong signature: re-sign a different
	// assertion with the same key and graft its signature segment onto this token. The
	// header+payload still parse, so this exercises the cryptographic-mismatch path
	// (ErrSignature), not the malformed-length path.
	a2 := a
	a2.Subject = a.Subject + "-other"
	other, _ := Sign(priv, a2)
	dot1 := indexByte(token, '.')
	dot2 := dot1 + 1 + indexByte(token[dot1+1:], '.')
	odot1 := indexByte(other, '.')
	odot2 := odot1 + 1 + indexByte(other[odot1+1:], '.')
	grafted := append(append([]byte{}, token[:dot2+1]...), other[odot2+1:]...)
	if _, err := Verify(&priv.PublicKey, grafted, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong signature: want ErrSignature, got %v", err)
	}
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func TestVerifyExpired(t *testing.T) {
	priv, _ := GenerateKey()
	issued := time.Now()
	a := sample(issued)
	token, _ := Sign(priv, a)
	// Verify well past expiry.
	if _, err := Verify(&priv.PublicKey, token, issued.Add(10*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: want ErrExpired, got %v", err)
	}
}

func TestVerifyNotYetValid(t *testing.T) {
	priv, _ := GenerateKey()
	issued := time.Now()
	a := sample(issued)
	token, _ := Sign(priv, a)
	// Verify before issuance.
	if _, err := Verify(&priv.PublicKey, token, issued.Add(-10*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("not-yet-valid: want ErrExpired, got %v", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	priv, _ := GenerateKey()
	other, _ := GenerateKey()
	now := time.Now()
	token, _ := Sign(priv, sample(now))
	if _, err := Verify(&other.PublicKey, token, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: want ErrSignature, got %v", err)
	}
}

func TestVerifyMalformed(t *testing.T) {
	priv, _ := GenerateKey()
	now := time.Now()
	for _, tok := range []string{"", "not-a-jws", "only.two", "a.b.c.d", "..", "a..c"} {
		if _, err := Verify(&priv.PublicKey, []byte(tok), now); !errors.Is(err, ErrMalformed) {
			t.Fatalf("malformed %q: want ErrMalformed, got %v", tok, err)
		}
	}
}

func TestPEMRoundTrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	privPEM, err := MarshalPrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	pubPEM, err := MarshalPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}

	gotPriv, err := ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("parse priv: %v", err)
	}
	gotPub, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}

	// End-to-end: sign with the gateway (parsed private) half, verify with the Core
	// (parsed public) half — proves the distributed key material works.
	now := time.Now()
	token, err := Sign(gotPriv, sample(now))
	if err != nil {
		t.Fatalf("sign with parsed key: %v", err)
	}
	if _, err := Verify(gotPub, token, now); err != nil {
		t.Fatalf("verify with parsed pinned key: %v", err)
	}
}

func TestParsePEMRejectsWrongType(t *testing.T) {
	if _, err := ParsePrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error on non-PEM private")
	}
	if _, err := ParsePublicKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error on non-PEM public")
	}
}
