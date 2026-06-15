package jws

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := key(t)
	payload := []byte(`{"hello":"world"}`)
	env, err := SignES256(priv, Header{Typ: "ncp-request+jws", Ver: 1, Kid: "k1"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	h, got, err := Verify(env, &priv.PublicKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if h.Alg != Alg || h.Typ != "ncp-request+jws" || h.Kid != "k1" {
		t.Fatalf("header = %+v", h)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %s", got)
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	priv := key(t)
	env, _ := SignES256(priv, Header{Typ: "x"}, []byte("original"))
	env.Payload = b64.EncodeToString([]byte("tampered"))
	if _, _, err := Verify(env, &priv.PublicKey); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	env, _ := SignES256(key(t), Header{Typ: "x"}, []byte("p"))
	if _, _, err := Verify(env, &key(t).PublicKey); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestParseP256PublicPoint(t *testing.T) {
	priv := key(t)
	ek, _ := priv.PublicKey.ECDH()
	want := ek.Bytes() // the 0x04||X||Y uncompressed point
	pub, err := ParseP256PublicPoint(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("parsed point does not round-trip to the original encoding")
	}
	if _, err := ParseP256PublicPoint([]byte{0x04, 0x01}); err == nil {
		t.Fatal("want error on malformed point")
	}
}
