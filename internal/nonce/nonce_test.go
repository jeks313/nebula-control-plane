package nonce

import (
	"errors"
	"testing"
	"time"
)

func ring(t *testing.T, keys ...[]byte) *Keyring {
	t.Helper()
	k, err := NewKeyring(keys, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func key(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestMintVerifyRoundTrip(t *testing.T) {
	k := ring(t, key(1))
	binding := []byte("pubkey-hash-abc")
	n, exp := k.Mint(binding)
	if !exp.After(time.Now()) {
		t.Fatalf("expiry %v not in the future", exp)
	}
	if err := k.Verify(n, binding); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestWrongBindingRejected(t *testing.T) {
	k := ring(t, key(1))
	n, _ := k.Mint([]byte("host-A"))
	if err := k.Verify(n, []byte("host-B")); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("err = %v, want ErrBadMAC", err)
	}
}

func TestForgedNonceRejected(t *testing.T) {
	k := ring(t, key(1))
	other := ring(t, key(2)) // attacker mints with a different key
	n, _ := other.Mint([]byte("host-A"))
	if err := k.Verify(n, []byte("host-A")); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("err = %v, want ErrBadMAC", err)
	}
}

func TestExpiredRejected(t *testing.T) {
	k := ring(t, key(1))
	binding := []byte("host-A")
	// Mint 61s in the past (TTL is 60s).
	k.now = func() time.Time { return time.Now().Add(-61 * time.Second) }
	n, _ := k.Mint(binding)
	k.now = time.Now
	if err := k.Verify(n, binding); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestFutureBeyondSkewRejected(t *testing.T) {
	k := ring(t, key(1))
	binding := []byte("host-A")
	k.now = func() time.Time { return time.Now().Add(31 * time.Second) } // > MaxSkew (30s)
	n, _ := k.Mint(binding)
	k.now = time.Now
	if err := k.Verify(n, binding); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestMalformedRejected(t *testing.T) {
	k := ring(t, key(1))
	for _, bad := range []string{"", "!!!notbase64!!!", "AAAA"} {
		if err := k.Verify(bad, []byte("x")); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Verify(%q) = %v, want ErrMalformed", bad, err)
		}
	}
}

// TestRotationOverlap: a nonce minted under the old key still verifies after the
// new key becomes primary, as long as the old key remains in the ring.
func TestRotationOverlap(t *testing.T) {
	old := ring(t, key(9))
	binding := []byte("host-A")
	n, _ := old.Mint(binding)

	rotated := ring(t, key(7), key(9)) // new primary, old kept for overlap
	if err := rotated.Verify(n, binding); err != nil {
		t.Fatalf("verify across rotation: %v", err)
	}

	dropped := ring(t, key(7)) // old key retired
	if err := dropped.Verify(n, binding); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("err = %v, want ErrBadMAC after old key dropped", err)
	}
}

func TestNewKeyringValidation(t *testing.T) {
	if _, err := NewKeyring(nil, 0, 0); err == nil {
		t.Fatal("want error for no keys")
	}
	if _, err := NewKeyring([][]byte{make([]byte, 8)}, 0, 0); err == nil {
		t.Fatal("want error for short key")
	}
}
