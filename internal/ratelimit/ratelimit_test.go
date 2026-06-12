package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenDeny(t *testing.T) {
	l := New(1, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("4th request should be denied")
	}
}

func TestRefill(t *testing.T) {
	l := New(10, 1) // 10 tokens/sec
	now := time.Now()
	l.now = func() time.Time { return now }

	if !l.Allow("k") {
		t.Fatal("first allowed")
	}
	if l.Allow("k") {
		t.Fatal("second denied (burst 1, no time passed)")
	}
	now = now.Add(200 * time.Millisecond) // +2 tokens
	if !l.Allow("k") {
		t.Fatal("should be allowed after refill")
	}
}

func TestPerKeyIsolation(t *testing.T) {
	l := New(1, 1)
	if !l.Allow("a") || !l.Allow("b") {
		t.Fatal("different keys have independent buckets")
	}
	if l.Allow("a") {
		t.Fatal("key a exhausted")
	}
}

func TestZeroBurstDisables(t *testing.T) {
	l := New(1, 0)
	for i := 0; i < 100; i++ {
		if !l.Allow("k") {
			t.Fatal("zero burst should disable limiting")
		}
	}
	var nilLimiter *Limiter
	if !nilLimiter.Allow("k") {
		t.Fatal("nil limiter allows")
	}
}
