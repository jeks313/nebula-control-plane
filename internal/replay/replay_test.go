package replay

import (
	"testing"
	"time"
)

// mustObserve asserts Observe returns no error and yields firstTime.
func mustObserve(t *testing.T, o Observer, nonce string) bool {
	t.Helper()
	first, err := o.Observe(nonce)
	if err != nil {
		t.Fatalf("Observe(%q): unexpected error %v", nonce, err)
	}
	return first
}

func TestObserveDetectsReplay(t *testing.T) {
	c := New(time.Minute)
	if !mustObserve(t, c, "n1") {
		t.Fatal("first observe should be firstTime=true")
	}
	if mustObserve(t, c, "n1") {
		t.Fatal("second observe of same nonce should be a replay (false)")
	}
	if !mustObserve(t, c, "n2") {
		t.Fatal("a different nonce is firstTime=true")
	}
}

func TestObserveExpires(t *testing.T) {
	c := New(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }
	if _, err := c.Observe("n1"); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	now = now.Add(2 * time.Minute) // past TTL
	if !mustObserve(t, c, "n1") {
		t.Fatal("after TTL the nonce should be accepted again")
	}
}
