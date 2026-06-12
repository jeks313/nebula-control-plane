package replay

import (
	"testing"
	"time"
)

func TestObserveDetectsReplay(t *testing.T) {
	c := New(time.Minute)
	if !c.Observe("n1") {
		t.Fatal("first observe should be firstTime=true")
	}
	if c.Observe("n1") {
		t.Fatal("second observe of same nonce should be a replay (false)")
	}
	if !c.Observe("n2") {
		t.Fatal("a different nonce is firstTime=true")
	}
}

func TestObserveExpires(t *testing.T) {
	c := New(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Observe("n1")
	now = now.Add(2 * time.Minute) // past TTL
	if !c.Observe("n1") {
		t.Fatal("after TTL the nonce should be accepted again")
	}
}
