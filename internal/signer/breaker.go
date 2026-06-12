package signer

import (
	"sync"
	"time"
)

// breaker is the fleet-wide signing circuit breaker (implementation-plan M2.5):
// a sliding-window rate ceiling that, once breached, LATCHES open. A breach is a
// security event (a compromised Core trying to mint a fleet), so it stays halted
// until an operator explicitly resets it — it does not silently re-arm when the
// rate drops.
type breaker struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	events []time.Time
	open   bool
	now    func() time.Time
}

func newBreaker(maxPerWindow int, window time.Duration, now func() time.Time) *breaker {
	return &breaker{max: maxPerWindow, window: window, now: now}
}

// acquire attempts to consume one unit of the budget. allowed reports whether
// the caller may proceed; justTripped is true only on the call that flips the
// breaker open (so the alarm fires exactly once).
func (b *breaker) acquire() (allowed bool, justTripped bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.open {
		return false, false
	}
	// A non-positive ceiling means "no limit configured" — allow.
	if b.max <= 0 {
		return true, false
	}

	cutoff := b.now().Add(-b.window)
	kept := b.events[:0]
	for _, t := range b.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.events = kept

	if len(b.events) >= b.max {
		b.open = true
		return false, true
	}
	b.events = append(b.events, b.now())
	return true, false
}

// reset re-arms the breaker (an operator action).
func (b *breaker) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.open = false
	b.events = nil
}
