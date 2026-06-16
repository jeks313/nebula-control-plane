package signer

import (
	"context"
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
// breaker open (so the alarm fires exactly once). The in-memory breaker never errors.
func (b *breaker) acquire(_ context.Context) (allowed, justTripped bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.open {
		return false, false, nil
	}
	// A non-positive ceiling means "no limit configured" — allow.
	if b.max <= 0 {
		return true, false, nil
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
		return false, true, nil
	}
	b.events = append(b.events, b.now())
	return true, false, nil
}

// reset re-arms the breaker (an operator action).
func (b *breaker) reset(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.open = false
	b.events = nil
	return nil
}

// limit returns the configured ceiling.
func (b *breaker) limit() int { return b.max }

// isOpen reports whether the breaker is latched open.
func (b *breaker) isOpen(_ context.Context) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open, nil
}
