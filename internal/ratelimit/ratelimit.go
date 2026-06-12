// Package ratelimit is a small in-process token-bucket limiter for the
// enrollment gateway's edge rate-limiting (implementation-plan 3.3). It is
// keyed (by source IP, by pubkey hash); production may front this with a shared
// limiter, but per-instance shedding is the floor.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a per-key token bucket: refill `rate` tokens/sec up to `burst`.
type Limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

// New returns a limiter allowing `burst` immediate requests per key, refilling
// at `ratePerSec`. A non-positive burst disables limiting (Allow always true).
func New(ratePerSec float64, burst int) *Limiter {
	return &Limiter{
		rate:    ratePerSec,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Allow reports whether one request for key may proceed, consuming a token.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.burst <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
