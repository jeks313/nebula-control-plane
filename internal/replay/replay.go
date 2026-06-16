// Package replay is Core's nonce replay guard (protocol spec §4.3): the stateless
// gateway nonce carries freshness + binding but cannot be single-use, so Core
// remembers accepted nonces for the freshness window and rejects repeats.
//
// Two implementations satisfy Observer: the in-process Cache (a single Core / dev),
// and SQLStore (a shared DB table) so an HA Harbor with ≥2 Core processes enforces
// single-use across the whole fleet — a per-process cache would let a nonce be
// reused once per Core. This guard runs on CORE only (the credential-less gateway
// never sees it); minting stays a stateless HMAC, so gateways need no coordination.
package replay

import (
	"sync"
	"time"
)

// Observer records a nonce and reports whether this is its first sighting (true) or
// a replay (false). A non-nil error is an infrastructure failure (e.g. the shared
// store is unreachable) — distinct from a replay, so the caller can retry rather than
// terminally reject the request.
type Observer interface {
	Observe(nonce string) (firstTime bool, err error)
}

// Cache records seen nonces in memory until they expire. Single-process only.
type Cache struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]int64 // nonce -> expiry (unix ns)
	now  func() time.Time
}

// New returns a cache that remembers nonces for ttl.
func New(ttl time.Duration) *Cache {
	return &Cache{ttl: ttl, seen: make(map[string]int64), now: time.Now}
}

// Observe records a nonce and reports whether this is the first time it's been seen.
// A false return means a replay. The in-memory cache never errors. Expired entries are
// pruned opportunistically.
func (c *Cache) Observe(nonce string) (firstTime bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now().UnixNano()
	if exp, ok := c.seen[nonce]; ok && exp > now {
		return false, nil
	}
	// prune occasionally to bound memory
	if len(c.seen) > 0 {
		for k, exp := range c.seen {
			if exp <= now {
				delete(c.seen, k)
			}
		}
	}
	c.seen[nonce] = now + int64(c.ttl)
	return true, nil
}
