// Package replay is Core's nonce replay cache (protocol spec §4.3): the
// stateless gateway nonce carries freshness + binding but cannot be single-use,
// so Core remembers accepted nonces for the freshness window and rejects
// repeats. This in-process cache covers a single Core; HA Harbor needs a shared
// store (tracked for M9.5).
package replay

import (
	"sync"
	"time"
)

// Cache records seen nonces until they expire.
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

// Observe records a nonce and reports whether this is the first time it's been
// seen. A false return means a replay. Expired entries are pruned opportunistically.
func (c *Cache) Observe(nonce string) (firstTime bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now().UnixNano()
	if exp, ok := c.seen[nonce]; ok && exp > now {
		return false
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
	return true
}
