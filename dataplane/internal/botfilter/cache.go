package botfilter

import (
	"sync"
	"time"
)

// verdictCacheMaxEntries caps memory: source-IP verdicts are cheap to recompute
// (one mmdb lookup and at most one PTR query), so a full flush on saturation is
// acceptable rather than tracking eviction order.
const verdictCacheMaxEntries = 8192

// verdict is the cached outcome of the IP-based signals for one source IP.
// The UA signal is never cached (it varies per request).
type verdict struct {
	blocked bool
	reason  string
}

// verdictCache is a TTL cache of per-source-IP verdicts, mirroring the
// authzCache shape in the proxy package. Correctness never depends on cache
// contents: any entry may vanish at any time.
type verdictCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]verdictEntry
}

type verdictEntry struct {
	v       verdict
	expires time.Time
}

func newVerdictCache(ttl time.Duration) *verdictCache {
	return &verdictCache{ttl: ttl, entries: make(map[string]verdictEntry)}
}

func (c *verdictCache) get(ip string, now time.Time) (verdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[ip]
	if !ok {
		return verdict{}, false
	}
	if now.After(e.expires) {
		delete(c.entries, ip)
		return verdict{}, false
	}
	return e.v, true
}

func (c *verdictCache) put(ip string, v verdict, now time.Time) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= verdictCacheMaxEntries {
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= verdictCacheMaxEntries {
			// Still full of live entries: drop everything rather than track
			// eviction order; a refill costs one lookup per key.
			c.entries = make(map[string]verdictEntry)
		}
	}
	c.entries[ip] = verdictEntry{v: v, expires: now.Add(c.ttl)}
}
