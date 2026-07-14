package proxy

import (
	"crypto/sha256"
	"strconv"
	"sync"
	"time"
)

const (
	authzCacheMaxEntries = 4096
	authzCacheTTLCap     = 60 * time.Second
)

// authzCache holds host-scope allow decisions from the control plane so
// media-segment request storms don't pay a control-plane round-trip each.
// Only allow decisions the control plane marked host-cacheable are stored;
// denies and auth_required are never cached. Correctness never depends on
// cache contents: any entry may vanish at any time.
type authzCache struct {
	mu      sync.Mutex
	entries map[string]authzCacheEntry
}

type authzCacheEntry struct {
	headers map[string]string // identity headers to inject; never mutated after insert
	expires time.Time
}

func newAuthzCache() *authzCache {
	return &authzCache{entries: make(map[string]authzCacheEntry)}
}

// authzCacheKey binds a cached decision to everything it is conditioned on:
// host, backend port, client IP (sessions are IP-bound), and the gateway
// cookie (session id + secret). Hashed so raw cookie secrets are never
// retained in memory beyond the request.
func authzCacheKey(host string, backendPort int, sourceIP, cookie string) string {
	h := sha256.Sum256([]byte(host + "\x00" + strconv.Itoa(backendPort) +
		"\x00" + sourceIP + "\x00" + cookie))
	return string(h[:])
}

func (c *authzCache) get(key string, now time.Time) (map[string]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if now.After(e.expires) {
		delete(c.entries, key)
		return nil, false
	}
	return e.headers, true
}

func (c *authzCache) put(key string, headers map[string]string, ttl time.Duration, now time.Time) {
	if ttl <= 0 {
		return
	}
	if ttl > authzCacheTTLCap {
		ttl = authzCacheTTLCap
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= authzCacheMaxEntries {
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= authzCacheMaxEntries {
			// Still full of live entries: drop everything rather than track
			// eviction order; a refill costs one control-plane check per key.
			c.entries = make(map[string]authzCacheEntry)
		}
	}
	c.entries[key] = authzCacheEntry{headers: headers, expires: now.Add(ttl)}
}

func (c *authzCache) purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]authzCacheEntry)
}
