package discovery

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Default TTLs for cached discovery results when no explicit TTL is
// provided by the source (DISCOVERY.md §6.1, §7.3).
const (
	DefaultTTLSEMP     = 1 * time.Hour
	DefaultTTLLegacy   = 24 * time.Hour
	DefaultTTLNotFound = 1 * time.Hour
)

// Cache is the discovery result cache. Resolvers consult the cache before
// performing any DNS or HTTPS lookups, and write fresh results back to it
// with the TTL declared in the response.
//
// Implementations MUST:
//
//   - respect TTLs from the source,
//   - invalidate entries on delivery failure (DISCOVERY.md §6.1),
//   - encrypt cached results at rest where feasible.
type Cache interface {
	// Get returns the cached result for address and a bool reporting
	// whether the entry exists and is still within its TTL.
	Get(ctx context.Context, address string) (*Result, bool)

	// Put stores result with the given TTL.
	Put(ctx context.Context, address string, result *Result, ttl time.Duration) error

	// Invalidate removes the cached entry for address. Called by senders
	// after a delivery failure.
	Invalidate(ctx context.Context, address string) error
}

// NewMemCache returns an in-memory Cache suitable for a single-
// process server. Entries are keyed by a normalized (lowercase)
// version of the address so "Alice@Example.com" and
// "alice@example.com" share one entry.
//
// This implementation is NOT encrypted at rest — it is strictly for
// demo binaries and tests. A production deployment would back the
// cache with a persistent, encrypted store.
func NewMemCache() Cache {
	return &memCache{entries: make(map[string]memCacheEntry)}
}

type memCacheEntry struct {
	result    *Result
	expiresAt time.Time
}

type memCache struct {
	mu      sync.Mutex
	entries map[string]memCacheEntry
	// nowFunc is a package-private time source so tests can freeze
	// or advance time without sleeping.
	nowFunc func() time.Time
}

func (c *memCache) now() time.Time {
	if c.nowFunc != nil {
		return c.nowFunc()
	}
	return time.Now()
}

func (c *memCache) Get(_ context.Context, address string) (*Result, bool) {
	key := strings.ToLower(address)
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !entry.expiresAt.IsZero() && c.now().After(entry.expiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	// Return a shallow copy so callers can't mutate the cached value.
	copy := *entry.result
	return &copy, true
}

func (c *memCache) Put(_ context.Context, address string, result *Result, ttl time.Duration) error {
	if result == nil {
		return nil
	}
	key := strings.ToLower(address)
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := *result
	entry := memCacheEntry{result: &cp}
	if ttl > 0 {
		entry.expiresAt = c.now().Add(ttl)
	}
	c.entries[key] = entry
	return nil
}

func (c *memCache) Invalidate(_ context.Context, address string) error {
	key := strings.ToLower(address)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
	return nil
}
