package discovery

import (
	"context"
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
