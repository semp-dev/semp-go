package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// FallbackTimeout is the per-transport dial timeout RECOMMENDED by
// TRANSPORT.md §5.4 before moving to the next transport.
const FallbackTimeout = 10 * time.Second

// RecommendedFallbackOrder is the priority list from TRANSPORT.md §5.3:
// QUIC > WebSocket > HTTP/2 > gRPC. The connecting party SHOULD prefer
// transports earlier in this list when multiple are mutually supported,
// unless operational context dictates otherwise.
var RecommendedFallbackOrder = []ID{
	IDQUIC,
	IDWebSocket,
	IDHTTP2,
	IDgRPC,
}

// Candidate is one (transport, endpoint) pair the caller wants to try.
// Real deployments populate Candidate slices from a discovery record
// (DISCOVERY.md §5.2) that pairs each supported transport with its
// server-side endpoint URL. Operators may also hand-construct
// candidates from static config.
//
// Cache is an optional hint used by the fallback cache: on a
// successful dial, the (ID, Endpoint) pair is remembered for the
// TTL duration so subsequent connections to the same domain try
// the cached transport first (TRANSPORT.md §5.6).
type Candidate struct {
	// Transport is the transport binding that will perform the dial.
	Transport Transport

	// Endpoint is the transport-specific dial target, e.g.
	// "wss://semp.example.com/v1/ws" or "https://semp.example.com".
	Endpoint string
}

// ID returns the transport's wire ID, or the empty string if the
// candidate's Transport field is nil.
func (c Candidate) ID() ID {
	if c.Transport == nil {
		return ""
	}
	return c.Transport.ID()
}

// String returns a human-readable candidate summary suitable for log
// lines and error messages: "<transport-id> <endpoint>".
func (c Candidate) String() string {
	return string(c.ID()) + " " + c.Endpoint
}

// FallbackError is returned by Fallback when every candidate fails.
// It carries the per-candidate error list so callers can surface
// diagnostic detail without losing the structured outcome for
// metrics.
//
// FallbackError is always constructed with at least one Attempt.
// Callers should unwrap with errors.As or use Unwrap to recover the
// last per-candidate error for compatibility with code that does
// not know about FallbackError.
type FallbackError struct {
	// Attempts is the per-candidate failure record in dial order.
	// Each entry's Candidate is the candidate that was tried and
	// Err is the error it produced. The slice is never empty —
	// Fallback only returns FallbackError after at least one dial
	// attempt has failed.
	Attempts []FallbackAttempt
}

// FallbackAttempt is one entry in FallbackError.Attempts.
type FallbackAttempt struct {
	Candidate Candidate
	Err       error
}

// Error implements the error interface. The message summarizes every
// attempt on a single line so log lines stay scannable. Callers that
// need structured data should inspect the Attempts field directly.
func (e *FallbackError) Error() string {
	if e == nil || len(e.Attempts) == 0 {
		return "transport: no candidates attempted"
	}
	var b strings.Builder
	b.WriteString("transport: all ")
	fmt.Fprintf(&b, "%d", len(e.Attempts))
	b.WriteString(" candidate(s) failed:")
	for i, a := range e.Attempts {
		b.WriteString(" [")
		fmt.Fprintf(&b, "%d", i+1)
		b.WriteString("] ")
		b.WriteString(a.Candidate.String())
		b.WriteString(": ")
		if a.Err != nil {
			b.WriteString(a.Err.Error())
		} else {
			b.WriteString("<nil>")
		}
		if i < len(e.Attempts)-1 {
			b.WriteString(";")
		}
	}
	return b.String()
}

// Unwrap returns the LAST attempt's error so errors.Is /  errors.As
// still work on code that treats Fallback like a simple wrapper. To
// inspect every attempt, type-assert to *FallbackError and walk
// Attempts.
func (e *FallbackError) Unwrap() error {
	if e == nil || len(e.Attempts) == 0 {
		return nil
	}
	return e.Attempts[len(e.Attempts)-1].Err
}

// Is reports whether any attempt's error matches target. This makes
// code like errors.Is(err, context.Canceled) return true if any
// underlying attempt was canceled, not just the last one.
func (e *FallbackError) Is(target error) bool {
	if e == nil {
		return false
	}
	for _, a := range e.Attempts {
		if errors.Is(a.Err, target) {
			return true
		}
	}
	return false
}

// Fallback attempts each candidate sequentially, returning the first
// Conn that successfully dials. Per TRANSPORT.md §5.4:
//
//   - Attempts MUST be sequential, not concurrent. Concurrent attempts
//     to the same server on multiple transports waste resources and
//     may trigger rate limiting.
//   - Each attempt is bounded by FallbackTimeout (10 s RECOMMENDED).
//     A candidate that doesn't establish a connection within the
//     timeout is treated as failed and the next candidate is tried.
//   - If all candidates fail, Fallback returns a *FallbackError that
//     records every attempt so operators can triage failure patterns.
//
// The caller's ctx governs the overall deadline. If ctx is already
// canceled Fallback returns ctx.Err() without attempting any dial.
// If ctx is canceled mid-sequence, Fallback stops trying further
// candidates and returns a *FallbackError that includes the already-
// recorded attempts plus a final entry tagged with the context error.
//
// Nil or empty candidate lists return an error immediately rather
// than a nil Conn.
//
// The endpoint parameter is intentionally NOT part of the signature:
// different transports dial different endpoint URLs (ws://, https://,
// quic://) so the caller bundles them into Candidate structs.
func Fallback(ctx context.Context, candidates []Candidate) (Conn, error) {
	conn, _, err := dialCandidates(ctx, candidates)
	return conn, err
}

// dialCandidates is the core sequential dial loop used by both
// Fallback and CachedFallback. On success it returns (conn, index,
// nil) where index is the position of the successful candidate in
// the input slice. On failure every candidate has been attempted and
// the returned error is a *FallbackError with the per-candidate
// breakdown.
func dialCandidates(ctx context.Context, candidates []Candidate) (Conn, int, error) {
	if len(candidates) == 0 {
		return nil, -1, errors.New("transport: fallback called with no candidates")
	}
	if err := ctx.Err(); err != nil {
		return nil, -1, err
	}
	fe := &FallbackError{}
	for i, c := range candidates {
		// Bail out before spending another dial quantum if ctx is
		// already canceled.
		if err := ctx.Err(); err != nil {
			fe.Attempts = append(fe.Attempts, FallbackAttempt{
				Candidate: c,
				Err:       fmt.Errorf("transport: context canceled before dial: %w", err),
			})
			return nil, -1, fe
		}
		if c.Transport == nil {
			fe.Attempts = append(fe.Attempts, FallbackAttempt{
				Candidate: c,
				Err:       errors.New("transport: nil Transport in candidate"),
			})
			continue
		}
		dialCtx, cancel := context.WithTimeout(ctx, FallbackTimeout)
		conn, err := c.Transport.Dial(dialCtx, c.Endpoint)
		cancel()
		if err == nil && conn != nil {
			return conn, i, nil
		}
		if err == nil {
			err = errors.New("transport: dial returned nil conn and nil error")
		}
		fe.Attempts = append(fe.Attempts, FallbackAttempt{
			Candidate: c,
			Err:       err,
		})
	}
	return nil, -1, fe
}

// Order sorts candidates by RecommendedFallbackOrder so the highest-
// priority transport is attempted first. Candidates whose transport
// is not in the recommended list retain their original relative order
// and are placed after every recommended transport.
//
// Order is a pure function — it returns a fresh slice and does not
// mutate the input.
func Order(candidates []Candidate) []Candidate {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]Candidate, 0, len(candidates))
	used := make([]bool, len(candidates))

	// Walk the recommended order, appending any matching candidate.
	// We preserve duplicates (multiple endpoints per transport) in
	// their original relative order.
	for _, want := range RecommendedFallbackOrder {
		for i, c := range candidates {
			if used[i] {
				continue
			}
			if c.ID() == want {
				out = append(out, c)
				used[i] = true
			}
		}
	}
	// Anything left (unknown or extended transports) goes after.
	for i, c := range candidates {
		if !used[i] {
			out = append(out, c)
			used[i] = true
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Fallback cache
// -----------------------------------------------------------------------------

// FallbackCache memoizes the most recently successful transport per
// domain, as recommended by TRANSPORT.md §5.6: "When a transport fails
// and fallback succeeds, implementations SHOULD cache the successful
// transport for the target domain with a TTL matching the discovery
// cache TTL."
//
// FallbackCache is safe for concurrent use. The zero value is not
// usable — construct one via NewFallbackCache.
type FallbackCache struct {
	mu      sync.Mutex
	entries map[string]fallbackCacheEntry
	ttl     time.Duration
	nowFunc func() time.Time
}

type fallbackCacheEntry struct {
	id        ID
	endpoint  string
	expiresAt time.Time
}

// NewFallbackCache returns an empty FallbackCache with the given TTL.
// A zero or negative TTL picks a conservative default (5 minutes).
// Pass a non-nil now hook to override the wall clock in tests.
func NewFallbackCache(ttl time.Duration, now func() time.Time) *FallbackCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &FallbackCache{
		entries: map[string]fallbackCacheEntry{},
		ttl:     ttl,
		nowFunc: now,
	}
}

// Remember records that a dial succeeded on transport id for domain.
// Overwrites any existing entry for that domain and resets the TTL.
func (c *FallbackCache) Remember(domain string, id ID, endpoint string) {
	if c == nil || domain == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[strings.ToLower(domain)] = fallbackCacheEntry{
		id:        id,
		endpoint:  endpoint,
		expiresAt: c.nowFunc().Add(c.ttl),
	}
}

// Lookup returns the cached transport id and endpoint for domain,
// plus ok=true if an unexpired entry exists. Expired entries are
// treated as absent and evicted on read.
func (c *FallbackCache) Lookup(domain string) (id ID, endpoint string, ok bool) {
	if c == nil || domain == "" {
		return "", "", false
	}
	key := strings.ToLower(domain)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, present := c.entries[key]
	if !present {
		return "", "", false
	}
	if c.nowFunc().After(e.expiresAt) {
		delete(c.entries, key)
		return "", "", false
	}
	return e.id, e.endpoint, true
}

// Invalidate drops the cached entry for domain. Per TRANSPORT.md §5.6
// the cache MUST be invalidated when discovery records for the domain
// are refreshed — a domain that previously failed on QUIC may have
// resolved the issue and the connecting party should not permanently
// avoid a transport based on a single failure.
func (c *FallbackCache) Invalidate(domain string) {
	if c == nil || domain == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, strings.ToLower(domain))
}

// Len returns the number of unexpired entries currently in the cache.
// Expired entries encountered during the walk are evicted.
func (c *FallbackCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowFunc()
	live := 0
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
			continue
		}
		live++
	}
	return live
}

// CachedFallback is the same as Fallback but consults cache first:
// if domain has a live cached entry, the candidate whose ID matches
// the cached transport is moved to the head of the dial list so it
// is attempted first. On success the cache is refreshed with the
// candidate that actually dialed through — which may or may not be
// the one the cache suggested, because the cache hint is a
// preference, not a guarantee. On total failure the cache entry is
// invalidated so the next call does not preferentially retry a
// known-bad transport.
//
// If cache is nil, CachedFallback behaves identically to Fallback.
func CachedFallback(ctx context.Context, cache *FallbackCache, domain string, candidates []Candidate) (Conn, error) {
	if cache == nil {
		return Fallback(ctx, candidates)
	}
	if len(candidates) == 0 {
		return nil, errors.New("transport: fallback called with no candidates")
	}

	// Reorder candidates so the cached transport, if any, comes first.
	ordered := candidates
	if cachedID, _, ok := cache.Lookup(domain); ok {
		ordered = moveFirstMatching(candidates, cachedID)
	}

	conn, idx, err := dialCandidates(ctx, ordered)
	if err != nil {
		// Every candidate failed (including the cache hint, if any).
		// Invalidate so the next call doesn't preferentially retry
		// a known-bad transport.
		cache.Invalidate(domain)
		return nil, err
	}
	// Remember the transport that ACTUALLY worked, not the cache
	// hint — dialCandidates returns the index of the successful
	// candidate so we can cache the right one even when the first
	// N candidates (including any stale cache hint) failed.
	successful := ordered[idx]
	cache.Remember(domain, successful.ID(), successful.Endpoint)
	return conn, nil
}

// moveFirstMatching returns a fresh slice with the first candidate
// whose ID == want moved to the front. If no candidate matches, the
// input slice is returned by identity (no allocation).
func moveFirstMatching(candidates []Candidate, want ID) []Candidate {
	idx := -1
	for i, c := range candidates {
		if c.ID() == want {
			idx = i
			break
		}
	}
	if idx < 0 || idx == 0 {
		return candidates
	}
	out := make([]Candidate, 0, len(candidates))
	out = append(out, candidates[idx])
	out = append(out, candidates[:idx]...)
	out = append(out, candidates[idx+1:]...)
	return out
}
