package delivery

import (
	"sync"
	"time"
)

// Persistent silent recipient state per draft-gokce-semp-delivery
// §4.5 / DELIVERY.md §2.5. After repeated `silent` outcomes the
// sending server tightens its retry deadline for the same recipient
// so it does not waste effort retrying a recipient that consistently
// fails to acknowledge.
//
// Counter behavior:
//   - Inc(now): one more `silent` outcome for the recipient at now.
//     Records the first-occurrence timestamp when the counter rises
//     from 0 so the minimum observation window can be enforced.
//   - Reset(now): any non-`silent` outcome (delivered / rejected)
//     clears the counter.
//   - Effective(now): reports the current per-recipient effective
//     deadline. Returns the configured ShortDeadline when both the
//     count and observation-window thresholds are met; otherwise
//     returns 0 (caller uses its default deadline).
//   - Expired(now): reports whether the counter has been idle long
//     enough to drop. Callers prune by walking the registry on a
//     janitor cadence.
//
// The state is purely sender-side. It MUST NOT be transmitted on
// the wire and MUST NOT be published as a trust-gossip observation.
// Two senders correctly disagree on which recipients are persistently
// silent because each only sees its own envelopes.

// PersistentSilentDefaults are the §4.5 spec defaults.
//
//   - Threshold:           5 consecutive silents
//   - ObservationWindow:   24h minimum before tightening engages
//   - ShortDeadline:       4h tightened retry deadline
//   - IdleExpiry:          30d after which the counter is dropped
const (
	PersistentSilentDefaultThreshold         = 5
	PersistentSilentDefaultObservationWindow = 24 * time.Hour
	PersistentSilentDefaultShortDeadline     = 4 * time.Hour
	PersistentSilentDefaultIdleExpiry        = 30 * 24 * time.Hour
)

// PersistentSilentConfig configures a PersistentSilentCounter.
// Zero values fall back to the spec defaults at NewPersistentSilentCounter.
type PersistentSilentConfig struct {
	Threshold         int
	ObservationWindow time.Duration
	ShortDeadline     time.Duration
	IdleExpiry        time.Duration
}

// persistentSilentEntry is the per-recipient state.
type persistentSilentEntry struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

// PersistentSilentCounter is the sender-side ledger keyed by
// recipient address. Safe for concurrent use.
type PersistentSilentCounter struct {
	cfg     PersistentSilentConfig
	mu      sync.Mutex
	entries map[string]persistentSilentEntry
}

// NewPersistentSilentCounter returns a fresh counter. A zero
// Config gets the spec defaults; non-zero individual fields
// override only that field.
func NewPersistentSilentCounter(cfg PersistentSilentConfig) *PersistentSilentCounter {
	if cfg.Threshold <= 0 {
		cfg.Threshold = PersistentSilentDefaultThreshold
	}
	if cfg.ObservationWindow <= 0 {
		cfg.ObservationWindow = PersistentSilentDefaultObservationWindow
	}
	if cfg.ShortDeadline <= 0 {
		cfg.ShortDeadline = PersistentSilentDefaultShortDeadline
	}
	if cfg.IdleExpiry <= 0 {
		cfg.IdleExpiry = PersistentSilentDefaultIdleExpiry
	}
	return &PersistentSilentCounter{
		cfg:     cfg,
		entries: make(map[string]persistentSilentEntry),
	}
}

// Inc records one `silent` outcome for recipient at now. Returns
// the running count after the increment.
func (c *PersistentSilentCounter) Inc(recipient string, now time.Time) int {
	if c == nil || recipient == "" {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[recipient]
	if e.count == 0 {
		e.firstSeen = now
	}
	e.count++
	e.lastSeen = now
	c.entries[recipient] = e
	return e.count
}

// Reset clears the counter for recipient. Idempotent on missing
// entries. Callers invoke Reset on any non-silent outcome
// (delivered, rejected, etc.).
func (c *PersistentSilentCounter) Reset(recipient string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, recipient)
}

// Effective returns the §4.5 shortened deadline for recipient at
// now, or 0 when the counter has not yet met both the threshold
// and the minimum observation window. A zero return tells the
// caller to fall back to its default per-envelope deadline.
func (c *PersistentSilentCounter) Effective(recipient string, now time.Time) time.Duration {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[recipient]
	if !ok {
		return 0
	}
	if e.count < c.cfg.Threshold {
		return 0
	}
	if now.Sub(e.firstSeen) < c.cfg.ObservationWindow {
		return 0
	}
	return c.cfg.ShortDeadline
}

// Count returns the current silent count for recipient. Useful for
// metrics and tests.
func (c *PersistentSilentCounter) Count(recipient string) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries[recipient].count
}

// PruneExpired drops entries whose lastSeen is older than
// IdleExpiry relative to now. Returns the number of entries
// removed. Callers run this on a janitor cadence so the registry
// does not grow without bound.
func (c *PersistentSilentCounter) PruneExpired(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for k, e := range c.entries {
		if now.Sub(e.lastSeen) >= c.cfg.IdleExpiry {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}
