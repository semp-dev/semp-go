package session

import (
	"context"
	"time"
)

// ExpiryLog records session IDs that have expired or been invalidated.
// Receiving servers consult the expiry log when verifying postmark
// session_id values: a session_id that names a retired session MUST cause
// the envelope to be rejected with reason code handshake_invalid
// (SESSION.md §5.2).
//
// Entries are retained for the maximum postmark.expires window (default
// one hour per ENVELOPE.md §10.2). Only the session_id and its retirement
// timestamp are kept; no key material is retained.
type ExpiryLog interface {
	// Retire records that the given session_id has been retired at the
	// given time.
	Retire(ctx context.Context, sessionID string, retiredAt time.Time) error

	// Retired reports whether the given session_id is in the expiry log
	// (i.e. it has been retired and the entry has not yet aged out).
	Retired(ctx context.Context, sessionID string) (bool, error)

	// Sweep removes entries older than now - retention. Implementations
	// SHOULD call Sweep periodically to bound memory usage.
	Sweep(ctx context.Context, now time.Time, retention time.Duration) error
}

// Bounds defines the per-server concurrent session limits enforced via
// SESSION.md §2.5.3.
type Bounds struct {
	// MaxClientSessions is the maximum number of concurrently active
	// client sessions across all users. Default 10,000.
	MaxClientSessions int

	// MaxFederationSessions is the maximum number of concurrently active
	// federation sessions across all peers. Default 1,000.
	MaxFederationSessions int
}

// DefaultBounds returns the recommended defaults from SESSION.md §2.5.3.
func DefaultBounds() Bounds {
	return Bounds{
		MaxClientSessions:     10000,
		MaxFederationSessions: 1000,
	}
}
