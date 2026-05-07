package closure

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Retention bounds for the §6.1 post-finalization retention window.
// "The retention window begins at finalization and lasts at least
// 180 days (RECOMMENDED 365 days)."
const (
	// MinRetention is the spec's hard lower bound. Sub-floor values
	// are clamped up by PruneFinalized.
	MinRetention = 180 * 24 * time.Hour

	// RecommendedRetention is the §6.1 recommended default.
	RecommendedRetention = 365 * 24 * time.Hour
)

// Store is the persistence interface for closure state. Driver
// uses it for two distinct concerns:
//
//   - Pending state: active closure requests (Submit / Cancel /
//     Tick). Mirrors what the in-memory Driver previously held.
//   - Finalized state: closed accounts within their §6.1 retention
//     window. Used by IsAccountClosed for §5 ingress enforcement
//     and by §6 local-part reassignment checks.
//
// Production deployments plug in a durable backend; tests and
// demos use NewInMemoryStore.
type Store interface {
	// PutPending inserts r as the active pending request for
	// r.UserID. Returns ErrAlreadyPending if a request is already
	// pending for the same user (the Driver enforces the §2.4
	// "at most one active closure" rule via this error).
	PutPending(ctx context.Context, r *Record) error

	// GetPending returns the pending request for userID, or nil
	// when none is pending.
	GetPending(ctx context.Context, userID string) (*Record, error)

	// DeletePending removes the pending request for userID.
	// Idempotent on a missing entry.
	DeletePending(ctx context.Context, userID string) error

	// DuePending returns every pending request whose
	// FinalizationAt is at or before now, in deterministic order
	// (by user_id ascending). Tick consumes this slice.
	DuePending(ctx context.Context, now time.Time) ([]*Record, error)

	// CountPending returns the number of pending requests, useful
	// for operator monitoring. Implementations SHOULD answer this
	// from a maintained counter rather than walking every entry.
	CountPending(ctx context.Context) (int, error)

	// PutFinalized records that userID's closure finalized at the
	// given timestamp. Used by IsAccountClosed and by the §6.1
	// retention prune.
	PutFinalized(ctx context.Context, userID string, finalizedAt time.Time) error

	// GetFinalized returns the finalization timestamp for userID,
	// or (zero, false, nil) if no finalization is recorded.
	GetFinalized(ctx context.Context, userID string) (finalizedAt time.Time, found bool, err error)

	// PruneFinalized evicts finalized entries older than retainFor.
	// retainFor MUST be at least MinRetention; smaller values clamp
	// up. Returns the number of entries evicted.
	PruneFinalized(ctx context.Context, retainFor time.Duration) (int, error)
}

// inMemoryStore is the reference Store implementation. Concurrency-
// safe; production deployments use a durable backend.
type inMemoryStore struct {
	mu sync.Mutex
	// pending keyed by user_id.
	pending map[string]*Record
	// finalized keyed by user_id.
	finalized map[string]time.Time
}

// NewInMemoryStore returns a fresh in-memory Store.
func NewInMemoryStore() Store {
	return &inMemoryStore{
		pending:   make(map[string]*Record),
		finalized: make(map[string]time.Time),
	}
}

// PutPending inserts r; returns ErrAlreadyPending on collision with
// an existing entry for r.UserID.
func (s *inMemoryStore) PutPending(_ context.Context, r *Record) error {
	if r == nil {
		return errors.New("closure: store put nil record")
	}
	if r.UserID == "" {
		return errors.New("closure: store put record missing user_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pending[r.UserID]; exists {
		return fmt.Errorf("%w: %s", ErrAlreadyPending, r.UserID)
	}
	cp := *r
	s.pending[r.UserID] = &cp
	return nil
}

// GetPending returns a defensive copy or nil.
func (s *inMemoryStore) GetPending(_ context.Context, userID string) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.pending[userID]
	if !ok {
		return nil, nil
	}
	cp := *r
	return &cp, nil
}

// DeletePending is idempotent on a missing entry.
func (s *inMemoryStore) DeletePending(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, userID)
	return nil
}

// DuePending returns due records sorted by user_id.
func (s *inMemoryStore) DuePending(_ context.Context, now time.Time) ([]*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	due := make([]*Record, 0)
	for _, r := range s.pending {
		if !now.Before(r.FinalizationAt()) {
			cp := *r
			due = append(due, &cp)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].UserID < due[j].UserID })
	return due, nil
}

// CountPending returns the number of pending entries.
func (s *inMemoryStore) CountPending(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending), nil
}

// PutFinalized records the finalization timestamp.
func (s *inMemoryStore) PutFinalized(_ context.Context, userID string, finalizedAt time.Time) error {
	if userID == "" {
		return errors.New("closure: store put_finalized missing user_id")
	}
	if finalizedAt.IsZero() {
		return errors.New("closure: store put_finalized zero timestamp")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finalized[userID] = finalizedAt
	return nil
}

// GetFinalized returns the timestamp + presence flag.
func (s *inMemoryStore) GetFinalized(_ context.Context, userID string) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.finalized[userID]
	if !ok {
		return time.Time{}, false, nil
	}
	return t, true, nil
}

// PruneFinalized clamps retainFor to MinRetention and evicts
// entries older than the resulting cutoff.
func (s *inMemoryStore) PruneFinalized(_ context.Context, retainFor time.Duration) (int, error) {
	if retainFor < MinRetention {
		retainFor = MinRetention
	}
	cutoff := time.Now().UTC().Add(-retainFor)
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for k, t := range s.finalized {
		if t.Before(cutoff) {
			delete(s.finalized, k)
			removed++
		}
	}
	return removed, nil
}
