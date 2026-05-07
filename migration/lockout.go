package migration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// LockoutRegistry tracks §6.1 forwarding-window lockouts: the old
// provider MUST NOT reassign a migrated local-part while its
// forwarding window has not been reached. The §4.2 obligation also
// reads "MUST NOT countersign a second migration record for the
// same old address while a prior record is in its forwarding
// window"; AcceptSubmission consults this registry before
// countersigning to detect the duplicate-submission case.
//
// Implementations are operator-supplied. The library's reference
// in-memory implementation (NewInMemoryLockoutRegistry) covers
// tests and small deployments; production servers wire a durable
// backend.
type LockoutRegistry interface {
	// Reserve marks localpart locked out until the given timestamp.
	// recordID identifies the migration record that established
	// the reservation, used by IsLockedOut for diagnostics.
	//
	// Returns ErrLocalPartLockedOut if a prior reservation already
	// covers localpart and has not yet expired. Operators MUST
	// reject duplicate submissions with this error.
	Reserve(ctx context.Context, localpart string, until time.Time, recordID string) error

	// IsLockedOut reports whether localpart is currently locked
	// out at now. When locked, returns the establishing
	// migration_record_id and the until-timestamp; the caller
	// surfaces these in the §6.1 rejection so the requesting
	// principal knows when the lockout lifts.
	IsLockedOut(ctx context.Context, localpart string, now time.Time) (recordID string, until time.Time, locked bool, err error)

	// Release removes the reservation for localpart unconditionally.
	// Operators call Release when the forwarding window has
	// elapsed and they choose to make the local-part available
	// for reassignment per §6.2. Release on a missing entry is a
	// no-op.
	Release(ctx context.Context, localpart string) error

	// PruneExpired removes reservations whose until is at or
	// before now. Operators call this on a janitor cadence so the
	// store does not retain stale entries indefinitely.
	PruneExpired(ctx context.Context, now time.Time) (int, error)
}

// ErrLocalPartLockedOut is returned by Reserve when the local-part
// is already covered by an unexpired reservation. AcceptSubmission
// surfaces this typed error so the operator's HTTP layer maps it
// to the §6.1 policy_forbidden rejection.
var ErrLocalPartLockedOut = errors.New("migration: local-part is locked out by an active migration")

// inMemoryLockoutRegistry is the reference implementation.
// Concurrency-safe.
type inMemoryLockoutRegistry struct {
	mu      sync.Mutex
	entries map[string]lockoutEntry
}

type lockoutEntry struct {
	until    time.Time
	recordID string
}

// NewInMemoryLockoutRegistry returns a fresh in-memory registry.
func NewInMemoryLockoutRegistry() LockoutRegistry {
	return &inMemoryLockoutRegistry{entries: make(map[string]lockoutEntry)}
}

// Reserve inserts an entry; returns ErrLocalPartLockedOut on
// collision with an unexpired entry. An expired entry is
// transparently overwritten — equivalent to the §6.2 "after the
// window the local-part MAY be reassigned" rule, just realized
// lazily on next Reserve rather than on a janitor sweep.
func (r *inMemoryLockoutRegistry) Reserve(_ context.Context, localpart string, until time.Time, recordID string) error {
	if localpart == "" {
		return errors.New("migration: reserve empty localpart")
	}
	if until.IsZero() {
		return errors.New("migration: reserve zero until")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	if existing, ok := r.entries[localpart]; ok {
		if existing.until.After(now) {
			return fmt.Errorf("%w: localpart=%q until=%s record_id=%s",
				ErrLocalPartLockedOut, localpart, existing.until.Format(time.RFC3339), existing.recordID)
		}
		// Expired: silently replace.
	}
	r.entries[localpart] = lockoutEntry{until: until, recordID: recordID}
	return nil
}

// IsLockedOut returns the active reservation, if any.
func (r *inMemoryLockoutRegistry) IsLockedOut(_ context.Context, localpart string, now time.Time) (string, time.Time, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[localpart]
	if !ok {
		return "", time.Time{}, false, nil
	}
	if !e.until.After(now) {
		return "", time.Time{}, false, nil
	}
	return e.recordID, e.until, true, nil
}

// Release lifts a reservation. Idempotent on missing entries.
func (r *inMemoryLockoutRegistry) Release(_ context.Context, localpart string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, localpart)
	return nil
}

// PruneExpired sweeps expired entries.
func (r *inMemoryLockoutRegistry) PruneExpired(_ context.Context, now time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	for k, e := range r.entries {
		if !e.until.After(now) {
			delete(r.entries, k)
			removed++
		}
	}
	return removed, nil
}
