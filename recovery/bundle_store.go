package recovery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// BundleStore is the home-server-side storage for SEMP_BACKUP_BUNDLE
// records per RECOVERY.md §4. The server hosts encrypted backup
// bundles uploaded by users, retains the current bundle
// indefinitely, retains superseded bundles for at least 30 days,
// and serves downloads without requiring an authenticated session
// (so a user with no remaining private keys can still restore).
//
// Implementations MUST:
//
//   - Treat encrypted_payload as opaque (per §4.2 the server MUST
//     NOT decrypt or attempt to decrypt the payload).
//   - Verify the signature against the user's current identity key
//     before storing - done outside this interface by the upload
//     handler; the Store itself is signature-agnostic and persists
//     whatever bytes it is handed.
//   - Apply the §4.4 retention rules: current bundle retained
//     indefinitely; superseded bundles retained for at least
//     MinSupersededRetention (30 days).
//
// Production deployments plug in a durable backend (object store,
// SQL, etc.); tests and demos use NewInMemoryBundleStore.
type BundleStore interface {
	// PutCurrent installs bundle as the current bundle for
	// userID, marking any prior current bundle as superseded as
	// of supersededAt. The supersedes pointer on bundle MUST
	// match the prior current bundle's BundleID (or both must be
	// nil/empty, for the first-ever bundle); PutCurrent enforces
	// this rule and returns ErrSupersedesMismatch on violation.
	PutCurrent(ctx context.Context, userID string, bundle *BackupBundle, supersededAt time.Time) error

	// GetCurrent returns the current bundle for userID. Returns
	// (nil, ErrBundleNotFound) when no current bundle exists.
	GetCurrent(ctx context.Context, userID string) (*BackupBundle, error)

	// History returns every retained bundle for userID, current
	// first then superseded in newest-superseded-first order. Used
	// for the §4.1 `?history=true` download path.
	History(ctx context.Context, userID string) ([]*BackupBundle, error)

	// DeleteAll removes every bundle for userID per §4.1's DELETE.
	// Authenticated; the upload handler enforces the session-
	// bound-to-user check before calling DeleteAll.
	DeleteAll(ctx context.Context, userID string) error

	// PruneSuperseded evicts superseded bundles whose
	// supersededAt is more than retainFor in the past. retainFor
	// MUST be at least MinSupersededRetention (30 days);
	// implementations clamp lower values up.
	PruneSuperseded(ctx context.Context, retainFor time.Duration) (int, error)
}

// MinSupersededRetention is the §4.4 retention floor for superseded
// bundles. Implementations MUST retain superseded bundles for at
// least this long; PruneSuperseded clamps lower retention windows
// up to this floor.
const MinSupersededRetention = 30 * 24 * time.Hour

// Sentinel errors. Implementations SHOULD return these wrapped so
// callers can branch via errors.Is.
var (
	// ErrBundleNotFound is returned by GetCurrent when no current
	// bundle exists for the user.
	ErrBundleNotFound = errors.New("recovery: no current bundle for user")

	// ErrSupersedesMismatch is returned by PutCurrent when the
	// uploaded bundle's supersedes pointer does not match the
	// prior current bundle's ID. This signals either a forged
	// upload or a stale client; the server MUST reject either way
	// per §4.2 step 3.
	ErrSupersedesMismatch = errors.New("recovery: bundle supersedes pointer does not match prior current bundle")
)

// inMemoryBundleStore is the reference BundleStore implementation
// used by tests and demos. Concurrency-safe; production deployments
// use a durable backend.
type inMemoryBundleStore struct {
	mu sync.Mutex
	// per-user records.
	records map[string]*userBundles
	// nowFn supplies the wall-clock for retention cutoffs. Tests
	// inject a fake clock; production uses time.Now().UTC.
	nowFn func() time.Time
}

type userBundles struct {
	current     *BackupBundle
	superseded  []supersededBundle
}

type supersededBundle struct {
	bundle       *BackupBundle
	supersededAt time.Time
}

// NewInMemoryBundleStore returns an in-memory BundleStore using
// time.Now().UTC for retention cutoffs.
func NewInMemoryBundleStore() BundleStore {
	return NewInMemoryBundleStoreWithClock(nil)
}

// NewInMemoryBundleStoreWithClock returns an in-memory BundleStore
// with an injectable wall-clock source. Pass nil to use
// time.Now().UTC. Tests pass a fake clock to make PruneSuperseded
// deterministic.
func NewInMemoryBundleStoreWithClock(nowFn func() time.Time) BundleStore {
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	return &inMemoryBundleStore{
		records: make(map[string]*userBundles),
		nowFn:   nowFn,
	}
}

// PutCurrent installs bundle as userID's current bundle. The
// supersedes pointer MUST match the prior current bundle's
// BundleID, or both MUST be empty for the first upload.
func (s *inMemoryBundleStore) PutCurrent(_ context.Context, userID string, bundle *BackupBundle, supersededAt time.Time) error {
	if userID == "" {
		return errors.New("recovery: bundle store put empty user_id")
	}
	if bundle == nil {
		return errors.New("recovery: bundle store put nil bundle")
	}
	if bundle.UserID != userID {
		return fmt.Errorf("recovery: bundle.user_id %q does not match userID arg %q", bundle.UserID, userID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[userID]
	if !ok {
		rec = &userBundles{}
		s.records[userID] = rec
	}

	// Validate the supersedes pointer per §4.2 step 3.
	priorID := ""
	if rec.current != nil {
		priorID = rec.current.BundleID
	}
	supersedesPtr := ""
	if bundle.Supersedes != nil {
		supersedesPtr = *bundle.Supersedes
	}
	if supersedesPtr != priorID {
		return fmt.Errorf("%w: bundle supersedes %q, prior current %q",
			ErrSupersedesMismatch, supersedesPtr, priorID)
	}

	// Move the prior current to the superseded list.
	if rec.current != nil {
		rec.superseded = append(rec.superseded, supersededBundle{
			bundle:       rec.current,
			supersededAt: supersededAt,
		})
	}
	cp := *bundle
	rec.current = &cp
	return nil
}

// GetCurrent returns userID's current bundle, or ErrBundleNotFound.
func (s *inMemoryBundleStore) GetCurrent(_ context.Context, userID string) (*BackupBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[userID]
	if !ok || rec.current == nil {
		return nil, fmt.Errorf("%w: %s", ErrBundleNotFound, userID)
	}
	cp := *rec.current
	return &cp, nil
}

// History returns the current bundle followed by superseded bundles,
// newest superseded first.
func (s *inMemoryBundleStore) History(_ context.Context, userID string) ([]*BackupBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[userID]
	if !ok {
		return nil, nil
	}
	out := make([]*BackupBundle, 0, 1+len(rec.superseded))
	if rec.current != nil {
		cp := *rec.current
		out = append(out, &cp)
	}
	// Sort superseded by supersededAt descending.
	sorted := make([]supersededBundle, len(rec.superseded))
	copy(sorted, rec.superseded)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].supersededAt.After(sorted[j].supersededAt)
	})
	for _, sb := range sorted {
		cp := *sb.bundle
		out = append(out, &cp)
	}
	return out, nil
}

// DeleteAll wipes userID's records. Implementations called via the
// §4.1 DELETE path; the upload handler must have authenticated the
// session against userID before calling.
func (s *inMemoryBundleStore) DeleteAll(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, userID)
	return nil
}

// PruneSuperseded evicts superseded bundles whose supersededAt is
// more than retainFor in the past. retainFor is clamped to
// MinSupersededRetention.
//
// Returns the number of bundles evicted across all users.
func (s *inMemoryBundleStore) PruneSuperseded(_ context.Context, retainFor time.Duration) (int, error) {
	if retainFor < MinSupersededRetention {
		retainFor = MinSupersededRetention
	}
	cutoff := s.nowFn().Add(-retainFor)
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for _, rec := range s.records {
		kept := rec.superseded[:0]
		for _, sb := range rec.superseded {
			if sb.supersededAt.Before(cutoff) {
				removed++
				continue
			}
			kept = append(kept, sb)
		}
		rec.superseded = kept
	}
	return removed, nil
}
