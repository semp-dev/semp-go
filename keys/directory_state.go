package keys

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/semp-dev/semp-go/crypto"
)

// DirectoryState is the per-user mutable state a home server keeps
// for KEY.md §10.6 device-directory publication. Each enrollment
// (§10.1) or revocation (§10.5) bumps Revision and produces a
// fresh signed DeviceDirectory record.
//
// DirectoryState is concurrency-safe; concurrent writers see each
// other's increments via the internal mutex.
type DirectoryState struct {
	mu sync.Mutex

	userID         string
	identityPriv   []byte
	identityKeyID  Fingerprint
	suite          crypto.Suite
	now            func() time.Time

	devices  map[string]DeviceDirectoryEntry // keyed by device_id
	revision int64
	current  *DeviceDirectory // last issued, signed
}

// DirectoryStateConfig groups the inputs to NewDirectoryState.
type DirectoryStateConfig struct {
	UserID        string
	Suite         crypto.Suite
	IdentityPriv  []byte
	IdentityKeyID Fingerprint

	// Initial seeds the directory with a starting set of devices,
	// typically loaded from durable storage at startup. The
	// constructor sorts them by device_id and emits revision 1.
	// Pass nil to start empty (revision 0; first Add bumps to 1).
	Initial []DeviceDirectoryEntry

	// Now is the wall-clock used to stamp DeviceDirectory.IssuedAt.
	// Defaults to time.Now().UTC() when nil.
	Now func() time.Time
}

// NewDirectoryState constructs a per-user directory state. When
// Initial is non-empty, the state immediately emits revision 1 with
// that seed; callers can then read .Current() to publish. When
// Initial is empty, .Current() returns nil until the first Add.
func NewDirectoryState(cfg DirectoryStateConfig) (*DirectoryState, error) {
	if cfg.UserID == "" {
		return nil, errors.New("keys: directory state missing user_id")
	}
	if cfg.Suite == nil {
		return nil, errors.New("keys: directory state missing suite")
	}
	if len(cfg.IdentityPriv) == 0 || cfg.IdentityKeyID == "" {
		return nil, errors.New("keys: directory state missing identity key")
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	s := &DirectoryState{
		userID:        cfg.UserID,
		suite:         cfg.Suite,
		identityPriv:  cfg.IdentityPriv,
		identityKeyID: cfg.IdentityKeyID,
		now:           now,
		devices:       make(map[string]DeviceDirectoryEntry, len(cfg.Initial)),
	}
	for _, d := range cfg.Initial {
		if d.DeviceID == "" {
			return nil, errors.New("keys: directory initial seed entry missing device_id")
		}
		if _, dup := s.devices[d.DeviceID]; dup {
			return nil, fmt.Errorf("keys: directory initial seed has duplicate device_id %q", d.DeviceID)
		}
		s.devices[d.DeviceID] = d
	}
	if len(s.devices) > 0 {
		if err := s.emitLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// AddDevice records an enrollment per KEY.md §10.1 and emits a new
// directory revision. Returns an error if device_id is empty or
// already present (the home server should reject the duplicate at
// the §10.1 step 3 verification before reaching this layer; the
// guard here is defense in depth).
func (s *DirectoryState) AddDevice(_ context.Context, entry DeviceDirectoryEntry) (*DeviceDirectory, error) {
	if entry.DeviceID == "" {
		return nil, errors.New("keys: directory entry missing device_id")
	}
	if entry.DevicePublicKey == "" {
		return nil, errors.New("keys: directory entry missing device_public_key")
	}
	switch entry.Role {
	case DeviceRoleFullAccess:
		if entry.CertificateID != nil {
			return nil, errors.New("keys: directory entry full_access MUST have certificate_id = null")
		}
	case DeviceRoleDelegated:
		if entry.CertificateID == nil || *entry.CertificateID == "" {
			return nil, errors.New("keys: directory entry delegated MUST set certificate_id")
		}
	default:
		return nil, fmt.Errorf("keys: directory entry role %q is not valid", entry.Role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.devices[entry.DeviceID]; exists {
		return nil, fmt.Errorf("keys: directory already contains device_id %q", entry.DeviceID)
	}
	s.devices[entry.DeviceID] = entry
	if err := s.emitLocked(); err != nil {
		return nil, err
	}
	return s.current, nil
}

// RevokeDevice records a revocation per KEY.md §10.5 by removing
// deviceID from the active set and emitting a new directory
// revision. Returns the new directory and a boolean indicating
// whether a removal actually happened (false when the device
// wasn't in the directory; the directory is unchanged in that
// case and no new revision is emitted).
func (s *DirectoryState) RevokeDevice(_ context.Context, deviceID string) (*DeviceDirectory, bool, error) {
	if deviceID == "" {
		return nil, false, errors.New("keys: directory revoke missing device_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.devices[deviceID]; !exists {
		return s.current, false, nil
	}
	delete(s.devices, deviceID)
	if err := s.emitLocked(); err != nil {
		return nil, false, err
	}
	return s.current, true, nil
}

// Current returns the most recently emitted directory, or nil if
// no directory has been emitted yet (empty initial state and no
// AddDevice calls). The returned pointer is the live record;
// callers MUST NOT mutate it. To send to a peer, marshal to JSON
// or pass to envelope canonicalizer.
func (s *DirectoryState) Current() *DeviceDirectory {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// Revision returns the current monotonic revision counter.
func (s *DirectoryState) Revision() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revision
}

// emitLocked builds and signs a new DeviceDirectory from the
// current device map, increments revision, and stores the result
// in s.current. Caller MUST hold s.mu.
func (s *DirectoryState) emitLocked() error {
	s.revision++
	entries := make([]DeviceDirectoryEntry, 0, len(s.devices))
	for _, d := range s.devices {
		entries = append(entries, d)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].DeviceID < entries[j].DeviceID
	})
	dir := &DeviceDirectory{
		UserID:   s.userID,
		Revision: s.revision,
		IssuedAt: s.now(),
		Devices:  entries,
	}
	if err := SignDeviceDirectory(s.suite.Signer(), s.identityPriv, s.identityKeyID, dir); err != nil {
		// Roll back the revision bump so the next attempt does not
		// skip a number.
		s.revision--
		return fmt.Errorf("keys: sign device directory: %w", err)
	}
	s.current = dir
	return nil
}

// DirectoryStore is the multi-user wrapper a home server keeps:
// one DirectoryState per account it hosts. Lookups are by user_id.
type DirectoryStore struct {
	mu     sync.RWMutex
	states map[string]*DirectoryState
}

// NewDirectoryStore returns an empty DirectoryStore.
func NewDirectoryStore() *DirectoryStore {
	return &DirectoryStore{states: make(map[string]*DirectoryState)}
}

// Register associates a fresh DirectoryState with userID. Returns
// an error if userID is already present.
func (s *DirectoryStore) Register(userID string, state *DirectoryState) error {
	if userID == "" {
		return errors.New("keys: directory store register missing user_id")
	}
	if state == nil {
		return errors.New("keys: directory store register missing state")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.states[userID]; exists {
		return fmt.Errorf("keys: directory store already has user %q", userID)
	}
	s.states[userID] = state
	return nil
}

// Lookup returns the DirectoryState for userID, or nil if not
// registered.
func (s *DirectoryStore) Lookup(userID string) *DirectoryState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.states[userID]
}
