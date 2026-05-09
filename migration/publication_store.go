package migration

import (
	"context"
	"errors"
	"sync"
)

// PublicationStore is the persistence interface a migration
// publication endpoint plugs into. It stores 4-sig MigrationRecord
// values keyed by old address (per §6.2 the published record
// stays accessible as historical evidence) and by record id.
type PublicationStore interface {
	PutRecord(ctx context.Context, r *MigrationRecord) error
	GetByOldAddress(ctx context.Context, oldAddress string) (*MigrationRecord, error)
	GetByRecordID(ctx context.Context, recordID string) (*MigrationRecord, error)
}

// inMemoryPublicationStore is the reference PublicationStore. Per
// §6.2 the store retains records as historical evidence even after
// the local-part is reassigned; this implementation never evicts
// (the spec does not require expiry).
type inMemoryPublicationStore struct {
	mu sync.Mutex
	// most-recent record per old address.
	byAddress map[string]*MigrationRecord
	// every record by id.
	byID map[string]*MigrationRecord
}

// NewInMemoryPublicationStore returns a fresh in-memory
// PublicationStore.
func NewInMemoryPublicationStore() PublicationStore {
	return &inMemoryPublicationStore{
		byAddress: make(map[string]*MigrationRecord),
		byID:      make(map[string]*MigrationRecord),
	}
}

func (s *inMemoryPublicationStore) PutRecord(_ context.Context, r *MigrationRecord) error {
	if r == nil {
		return errors.New("migration: publication store put nil record")
	}
	if r.RecordID == "" {
		return errors.New("migration: publication store put record missing record_id")
	}
	if r.OldAddress == "" {
		return errors.New("migration: publication store put record missing old_address")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *r
	s.byAddress[r.OldAddress] = &cp
	s.byID[r.RecordID] = &cp
	return nil
}

func (s *inMemoryPublicationStore) GetByOldAddress(_ context.Context, oldAddress string) (*MigrationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byAddress[oldAddress]
	if !ok {
		return nil, nil
	}
	cp := *r
	return &cp, nil
}

func (s *inMemoryPublicationStore) GetByRecordID(_ context.Context, recordID string) (*MigrationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[recordID]
	if !ok {
		return nil, nil
	}
	cp := *r
	return &cp, nil
}
