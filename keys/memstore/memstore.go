// Package memstore is a minimal in-memory implementation of keys.Store
// and keys.PrivateStore. It is intended for tests, single-process demos,
// and the reference cmd/semp-server / cmd/semp-cli binaries.
//
// memstore is NOT a production storage layer:
//
//   - Private keys are held in memory in plaintext (no encryption at rest,
//     no Argon2id KDF, no hardware backing). This violates KEY.md §9.1.
//   - There is no concurrency tuning beyond a single sync.RWMutex.
//   - There is no persistence: process restart loses all stored material.
//
// Production deployments MUST implement keys.Store / keys.PrivateStore
// against an encrypted-at-rest backing store and the platform's hardware
// security primitives where available.
package memstore

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/semp-dev/semp-go/keys"
)

// Store is the in-memory store. The zero value is not usable; call New.
type Store struct {
	mu          sync.RWMutex
	domainKeys  map[string]*keys.Record               // domain -> domain public key record
	userKeys    map[string][]*keys.Record             // address -> all user key records
	privateKeys map[keys.Fingerprint][]byte           // fingerprint -> raw private key bytes
	deviceCerts map[keys.Fingerprint]*keys.DeviceCertificate
}

// New constructs a fresh in-memory store.
func New() *Store {
	return &Store{
		domainKeys:  make(map[string]*keys.Record),
		userKeys:    make(map[string][]*keys.Record),
		privateKeys: make(map[keys.Fingerprint][]byte),
		deviceCerts: make(map[keys.Fingerprint]*keys.DeviceCertificate),
	}
}

// PutDomainKey records a domain public key record for domain. Returns the
// computed fingerprint.
func (s *Store) PutDomainKey(domain string, pub []byte) keys.Fingerprint {
	fp := keys.Compute(pub)
	rec := &keys.Record{
		Type:      keys.TypeDomain,
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		KeyID:     fp,
		Created:   time.Now(),
		Expires:   time.Now().Add(365 * 24 * time.Hour),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domainKeys[domain] = rec
	return fp
}

// PutUserKey records a user public key for address with the given key
// type and algorithm. Returns the computed fingerprint.
func (s *Store) PutUserKey(address string, kt keys.Type, algorithm string, pub []byte) keys.Fingerprint {
	fp := keys.Compute(pub)
	rec := &keys.Record{
		Address:   address,
		Type:      kt,
		Algorithm: algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		KeyID:     fp,
		Created:   time.Now(),
		Expires:   time.Now().Add(365 * 24 * time.Hour),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userKeys[address] = append(s.userKeys[address], rec)
	return fp
}

// PutPrivateKey stores a private key under its fingerprint. The bytes are
// copied so callers may zeroize their own buffers.
func (s *Store) PutPrivateKey(fp keys.Fingerprint, priv []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(priv))
	copy(cp, priv)
	s.privateKeys[fp] = cp
}

// LookupDomainKey implements keys.Store.
func (s *Store) LookupDomainKey(_ context.Context, domain string) (*keys.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.domainKeys[domain]
	if !ok {
		return nil, nil
	}
	return rec, nil
}

// LookupUserKeys implements keys.Store.
func (s *Store) LookupUserKeys(_ context.Context, address string, types ...keys.Type) ([]*keys.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.userKeys[address]
	if len(types) == 0 {
		return append([]*keys.Record(nil), all...), nil
	}
	want := make(map[keys.Type]bool, len(types))
	for _, t := range types {
		want[t] = true
	}
	out := make([]*keys.Record, 0, len(all))
	for _, rec := range all {
		if want[rec.Type] {
			out = append(out, rec)
		}
	}
	return out, nil
}

// PutRecord implements keys.Store. Domain records are ignored (use
// PutDomainKey directly because the domain name is not on the record).
func (s *Store) PutRecord(_ context.Context, rec *keys.Record) error {
	if rec == nil {
		return errors.New("memstore: nil record")
	}
	if rec.Type == keys.TypeDomain {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userKeys[rec.Address] = append(s.userKeys[rec.Address], rec)
	return nil
}

// PutRevocation implements keys.Store. The revocation is attached to any
// record (user or domain) whose fingerprint matches keyID.
func (s *Store) PutRevocation(_ context.Context, keyID keys.Fingerprint, rev *keys.Revocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, list := range s.userKeys {
		for _, rec := range list {
			if rec.KeyID == keyID {
				rec.Revocation = rev
			}
		}
	}
	for _, rec := range s.domainKeys {
		if rec.KeyID == keyID {
			rec.Revocation = rev
		}
	}
	return nil
}

// LookupDeviceCertificate implements keys.Store.
func (s *Store) LookupDeviceCertificate(_ context.Context, deviceKeyID keys.Fingerprint) (*keys.DeviceCertificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cert, ok := s.deviceCerts[deviceKeyID]
	if !ok {
		return nil, nil
	}
	return cert, nil
}

// PutDeviceCertificate implements keys.Store.
func (s *Store) PutDeviceCertificate(_ context.Context, cert *keys.DeviceCertificate) error {
	if cert == nil {
		return errors.New("memstore: nil certificate")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceCerts[cert.DeviceKeyID] = cert
	return nil
}

// LoadPrivateKey implements keys.PrivateStore.
func (s *Store) LoadPrivateKey(_ context.Context, keyID keys.Fingerprint) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	priv, ok := s.privateKeys[keyID]
	if !ok {
		return nil, errors.New("memstore: private key not found")
	}
	out := make([]byte, len(priv))
	copy(out, priv)
	return out, nil
}

// StorePrivateKey implements keys.PrivateStore.
func (s *Store) StorePrivateKey(_ context.Context, keyID keys.Fingerprint, priv []byte) error {
	s.PutPrivateKey(keyID, priv)
	return nil
}
