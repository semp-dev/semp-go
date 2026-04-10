package test

import (
	"context"
	"encoding/base64"
	"sync"
	"time"

	"github.com/semp-dev/semp-go/handshake"
	"github.com/semp-dev/semp-go/keys"
)

// memStore is a minimal in-memory implementation of keys.PrivateStore for
// use in single-process handshake and envelope tests. It is intentionally
// not safe for production use: it stores private key material in plaintext
// in memory and uses no access control.
//
// memStore satisfies both keys.Store and keys.PrivateStore so the same
// fixture can drive client-side and server-side test code paths.
type memStore struct {
	mu          sync.RWMutex
	domainKeys  map[string]*keys.Record               // domain -> domain public key record
	userKeys    map[string][]*keys.Record             // address -> all user key records
	privateKeys map[keys.Fingerprint][]byte           // fingerprint -> raw private key bytes
	deviceCerts map[keys.Fingerprint]*keys.DeviceCertificate
}

func newMemStore() *memStore {
	return &memStore{
		domainKeys:  make(map[string]*keys.Record),
		userKeys:    make(map[string][]*keys.Record),
		privateKeys: make(map[keys.Fingerprint][]byte),
		deviceCerts: make(map[keys.Fingerprint]*keys.DeviceCertificate),
	}
}

// putDomainKey records a domain public key record for domain.
func (m *memStore) putDomainKey(domain string, pub []byte) keys.Fingerprint {
	fp := keys.Compute(pub)
	rec := &keys.Record{
		Type:      keys.TypeDomain,
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		KeyID:     fp,
		Created:   time.Now(),
		Expires:   time.Now().Add(365 * 24 * time.Hour),
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.domainKeys[domain] = rec
	return fp
}

// putUserKey records a user public key for address with the given key type.
func (m *memStore) putUserKey(address string, kt keys.Type, pub []byte) keys.Fingerprint {
	fp := keys.Compute(pub)
	rec := &keys.Record{
		Address:   address,
		Type:      kt,
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		KeyID:     fp,
		Created:   time.Now(),
		Expires:   time.Now().Add(365 * 24 * time.Hour),
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userKeys[address] = append(m.userKeys[address], rec)
	return fp
}

// putPrivateKey stores a private key under its fingerprint.
func (m *memStore) putPrivateKey(fp keys.Fingerprint, priv []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(priv))
	copy(cp, priv)
	m.privateKeys[fp] = cp
}

// keys.Store implementation

func (m *memStore) LookupDomainKey(_ context.Context, domain string) (*keys.Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.domainKeys[domain]
	if !ok {
		return nil, nil
	}
	return rec, nil
}

func (m *memStore) LookupUserKeys(_ context.Context, address string, types ...keys.Type) ([]*keys.Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := m.userKeys[address]
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

func (m *memStore) PutRecord(_ context.Context, rec *keys.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec.Type == keys.TypeDomain {
		// We don't know which domain this is for; the caller would have to
		// use putDomainKey. PutRecord is implemented as a no-op for domain
		// records in this fixture.
		return nil
	}
	m.userKeys[rec.Address] = append(m.userKeys[rec.Address], rec)
	return nil
}

func (m *memStore) PutRevocation(_ context.Context, keyID keys.Fingerprint, rev *keys.Revocation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, list := range m.userKeys {
		for _, rec := range list {
			if rec.KeyID == keyID {
				rec.Revocation = rev
			}
		}
	}
	for _, rec := range m.domainKeys {
		if rec.KeyID == keyID {
			rec.Revocation = rev
		}
	}
	return nil
}

func (m *memStore) LookupDeviceCertificate(_ context.Context, deviceKeyID keys.Fingerprint) (*keys.DeviceCertificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cert, ok := m.deviceCerts[deviceKeyID]
	if !ok {
		return nil, nil
	}
	return cert, nil
}

func (m *memStore) PutDeviceCertificate(_ context.Context, cert *keys.DeviceCertificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deviceCerts[cert.DeviceKeyID] = cert
	return nil
}

// keys.PrivateStore implementation

func (m *memStore) LoadPrivateKey(_ context.Context, keyID keys.Fingerprint) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	priv, ok := m.privateKeys[keyID]
	if !ok {
		return nil, errKeyNotFound
	}
	out := make([]byte, len(priv))
	copy(out, priv)
	return out, nil
}

func (m *memStore) StorePrivateKey(_ context.Context, keyID keys.Fingerprint, priv []byte) error {
	m.putPrivateKey(keyID, priv)
	return nil
}

// errKeyNotFound is returned by LoadPrivateKey when the requested key is not
// stored. We use a sentinel rather than fmt.Errorf so callers can match it
// with errors.Is in tests if needed.
var errKeyNotFound = errStr("test: private key not found")

type errStr string

func (e errStr) Error() string { return string(e) }

// permitAllPolicy is the simplest possible Policy: no PoW, no blocks,
// 5-minute TTL, send+receive permissions.
type permitAllPolicy struct{}

func (permitAllPolicy) RequirePoW(_, _ string) *handshake.PoWRequired { return nil }
func (permitAllPolicy) BlockedDomain(_ string) bool                   { return false }
func (permitAllPolicy) SessionTTL(_ string) int                       { return 300 }
func (permitAllPolicy) Permissions(_ string) []string                 { return []string{"send", "receive"} }

// powGatePolicy returns a fixed PoW challenge once and then never again.
// Used by the PoW round-trip test to exercise the conditional path.
type powGatePolicy struct {
	challenge *handshake.PoWRequired
	served    bool
}

func (p *powGatePolicy) RequirePoW(_, _ string) *handshake.PoWRequired {
	if p.served {
		return nil
	}
	p.served = true
	return p.challenge
}
func (p *powGatePolicy) BlockedDomain(_ string) bool   { return false }
func (p *powGatePolicy) SessionTTL(_ string) int       { return 300 }
func (p *powGatePolicy) Permissions(_ string) []string { return []string{"send", "receive"} }
