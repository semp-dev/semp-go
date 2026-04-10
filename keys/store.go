package keys

import "context"

// Store is the persistence interface for SEMP keys. A Store implementation
// holds public keys for known correspondents and (on the user side) the
// user's own private key material in encrypted-at-rest form per KEY.md §9.1.
//
// Server implementations and client implementations have different storage
// needs but expose the same interface so that handshake, envelope, and
// delivery code can be written once.
type Store interface {
	// LookupDomainKey returns the current domain key for the given domain,
	// or an error if no key is known.
	LookupDomainKey(ctx context.Context, domain string) (*Record, error)

	// LookupUserKeys returns all current key records for the given user
	// address, optionally filtered by key type. An empty types slice means
	// "all known types".
	LookupUserKeys(ctx context.Context, address string, types ...Type) ([]*Record, error)

	// PutRecord persists a fetched key record. Implementations SHOULD
	// respect the key's Expires timestamp when caching.
	PutRecord(ctx context.Context, rec *Record) error

	// PutRevocation records a revocation. Once a key is revoked, subsequent
	// LookupUserKeys / LookupDomainKey calls MUST surface the revocation in
	// the returned record.
	PutRevocation(ctx context.Context, keyID Fingerprint, rev *Revocation) error

	// LookupDeviceCertificate returns the current scoped device certificate
	// for the given device key, if any. A return of (nil, nil) means the
	// device is full-access (no certificate is on file).
	LookupDeviceCertificate(ctx context.Context, deviceKeyID Fingerprint) (*DeviceCertificate, error)

	// PutDeviceCertificate persists a delegated device certificate.
	PutDeviceCertificate(ctx context.Context, cert *DeviceCertificate) error
}

// PrivateStore extends Store with access to the user's own private keys.
// Only client implementations need this; server implementations never hold
// user private keys (CLIENT.md §10.1, KEY.md §9.1).
type PrivateStore interface {
	Store

	// LoadPrivateKey returns the decrypted private key material for the
	// given key fingerprint. Implementations are responsible for prompting
	// the user for unlock credentials when required.
	LoadPrivateKey(ctx context.Context, keyID Fingerprint) ([]byte, error)

	// StorePrivateKey writes encrypted private key material for the given
	// key fingerprint. Implementations MUST encrypt at rest using a KDF
	// such as Argon2id (KEY.md §9.2).
	StorePrivateKey(ctx context.Context, keyID Fingerprint, privateKey []byte) error
}
