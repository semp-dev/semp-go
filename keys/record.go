package keys

import "time"

// Record is a single key record as it appears in a SEMP_KEYS response
// (KEY.md §4.3, §4.4) or in a domain key publication (KEY.md §2.3).
type Record struct {
	// Address is the user address this key belongs to. Empty for domain keys.
	Address string `json:"address,omitempty"`

	// Type is the key role.
	Type Type `json:"key_type"`

	// Algorithm is the cryptographic algorithm identifier, e.g. "ed25519",
	// "pq-kyber768-x25519".
	Algorithm string `json:"algorithm"`

	// PublicKey is the base64-encoded public key material.
	PublicKey string `json:"public_key"`

	// KeyID is the SHA-256 fingerprint of the public key bytes.
	KeyID Fingerprint `json:"key_id"`

	// Created is the time the key was generated.
	Created time.Time `json:"created"`

	// Expires is the time after which the key SHOULD NOT be used for new
	// operations. Past-expiry keys remain valid for decrypting historical
	// envelopes.
	Expires time.Time `json:"expires"`

	// Signatures is the optional set of signatures attached to this key:
	// always at least the issuing domain's signature, and optionally a
	// self-signature from the user's identity key plus any web-of-trust
	// signatures from third parties (KEY.md §5).
	Signatures []Signature `json:"signatures,omitempty"`

	// Revocation is non-nil iff the key has been revoked. The presence of
	// this field is itself the indicator that the key MUST NOT be used for
	// new encryption operations.
	Revocation *Revocation `json:"revocation,omitempty"`
}

// Signature is one entry in a key record's signatures array (KEY.md §5).
type Signature struct {
	// Signer is the address or domain that produced the signature.
	Signer string `json:"signer"`

	// KeyID is the fingerprint of the signing key.
	KeyID Fingerprint `json:"key_id"`

	// Value is the base64-encoded signature bytes.
	Value string `json:"value"`

	// Timestamp is when the signature was created.
	Timestamp time.Time `json:"timestamp"`

	// TrustLevel is an optional informational tag attached by web-of-trust
	// signers, e.g. "high". It is not used to gate validity.
	TrustLevel string `json:"trust_level,omitempty"`
}
