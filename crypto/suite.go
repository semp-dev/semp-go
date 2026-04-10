package crypto

// SuiteID is the on-the-wire identifier for an algorithm suite, e.g.
// "pq-kyber768-x25519". It appears in seal.algorithm and in handshake
// negotiation messages.
type SuiteID string

// Defined suite identifiers.
const (
	// SuiteIDX25519ChaCha20Poly1305 is the baseline suite. Implementations
	// MUST support this suite for interoperability (ENVELOPE.md §7.3.2).
	SuiteIDX25519ChaCha20Poly1305 SuiteID = "x25519-chacha20-poly1305"

	// SuiteIDPQKyber768X25519 is the post-quantum hybrid suite. Combines
	// Kyber768 KEM with X25519 in a concat-KDF construction. RECOMMENDED.
	SuiteIDPQKyber768X25519 SuiteID = "pq-kyber768-x25519"
)

// Suite is the abstract bundle of cryptographic primitives that govern a
// SEMP session. Every component is determined together: implementations
// negotiate suites, not individual primitives (ENVELOPE.md §7.3.3).
type Suite interface {
	// ID returns the on-the-wire suite identifier.
	ID() SuiteID

	// KEM returns the key encapsulation mechanism for ephemeral key
	// agreement during the handshake.
	KEM() KEM

	// AEAD returns the authenticated symmetric cipher used to encrypt
	// brief, enclosure, and handshake payloads.
	AEAD() AEAD

	// MAC returns a MAC instance keyed with k. The same primitive is used
	// for handshake message MACs and for seal.session_mac.
	MAC(k []byte) MAC

	// KDF returns the key derivation function used to expand the ephemeral
	// shared secret into the five session keys.
	KDF() KDF

	// Signer returns the signature algorithm used for domain key signatures
	// and identity proofs.
	Signer() Signer
}

// LookupSuite returns the Suite registered for id, or nil if id is unknown.
//
// TODO(ENVELOPE.md §7.3.2): wire up the two built-in suites once their
// constructors are implemented.
func LookupSuite(id SuiteID) Suite {
	_ = id
	return nil
}

// Negotiate returns the strongest mutually supported suite from the offered
// and accepted lists, preferring the post-quantum hybrid when both peers
// support it. Servers MUST NOT downgrade to a suite that lacks post-quantum
// components if both parties support one (SESSION.md §4.3).
//
// TODO(HANDSHAKE.md §2.3, SESSION.md §4.3): implement preference ordering.
func Negotiate(offered []SuiteID, accepted []SuiteID) (SuiteID, error) {
	_, _ = offered, accepted
	return "", nil
}
