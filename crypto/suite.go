package crypto

import "errors"

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

// suiteX25519ChaCha20Poly1305 is the concrete baseline suite.
//
// All five primitives are stateless singletons; constructing a Suite is a
// pointer assignment.
type suiteX25519ChaCha20Poly1305 struct {
	kem    KEM
	aead   AEAD
	kdf    KDF
	signer Signer
}

// SuiteBaseline is the x25519-chacha20-poly1305 suite. Every conformant
// SEMP implementation MUST support this suite for interoperability
// (ENVELOPE.md §7.3.2).
var SuiteBaseline Suite = &suiteX25519ChaCha20Poly1305{
	kem:    NewKEMX25519(),
	aead:   NewAEADChaCha20Poly1305(),
	kdf:    NewKDFHKDFSHA512(),
	signer: NewSignerEd25519(),
}

func (s *suiteX25519ChaCha20Poly1305) ID() SuiteID      { return SuiteIDX25519ChaCha20Poly1305 }
func (s *suiteX25519ChaCha20Poly1305) KEM() KEM         { return s.kem }
func (s *suiteX25519ChaCha20Poly1305) AEAD() AEAD       { return s.aead }
func (s *suiteX25519ChaCha20Poly1305) MAC(k []byte) MAC { return newHMACSHA256(k) }
func (s *suiteX25519ChaCha20Poly1305) KDF() KDF         { return s.kdf }
func (s *suiteX25519ChaCha20Poly1305) Signer() Signer   { return s.signer }

// SuitePQ is the pq-kyber768-x25519 hybrid suite, RECOMMENDED for new
// deployments. The Kyber768 component requires github.com/cloudflare/circl,
// which is not yet wired into this milestone — SuitePQ is therefore nil
// until that dependency is added. Code that calls LookupSuite or Negotiate
// will simply fall back to SuiteBaseline when SuitePQ is unavailable.
//
// TODO(SESSION.md §4.1): wire up Kyber768 from cloudflare/circl and
// instantiate SuitePQ as a real Suite.
var SuitePQ Suite

// LookupSuite returns the Suite registered for id, or nil if id is unknown
// or if the requested suite is not yet wired up in this build (e.g. SuitePQ
// before the Kyber dependency lands).
func LookupSuite(id SuiteID) Suite {
	switch id {
	case SuiteIDX25519ChaCha20Poly1305:
		return SuiteBaseline
	case SuiteIDPQKyber768X25519:
		return SuitePQ
	default:
		return nil
	}
}

// Negotiate returns the strongest mutually supported suite from the offered
// and accepted lists, preferring the post-quantum hybrid when both peers
// support it. Servers MUST NOT downgrade to a suite that lacks post-quantum
// components if both parties support one (SESSION.md §4.3).
//
// Preference order: pq-kyber768-x25519 > x25519-chacha20-poly1305.
//
// Returns ("", error) if no suite is mutually supported, or if the only
// mutually offered suite is unavailable in this build (e.g. SuitePQ when
// Kyber is not wired).
func Negotiate(offered []SuiteID, accepted []SuiteID) (SuiteID, error) {
	wants := make(map[SuiteID]bool, len(accepted))
	for _, id := range accepted {
		wants[id] = true
	}
	preference := []SuiteID{
		SuiteIDPQKyber768X25519,
		SuiteIDX25519ChaCha20Poly1305,
	}
	for _, id := range preference {
		if !wants[id] {
			continue
		}
		if !contains(offered, id) {
			continue
		}
		if LookupSuite(id) == nil {
			// Mutually offered but not yet implemented in this build —
			// keep looking for a weaker but available suite.
			continue
		}
		return id, nil
	}
	return "", errors.New("crypto: no mutually supported algorithm suite")
}

func contains(s []SuiteID, target SuiteID) bool {
	for _, id := range s {
		if id == target {
			return true
		}
	}
	return false
}
