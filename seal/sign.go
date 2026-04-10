package seal

import (
	"github.com/semp-dev/semp-go/crypto"
)

// Signer computes the dual integrity proofs that live in Seal.Signature and
// Seal.SessionMAC. Both proofs cover the same canonical envelope bytes per
// ENVELOPE.md §4.3.
type Signer struct {
	// Suite is the negotiated algorithm suite (signing + MAC primitives).
	Suite crypto.Suite

	// DomainPrivateKey is the sender domain's long-term private key. Used
	// only by the sender's home server when computing Seal.Signature; the
	// client never holds this material (CLIENT.md §1.3).
	DomainPrivateKey []byte

	// EnvMAC is K_env_mac for the active session, used to compute
	// Seal.SessionMAC.
	EnvMAC []byte
}

// Sign computes Seal.Signature and Seal.SessionMAC over the canonical bytes
// of the envelope and stores them in seal.
//
// canonicalBytes MUST be the canonical serialization with both Signature
// and SessionMAC fields set to "" and Postmark.HopCount omitted, per
// ENVELOPE.md §4.3.
//
// TODO(ENVELOPE.md §4.3, §7.1 steps 10–12): implement.
func (s *Signer) Sign(seal *Seal, canonicalBytes []byte) error {
	_, _ = seal, canonicalBytes
	return nil
}

// Verifier checks Seal.Signature and Seal.SessionMAC. Routing servers
// verify only Signature; receiving servers verify both.
type Verifier struct {
	Suite crypto.Suite
}

// VerifySignature verifies Seal.Signature against the sender's published
// domain public key. Routing servers MUST call this before forwarding
// (ENVELOPE.md §9.1 step 1).
//
// TODO(ENVELOPE.md §9.1): implement.
func (v *Verifier) VerifySignature(seal *Seal, canonicalBytes, domainPublicKey []byte) error {
	_, _, _ = seal, canonicalBytes, domainPublicKey
	return nil
}

// VerifySessionMAC verifies Seal.SessionMAC using K_env_mac from the
// referenced session. Receiving servers MUST call this before processing
// the brief (ENVELOPE.md §9.1 step 4).
//
// TODO(ENVELOPE.md §9.1): implement.
func (v *Verifier) VerifySessionMAC(seal *Seal, canonicalBytes, envMAC []byte) error {
	_, _, _ = seal, canonicalBytes, envMAC
	return nil
}
