package seal

import (
	"encoding/base64"
	"errors"
	"fmt"

	"semp.dev/semp-go/crypto"
)

// Signer computes the dual integrity proofs that live in Seal.Signature and
// Seal.SessionMAC. Both proofs cover the same canonical envelope bytes per
// ENVELOPE.md §4.3.
//
// Two proofs, two purposes:
//
//   - Signature is the routing-layer proof. It is verifiable by any server
//     using the sender domain's published public key. Routing servers
//     verify it before forwarding (ENVELOPE.md §9.1 step 1).
//
//   - SessionMAC is the delivery-layer proof. It is verifiable only by the
//     receiving server, which holds K_env_mac for the referenced session.
//     It binds the envelope to the specific handshake session under which
//     the sending server sealed it.
//
// Neither proof covers the other: the canonical bytes used as input to
// both have signature and session_mac elided to "" (and hop_count omitted),
// so the order in which Signer fills them in does not matter.
type Signer struct {
	// Suite is the negotiated algorithm suite (signing + MAC primitives).
	Suite crypto.Suite

	// DomainPrivateKey is the sender domain's long-term private key. Used
	// only by the sender's home server when computing Seal.Signature; the
	// client never holds this material (CLIENT.md §1.3).
	DomainPrivateKey []byte

	// EnvMAC is K_env_mac for the active session, used to compute
	// Seal.SessionMAC. Sourced from session.Session.EnvMAC().
	EnvMAC []byte
}

// Sign computes Seal.Signature and Seal.SessionMAC over canonicalBytes and
// stores them in seal.
//
// canonicalBytes MUST be the canonical serialization with both Signature
// and SessionMAC fields set to "" and Postmark.HopCount omitted, per
// ENVELOPE.md §4.3. Use envelope.Envelope.CanonicalBytes() to obtain it.
//
// After Sign returns, the seal struct is ready to be re-encoded into the
// envelope. The actual seal.signature and seal.session_mac field values
// are base64-encoded for the wire.
func (s *Signer) Sign(seal *Seal, canonicalBytes []byte) error {
	if s == nil || s.Suite == nil {
		return errors.New("seal: nil signer or suite")
	}
	if seal == nil {
		return errors.New("seal: nil seal")
	}
	if len(canonicalBytes) == 0 {
		return errors.New("seal: empty canonical bytes")
	}

	// Domain key signature.
	if len(s.DomainPrivateKey) == 0 {
		return errors.New("seal: missing domain private key")
	}
	sig, err := s.Suite.Signer().Sign(s.DomainPrivateKey, canonicalBytes)
	if err != nil {
		return fmt.Errorf("seal: domain key sign: %w", err)
	}
	seal.Signature = base64.StdEncoding.EncodeToString(sig)

	// Session MAC.
	if len(s.EnvMAC) == 0 {
		return errors.New("seal: missing session env MAC key")
	}
	mac := crypto.ComputeMAC(s.EnvMAC, canonicalBytes)
	seal.SessionMAC = base64.StdEncoding.EncodeToString(mac)
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
// canonicalBytes MUST be the canonical serialization produced by
// envelope.Envelope.CanonicalBytes() — i.e. with the signature and
// session MAC fields elided. The verifier does NOT recompute canonical
// bytes from the seal it is verifying; that is the caller's responsibility
// because the canonical bytes depend on the entire envelope, not just the
// seal.
func (v *Verifier) VerifySignature(seal *Seal, canonicalBytes, domainPublicKey []byte) error {
	if v == nil || v.Suite == nil {
		return errors.New("seal: nil verifier or suite")
	}
	if seal == nil {
		return errors.New("seal: nil seal")
	}
	if seal.Signature == "" {
		return errors.New("seal: empty signature field")
	}
	sig, err := base64.StdEncoding.DecodeString(seal.Signature)
	if err != nil {
		return fmt.Errorf("seal: signature base64: %w", err)
	}
	if err := v.Suite.Signer().Verify(domainPublicKey, canonicalBytes, sig); err != nil {
		return fmt.Errorf("seal: domain key verify: %w", err)
	}
	return nil
}

// VerifySessionMAC verifies Seal.SessionMAC using K_env_mac from the
// referenced session. Receiving servers MUST call this before processing
// the brief (ENVELOPE.md §9.1 step 4).
//
// The MAC comparison is constant-time via crypto.Verify.
func (v *Verifier) VerifySessionMAC(seal *Seal, canonicalBytes, envMAC []byte) error {
	if v == nil || v.Suite == nil {
		return errors.New("seal: nil verifier or suite")
	}
	if seal == nil {
		return errors.New("seal: nil seal")
	}
	if seal.SessionMAC == "" {
		return errors.New("seal: empty session_mac field")
	}
	if len(envMAC) == 0 {
		return errors.New("seal: empty envMAC")
	}
	tag, err := base64.StdEncoding.DecodeString(seal.SessionMAC)
	if err != nil {
		return fmt.Errorf("seal: session_mac base64: %w", err)
	}
	expected := crypto.ComputeMAC(envMAC, canonicalBytes)
	if !crypto.Verify(expected, tag) {
		return errors.New("seal: session_mac mismatch")
	}
	return nil
}
