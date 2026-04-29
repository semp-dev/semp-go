package handshake

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// firstContactBindingTag is the domain-separation prefix mixed into
// the first-contact prefix binding hash per HANDSHAKE.md section
// 2.2a.3. The version suffix lets future revisions of the binding
// rule (for example, a switch to a different hash) coexist with this
// one without ambiguity.
const firstContactBindingTag = "SEMP-FIRST-CONTACT-V1:"

// firstContactFieldSep is the NUL octet placed between the three
// input fields (sender_domain, recipient_address, postmark_id) in
// the binding hash. NUL is forbidden in all three field types by
// ENVELOPE.md sections 2.2 and 2.3, so its appearance here is
// unambiguous: no field can contain a NUL that would shift a
// boundary.
const firstContactFieldSep = 0x00

// FirstContactBindingHashSize is the length in bytes of the
// binding-hash portion of a first-contact PoW prefix. 32 bytes for
// SHA-256.
const FirstContactBindingHashSize = sha256.Size

// FirstContactPrefixRandBytes is the size of the random nonce prepended
// to the binding hash inside the prefix, per HANDSHAKE.md section
// 2.2a.3. MUST be at least 16 bytes.
const FirstContactPrefixRandBytes = 16

// ComputeFirstContactPrefix returns the raw bytes of a first-contact
// PoW challenge prefix that binds a solved token to a specific envelope
// per HANDSHAKE.md section 2.2a.3:
//
//   prefix = random_bytes(16) || SHA-256(
//       "SEMP-FIRST-CONTACT-V1:" ||
//       sender_domain || 0x00 ||
//       recipient_address || 0x00 ||
//       postmark_id
//   )
//
// The returned slice is the raw pre-base64 bytes. Callers typically
// base64-encode it for transmission as FirstContactToken.Prefix.
//
// The random nonce prevents different rejections for the same triple
// from producing identical prefixes; the domain-separated, NUL-bounded
// hash binds the prefix to the triple so a token cannot be transplanted
// to a different sender, recipient, or envelope, and so the same
// SHA-256 cannot be reinterpreted in another protocol context.
func ComputeFirstContactPrefix(senderDomain, recipientAddress, postmarkID string) ([]byte, error) {
	if senderDomain == "" || recipientAddress == "" || postmarkID == "" {
		return nil, errors.New("handshake: first-contact prefix requires sender_domain, recipient_address, and postmark_id")
	}
	random := make([]byte, FirstContactPrefixRandBytes)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("handshake: first-contact random: %w", err)
	}
	out := make([]byte, 0, FirstContactPrefixRandBytes+FirstContactBindingHashSize)
	out = append(out, random...)
	out = append(out, firstContactBindingHash(senderDomain, recipientAddress, postmarkID)...)
	return out, nil
}

// VerifyFirstContactBinding checks that a previously-issued prefix binds
// to the given (sender_domain, recipient_address, postmark_id) triple.
// The prefix is expected in raw bytes (the pre-base64 form); callers
// that have a base64 string from FirstContactToken.Prefix should
// base64-decode before calling.
//
// Verification is structural: it recomputes the tail SHA-256 over the
// claimed triple and compares against the last 32 bytes of the prefix.
// The leading random portion is unchecked; its only role is freshness.
//
// VerifyFirstContactBinding does NOT verify the PoW solution itself;
// pair it with VerifySolution for a full check.
func VerifyFirstContactBinding(prefix []byte, senderDomain, recipientAddress, postmarkID string) error {
	if senderDomain == "" || recipientAddress == "" || postmarkID == "" {
		return errors.New("handshake: first-contact verify requires sender_domain, recipient_address, and postmark_id")
	}
	if len(prefix) < FirstContactPrefixRandBytes+FirstContactBindingHashSize {
		return fmt.Errorf("handshake: first-contact prefix too short: %d bytes", len(prefix))
	}
	want := firstContactBindingHash(senderDomain, recipientAddress, postmarkID)
	got := prefix[len(prefix)-FirstContactBindingHashSize:]
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return errors.New("handshake: first-contact prefix binding mismatch")
	}
	return nil
}

// DecodeFirstContactPrefix parses the base64-encoded prefix carried in
// a FirstContactToken and returns its raw bytes.
func DecodeFirstContactPrefix(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("handshake: first-contact prefix base64: %w", err)
	}
	return raw, nil
}

// firstContactBindingHash computes the domain-separated, NUL-bounded
// SHA-256 over the binding triple per HANDSHAKE.md section 2.2a.3:
//
//   H( "SEMP-FIRST-CONTACT-V1:" ||
//      sender_domain || 0x00 ||
//      recipient_address || 0x00 ||
//      postmark_id )
//
// The leading tag isolates this hash from any other SHA-256 use in
// the protocol. The NUL separators prevent boundary-shift collisions
// (e.g., ("alic", "ebob@y", "pid") and ("alice", "bob@y", "pid")
// produce the same concatenation without separators); NUL is forbidden
// in all three input fields by ENVELOPE.md sections 2.2 and 2.3.
func firstContactBindingHash(senderDomain, recipientAddress, postmarkID string) []byte {
	h := sha256.New()
	h.Write([]byte(firstContactBindingTag))
	h.Write([]byte(senderDomain))
	h.Write([]byte{firstContactFieldSep})
	h.Write([]byte(recipientAddress))
	h.Write([]byte{firstContactFieldSep})
	h.Write([]byte(postmarkID))
	return h.Sum(nil)
}
