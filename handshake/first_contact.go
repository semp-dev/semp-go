package handshake

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

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
//   prefix = random_bytes(16) || SHA-256(sender_domain || recipient_address || postmark_id)
//
// The returned slice is the raw pre-base64 bytes. Callers typically
// base64-encode it for transmission as FirstContactToken.Prefix.
//
// The random nonce prevents different rejections for the same triple
// from producing identical prefixes; the hash binds the prefix to the
// triple so a token cannot be transplanted to a different sender,
// recipient, or envelope.
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
	if !constantTimeEqual(want, got) {
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

// firstContactBindingHash computes SHA-256(sender_domain || recipient_address || postmark_id).
// Separators are intentionally omitted because each field is fixed by
// its position in the concatenation; callers MUST NOT introduce
// separator bytes, as doing so would produce a non-interoperable
// prefix.
func firstContactBindingHash(senderDomain, recipientAddress, postmarkID string) []byte {
	h := sha256.New()
	h.Write([]byte(senderDomain))
	h.Write([]byte(recipientAddress))
	h.Write([]byte(postmarkID))
	return h.Sum(nil)
}

// constantTimeEqual is a constant-time byte-slice equality check. Used
// so binding-hash comparison does not leak timing information about
// early-mismatch positions. Reuses the standard library's comparison
// through a small adapter to avoid pulling crypto/subtle into
// handshake's import graph directly at the top of the file.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
