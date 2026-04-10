package handshake

import (
	"crypto/sha256"
	"errors"
)

// ConfirmationHash computes SHA-256(canonical(message_1) || canonical(message_2)),
// the value the client embeds in the confirm message to bind the identity
// proof to the specific exchange that preceded it (HANDSHAKE.md §2.5.3).
//
// Both arguments MUST already be in canonical form (lexicographically sorted
// JSON keys, no insignificant whitespace) — this function does not perform
// canonicalization itself. Callers obtain canonical bytes via
// internal/canonical.Marshal applied to a *handshake.ClientInit or
// *handshake.ServerResponse value, or by retaining the canonical bytes that
// were transmitted on the wire.
//
// The returned slice is the raw 32-byte SHA-256 digest. Callers that need
// the value for `confirm.confirmation_hash` typically base64-encode it.
//
// Reference: HANDSHAKE.md §2.5.3, VECTORS.md §5.1.
func ConfirmationHash(message1, message2 []byte) ([]byte, error) {
	if len(message1) == 0 || len(message2) == 0 {
		return nil, errors.New("handshake: empty message bytes for confirmation hash")
	}
	h := sha256.New()
	h.Write(message1)
	h.Write(message2)
	return h.Sum(nil), nil
}
