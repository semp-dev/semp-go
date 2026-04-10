package handshake

// ConfirmationHash computes SHA-256(canonical(message_1) || canonical(message_2)),
// the value the client embeds in the confirm message to bind the identity
// proof to the specific exchange that preceded it (HANDSHAKE.md §2.5.3).
//
// The canonicalization rules are the same as for envelope seal computation:
// lexicographically sorted JSON keys, no insignificant whitespace.
//
// TODO(HANDSHAKE.md §2.5.3, ENVELOPE.md §4.3): implement using
// internal/canonical.Marshal and crypto/sha256.
func ConfirmationHash(message1, message2 []byte) ([]byte, error) {
	_, _ = message1, message2
	return nil, nil
}
