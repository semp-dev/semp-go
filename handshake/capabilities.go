package handshake

import "github.com/semp-dev/semp-go/crypto"

// NegotiateCapabilities returns the agreed session parameters from the
// client's offered capabilities and the server's accepted set, preferring
// the post-quantum hybrid suite when both peers support it (HANDSHAKE.md
// §6.4, SESSION.md §4.3).
//
// The returned Negotiated MUST be honored verbatim by both parties for the
// duration of the session.
//
// TODO(HANDSHAKE.md §6.4): implement preference ordering and downgrade
// protection.
func NegotiateCapabilities(offered, accepted Capabilities) (Negotiated, error) {
	_, _ = offered, accepted
	return Negotiated{}, nil
}

// DefaultClientCapabilities returns a Capabilities value that advertises
// the algorithms a baseline conformant client supports (ENVELOPE.md §7.3.2).
func DefaultClientCapabilities() Capabilities {
	return Capabilities{
		EncryptionAlgorithms: []string{
			string(crypto.SuiteIDPQKyber768X25519),
			string(crypto.SuiteIDX25519ChaCha20Poly1305),
		},
		Compression: []string{"none"},
		Features:    []string{},
	}
}
