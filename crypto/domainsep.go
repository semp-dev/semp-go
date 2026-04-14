package crypto

// Domain separation prefixes for Ed25519 signatures. Each SEMP context
// that signs with a domain key prepends a unique prefix to the message
// before signing. This prevents cross-context signature confusion where
// a signature valid in one context could be misinterpreted in another.
const (
	// SigCtxHandshake prefixes handshake message signatures.
	SigCtxHandshake = "SEMP-HANDSHAKE:"

	// SigCtxEnvelope prefixes envelope seal signatures.
	SigCtxEnvelope = "SEMP-ENVELOPE:"

	// SigCtxKeys prefixes key response signatures.
	SigCtxKeys = "SEMP-KEYS:"

	// SigCtxDiscovery prefixes discovery response signatures.
	SigCtxDiscovery = "SEMP-DISCOVERY:"

	// SigCtxIdentity prefixes identity proof signatures in the handshake.
	SigCtxIdentity = "SEMP-IDENTITY:"

	// SigCtxRevocation prefixes key revocation signatures.
	SigCtxRevocation = "SEMP-REVOCATION:"
)

// PrefixedMessage prepends a domain-separation context prefix to a message.
func PrefixedMessage(prefix string, message []byte) []byte {
	out := make([]byte, len(prefix)+len(message))
	copy(out, prefix)
	copy(out[len(prefix):], message)
	return out
}
