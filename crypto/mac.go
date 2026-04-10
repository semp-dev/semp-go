package crypto

// MAC is a keyed message authentication primitive. Both currently defined
// SEMP suites use HMAC-SHA-256 for handshake message MACs and for
// seal.session_mac (ENVELOPE.md §7.3.1).
//
// MAC is stateful: callers Write all input bytes, then call Sum to retrieve
// the tag, then Reset to reuse the same instance.
type MAC interface {
	// Size returns the tag length in bytes (32 for HMAC-SHA-256).
	Size() int

	// Write feeds input bytes into the MAC. Always returns len(p), nil.
	Write(p []byte) (int, error)

	// Sum appends the current tag to b and returns the result. Sum does not
	// reset the MAC; subsequent Writes continue accumulating.
	Sum(b []byte) []byte

	// Reset clears the accumulated state without changing the key.
	Reset()
}

// Verify is a constant-time equality check between MAC tags. Implementations
// MUST use constant-time comparison to avoid leaking tag bytes through
// timing side channels (SESSION.md §5.6).
//
// TODO(SESSION.md §5.6): implement using crypto/subtle.ConstantTimeCompare
// once the crypto primitives land.
func Verify(expected, actual []byte) bool {
	_, _ = expected, actual
	return false
}
