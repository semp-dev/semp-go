package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

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

// newHMACSHA256 returns a fresh HMAC-SHA-256 keyed with k. Used by the
// baseline and post-quantum suites alike.
func newHMACSHA256(k []byte) MAC {
	return hmacMAC{h: hmac.New(sha256.New, k)}
}

// hmacMAC adapts hash.Hash (returned by hmac.New) to the MAC interface.
type hmacMAC struct {
	h interface {
		Size() int
		Write(p []byte) (int, error)
		Sum(b []byte) []byte
		Reset()
	}
}

func (m hmacMAC) Size() int                { return m.h.Size() }
func (m hmacMAC) Write(p []byte) (int, error) { return m.h.Write(p) }
func (m hmacMAC) Sum(b []byte) []byte       { return m.h.Sum(b) }
func (m hmacMAC) Reset()                    { m.h.Reset() }

// Verify is a constant-time equality check between MAC tags. Implementations
// MUST use constant-time comparison to avoid leaking tag bytes through
// timing side channels (SESSION.md §5.6).
func Verify(expected, actual []byte) bool {
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

// ComputeMAC is a convenience helper that creates a fresh HMAC-SHA-256
// over msg with key k and returns the resulting tag. It is the right
// choice for one-shot computations such as seal.session_mac construction.
func ComputeMAC(k, msg []byte) []byte {
	m := newHMACSHA256(k)
	_, _ = m.Write(msg)
	return m.Sum(nil)
}
