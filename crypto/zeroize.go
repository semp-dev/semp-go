package crypto

import "runtime"

// Zeroize overwrites b with zero bytes. SEMP requires secure erasure of
// session keys (SESSION.md §2.2, §2.4) and ephemeral private keys
// immediately after the shared secret is computed.
//
// The implementation uses an explicit byte-by-byte loop and a
// runtime.KeepAlive at the end so that the Go compiler does not eliminate
// the writes as dead stores. This is the standard non-elidable secure-zero
// pattern for pure Go; it does not require unsafe or assembly.
//
// Reference: SESSION.md §2.2.
func Zeroize(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	// Defeat dead-store elimination: the compiler must assume the contents
	// of b are still live after the loop, so the writes cannot be removed.
	runtime.KeepAlive(&b[0])
}
