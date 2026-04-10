package crypto

// Zeroize overwrites b with zero bytes. SEMP requires secure erasure of
// session keys (SESSION.md §2.2, §2.4) and ephemeral private keys
// immediately after the shared secret is computed.
//
// The simple loop below is sufficient for the skeleton. A production
// implementation should use a primitive that the Go compiler cannot elide
// as dead code, e.g. runtime/memclrNoHeapPointers via go:linkname or a
// platform-specific secure-zero call where one is available.
//
// TODO(SESSION.md §2.2): adopt a non-elidable secure-zero primitive.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
