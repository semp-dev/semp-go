package test

import "encoding/hex"

// mustHex decodes a hex string or panics. Used by tests that hand-pin
// byte values from the spec.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("test hex decode failed: " + err.Error())
	}
	return b
}

// bytesEqual is a constant-time-irrelevant byte comparison helper for
// tests. Tests use this to compare derived byte sequences (session keys,
// MACs, signatures) without pulling in bytes.Equal at every call site.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
