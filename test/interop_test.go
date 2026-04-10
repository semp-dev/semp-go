package test

import "testing"

// TestInteropPlaceholder is a stub for the cross-implementation
// interoperability test suite that will exercise semp-go against the
// sibling language implementations in ../semp-rust, ../semp-py, etc.
//
// The skeleton skips it; flipping the t.Skip line will be the entry point
// when the interop harness is built.
func TestInteropPlaceholder(t *testing.T) {
	t.Skip("interop suite is a follow-up milestone")
}
