// Package test holds integration and interoperability tests for semp-go.
//
// The skeleton contains two placeholder test files:
//
//   - vectors_test.go preloads the deterministic test vectors from
//     VECTORS.md §2 (HKDF-SHA-512 session key derivation) so that flipping
//     each vector from t.Skip to a real assertion will be a one-line
//     change once the crypto package implements DeriveSessionKeys.
//
//   - interop_test.go is a placeholder for cross-implementation
//     interoperability tests against the sibling language implementations
//     (semp-rust, semp-py, etc.).
//
// Both files compile and run; all assertions are gated behind t.Skip until
// the underlying packages are implemented.
package test
