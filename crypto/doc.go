// Package crypto provides the cryptographic primitives used by SEMP. It
// abstracts the negotiated algorithm suite (key encapsulation mechanism,
// authenticated encryption, MAC, key derivation, signing) behind a single
// Suite interface so that callers in handshake, session, seal, and envelope
// can write code that is agnostic to the specific primitives in use.
//
// Two suites are defined by the spec:
//
//   - x25519-chacha20-poly1305 (baseline, MUST support)
//   - pq-kyber768-x25519       (post-quantum hybrid, RECOMMENDED)
//
// Both suites use the same symmetric cipher (ChaCha20-Poly1305), the same
// MAC (HMAC-SHA-256), the same KDF (HKDF-SHA-512), and the same signing
// algorithm (Ed25519). They differ only in their key encapsulation
// mechanism: pure X25519 versus a Kyber768 + X25519 hybrid that
// concatenates both shared secrets before they are fed into HKDF.
//
// Specification references:
//
//   - ENVELOPE.md §7.3   — algorithm suite definitions and requirements.
//   - HANDSHAKE.md §2.4  — shared secret derivation procedure.
//   - SESSION.md §2.1    — five session key labels and their lifetimes.
//   - SESSION.md §4      — post-quantum hybrid construction.
//   - VECTORS.md §2      — deterministic key derivation test vectors.
package crypto
