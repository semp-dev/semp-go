// Package seal defines the cryptographic seal that wraps every SEMP
// envelope. The seal carries two independent integrity proofs over the same
// canonical envelope bytes:
//
//   - Signature   — produced with the sender's domain key, verifiable by any
//                   routing server using the sender's published domain key.
//                   This is the routing-layer integrity proof.
//
//   - SessionMAC  — produced with K_env_mac derived during the handshake,
//                   verifiable only by the receiving server. This is the
//                   delivery-layer session enforcement proof.
//
// Together they make the envelope and the handshake session
// cryptographically inseparable at delivery: a forged envelope that passes
// domain key verification but was not produced within a valid session will
// fail the session MAC check.
//
// The seal also carries the per-recipient wrapped symmetric keys K_brief
// (wrapped under both the recipient server's domain key and the recipient
// client's encryption key) and K_enclosure (wrapped under the recipient
// client's encryption key only).
//
// Specification reference: ENVELOPE.md §4.
package seal
