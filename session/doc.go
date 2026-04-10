// Package session implements SEMP session lifecycle management: session
// state, key derivation handoff from the handshake, TTL bookkeeping,
// proactive rekeying via SEMP_REKEY, the expiry log used for replay
// prevention, and the concurrent-session bounds enforced by servers.
//
// Sessions provide forward secrecy. The ephemeral private keys exchanged in
// the handshake are erased immediately after the shared secret is computed,
// so a future compromise of any long-term key cannot retroactively decrypt
// past sessions.
//
// Specification reference: SESSION.md.
package session
