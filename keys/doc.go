// Package keys defines SEMP key types, key records, fingerprints, revocation
// records, scoped device certificates, and the KeyStore interface used by
// servers and clients to look up and persist key material.
//
// SEMP defines five key types (KEY.md §1):
//
//   - domain     — server identity, signs envelopes and handshake messages
//   - identity   — long-term user identity, signs handshake identity proofs
//   - encryption — wraps the per-envelope symmetric keys (K_brief, K_enclosure)
//   - device     — device-specific key for cross-device authorization
//   - session    — ephemeral, never persisted, lives in package session
//
// This package covers the four persistent key types. Session keys live in
// package session because their lifecycle is bound to the handshake.
//
// Specification reference: KEY.md.
package keys
