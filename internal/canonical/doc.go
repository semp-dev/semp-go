// Package canonical produces the canonical byte serialization of SEMP
// objects: lexicographically sorted JSON keys, no insignificant whitespace,
// and configurable field elision. Every signature, MAC, and confirmation
// hash in SEMP is computed over the output of this package, so all
// implementations must reproduce its byte-for-byte output identically.
//
// The package is internal so that downstream callers go through layer-aware
// helpers (envelope.CanonicalBytes, handshake.ConfirmationHash, …) instead
// of touching the JSON layer directly. Keeping the canonicalizer here means
// the rules in ENVELOPE.md §4.3 live in exactly one file.
//
// Specification references:
//
//   - ENVELOPE.md §4.3   — canonical envelope serialization for seal.signature
//                          and seal.session_mac.
//   - HANDSHAKE.md §2.5.3 — confirmation hash over canonical(message_1) ||
//                           canonical(message_2).
//   - DISCOVERY.md §4.6  — signed SEMP_DISCOVERY responses.
//   - VECTORS.md §3      — canonical serialization test vectors.
package canonical
