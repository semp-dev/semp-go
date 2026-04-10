// Package brief defines the inner private header of a SEMP envelope. The
// brief contains the routing metadata of a correspondence — full sender and
// recipient addresses, timestamps, threading and reply pointers — that in
// SMTP would be exposed in plaintext.
//
// The brief is encrypted under K_brief, which the seal wraps for both the
// recipient server's domain key and the recipient client's encryption key.
// The recipient server can decrypt the brief to enforce delivery policy
// (block lists, recipient status visibility) but cannot read the enclosure.
//
// The subject is intentionally NOT in the brief: it is semantic content and
// belongs in the enclosure where it is protected from server exposure
// (DESIGN.md §5.4, ENVELOPE.md §3 commentary).
//
// Specification references:
//
//   - ENVELOPE.md §5  — brief schema and fields.
//   - CLIENT.md §3.5  — BCC handling via per-recipient envelope copies.
package brief
