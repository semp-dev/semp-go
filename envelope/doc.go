// Package envelope defines the top-level SEMP envelope: postmark, seal,
// brief, enclosure. It provides constructors, JSON encode/decode for the
// `application/semp-envelope` MIME type, the canonical-form producer
// consumed by the seal layer for signature and MAC computation, and the
// envelope rejection reason code set used by receiving servers.
//
// This package is the natural top-level entry point for code that needs to
// work with whole envelopes — composing them on the sender side, parsing
// them on the receiver side, exporting them as `.semp` files at rest.
//
// Specification references:
//
//   - ENVELOPE.md  — top-level envelope schema, encryption flow, decryption
//                    flow, server responsibilities, rejection reason codes.
//   - MIME.md      — `application/semp-envelope` media type and `.semp` file
//                    format.
//   - ERRORS.md §3 — envelope reason codes registry.
package envelope
