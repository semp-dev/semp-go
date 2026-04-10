// Package transport defines the abstraction over the wire transports that
// SEMP runs on. SEMP is transport-agnostic: the same envelope, the same
// handshake, and the same session semantics work over WebSocket, HTTP/2,
// QUIC, gRPC, or any custom binding that satisfies the seven minimum
// requirements in TRANSPORT.md §2.
//
// This package defines the Transport and Conn interfaces, the synchronous
// and asynchronous profiles, the framing helper for stream-oriented
// transports, and the recommended transport fallback order. The three core
// bindings live in subpackages:
//
//   - transport/ws   — WebSocket binding (RECOMMENDED default).
//   - transport/h2   — HTTP/2 binding.
//   - transport/quic — QUIC / HTTP/3 binding.
//
// Specification reference: TRANSPORT.md.
package transport
