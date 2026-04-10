// Package quic implements the SEMP QUIC transport binding. The binding
// follows the same endpoint structure and message encoding as the HTTP/2
// binding (transport/h2), carried over HTTP/3 instead.
//
// QUIC offers concrete advantages over HTTP/2 for SEMP:
//
//   - No head-of-line blocking. Multiple concurrent envelope deliveries
//     proceed independently even when individual packets are lost.
//   - Connection migration. A QUIC connection survives network changes
//     (e.g. Wi-Fi → cellular) without re-handshaking at the transport level.
//   - 0-RTT and 1-RTT connection setup, reducing time to first SEMP message.
//   - TLS 1.3 is integral to QUIC; the confidentiality requirement is
//     satisfied by definition.
//
// Some network middleboxes block UDP. Implementations MUST fall back to
// HTTP/2 or WebSocket via transport.Fallback when QUIC is unreachable.
//
// Specification reference: TRANSPORT.md §4.3.
package quic
