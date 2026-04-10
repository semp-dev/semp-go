// Package handshake implements the SEMP handshake state machines and
// message types. It covers the four-message client-to-server handshake, the
// four-message server-to-server federation handshake, the optional
// proof-of-work interstitial, capability negotiation, and the confirmation
// hash that binds the identity proof to the prior handshake messages.
//
// Two state machine types are exported:
//
//   - handshake.Client       — drives the client side of a client handshake.
//   - handshake.Server       — drives the server side of a client handshake.
//   - handshake.Initiator    — drives a federation handshake from the side
//                              that opened the connection.
//   - handshake.Responder    — drives the receiving side of a federation
//                              handshake.
//
// Each state machine consumes inbound bytes through OnX methods and emits
// outbound bytes from corresponding methods. The state machine never
// performs network I/O directly; the caller is responsible for moving bytes
// between the state machine and the transport.
//
// Specification references:
//
//   - HANDSHAKE.md       — full handshake protocol.
//   - REPUTATION.md §8.3 — proof-of-work challenge construction and
//                          verification.
//   - SESSION.md §2.1    — session key derivation procedure (consumed here).
package handshake
