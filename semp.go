package semp

// ProtocolVersion is the SEMP protocol version implemented by this module.
// It MUST appear verbatim in the `version` field of every wire message that
// carries one (handshake, envelope, discovery, key request, etc.).
//
// Reference: every spec document declares "Version: 0.2.0-draft" in its
// header as of the current catch-up baseline. The wire ProtocolVersion
// tracks the semver on handshake and envelope messages and is distinct
// from the spec document revision.
const ProtocolVersion = "1.0.0"

// SubprotocolWebSocket is the WebSocket subprotocol identifier sent in the
// HTTP Upgrade `Sec-WebSocket-Protocol` header during a SEMP WebSocket
// handshake.
//
// Reference: TRANSPORT.md §4.1.1.
const SubprotocolWebSocket = "semp.v1"

// MIMEEnvelope is the IANA media type for serialized SEMP envelopes, used as
// the `Content-Type` for envelope payloads on every HTTP-based transport and
// as the file association for `.semp` files at rest.
//
// Reference: MIME.md §1.1.
const MIMEEnvelope = "application/semp-envelope"

// FileExtensionEnvelope is the file extension for SEMP envelope files at rest.
//
// Reference: MIME.md §2.1.
const FileExtensionEnvelope = ".semp"
