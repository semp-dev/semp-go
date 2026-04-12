package envelope

import (
	"semp.dev/semp-go/internal/canonical"
	"semp.dev/semp-go/seal"
)

// MessageType is the wire-level type discriminator for an envelope. Per
// ENVELOPE.md §2.2, the value is always "SEMP_ENVELOPE".
const MessageType = "SEMP_ENVELOPE"

// Envelope is the top-level wire format of a SEMP envelope (ENVELOPE.md §2.1).
//
// The Brief and Enclosure fields are opaque base64-encoded encrypted blobs
// at the transport layer. Their internal structure is meaningful only after
// decryption with K_brief and K_enclosure respectively (see brief and
// enclosure packages for the decrypted forms).
type Envelope struct {
	// Type is the message type discriminator. Always MessageType.
	Type string `json:"type"`

	// Version is the SEMP protocol version (semver), e.g. "1.0.0".
	Version string `json:"version"`

	// Postmark is the outer public routing header.
	Postmark Postmark `json:"postmark"`

	// Seal is the cryptographic integrity proof and per-recipient key wraps.
	Seal seal.Seal `json:"seal"`

	// Brief is the base64-encoded encrypted brief payload.
	Brief string `json:"brief"`

	// Enclosure is the base64-encoded encrypted enclosure payload.
	Enclosure string `json:"enclosure"`
}

// New constructs an empty Envelope with Type and Version set to their
// defaults.
func New() *Envelope {
	return &Envelope{
		Type:    MessageType,
		Version: "1.0.0",
	}
}

// CanonicalBytes returns the canonical JSON serialization of the envelope
// with Seal.Signature and Seal.SessionMAC set to the empty string and
// Postmark.HopCount omitted, ready for signature or MAC computation.
//
// This is the byte sequence over which both seal.signature (Ed25519) and
// seal.session_mac (HMAC-SHA-256) are computed. The two proofs are
// independent — neither covers the other — so the elision applies to both
// the input to signing and the input to MAC computation.
//
// Reference: ENVELOPE.md §4.3.
func (e *Envelope) CanonicalBytes() ([]byte, error) {
	return canonical.MarshalWithElision(e, canonical.EnvelopeElider())
}
