package enclosure

import (
	"time"

	"semp.dev/semp-go/extensions"
)

// Enclosure is the decrypted form of the envelope.enclosure field. It
// contains the message body in one or more representations, plus any
// attachments (ENVELOPE.md section 6.1).
type Enclosure struct {
	// Subject is the (optional) subject line. The subject lives here, not
	// in the brief, because it is semantic content rather than routing
	// metadata. The recipient server cannot read it.
	Subject string `json:"subject,omitempty"`

	// ContentType is the MIME type of the body. Use "multipart/alternative"
	// when Body contains multiple representations of the same content.
	ContentType string `json:"content_type"`

	// Body is the map of MIME type to (already encrypted) body bytes. When
	// ContentType is a single MIME type, Body MUST contain exactly one key
	// matching that type.
	Body Body `json:"body"`

	// Attachments is the optional list of attached files.
	Attachments []Attachment `json:"attachments,omitempty"`

	// ForwardedFrom is the forwarding-evidence block present when the
	// envelope is a forward of a previously received envelope. nil on
	// fresh envelopes. See ENVELOPE.md section 6.6.
	ForwardedFrom *ForwardedFrom `json:"forwarded_from,omitempty"`

	// Extensions are content-layer extensions visible only to the recipient
	// client.
	Extensions extensions.Map `json:"extensions,omitempty"`

	// SenderSignature is the sender-identity signature over the canonical
	// enclosure bytes, computed per ENVELOPE.md section 6.5. Required on
	// every enclosure by the spec; modeled as a pointer here to keep
	// non-signing callers compiling during catch-up. Integrations that
	// follow the spec strictly MUST populate this field via SignEnclosure
	// before encryption.
	SenderSignature *Signature `json:"sender_signature,omitempty"`
}

// Signature is a reusable signature block used by sender_signature,
// forwarder_attestation, and any future enclosure-layer signature
// (ENVELOPE.md section 6.5.2).
type Signature struct {
	// Algorithm is the signature algorithm. For the baseline and PQ
	// suites this is "ed25519".
	Algorithm string `json:"algorithm"`

	// KeyID is the fingerprint of the public key used to produce Value.
	KeyID string `json:"key_id"`

	// Value is the base64-encoded signature.
	Value string `json:"value"`
}

// ForwardedFrom carries the original envelope's enclosure plaintext and
// the forwarder's attestation when the new envelope is a forward
// (ENVELOPE.md section 6.6).
type ForwardedFrom struct {
	// OriginalEnclosurePlaintext is the full decrypted enclosure of the
	// original envelope, preserved verbatim including its own
	// sender_signature. A forwarder MUST NOT modify any field of this
	// subobject; doing so would invalidate the original sender's
	// signature.
	OriginalEnclosurePlaintext *Enclosure `json:"original_enclosure_plaintext"`

	// OriginalSeal is the original envelope's seal, preserved verbatim.
	// Advisory only; not verified by recipients.
	OriginalSeal any `json:"original_seal,omitempty"`

	// OriginalPostmark is the original envelope's postmark, preserved
	// verbatim. Advisory only.
	OriginalPostmark any `json:"original_postmark,omitempty"`

	// OriginalSenderAddress is the sender address from the original
	// envelope's brief.from. Bound by ForwarderAttestation.
	OriginalSenderAddress string `json:"original_sender_address"`

	// ReceivedAt is the time the forwarder received the original
	// envelope. ISO 8601 UTC on the wire.
	ReceivedAt time.Time `json:"received_at"`

	// ForwarderAttestation is the forwarder's identity-key signature
	// over the canonical bytes of this ForwardedFrom block (see
	// SignForwarderAttestation in this package).
	ForwarderAttestation *Signature `json:"forwarder_attestation"`
}
