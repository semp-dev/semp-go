package enclosure

import "github.com/semp-dev/semp-go/extensions"

// Enclosure is the decrypted form of the envelope.enclosure field. It
// contains the message body in one or more representations, plus any
// attachments (ENVELOPE.md §6.1).
type Enclosure struct {
	// Subject is the (optional) subject line. The subject lives here, not
	// in the brief, because it is semantic content rather than routing
	// metadata. The recipient server cannot read it (DESIGN.md §5.4).
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

	// Extensions are content-layer extensions visible only to the recipient
	// client.
	Extensions extensions.Map `json:"extensions,omitempty"`
}
