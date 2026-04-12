package brief

import (
	"time"

	"semp.dev/semp-go/extensions"
)

// Brief is the decrypted form of the envelope.brief field. It is encrypted
// in transit under K_brief; this struct represents the JSON payload after
// decryption (ENVELOPE.md §5.1).
type Brief struct {
	// MessageID is the globally unique message identifier. Used for
	// threading and recipient-side deduplication. Distinct from
	// Postmark.ID, which is a per-transaction routing identifier.
	MessageID string `json:"message_id"`

	// From is the full sender address.
	From Address `json:"from"`

	// To is the list of primary recipient addresses.
	To []Address `json:"to"`

	// CC is the optional list of carbon copy recipient addresses.
	CC []Address `json:"cc,omitempty"`

	// BCC contains, for an envelope copy delivered to a specific BCC
	// recipient, only that recipient's address. The field MUST be absent
	// from envelope copies delivered to To and CC recipients
	// (CLIENT.md §3.5, ENVELOPE.md §5.3).
	BCC []Address `json:"bcc,omitempty"`

	// ReplyTo redirects replies to a different address than From.
	ReplyTo *Address `json:"reply_to,omitempty"`

	// SentAt is the wall-clock time of message creation at the sender, in
	// UTC. The receiving server MAY compare it against Postmark.Expires.
	SentAt time.Time `json:"sent_at"`

	// ThreadID groups related messages into a conversation. Stable for the
	// life of the thread; MUST NOT change when recipients are added.
	ThreadID string `json:"thread_id,omitempty"`

	// GroupID identifies a group or mailing list. Used by sending clients
	// to expand membership before generating per-recipient envelopes.
	GroupID string `json:"group_id,omitempty"`

	// InReplyTo is the MessageID of the message being replied to.
	InReplyTo string `json:"in_reply_to,omitempty"`

	// Extensions are private metadata extensions visible only to the
	// recipient server and recipient client.
	Extensions extensions.Map `json:"extensions,omitempty"`
}
