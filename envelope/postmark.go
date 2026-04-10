package envelope

import (
	"time"

	"github.com/semp-dev/semp-go/extensions"
)

// Postmark is the outer public routing header of an envelope (ENVELOPE.md §3.1).
//
// The postmark MUST contain only what a routing server needs to deliver the
// envelope. It MUST NOT contain sender or recipient addresses in full, must
// not contain a subject, and must not contain a precise per-message
// timestamp that could be used to correlate communication patterns.
type Postmark struct {
	// ID is an opaque routing identifier scoped to this delivery
	// transaction. ULID RECOMMENDED. Used for hop-level deduplication and
	// loop detection only — NOT a persistent global message ID. The
	// persistent identifier lives in brief.MessageID.
	ID string `json:"id"`

	// SessionID is the handshake session this envelope was produced under.
	// An envelope without a SessionID MUST be rejected with reason code
	// `no_session` (ENVELOPE.md §9.1).
	SessionID string `json:"session_id"`

	// FromDomain is the sender's domain only — no local part, no display
	// name. The full sender address lives in the encrypted brief.
	FromDomain string `json:"from_domain"`

	// ToDomain is the recipient's domain only.
	ToDomain string `json:"to_domain"`

	// Expires is the envelope's UTC expiry timestamp. Servers MUST reject
	// envelopes whose Expires is in the past (ENVELOPE.md §9.1, §10.2).
	Expires time.Time `json:"expires"`

	// HopCount is the optional relay hop counter. When present, starts at
	// 0 and is incremented by each relay. Excluded from canonical
	// serialization because it is mutable in transit (ENVELOPE.md §4.3).
	HopCount *int `json:"hop_count,omitempty"`

	// Extensions are postmark-layer extensions visible to all routing
	// servers. MUST NOT contain private metadata (ENVELOPE.md §8).
	Extensions extensions.Map `json:"extensions,omitempty"`
}
