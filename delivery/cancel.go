package delivery

import "time"

// CancelStep is the SubmissionStep value for cancel requests and
// responses per DELIVERY.md §2.7.
const (
	SubmissionStepCancel         SubmissionStep = "cancel"
	SubmissionStepCancelResponse SubmissionStep = "cancel_response"
)

// CancelRequest is a SEMP_SUBMISSION message with step="cancel" per
// DELIVERY.md §2.7.1 / CLIENT.md §6.6. The client identifies the
// target envelope by EnvelopeID; an optional Recipient narrows
// cancellation to one queue state record. Empty Recipient means
// whole-envelope cancel (every still-non-terminal record).
type CancelRequest struct {
	Type       string         `json:"type"`
	Step       SubmissionStep `json:"step"`
	Version    string         `json:"version"`
	EnvelopeID string         `json:"envelope_id"`
	Recipient  string         `json:"recipient,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
}

// CancelResponse is the per-record summary returned by the sending
// server in response to a CancelRequest per DELIVERY.md §2.7.2. Each
// CancelResult names the recipient and the resulting terminal
// state. A no-op (record was already terminal) returns the prior
// terminal state without changing it; the caller distinguishes by
// comparing State to the expected QueueStateCanceled.
type CancelResponse struct {
	Type       string         `json:"type"`
	Step       SubmissionStep `json:"step"`
	Version    string         `json:"version"`
	EnvelopeID string         `json:"envelope_id"`
	Timestamp  time.Time      `json:"timestamp"`
	Results    []CancelResult `json:"results"`
}

// CancelResult is one entry in CancelResponse.Results per §2.7.2.
type CancelResult struct {
	Recipient string           `json:"recipient"`
	State     QueueRecordState `json:"state"`
	// Reason is an optional human-readable explanation for unusual
	// outcomes (for example, "already delivered, cancellation no-op
	// per §2.7.4").
	Reason string `json:"reason,omitempty"`
}
