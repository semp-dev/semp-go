package delivery

import (
	"time"

	semp "github.com/semp-dev/semp-go"
)

// SubmissionType is the wire-level type discriminator for envelope
// submission responses (CLIENT.md §6.1).
const SubmissionType = "SEMP_SUBMISSION"

// SubmissionStep is the discriminator for which submission message variant
// this is. The spec defines two: response (the synchronous outcome) and
// event (the asynchronous follow-up for queued envelopes per §6.5).
type SubmissionStep string

// SubmissionStep values.
const (
	SubmissionStepResponse SubmissionStep = "response"
	SubmissionStepEvent    SubmissionStep = "event"
)

// SubmissionResponse is the structured response a home server returns to
// a client after the client submits an envelope (CLIENT.md §6.1).
type SubmissionResponse struct {
	Type       string             `json:"type"`
	Step       SubmissionStep     `json:"step"`
	Version    string             `json:"version"`
	EnvelopeID string             `json:"envelope_id"`
	Timestamp  time.Time          `json:"timestamp"`
	Results    []SubmissionResult `json:"results"`
}

// SubmissionResult is one entry in SubmissionResponse.Results, describing
// the per-recipient delivery outcome (CLIENT.md §6.2).
type SubmissionResult struct {
	Recipient  string              `json:"recipient"`
	Status     semp.SubmissionStatus `json:"status"`
	ReasonCode semp.ReasonCode     `json:"reason_code,omitempty"`
	Reason     string              `json:"reason,omitempty"`
}

// NewSubmissionResponse builds a fully-populated SubmissionResponse for
// the given envelope_id with the timestamp set to time.Now().UTC().
func NewSubmissionResponse(envelopeID string, results []SubmissionResult) *SubmissionResponse {
	return &SubmissionResponse{
		Type:       SubmissionType,
		Step:       SubmissionStepResponse,
		Version:    semp.ProtocolVersion,
		EnvelopeID: envelopeID,
		Timestamp:  time.Now().UTC(),
		Results:    results,
	}
}

// SubmissionEvent is the asynchronous follow-up notification a server
// MUST send when a previously-queued envelope's outcome resolves
// (CLIENT.md §6.5). The shape is intentionally similar to
// SubmissionResponse but is a single per-recipient event rather than a
// batch.
type SubmissionEvent struct {
	Type       string                `json:"type"`
	Step       SubmissionStep        `json:"step"`
	Version    string                `json:"version"`
	EnvelopeID string                `json:"envelope_id"`
	Recipient  string                `json:"recipient"`
	Status     semp.SubmissionStatus `json:"status"`
	ReasonCode semp.ReasonCode       `json:"reason_code,omitempty"`
	Reason     string                `json:"reason,omitempty"`
	Timestamp  time.Time             `json:"timestamp"`
}
