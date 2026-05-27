package envelope

import (
	"time"

	semp "github.com/semp-dev/semp-go"
)

// Rejection is the structured rejection response a server returns when it
// declines an envelope. Per ENVELOPE.md §9.2, every rejection MUST carry a
// reason code, a human-readable description, and the postmark ID of the
// rejected envelope.
type Rejection struct {
	// EnvelopeID is the postmark.id of the rejected envelope.
	EnvelopeID string `json:"envelope_id"`

	// Code is the machine-readable reason code.
	Code semp.ReasonCode `json:"reason_code"`

	// Reason is a human-readable description suitable for logs and UIs.
	Reason string `json:"reason"`

	// Timestamp is when the rejection was generated.
	Timestamp time.Time `json:"timestamp"`
}

// Error implements the error interface so a Rejection may be returned
// directly from envelope processing functions.
func (r *Rejection) Error() string {
	if r == nil {
		return "<nil rejection>"
	}
	return "envelope rejected (" + string(r.Code) + "): " + r.Reason
}

// AsSEMPError converts r into a *semp.Error so that callers can use
// errors.As to extract a uniform error shape across all SEMP layers.
func (r *Rejection) AsSEMPError() *semp.Error {
	if r == nil {
		return nil
	}
	return &semp.Error{Code: r.Code, Message: r.Reason}
}
