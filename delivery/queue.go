package delivery

import "time"

// QueueRecordState names the lifecycle position of a queue state
// record per DELIVERY.md §2.5.
type QueueRecordState string

// Queue record states.
const (
	QueueStateQueued    QueueRecordState = "queued"
	QueueStateDelivered QueueRecordState = "delivered"
	QueueStateRejected  QueueRecordState = "rejected"
	QueueStateExpired   QueueRecordState = "expired"
	QueueStateCanceled  QueueRecordState = "canceled"
)

// IsTerminal reports whether s is a terminal state (no further
// transitions). Cancellation is one of three terminal states; the
// others are delivered, rejected, and expired. Only QueueStateQueued
// is non-terminal.
func (s QueueRecordState) IsTerminal() bool {
	return s != QueueStateQueued
}

// QueueState is the per-recipient queue state record per
// DELIVERY.md §2.5. The sending server maintains one record per
// (envelope_id, recipient) pair; the record is authoritative for
// what the sending client displays to the user.
type QueueState struct {
	EnvelopeID     string           `json:"envelope_id"`
	Recipient      string           `json:"recipient"`
	State          QueueRecordState `json:"state"`
	Attempts       int              `json:"attempts"`
	LastAttemptAt  *time.Time       `json:"last_attempt_at"`
	LastOutcome    *string          `json:"last_outcome"`
	LastReasonCode *string          `json:"last_reason_code"`
	NextAttemptAt  *time.Time       `json:"next_attempt_at"`
	Deadline       time.Time        `json:"deadline"`
}

// SetTerminal transitions q to the given terminal state and clears
// NextAttemptAt. Idempotent: a no-op if q is already terminal (the
// caller is responsible for the §2.7.2 "MUST NOT override a prior
// terminal state" rule).
func (q *QueueState) SetTerminal(state QueueRecordState) {
	if q == nil {
		return
	}
	if !state.IsTerminal() {
		return
	}
	if q.State.IsTerminal() {
		return
	}
	q.State = state
	q.NextAttemptAt = nil
}
