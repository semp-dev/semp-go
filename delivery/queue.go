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
//
// TerminalAt is an internal-only field used by the scheduler's
// retention pruning to enforce the §2.5 "retain terminal record
// for at least 24 hours after termination" rule. It is excluded
// from JSON serialization so the wire shape matches the §2.5
// example exactly.
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

	// TerminalAt is the wall-clock time at which State transitioned
	// to a terminal value. Internal-only; the Scheduler's
	// PruneTerminal compares (now - TerminalAt) against the operator's
	// retention window. Zero on non-terminal records.
	TerminalAt time.Time `json:"-"`
}

// SetTerminal transitions q to the given terminal state, records
// the transition time, and clears NextAttemptAt. Idempotent: a
// no-op if q is already terminal (the caller is responsible for
// the §2.7.2 "MUST NOT override a prior terminal state" rule).
//
// The now parameter records the wall-clock transition time on
// TerminalAt for retention bookkeeping. Pass time.Now().UTC() in
// production; tests pass an injected clock.
func (q *QueueState) SetTerminal(state QueueRecordState, now time.Time) {
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
	q.TerminalAt = now
}
