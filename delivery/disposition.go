package delivery

import (
	"errors"
	"fmt"
	"time"
)

// Disposition data per DELIVERY.md §3.2 + CLIENT.md §4.5.7. The
// `delivery-disposition` sync kind is the control signal a staged
// device emits to tell the home server whether a held envelope
// should advance to the next stage or be suppressed.

// DispositionKind is the literal "kind" string that identifies a
// delivery-disposition sync marker.
const DispositionKind = "delivery-disposition"

// DispositionDecision is the disposition value per CLIENT.md §4.5.7.
type DispositionDecision string

// Disposition decisions.
const (
	// DispositionAdvance: envelope advances to the next stage.
	DispositionAdvance DispositionDecision = "advance"

	// DispositionSuppress: envelope is dropped without further
	// delivery. Conservative aggregation lets any suppress at any
	// stage win over advance from any stage-mate.
	DispositionSuppress DispositionDecision = "suppress"
)

// Recommended reason tags per CLIENT.md §4.5.7. Operators MAY define
// additional tags, but these names are reserved.
const (
	DispositionReasonSpam     = "spam"
	DispositionReasonAccepted = "accepted"
	DispositionReasonPolicy   = "policy"
	DispositionReasonOther    = "other"
)

// Disposition is the payload of a delivery-disposition sync marker.
// It carries the inner `data` object of the
// `semp.dev/device-sync` extension when that extension's kind is
// "delivery-disposition".
type Disposition struct {
	Kind             string              `json:"kind"`
	SourceEnvelopeID string              `json:"source_envelope_id"`
	Decision         DispositionDecision `json:"disposition"`
	Reason           string              `json:"reason,omitempty"`
	DeviceID         string              `json:"device_id"`
}

// Validate reports whether d is structurally well-formed per
// CLIENT.md §4.5.7. Does not verify authentication; the home server
// verifies §3.2.5 (session belongs to device_id) at receipt.
func (d *Disposition) Validate() error {
	if d == nil {
		return errors.New("delivery: nil disposition")
	}
	if d.Kind != DispositionKind {
		return fmt.Errorf("delivery: disposition kind %q, want %q", d.Kind, DispositionKind)
	}
	if d.SourceEnvelopeID == "" {
		return errors.New("delivery: disposition missing source_envelope_id")
	}
	if d.DeviceID == "" {
		return errors.New("delivery: disposition missing device_id")
	}
	switch d.Decision {
	case DispositionAdvance, DispositionSuppress:
		// ok
	case "":
		return errors.New("delivery: disposition missing decision")
	default:
		return fmt.Errorf("delivery: disposition decision %q is not a valid value", d.Decision)
	}
	return nil
}

// DispositionStageOutcome names the result of aggregating
// dispositions at a single staged-delivery stage per DELIVERY.md
// §3.2.3.
type DispositionStageOutcome string

// Stage outcomes.
const (
	// StageOutcomeAdvance: the envelope advances to the next stage.
	StageOutcomeAdvance DispositionStageOutcome = "advance"

	// StageOutcomeSuppress: any device at this stage emitted suppress;
	// the held envelope is dropped without further delivery.
	StageOutcomeSuppress DispositionStageOutcome = "suppress"
)

// AggregateDispositions applies the §3.2.3 conservative aggregation
// rule across the dispositions collected at one stage:
//
//   - If any disposition is suppress, return StageOutcomeSuppress.
//   - Otherwise return StageOutcomeAdvance (covers "any advance" and
//     "no dispositions at all" via §3.2.4 fail-open on timeout).
//
// AggregateDispositions does NOT itself enforce the §3.2.5
// authentication rules; the caller filters out late or off-stage
// dispositions before aggregating.
func AggregateDispositions(dispositions []Disposition) DispositionStageOutcome {
	for _, d := range dispositions {
		if d.Decision == DispositionSuppress {
			return StageOutcomeSuppress
		}
	}
	return StageOutcomeAdvance
}

// DefaultStageTimeout is the RECOMMENDED stage timeout per
// DELIVERY.md §3.2.2. Operators MAY configure longer windows.
const DefaultStageTimeout = 30 * time.Second

// StagedHeld represents one envelope held in the staged-delivery
// queue per DELIVERY.md §3.2.2. The envelope itself is not stored
// twice; this record is the per-stage pointer set the server
// maintains.
type StagedHeld struct {
	// EnvelopeID is the postmark.id of the held envelope.
	EnvelopeID string

	// Stages is the ordered list of stages still to deliver. Stages[0]
	// is the current pending stage; lower stages have already
	// delivered or been bypassed.
	Stages []StagedHeldStage

	// Deadline is the wall-clock time at which the current stage
	// times out (set by the home server when entering a stage).
	Deadline time.Time
}

// StagedHeldStage is one stage's pending-device set inside a
// StagedHeld record.
type StagedHeldStage struct {
	// Stage is the stage index (1-based, lower delivers first).
	Stage int

	// PendingDeviceIDs are the devices at this stage that the held
	// envelope was wrapped for and that have not yet emitted a
	// disposition.
	PendingDeviceIDs []string

	// Dispositions is the set of dispositions collected so far at
	// this stage. AggregateDispositions runs over this slice when
	// the wait terminates per §3.2.2.
	Dispositions []Disposition
}

// IsStageComplete reports whether the wait at the current stage
// MUST terminate per §3.2.2: either every device at the stage has
// emitted a disposition, or the deadline has passed.
//
// IsStageComplete does not return the outcome; the caller follows
// up with AggregateDispositions(s.Dispositions) to compute that.
func (s *StagedHeldStage) IsStageComplete(now time.Time, deadline time.Time) bool {
	if s == nil {
		return true
	}
	if len(s.PendingDeviceIDs) == 0 {
		return true
	}
	if !deadline.IsZero() && !now.Before(deadline) {
		return true
	}
	// All pending devices have emitted? Build a set of devices
	// already represented in Dispositions and check.
	seen := make(map[string]struct{}, len(s.Dispositions))
	for _, d := range s.Dispositions {
		seen[d.DeviceID] = struct{}{}
	}
	for _, id := range s.PendingDeviceIDs {
		if _, ok := seen[id]; !ok {
			return false
		}
	}
	return true
}
