package delivery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// StageDeliverFunc delivers an envelope to one stage's pending
// device set per DELIVERY.md §3.2.2. The runner invokes it once per
// stage transition, when the stage first becomes the current stage
// (Hold for stage 0; advance for stages 1..N).
//
// The function MUST NOT block on disposition collection; the
// runner's IngestDisposition + Tick are responsible for that.
type StageDeliverFunc func(ctx context.Context, envelopeID string, stage int, deviceIDs []string) error

// StageSuppressFunc is invoked once per envelope when the
// aggregation outcome at any stage is StageOutcomeSuppress. Per
// §3.2.3 the held envelope is dropped without further delivery.
// Implementations typically remove the envelope from any backing
// store and emit operator-visible telemetry.
type StageSuppressFunc func(ctx context.Context, envelopeID string, stage int) error

// StageCompleteFunc is invoked once per envelope when every stage
// has been delivered (the staged-delivery flow is complete with no
// suppress at any stage). It is the operator's hook to remove the
// in-flight bookkeeping for the envelope and surface "delivered"
// status to the sending side.
type StageCompleteFunc func(ctx context.Context, envelopeID string) error

// StagedRunner is the home-server runtime that drives the §3.2
// staged-delivery wait-and-aggregate loop. Hold registers a held
// envelope with its stage partition (output of §3.2.1) and
// immediately delivers to the lowest stage. IngestDisposition
// records a stage-N device's decision per §3.2.5. Tick advances
// envelopes whose current stage has completed (all pending devices
// emitted, or stage timeout elapsed per §3.2.4).
//
// StagedRunner is concurrency-safe; multiple goroutines may call
// Hold / IngestDisposition / Tick concurrently.
type StagedRunner struct {
	mu      sync.Mutex
	held    map[string]*StagedHeld
	timeout time.Duration

	deliver  StageDeliverFunc
	suppress StageSuppressFunc
	complete StageCompleteFunc

	nowFn func() time.Time
}

// StagedRunnerConfig bundles the runner's required and optional
// inputs.
type StagedRunnerConfig struct {
	// Deliver runs one stage's delivery to its pending device set.
	// Required.
	Deliver StageDeliverFunc

	// Suppress is invoked when a stage outcome is suppress. Required;
	// the operator MUST tear down the held envelope's backing
	// state on suppress.
	Suppress StageSuppressFunc

	// Complete is invoked when every stage has advanced without
	// suppress. Required; the operator finalizes the staged-delivery
	// flow here.
	Complete StageCompleteFunc

	// StageTimeout is the per-stage wait window per §3.2.2. Zero
	// falls back to DefaultStageTimeout (30s); operators MAY
	// configure longer windows for filters with known high
	// latency.
	StageTimeout time.Duration

	// NowFn supplies the wall-clock time. Defaults to
	// time.Now().UTC.
	NowFn func() time.Time
}

// NewStagedRunner returns a runner over cfg.
func NewStagedRunner(cfg StagedRunnerConfig) (*StagedRunner, error) {
	if cfg.Deliver == nil {
		return nil, errors.New("delivery: staged runner requires Deliver")
	}
	if cfg.Suppress == nil {
		return nil, errors.New("delivery: staged runner requires Suppress")
	}
	if cfg.Complete == nil {
		return nil, errors.New("delivery: staged runner requires Complete")
	}
	timeout := cfg.StageTimeout
	if timeout <= 0 {
		timeout = DefaultStageTimeout
	}
	now := cfg.NowFn
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &StagedRunner{
		held:     make(map[string]*StagedHeld),
		timeout:  timeout,
		deliver:  cfg.Deliver,
		suppress: cfg.Suppress,
		complete: cfg.Complete,
		nowFn:    now,
	}, nil
}

// Hold registers envelopeID with its stage partition and delivers
// to the lowest stage. stages[i].Stage MUST be monotonically
// increasing. Hold rejects an empty stage partition (no devices
// in any stage means staged delivery is a no-op; the caller
// SHOULD have skipped the runner entirely).
//
// Per §3.2.2 stages with no PendingDeviceIDs are pruned before the
// first delivery; if every stage is empty, Hold returns an error.
//
// Hold is idempotent on a duplicate envelopeID: it returns
// ErrEnvelopeAlreadyHeld so the caller can decide whether to log
// or skip.
func (r *StagedRunner) Hold(ctx context.Context, envelopeID string, stages []StagedHeldStage) error {
	if envelopeID == "" {
		return errors.New("delivery: hold empty envelope_id")
	}
	cleaned := make([]StagedHeldStage, 0, len(stages))
	for _, st := range stages {
		if len(st.PendingDeviceIDs) == 0 {
			continue
		}
		// Defensive copy of the device-id slice so caller mutations
		// after Hold do not race.
		devs := make([]string, len(st.PendingDeviceIDs))
		copy(devs, st.PendingDeviceIDs)
		cleaned = append(cleaned, StagedHeldStage{
			Stage:            st.Stage,
			PendingDeviceIDs: devs,
		})
	}
	if len(cleaned) == 0 {
		return errors.New("delivery: hold partition has no pending devices at any stage")
	}
	// Verify monotonic stage order.
	for i := 1; i < len(cleaned); i++ {
		if cleaned[i].Stage <= cleaned[i-1].Stage {
			return fmt.Errorf("delivery: hold stages not monotonically increasing: stage[%d]=%d <= stage[%d]=%d",
				i, cleaned[i].Stage, i-1, cleaned[i-1].Stage)
		}
	}

	r.mu.Lock()
	if _, exists := r.held[envelopeID]; exists {
		r.mu.Unlock()
		return ErrEnvelopeAlreadyHeld
	}
	now := r.nowFn()
	rec := &StagedHeld{
		EnvelopeID: envelopeID,
		Stages:     cleaned,
		Deadline:   now.Add(r.timeout),
	}
	r.held[envelopeID] = rec
	r.mu.Unlock()

	// Deliver outside the lock so a slow Deliver does not block
	// concurrent IngestDisposition / Tick calls.
	if err := r.deliver(ctx, envelopeID, cleaned[0].Stage, cleaned[0].PendingDeviceIDs); err != nil {
		// Best-effort cleanup: drop the hold record on Deliver
		// failure so the operator's retry path can re-Hold.
		r.mu.Lock()
		delete(r.held, envelopeID)
		r.mu.Unlock()
		return fmt.Errorf("delivery: stage %d deliver: %w", cleaned[0].Stage, err)
	}
	return nil
}

// ErrEnvelopeAlreadyHeld is returned by Hold when an envelope_id is
// already registered.
var ErrEnvelopeAlreadyHeld = errors.New("delivery: envelope is already held")

// IngestDisposition records d for envelopeID's current stage per
// §3.2.5. The submitterDeviceID is the device_id bound to the
// session that delivered the disposition; per §3.2.5 it MUST equal
// d.DeviceID. The runner rejects:
//
//   - Dispositions for unknown envelopes.
//   - Dispositions whose claimed device_id does not match the
//     session-bound submitter (the §3.2.5 authentication rule).
//   - Dispositions from a device not in the current stage's
//     pending set. Per §3.2.5 dispositions from later-stage devices
//     are off the decision path and MUST be discarded; same-or-
//     earlier-stage dispositions from devices not in the current
//     stage are discarded as out-of-band.
//   - Dispositions for an envelope that has already advanced past
//     this device's stage (late arrival).
//
// IngestDisposition does not itself trigger advancement; Tick
// observes the updated dispositions and advances when the stage
// becomes complete per IsStageComplete.
func (r *StagedRunner) IngestDisposition(_ context.Context, envelopeID, submitterDeviceID string, d Disposition) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if submitterDeviceID == "" {
		return errors.New("delivery: ingest: submitter device_id is required for §3.2.5 authentication")
	}
	if submitterDeviceID != d.DeviceID {
		return fmt.Errorf("delivery: ingest: submitter %q does not match disposition device_id %q (§3.2.5)",
			submitterDeviceID, d.DeviceID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.held[envelopeID]
	if !ok {
		return fmt.Errorf("delivery: ingest: no held envelope for %q", envelopeID)
	}
	if len(rec.Stages) == 0 {
		return fmt.Errorf("delivery: ingest: envelope %q has no remaining stages", envelopeID)
	}
	current := &rec.Stages[0]
	inStage := false
	for _, did := range current.PendingDeviceIDs {
		if did == d.DeviceID {
			inStage = true
			break
		}
	}
	if !inStage {
		return fmt.Errorf("delivery: ingest: device %q is not in current stage %d's pending set (§3.2.5)",
			d.DeviceID, current.Stage)
	}
	// Idempotent on a repeat from the same device: keep the FIRST
	// disposition the device sent. §3.2.5 does not address repeat
	// submissions explicitly; conservative aggregation favors the
	// earlier vote so a device cannot retroactively flip suppress to
	// advance.
	for _, prior := range current.Dispositions {
		if prior.DeviceID == d.DeviceID {
			return nil
		}
	}
	current.Dispositions = append(current.Dispositions, d)
	return nil
}

// Tick advances every held envelope whose current stage is
// complete per IsStageComplete. For each:
//
//   - If the stage outcome is StageOutcomeSuppress, invoke Suppress
//     and remove the envelope from the held queue.
//   - Otherwise invoke Deliver for the next stage and replace the
//     stage list with the tail. If no more stages remain, invoke
//     Complete and remove.
//
// Tick returns the number of envelopes advanced and the first
// non-fatal callback error encountered. Per-envelope errors do not
// abort the tick.
func (r *StagedRunner) Tick(ctx context.Context) (int, error) {
	now := r.nowFn()
	type pending struct {
		envelopeID string
		outcome    DispositionStageOutcome
		stage      int
		nextStage  int
		nextDevs   []string
		done       bool
	}
	var toRun []pending

	r.mu.Lock()
	for id, rec := range r.held {
		if len(rec.Stages) == 0 {
			continue
		}
		current := &rec.Stages[0]
		if !current.IsStageComplete(now, rec.Deadline) {
			continue
		}
		outcome := AggregateDispositions(current.Dispositions)
		if outcome == StageOutcomeSuppress {
			toRun = append(toRun, pending{envelopeID: id, outcome: outcome, stage: current.Stage})
			delete(r.held, id)
			continue
		}
		// Advance: pop the current stage, deliver to the next if any.
		rec.Stages = rec.Stages[1:]
		if len(rec.Stages) == 0 {
			toRun = append(toRun, pending{envelopeID: id, outcome: outcome, stage: current.Stage, done: true})
			delete(r.held, id)
			continue
		}
		next := &rec.Stages[0]
		nextDevs := make([]string, len(next.PendingDeviceIDs))
		copy(nextDevs, next.PendingDeviceIDs)
		rec.Deadline = now.Add(r.timeout)
		toRun = append(toRun, pending{
			envelopeID: id, outcome: outcome,
			stage: current.Stage, nextStage: next.Stage, nextDevs: nextDevs,
		})
	}
	r.mu.Unlock()

	// Sort so the order of callback invocations is deterministic
	// across runs; useful for tests. Production order across many
	// envelopes is not load-bearing.
	sort.Slice(toRun, func(i, j int) bool { return toRun[i].envelopeID < toRun[j].envelopeID })

	var firstErr error
	for _, p := range toRun {
		if p.outcome == StageOutcomeSuppress {
			if err := r.suppress(ctx, p.envelopeID, p.stage); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("delivery: suppress(%s): %w", p.envelopeID, err)
			}
			continue
		}
		if p.done {
			if err := r.complete(ctx, p.envelopeID); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("delivery: complete(%s): %w", p.envelopeID, err)
			}
			continue
		}
		if err := r.deliver(ctx, p.envelopeID, p.nextStage, p.nextDevs); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("delivery: deliver stage %d (%s): %w", p.nextStage, p.envelopeID, err)
		}
	}
	return len(toRun), firstErr
}

// HeldCount returns the number of envelopes currently held.
// Useful for operator monitoring and for tests.
func (r *StagedRunner) HeldCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.held)
}

// Snapshot returns a deep copy of the currently-held envelopes
// keyed by envelope_id. Callers can mutate the returned map without
// affecting the runner.
func (r *StagedRunner) Snapshot() map[string]*StagedHeld {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]*StagedHeld, len(r.held))
	for id, rec := range r.held {
		stages := make([]StagedHeldStage, len(rec.Stages))
		for i, s := range rec.Stages {
			devs := make([]string, len(s.PendingDeviceIDs))
			copy(devs, s.PendingDeviceIDs)
			disps := make([]Disposition, len(s.Dispositions))
			copy(disps, s.Dispositions)
			stages[i] = StagedHeldStage{
				Stage:            s.Stage,
				PendingDeviceIDs: devs,
				Dispositions:     disps,
			}
		}
		out[id] = &StagedHeld{
			EnvelopeID: rec.EnvelopeID,
			Stages:     stages,
			Deadline:   rec.Deadline,
		}
	}
	return out
}
