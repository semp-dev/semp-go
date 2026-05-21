package delivery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	semp "semp.dev/semp-go"
)

// AttemptResult is what a Scheduler's DeliverFunc returns for one
// delivery attempt against (envelope_id, recipient).
//
// Status mirrors the §1 acknowledgment vocabulary: Delivered means
// the recipient server explicitly acknowledged delivery; Rejected
// means it explicitly refused (with ReasonCode populated); Silent
// means no response within the sender's timeout window or any
// transport failure before an ack arrived.
type AttemptResult struct {
	Status     semp.Acknowledgment
	ReasonCode semp.ReasonCode
	Reason     string
}

// DeliverFunc performs a single delivery attempt. The Scheduler
// invokes it with a short-lived context tied to the per-tick budget
// and expects a Status decision back. The function MUST NOT mutate
// the queue state directly; the Scheduler owns state transitions.
//
// A Silent result (transport failure, timeout, anything that did
// not produce an explicit acknowledgment) is non-terminal and the
// Scheduler schedules a retry per §2.3.
type DeliverFunc func(ctx context.Context, envelopeID, recipient string) AttemptResult

// EventSink consumes terminal-state delivery events per §6.5. The
// Scheduler invokes it once per terminal transition (delivered,
// rejected, expired, canceled). Implementations MUST NOT block; a
// blocking sink stalls the tick loop.
type EventSink func(ev *SubmissionEvent)

// Store is the persistence interface for queue records. Production
// deployments plug in a durable backend; tests and demos use
// NewInMemoryStore.
//
// Per §2.1 the sending server MUST persist queued envelopes such
// that a restart does not drop them. The Store is the persistence
// boundary; the Scheduler is stateless across calls.
type Store interface {
	// Put inserts or updates a record by (envelope_id, recipient).
	Put(ctx context.Context, q *QueueState) error

	// Get fetches a record by (envelope_id, recipient). Returns nil
	// for unknown records (the caller distinguishes from a real
	// error via the returned error).
	Get(ctx context.Context, envelopeID, recipient string) (*QueueState, error)

	// DueRecords returns every non-terminal record whose
	// NextAttemptAt is at or before now, in deterministic order
	// (by NextAttemptAt ascending, ties broken by envelope_id).
	// The Scheduler's tick iterates this slice and runs the
	// DeliverFunc for each.
	DueRecords(ctx context.Context, now time.Time) ([]*QueueState, error)

	// ListTerminalOlderThan returns terminal records whose
	// TerminalAt is at or before cutoff. Used by PruneTerminal to
	// evict records past the §2.5 retention window.
	ListTerminalOlderThan(ctx context.Context, cutoff time.Time) ([]*QueueState, error)

	// Delete removes a record. Used by PruneTerminal.
	Delete(ctx context.Context, envelopeID, recipient string) error
}

// Scheduler drives the §4.5 delivery queue. It is the runtime that
// consumes the §2.3 retry helpers, the §2.5 queue state record, and
// the §2.7 cancellation flow, and runs them against an injectable
// DeliverFunc.
//
// Operators call Tick on a timer (every few seconds). Each Tick
// pulls due records from Store, runs DeliverFunc against each, and
// updates state per the per-attempt outcome:
//
//   - Delivered -> state = delivered, emit event.
//   - Rejected with non-recoverable reason -> state = rejected,
//     emit event (only the actual reason returned by the recipient
//     is recorded; §2.6 forbids fabricating reasons).
//   - Rejected with recoverable reason, or Silent, or transport
//     failure -> schedule next attempt via NextAttempt; advance
//     attempts counter.
//   - Effective deadline reached without terminal ack -> state =
//     expired, emit event.
//
// Cancellations submitted via Cancel transition the record to
// canceled iff it is still non-terminal.
//
// Scheduler is concurrency-safe; multiple goroutines may call
// Enqueue / Cancel / PruneTerminal concurrently. Tick itself is
// single-flighted: a second concurrent Tick returns an error
// rather than running attempts twice for the same record.
type Scheduler struct {
	cfg     RetryConfig
	store   Store
	deliver DeliverFunc
	horizon time.Duration

	tickMu    sync.Mutex
	eventMu   sync.Mutex
	eventSink EventSink

	// nowFn is the wall-clock source. Tests inject a deterministic
	// clock; production uses time.Now.
	nowFn func() time.Time
}

// SchedulerConfig bundles the Scheduler's required and optional
// inputs. Deliver, Store are required; the rest fall back to
// spec-aligned defaults when zero.
type SchedulerConfig struct {
	// Store persists queue records.
	Store Store

	// Deliver runs one attempt against (envelope_id, recipient).
	Deliver DeliverFunc

	// Retry is the backoff policy. Zero values fall back to the
	// §2.3 minima via SanitizeRetry.
	Retry RetryConfig

	// MaxRetryHorizon is the operator-configured horizon per §2.4.
	// Zero falls back to DefaultMaxRetryHorizon (72h); values above
	// MaxRetryHorizonCap (7d) are clamped down.
	MaxRetryHorizon time.Duration

	// EventSink, when non-nil, is invoked once per terminal
	// transition. Optional; operators that drive client
	// notifications elsewhere can leave it nil.
	EventSink EventSink

	// NowFn supplies the wall-clock time. Defaults to
	// time.Now().UTC. Tests inject a deterministic clock.
	NowFn func() time.Time
}

// NewScheduler returns a Scheduler over cfg. Returns an error if
// Store or Deliver is missing.
func NewScheduler(cfg SchedulerConfig) (*Scheduler, error) {
	if cfg.Store == nil {
		return nil, errors.New("delivery: scheduler requires a Store")
	}
	if cfg.Deliver == nil {
		return nil, errors.New("delivery: scheduler requires a DeliverFunc")
	}
	now := cfg.NowFn
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Scheduler{
		cfg:       SanitizeRetry(cfg.Retry),
		store:     cfg.Store,
		deliver:   cfg.Deliver,
		horizon:   cfg.MaxRetryHorizon,
		eventSink: cfg.EventSink,
		nowFn:     now,
	}, nil
}

// Enqueue inserts a new queue record for (envelope_id, recipient).
// State starts at queued; NextAttemptAt is now (deliver on next
// tick); Deadline is computed from postmarkExpires and the
// configured horizon per §2.4.
//
// Returns an error if a record for the same (envelope_id, recipient)
// already exists; callers MUST NOT enqueue the same envelope twice.
func (s *Scheduler) Enqueue(ctx context.Context, envelopeID, recipient string, postmarkExpires time.Time) error {
	if envelopeID == "" {
		return errors.New("delivery: enqueue empty envelope_id")
	}
	if recipient == "" {
		return errors.New("delivery: enqueue empty recipient")
	}
	now := s.nowFn()
	existing, err := s.store.Get(ctx, envelopeID, recipient)
	if err != nil {
		return fmt.Errorf("delivery: scheduler get: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("delivery: queue record already exists for (%s, %s)", envelopeID, recipient)
	}
	deadline := EffectiveDeadline(postmarkExpires, now, s.horizon)
	nextAt := now
	q := &QueueState{
		EnvelopeID:    envelopeID,
		Recipient:     recipient,
		State:         QueueStateQueued,
		Attempts:      0,
		NextAttemptAt: &nextAt,
		Deadline:      deadline,
	}
	if err := s.store.Put(ctx, q); err != nil {
		return fmt.Errorf("delivery: scheduler put: %w", err)
	}
	return nil
}

// Tick pulls every record whose NextAttemptAt has passed and
// processes it. Returns the number of records advanced (terminal or
// otherwise) and any error encountered while iterating; per-record
// errors are surfaced through queue-state fields rather than
// aborting the tick.
//
// Tick is single-flighted; a concurrent caller gets ErrTickInProgress.
func (s *Scheduler) Tick(ctx context.Context) (int, error) {
	if !s.tickMu.TryLock() {
		return 0, ErrTickInProgress
	}
	defer s.tickMu.Unlock()

	now := s.nowFn()
	due, err := s.store.DueRecords(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("delivery: scheduler due: %w", err)
	}
	advanced := 0
	for _, q := range due {
		if err := ctx.Err(); err != nil {
			return advanced, err
		}
		if q.State.IsTerminal() {
			continue
		}
		if !now.Before(q.Deadline) {
			s.transitionExpired(q, now)
			if err := s.store.Put(ctx, q); err != nil {
				return advanced, fmt.Errorf("delivery: scheduler expire put: %w", err)
			}
			advanced++
			continue
		}
		s.runAttempt(ctx, q, now)
		if err := s.store.Put(ctx, q); err != nil {
			return advanced, fmt.Errorf("delivery: scheduler attempt put: %w", err)
		}
		advanced++
	}
	return advanced, nil
}

// ErrTickInProgress is returned by Tick when a concurrent Tick is
// already running. Callers SHOULD treat it as a soft signal to back
// off and retry the next interval.
var ErrTickInProgress = errors.New("delivery: scheduler tick already in progress")

// runAttempt invokes Deliver and reconciles the result into q.
// Caller is responsible for persisting q after this method returns.
func (s *Scheduler) runAttempt(ctx context.Context, q *QueueState, now time.Time) {
	res := s.deliver(ctx, q.EnvelopeID, q.Recipient)
	q.Attempts++
	t := now
	q.LastAttemptAt = &t
	statusStr := string(res.Status)
	q.LastOutcome = &statusStr
	if res.ReasonCode != "" {
		rc := string(res.ReasonCode)
		q.LastReasonCode = &rc
	} else {
		q.LastReasonCode = nil
	}

	switch res.Status {
	case semp.AckDelivered:
		s.transitionTerminal(q, QueueStateDelivered, now,
			string(res.Status), string(res.ReasonCode), res.Reason)
		return
	case semp.AckRejected:
		// §2.2: only recoverable reasons retry. Non-recoverable is
		// terminal.
		if !IsRecoverable(string(res.ReasonCode)) {
			s.transitionTerminal(q, QueueStateRejected, now,
				string(res.Status), string(res.ReasonCode), res.Reason)
			return
		}
		// Recoverable rejection: fall through to retry-scheduling.
	case semp.AckSilent:
		// §2.2: silent is non-terminal. Fall through to retry-scheduling.
	default:
		// Defensive: an unrecognized status is treated as silent.
	}

	next, err := NextAttempt(s.cfg, now, q.Attempts-1)
	if err != nil {
		// Pathological: NextAttempt failed (random read failed).
		// Schedule a fixed conservative fallback so the queue does
		// not stall.
		next = now.Add(MinRetryInitialInterval)
	}
	if next.After(q.Deadline) {
		// The next attempt would land past the deadline; transition
		// straight to expired with the last outcome preserved.
		s.transitionExpired(q, now)
		return
	}
	nt := next
	q.NextAttemptAt = &nt
}

// transitionTerminal records a terminal state, populates last
// outcome fields, clears NextAttemptAt, and emits an event.
func (s *Scheduler) transitionTerminal(q *QueueState, state QueueRecordState, now time.Time,
	outcome, reasonCode, reason string) {
	if q.State.IsTerminal() {
		return
	}
	q.SetTerminal(state, now)
	if outcome != "" {
		out := outcome
		q.LastOutcome = &out
	}
	if reasonCode != "" {
		rc := reasonCode
		q.LastReasonCode = &rc
	}
	s.emit(q, reason)
}

// transitionExpired transitions q to the expired terminal state per
// §2.4.
func (s *Scheduler) transitionExpired(q *QueueState, now time.Time) {
	if q.State.IsTerminal() {
		return
	}
	q.SetTerminal(QueueStateExpired, now)
	// LastOutcome / LastReasonCode preserve the last attempted-result
	// values. §2.6 forbids fabricating a reason code; expired is its
	// own terminal state distinct from rejected.
	s.emit(q, "")
}

// emit invokes the event sink for q's current terminal state. No-op
// when no sink is configured.
func (s *Scheduler) emit(q *QueueState, reason string) {
	if s.eventSink == nil {
		return
	}
	s.eventMu.Lock()
	sink := s.eventSink
	s.eventMu.Unlock()
	ev := &SubmissionEvent{
		Type:       SubmissionType,
		Step:       SubmissionStepEvent,
		Version:    semp.ProtocolVersion,
		EnvelopeID: q.EnvelopeID,
		Recipient:  q.Recipient,
		Status:     queueStateToSubmissionStatus(q.State),
		Timestamp:  q.TerminalAt,
		Reason:     reason,
	}
	if q.LastReasonCode != nil {
		ev.ReasonCode = semp.ReasonCode(*q.LastReasonCode)
	}
	sink(ev)
}

// queueStateToSubmissionStatus maps the queue terminal state onto
// the §6 submission status used in delivery events. Canceled and
// expired both surface as Rejected on the event wire because the
// §6 status set does not include them; callers distinguishing
// these states inspect the queue record directly.
func queueStateToSubmissionStatus(s QueueRecordState) semp.SubmissionStatus {
	switch s {
	case QueueStateDelivered:
		return semp.StatusDelivered
	default:
		return semp.StatusRejected
	}
}

// Cancel attempts to transition (envelope_id, recipient) to the
// canceled terminal state per §2.7. Returns the resulting CancelResult.
//
// Per §2.7.4 the operation is idempotent: cancellation of a record
// already in a terminal state is a no-op that returns the prior
// state.
func (s *Scheduler) Cancel(ctx context.Context, envelopeID, recipient string) (CancelResult, error) {
	now := s.nowFn()
	q, err := s.store.Get(ctx, envelopeID, recipient)
	if err != nil {
		return CancelResult{}, fmt.Errorf("delivery: scheduler cancel get: %w", err)
	}
	if q == nil {
		return CancelResult{Recipient: recipient}, ErrUnknownRecord
	}
	if q.State.IsTerminal() {
		return CancelResult{
			Recipient: recipient,
			State:     q.State,
			Reason:    fmt.Sprintf("already %s; cancellation is a no-op per §2.7.4", q.State),
		}, nil
	}
	q.SetTerminal(QueueStateCanceled, now)
	if err := s.store.Put(ctx, q); err != nil {
		return CancelResult{}, fmt.Errorf("delivery: scheduler cancel put: %w", err)
	}
	s.emit(q, "client-initiated cancellation")
	return CancelResult{Recipient: recipient, State: QueueStateCanceled}, nil
}

// ErrUnknownRecord is returned by Cancel when no queue record
// exists for the requested (envelope_id, recipient).
var ErrUnknownRecord = errors.New("delivery: no queue record for envelope_id and recipient")

// CancelEnvelope cancels every still-non-terminal record for
// envelopeID across all recipients. Returns one CancelResult per
// record observed. Per §2.7.1, an empty Recipient on the wire
// CancelRequest means whole-envelope cancellation; this is the
// matching server-side helper.
//
// CancelEnvelope iterates the Store via DueRecords for any record
// with NextAttemptAt before far-future. Stores that need a
// stronger query interface SHOULD implement an Enumerate hook;
// the in-memory Store satisfies the call by returning every
// record.
func (s *Scheduler) CancelEnvelope(ctx context.Context, envelopeID string) ([]CancelResult, error) {
	enum, ok := s.store.(StoreEnumerator)
	if !ok {
		return nil, errors.New("delivery: store does not support whole-envelope cancellation")
	}
	all, err := enum.RecordsForEnvelope(ctx, envelopeID)
	if err != nil {
		return nil, fmt.Errorf("delivery: scheduler cancel enumerate: %w", err)
	}
	now := s.nowFn()
	out := make([]CancelResult, 0, len(all))
	for _, q := range all {
		if q.State.IsTerminal() {
			out = append(out, CancelResult{
				Recipient: q.Recipient,
				State:     q.State,
				Reason:    fmt.Sprintf("already %s; cancellation is a no-op per §2.7.4", q.State),
			})
			continue
		}
		q.SetTerminal(QueueStateCanceled, now)
		if err := s.store.Put(ctx, q); err != nil {
			return out, fmt.Errorf("delivery: scheduler cancel put (%s): %w", q.Recipient, err)
		}
		s.emit(q, "client-initiated cancellation")
		out = append(out, CancelResult{Recipient: q.Recipient, State: QueueStateCanceled})
	}
	return out, nil
}

// StoreEnumerator is the optional extension a Store implements when
// it can enumerate every record for one envelope_id. The in-memory
// Store satisfies it.
type StoreEnumerator interface {
	RecordsForEnvelope(ctx context.Context, envelopeID string) ([]*QueueState, error)
}

// PruneTerminal removes terminal records whose TerminalAt is more
// than retainFor in the past. Per §2.5 retainFor MUST be at least
// 24 hours; PruneTerminal clamps lower values up.
func (s *Scheduler) PruneTerminal(ctx context.Context, retainFor time.Duration) (int, error) {
	if retainFor < MinTerminalRetention {
		retainFor = MinTerminalRetention
	}
	cutoff := s.nowFn().Add(-retainFor)
	stale, err := s.store.ListTerminalOlderThan(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delivery: scheduler prune list: %w", err)
	}
	removed := 0
	for _, q := range stale {
		if err := s.store.Delete(ctx, q.EnvelopeID, q.Recipient); err != nil {
			return removed, fmt.Errorf("delivery: scheduler prune delete: %w", err)
		}
		removed++
	}
	return removed, nil
}

// MinTerminalRetention is the §2.5 retention floor: terminal queue
// records MUST be retained for at least this long after termination
// so a client reconnecting after a transient outage can observe the
// outcome.
const MinTerminalRetention = 24 * time.Hour

// inMemoryStore is the reference Store implementation used by tests
// and demos. Production deployments use a durable Store backed by
// the operator's chosen persistence layer.
type inMemoryStore struct {
	mu      sync.Mutex
	records map[string]*QueueState // key = envelope_id || "\x00" || recipient
}

// NewInMemoryStore returns an in-memory Store. It is concurrency-safe.
func NewInMemoryStore() Store {
	return &inMemoryStore{records: make(map[string]*QueueState)}
}

func storeKey(envelopeID, recipient string) string {
	return envelopeID + "\x00" + recipient
}

func (s *inMemoryStore) Put(_ context.Context, q *QueueState) error {
	if q == nil {
		return errors.New("delivery: in-memory store put nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *q // copy so caller mutations after Put do not race
	s.records[storeKey(q.EnvelopeID, q.Recipient)] = &cp
	return nil
}

func (s *inMemoryStore) Get(_ context.Context, envelopeID, recipient string) (*QueueState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.records[storeKey(envelopeID, recipient)]
	if !ok {
		return nil, nil
	}
	cp := *v
	return &cp, nil
}

func (s *inMemoryStore) DueRecords(_ context.Context, now time.Time) ([]*QueueState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*QueueState, 0)
	for _, v := range s.records {
		if v.State.IsTerminal() {
			continue
		}
		if v.NextAttemptAt == nil {
			continue
		}
		if v.NextAttemptAt.After(now) {
			continue
		}
		cp := *v
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		ai := *out[i].NextAttemptAt
		aj := *out[j].NextAttemptAt
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return out[i].EnvelopeID < out[j].EnvelopeID
	})
	return out, nil
}

func (s *inMemoryStore) ListTerminalOlderThan(_ context.Context, cutoff time.Time) ([]*QueueState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*QueueState, 0)
	for _, v := range s.records {
		if !v.State.IsTerminal() {
			continue
		}
		if v.TerminalAt.IsZero() {
			continue
		}
		if v.TerminalAt.After(cutoff) {
			continue
		}
		cp := *v
		out = append(out, &cp)
	}
	return out, nil
}

func (s *inMemoryStore) Delete(_ context.Context, envelopeID, recipient string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, storeKey(envelopeID, recipient))
	return nil
}

func (s *inMemoryStore) RecordsForEnvelope(_ context.Context, envelopeID string) ([]*QueueState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*QueueState, 0)
	for _, v := range s.records {
		if v.EnvelopeID != envelopeID {
			continue
		}
		cp := *v
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Recipient < out[j].Recipient })
	return out, nil
}
