package delivery_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/delivery"
)

// fakeClock is a manually-advanced wall-clock source used to drive
// the Scheduler deterministically. It is concurrency-safe; tests
// call Set or Advance to step the clock forward.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// scriptedDeliver returns a DeliverFunc that yields the n-th
// scripted result for each call (per envelope_id, recipient pair).
// Used to verify retry, terminal, and recoverable-vs-non-recoverable
// flows without a real network.
func scriptedDeliver(t *testing.T, results map[string][]delivery.AttemptResult) (delivery.DeliverFunc, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	var mu sync.Mutex
	cursor := make(map[string]int)
	return func(_ context.Context, envelopeID, recipient string) delivery.AttemptResult {
		calls.Add(1)
		mu.Lock()
		defer mu.Unlock()
		key := envelopeID + "|" + recipient
		idx := cursor[key]
		if idx >= len(results[key]) {
			t.Errorf("scriptedDeliver: ran out of results for %s (call #%d)", key, idx+1)
			return delivery.AttemptResult{Status: semp.AckSilent}
		}
		cursor[key] = idx + 1
		return results[key][idx]
	}, &calls
}

// TestSchedulerDeliveredHappyPath confirms a single Tick that
// returns delivered terminates the record and emits an event.
func TestSchedulerDeliveredHappyPath(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC))
	store := delivery.NewInMemoryStore()
	deliver, calls := scriptedDeliver(t, map[string][]delivery.AttemptResult{
		"env-1|alice@example.com": {{Status: semp.AckDelivered}},
	})
	var events []*delivery.SubmissionEvent
	var evMu sync.Mutex
	sched, err := delivery.NewScheduler(delivery.SchedulerConfig{
		Store:   store,
		Deliver: deliver,
		EventSink: func(ev *delivery.SubmissionEvent) {
			evMu.Lock()
			defer evMu.Unlock()
			events = append(events, ev)
		},
		NowFn: clk.Now,
	})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	if err := sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		clk.Now().Add(72*time.Hour)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	advanced, err := sched.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if advanced != 1 {
		t.Errorf("advanced = %d, want 1", advanced)
	}
	if calls.Load() != 1 {
		t.Errorf("Deliver call count = %d, want 1", calls.Load())
	}
	q, _ := store.Get(context.Background(), "env-1", "alice@example.com")
	if q == nil || q.State != delivery.QueueStateDelivered {
		t.Fatalf("state after delivered: %+v", q)
	}
	if q.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", q.Attempts)
	}
	if q.TerminalAt != clk.Now() {
		t.Errorf("TerminalAt = %s, want %s", q.TerminalAt, clk.Now())
	}
	evMu.Lock()
	defer evMu.Unlock()
	if len(events) != 1 || events[0].Status != semp.StatusDelivered {
		t.Errorf("events = %+v", events)
	}
}

// TestSchedulerNonRecoverableTerminates confirms a rejected with a
// non-recoverable reason terminates the record without retrying.
func TestSchedulerNonRecoverableTerminates(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC))
	store := delivery.NewInMemoryStore()
	deliver, _ := scriptedDeliver(t, map[string][]delivery.AttemptResult{
		"env-1|alice@example.com": {{
			Status:     semp.AckRejected,
			ReasonCode: semp.ReasonBlocked,
		}},
	})
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store: store, Deliver: deliver, NowFn: clk.Now,
	})
	_ = sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		clk.Now().Add(72*time.Hour))
	if _, err := sched.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	q, _ := store.Get(context.Background(), "env-1", "alice@example.com")
	if q.State != delivery.QueueStateRejected {
		t.Errorf("state = %s, want rejected", q.State)
	}
	if q.LastReasonCode == nil || *q.LastReasonCode != string(semp.ReasonBlocked) {
		t.Errorf("LastReasonCode = %v, want blocked", q.LastReasonCode)
	}
}

// TestSchedulerRecoverableRetries confirms recoverable rejection +
// silent both schedule a retry. After enough fake-clock advance the
// retry runs.
func TestSchedulerRecoverableRetries(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC))
	store := delivery.NewInMemoryStore()
	deliver, calls := scriptedDeliver(t, map[string][]delivery.AttemptResult{
		"env-1|alice@example.com": {
			{Status: semp.AckRejected, ReasonCode: semp.ReasonRateLimited},
			{Status: semp.AckSilent},
			{Status: semp.AckDelivered},
		},
	})
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store: store, Deliver: deliver, NowFn: clk.Now,
	})
	_ = sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		clk.Now().Add(72*time.Hour))

	// Tick 1 - recoverable rejection schedules a retry.
	if _, err := sched.Tick(context.Background()); err != nil {
		t.Fatalf("Tick 1: %v", err)
	}
	q, _ := store.Get(context.Background(), "env-1", "alice@example.com")
	if q.State != delivery.QueueStateQueued {
		t.Fatalf("after recoverable tick: state = %s, want queued", q.State)
	}
	if q.NextAttemptAt == nil {
		t.Fatal("NextAttemptAt is nil after recoverable rejection")
	}
	// Advance past NextAttemptAt; tick 2 - silent, schedules another.
	clk.Set(q.NextAttemptAt.Add(time.Second))
	if _, err := sched.Tick(context.Background()); err != nil {
		t.Fatalf("Tick 2: %v", err)
	}
	q, _ = store.Get(context.Background(), "env-1", "alice@example.com")
	if q.State != delivery.QueueStateQueued {
		t.Fatalf("after silent: state = %s", q.State)
	}
	if q.Attempts != 2 {
		t.Errorf("Attempts after 2 ticks = %d, want 2", q.Attempts)
	}
	// Advance past second NextAttemptAt; tick 3 delivers.
	clk.Set(q.NextAttemptAt.Add(time.Second))
	if _, err := sched.Tick(context.Background()); err != nil {
		t.Fatalf("Tick 3: %v", err)
	}
	q, _ = store.Get(context.Background(), "env-1", "alice@example.com")
	if q.State != delivery.QueueStateDelivered {
		t.Errorf("final state = %s, want delivered", q.State)
	}
	if calls.Load() != 3 {
		t.Errorf("Deliver call count = %d, want 3", calls.Load())
	}
}

// TestSchedulerExpiresAtDeadline confirms that the scheduler
// transitions to expired when an attempt would land past the
// deadline.
func TestSchedulerExpiresAtDeadline(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	store := delivery.NewInMemoryStore()
	deliver, _ := scriptedDeliver(t, map[string][]delivery.AttemptResult{
		"env-1|alice@example.com": {{Status: semp.AckSilent}},
	})
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store: store, Deliver: deliver, NowFn: clk.Now,
	})
	// Postmark expires in 30 seconds - well below the next-attempt
	// floor so the attempt's NextAttemptAt will be past Deadline.
	_ = sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		t0.Add(30*time.Second))
	if _, err := sched.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	q, _ := store.Get(context.Background(), "env-1", "alice@example.com")
	if q.State != delivery.QueueStateExpired {
		t.Errorf("state = %s, want expired", q.State)
	}
	if q.LastReasonCode != nil {
		t.Errorf("LastReasonCode preserved (silent) but unexpected: %s", *q.LastReasonCode)
	}
}

// TestSchedulerExpiresOnDeadlinePassed confirms that a tick
// observed AFTER the deadline transitions to expired without
// running Deliver.
func TestSchedulerExpiresOnDeadlinePassed(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	store := delivery.NewInMemoryStore()
	called := false
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store: store,
		Deliver: func(_ context.Context, _, _ string) delivery.AttemptResult {
			called = true
			return delivery.AttemptResult{Status: semp.AckDelivered}
		},
		NowFn: clk.Now,
	})
	_ = sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		t0.Add(time.Hour))
	// Advance past deadline; the record's NextAttemptAt was set to
	// t0 (immediate) so it is due.
	clk.Set(t0.Add(2 * time.Hour))
	if _, err := sched.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if called {
		t.Error("Deliver invoked for an envelope past its deadline")
	}
	q, _ := store.Get(context.Background(), "env-1", "alice@example.com")
	if q.State != delivery.QueueStateExpired {
		t.Errorf("state = %s, want expired", q.State)
	}
}

// TestSchedulerCancelTransitionsToCanceled confirms an in-flight
// record cancels cleanly and the cancel is idempotent on a
// follow-up call (already-terminal returns the prior state).
func TestSchedulerCancelTransitionsToCanceled(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC))
	store := delivery.NewInMemoryStore()
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store: store,
		Deliver: func(_ context.Context, _, _ string) delivery.AttemptResult {
			t.Error("Deliver should not be called between Enqueue and Cancel")
			return delivery.AttemptResult{Status: semp.AckDelivered}
		},
		NowFn: clk.Now,
	})
	_ = sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		clk.Now().Add(time.Hour))

	res, err := sched.Cancel(context.Background(), "env-1", "alice@example.com")
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if res.State != delivery.QueueStateCanceled {
		t.Errorf("Cancel result state = %s, want canceled", res.State)
	}
	// Idempotent: a second Cancel returns the prior state.
	res, err = sched.Cancel(context.Background(), "env-1", "alice@example.com")
	if err != nil {
		t.Fatalf("Cancel #2: %v", err)
	}
	if res.State != delivery.QueueStateCanceled {
		t.Errorf("Cancel idempotent result state = %s, want canceled", res.State)
	}
	if res.Reason == "" {
		t.Error("Cancel idempotent should populate Reason explaining the no-op")
	}
}

// TestSchedulerCancelUnknown confirms cancellation of an unknown
// (envelope, recipient) returns the typed sentinel.
func TestSchedulerCancelUnknown(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC))
	store := delivery.NewInMemoryStore()
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store: store,
		Deliver: func(_ context.Context, _, _ string) delivery.AttemptResult {
			return delivery.AttemptResult{Status: semp.AckDelivered}
		},
		NowFn: clk.Now,
	})
	_, err := sched.Cancel(context.Background(), "env-ghost", "nobody@example.com")
	if !errors.Is(err, delivery.ErrUnknownRecord) {
		t.Errorf("Cancel unknown: got %v, want ErrUnknownRecord", err)
	}
}

// TestSchedulerCancelEnvelopeMultipleRecipients confirms whole-
// envelope cancellation per §2.7.1.
func TestSchedulerCancelEnvelopeMultipleRecipients(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC))
	store := delivery.NewInMemoryStore()
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store: store,
		Deliver: func(_ context.Context, _, _ string) delivery.AttemptResult {
			return delivery.AttemptResult{Status: semp.AckDelivered}
		},
		NowFn: clk.Now,
	})
	for _, r := range []string{"alice@example.com", "bob@example.com", "carol@example.com"} {
		if err := sched.Enqueue(context.Background(), "env-1", r, clk.Now().Add(time.Hour)); err != nil {
			t.Fatalf("Enqueue %s: %v", r, err)
		}
	}
	results, err := sched.CancelEnvelope(context.Background(), "env-1")
	if err != nil {
		t.Fatalf("CancelEnvelope: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("CancelEnvelope results = %d, want 3", len(results))
	}
	for _, r := range results {
		if r.State != delivery.QueueStateCanceled {
			t.Errorf("recipient %s state = %s, want canceled", r.Recipient, r.State)
		}
	}
}

// TestSchedulerPruneTerminalRespectsRetention confirms the §2.5
// 24-hour retention floor is enforced; the prune does not remove
// records younger than retainFor.
func TestSchedulerPruneTerminalRespectsRetention(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	store := delivery.NewInMemoryStore()
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store: store,
		Deliver: func(_ context.Context, _, _ string) delivery.AttemptResult {
			return delivery.AttemptResult{Status: semp.AckDelivered}
		},
		NowFn: clk.Now,
	})
	_ = sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		clk.Now().Add(time.Hour))
	if _, err := sched.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	// Right after termination, prune is a no-op (within retention).
	clk.Set(t0.Add(time.Hour))
	if removed, err := sched.PruneTerminal(context.Background(), 24*time.Hour); err != nil || removed != 0 {
		t.Errorf("PruneTerminal early: removed=%d err=%v, want 0/nil", removed, err)
	}

	// Past the 24h retention floor: the record IS pruned.
	clk.Set(t0.Add(48 * time.Hour))
	removed, err := sched.PruneTerminal(context.Background(), 24*time.Hour)
	if err != nil {
		t.Fatalf("PruneTerminal late: %v", err)
	}
	if removed != 1 {
		t.Errorf("PruneTerminal late: removed=%d, want 1", removed)
	}
	q, _ := store.Get(context.Background(), "env-1", "alice@example.com")
	if q != nil {
		t.Errorf("record still present after prune: %+v", q)
	}
}

// TestSchedulerPruneFloorClampedTo24h confirms that callers passing
// a sub-spec retention window get clamped to the §2.5 floor.
func TestSchedulerPruneFloorClampedTo24h(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	store := delivery.NewInMemoryStore()
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store: store,
		Deliver: func(_ context.Context, _, _ string) delivery.AttemptResult {
			return delivery.AttemptResult{Status: semp.AckDelivered}
		},
		NowFn: clk.Now,
	})
	_ = sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		clk.Now().Add(time.Hour))
	if _, err := sched.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	// Caller asks for 1h retention; spec floor is 24h. Record at +1h
	// should NOT be pruned because the floor binds.
	clk.Set(t0.Add(time.Hour))
	if removed, err := sched.PruneTerminal(context.Background(), time.Hour); err != nil || removed != 0 {
		t.Errorf("PruneTerminal under-floor: removed=%d err=%v, want 0/nil (clamped to 24h)", removed, err)
	}
}

// TestSchedulerEnqueueRejectsDuplicate confirms a duplicate
// (envelope_id, recipient) is rejected.
func TestSchedulerEnqueueRejectsDuplicate(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC))
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store:   delivery.NewInMemoryStore(),
		Deliver: func(_ context.Context, _, _ string) delivery.AttemptResult { return delivery.AttemptResult{} },
		NowFn:   clk.Now,
	})
	if err := sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		clk.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Enqueue 1: %v", err)
	}
	if err := sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		clk.Now().Add(time.Hour)); err == nil {
		t.Error("Enqueue duplicate accepted")
	}
}

// TestSchedulerNoEventOnNonTerminal confirms the event sink is
// invoked only on terminal transitions.
func TestSchedulerNoEventOnNonTerminal(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC))
	store := delivery.NewInMemoryStore()
	deliver, _ := scriptedDeliver(t, map[string][]delivery.AttemptResult{
		"env-1|alice@example.com": {{Status: semp.AckSilent}},
	})
	var emitted int32
	sched, _ := delivery.NewScheduler(delivery.SchedulerConfig{
		Store: store, Deliver: deliver, NowFn: clk.Now,
		EventSink: func(*delivery.SubmissionEvent) { atomic.AddInt32(&emitted, 1) },
	})
	_ = sched.Enqueue(context.Background(), "env-1", "alice@example.com",
		clk.Now().Add(72*time.Hour))
	if _, err := sched.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if atomic.LoadInt32(&emitted) != 0 {
		t.Errorf("event count = %d on silent (non-terminal); want 0", emitted)
	}
}
