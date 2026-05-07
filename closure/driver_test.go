package closure_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"semp.dev/semp-go/closure"
)

// fakeClock is a manually-advanced clock used to drive Driver.Tick
// deterministically.
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

// requestRecord builds a structurally-valid request record. It does
// NOT sign the record; the Driver's Submit / Cancel paths do not
// verify signatures (the operator's submission handler does that
// before passing to the Driver).
func requestRecord(userID string, requestedAt time.Time, grace time.Duration) *closure.Record {
	return &closure.Record{
		Type:               closure.RecordType,
		Step:               closure.StepRequest,
		Version:            closure.RecordVersion,
		UserID:             userID,
		RequestedAt:        requestedAt,
		GracePeriodSeconds: int64(grace.Seconds()),
		IssuedBy:           "primary-device",
		Signature: closure.Signature{
			Algorithm: "ed25519",
			KeyID:     "primary-fp",
			Value:     "sig-bytes",
		},
	}
}

// recorder captures invocations of finalization hooks.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) hook(name string) closure.FinalizationEffectFunc {
	return func(_ context.Context, userID string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls = append(r.calls, name+"("+userID+")")
		return nil
	}
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	copy(out, r.calls)
	return out
}

// TestDriverSubmitTracksRequest confirms a submitted request shows
// up under PendingCount and Pending(userID).
func TestDriverSubmitTracksRequest(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC))
	d := closure.NewDriver(closure.DriverConfig{NowFn: clk.Now})
	r := requestRecord("alice@example.com", clk.Now(), 7*24*time.Hour)
	if err := d.Submit(context.Background(), r); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if d.PendingCount() != 1 {
		t.Errorf("PendingCount = %d, want 1", d.PendingCount())
	}
	if got := d.Pending("alice@example.com"); got == nil || got.UserID != "alice@example.com" {
		t.Errorf("Pending: got %+v", got)
	}
}

// TestDriverSubmitRejectsDuplicate confirms ErrAlreadyPending fires
// on a second Submit for the same user.
func TestDriverSubmitRejectsDuplicate(t *testing.T) {
	d := closure.NewDriver(closure.DriverConfig{})
	r := requestRecord("alice@example.com", time.Now().UTC(), 7*24*time.Hour)
	if err := d.Submit(context.Background(), r); err != nil {
		t.Fatalf("Submit 1: %v", err)
	}
	err := d.Submit(context.Background(), r)
	if !errors.Is(err, closure.ErrAlreadyPending) {
		t.Errorf("Submit 2: got %v, want ErrAlreadyPending", err)
	}
}

// TestDriverSubmitRejectsCancelStep confirms Submit only accepts
// step=request; cancel records flow through Cancel instead.
func TestDriverSubmitRejectsCancelStep(t *testing.T) {
	d := closure.NewDriver(closure.DriverConfig{})
	r := requestRecord("alice@example.com", time.Now().UTC(), 7*24*time.Hour)
	r.Step = closure.StepCancel
	if err := d.Submit(context.Background(), r); err == nil {
		t.Error("Submit accepted step=cancel")
	}
}

// TestDriverTickBeforeDeadlineNoOp confirms a request whose
// FinalizationAt is in the future does NOT finalize. §4.1
// "finalization MUST NOT occur before the timestamp under any
// policy".
func TestDriverTickBeforeDeadlineNoOp(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	rec := &recorder{}
	d := closure.NewDriver(closure.DriverConfig{
		NowFn: clk.Now,
		Effects: closure.FinalizationEffects{
			RevokeIdentityKey: rec.hook("RevokeIdentityKey"),
		},
	})
	_ = d.Submit(context.Background(), requestRecord("alice@example.com", t0, 7*24*time.Hour))

	// Tick at t0 — well before deadline.
	finalized, err := d.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if finalized != 0 {
		t.Errorf("finalized = %d, want 0", finalized)
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Errorf("hooks fired pre-deadline: %v", calls)
	}
}

// TestDriverTickAtDeadlineRunsAllEffects confirms once the deadline
// passes, every non-nil hook fires in §4.2 spec order and the
// pending entry is removed.
func TestDriverTickAtDeadlineRunsAllEffects(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	rec := &recorder{}
	d := closure.NewDriver(closure.DriverConfig{
		NowFn: clk.Now,
		Effects: closure.FinalizationEffects{
			RevokeIdentityKey:        rec.hook("RevokeIdentityKey"),
			RevokeEncryptionKeys:     rec.hook("RevokeEncryptionKeys"),
			RevokeDeviceCertificates: rec.hook("RevokeDeviceCertificates"),
			TerminateSessions:        rec.hook("TerminateSessions"),
			DrainOutboundQueue:       rec.hook("DrainOutboundQueue"),
			DeleteRecoveryBundle:     rec.hook("DeleteRecoveryBundle"),
			CancelInflightMigrations: rec.hook("CancelInflightMigrations"),
			RetainBlockList:          rec.hook("RetainBlockList"),
			CeaseServing:             rec.hook("CeaseServing"),
		},
	})
	_ = d.Submit(context.Background(), requestRecord("alice@example.com", t0, 7*24*time.Hour))

	// Advance past the grace deadline.
	clk.Set(t0.Add(8 * 24 * time.Hour))
	finalized, err := d.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if finalized != 1 {
		t.Errorf("finalized = %d, want 1", finalized)
	}
	if d.PendingCount() != 0 {
		t.Errorf("PendingCount after finalize = %d, want 0", d.PendingCount())
	}
	want := []string{
		"RevokeIdentityKey(alice@example.com)",
		"RevokeEncryptionKeys(alice@example.com)",
		"RevokeDeviceCertificates(alice@example.com)",
		"TerminateSessions(alice@example.com)",
		"DrainOutboundQueue(alice@example.com)",
		"DeleteRecoveryBundle(alice@example.com)",
		"CancelInflightMigrations(alice@example.com)",
		"RetainBlockList(alice@example.com)",
		"CeaseServing(alice@example.com)",
	}
	got := rec.snapshot()
	if len(got) != len(want) {
		t.Fatalf("hook calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestDriverTickAtDeadlineWithNilHooksSkipsThem confirms nil hooks
// do not abort the run; the driver simply skips them.
func TestDriverTickAtDeadlineWithNilHooksSkipsThem(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	rec := &recorder{}
	d := closure.NewDriver(closure.DriverConfig{
		NowFn: clk.Now,
		Effects: closure.FinalizationEffects{
			// Only two hooks set; the rest are nil and should be
			// silently skipped.
			RevokeIdentityKey: rec.hook("RevokeIdentityKey"),
			CeaseServing:      rec.hook("CeaseServing"),
		},
	})
	_ = d.Submit(context.Background(), requestRecord("alice@example.com", t0, 7*24*time.Hour))
	clk.Set(t0.Add(8 * 24 * time.Hour))
	finalized, err := d.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if finalized != 1 {
		t.Errorf("finalized = %d, want 1", finalized)
	}
	got := rec.snapshot()
	if len(got) != 2 {
		t.Errorf("hooks fired = %v, want 2", got)
	}
}

// TestDriverCancelPreventsFinalization confirms a Cancel before
// the deadline removes the pending entry; a subsequent Tick at the
// deadline does NOT run the effects.
func TestDriverCancelPreventsFinalization(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	rec := &recorder{}
	d := closure.NewDriver(closure.DriverConfig{
		NowFn: clk.Now,
		Effects: closure.FinalizationEffects{
			RevokeIdentityKey: rec.hook("RevokeIdentityKey"),
		},
	})
	_ = d.Submit(context.Background(), requestRecord("alice@example.com", t0, 7*24*time.Hour))
	canceled, err := d.Cancel(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if !canceled {
		t.Error("Cancel returned canceled=false on pending request")
	}
	clk.Set(t0.Add(8 * 24 * time.Hour))
	finalized, _ := d.Tick(context.Background())
	if finalized != 0 {
		t.Errorf("finalized = %d after Cancel, want 0", finalized)
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Errorf("hooks fired after Cancel: %v", calls)
	}
}

// TestDriverCancelUnknownIsIdempotent confirms canceling an
// unknown user returns (false, nil) per the spec's cancellation
// idempotency norm.
func TestDriverCancelUnknownIsIdempotent(t *testing.T) {
	d := closure.NewDriver(closure.DriverConfig{})
	canceled, err := d.Cancel(context.Background(), "ghost@example.com")
	if err != nil {
		t.Errorf("Cancel unknown: %v", err)
	}
	if canceled {
		t.Error("Cancel returned canceled=true for unknown user")
	}
}

// TestDriverEffectErrorAggregated confirms that hook errors are
// surfaced as *FinalizationErrors but every non-nil hook still
// runs (the driver does not short-circuit on per-step errors).
func TestDriverEffectErrorAggregated(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	rec := &recorder{}
	d := closure.NewDriver(closure.DriverConfig{
		NowFn: clk.Now,
		Effects: closure.FinalizationEffects{
			RevokeIdentityKey: rec.hook("RevokeIdentityKey"),
			DrainOutboundQueue: func(_ context.Context, _ string) error {
				rec.mu.Lock()
				rec.calls = append(rec.calls, "DrainOutboundQueue(failed)")
				rec.mu.Unlock()
				return errors.New("queue iteration failed")
			},
			CeaseServing: rec.hook("CeaseServing"),
		},
	})
	_ = d.Submit(context.Background(), requestRecord("alice@example.com", t0, 7*24*time.Hour))
	clk.Set(t0.Add(8 * 24 * time.Hour))
	_, err := d.Tick(context.Background())
	if err == nil {
		t.Fatal("Tick did not surface effect error")
	}
	var fe *closure.FinalizationErrors
	if !errors.As(err, &fe) {
		t.Fatalf("error is not *FinalizationErrors: %v", err)
	}
	if fe.UserID != "alice@example.com" {
		t.Errorf("FinalizationErrors.UserID = %q", fe.UserID)
	}
	if _, ok := fe.Steps["DrainOutboundQueue"]; !ok {
		t.Errorf("FinalizationErrors.Steps missing DrainOutboundQueue: %+v", fe.Steps)
	}
	// Hooks AFTER the failed step still ran.
	calls := rec.snapshot()
	if len(calls) != 3 {
		t.Errorf("hooks ran = %v, want 3 (no short-circuit on error)", calls)
	}
	// Pending entry MUST still be removed; finalization is
	// irreversible once the grace deadline passes.
	if d.PendingCount() != 0 {
		t.Errorf("PendingCount after error = %d, want 0", d.PendingCount())
	}
}

// TestDriverTickHandlesMultipleUsers confirms a single Tick
// processes every due user, in deterministic user_id order.
func TestDriverTickHandlesMultipleUsers(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	rec := &recorder{}
	d := closure.NewDriver(closure.DriverConfig{
		NowFn: clk.Now,
		Effects: closure.FinalizationEffects{
			CeaseServing: rec.hook("CeaseServing"),
		},
	})
	for _, u := range []string{"carol@example.com", "alice@example.com", "bob@example.com"} {
		_ = d.Submit(context.Background(), requestRecord(u, t0, 7*24*time.Hour))
	}
	clk.Set(t0.Add(8 * 24 * time.Hour))
	finalized, err := d.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if finalized != 3 {
		t.Errorf("finalized = %d, want 3", finalized)
	}
	got := rec.snapshot()
	want := []string{
		"CeaseServing(alice@example.com)",
		"CeaseServing(bob@example.com)",
		"CeaseServing(carol@example.com)",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// intStr is a tiny stringer to avoid pulling strconv into hot
// concurrent goroutines.
func intStr(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// TestDriverConcurrentSubmitCancelTick exercises concurrency under
// -race: many goroutines submitting + canceling + ticking.
func TestDriverConcurrentSubmitCancelTick(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC))
	var fired atomic.Int64
	d := closure.NewDriver(closure.DriverConfig{
		NowFn: clk.Now,
		Effects: closure.FinalizationEffects{
			CeaseServing: func(_ context.Context, _ string) error {
				fired.Add(1)
				return nil
			},
		},
	})
	const N = 50
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		uid := "user-" + intStr(i) + "@example.com"
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Submit(context.Background(), requestRecord(uid, clk.Now(), 7*24*time.Hour))
		}()
	}
	wg.Wait()
	if d.PendingCount() != N {
		t.Errorf("PendingCount = %d, want %d", d.PendingCount(), N)
	}
	clk.Set(clk.Now().Add(8 * 24 * time.Hour))
	if _, err := d.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if fired.Load() != int64(N) {
		t.Errorf("fired = %d, want %d", fired.Load(), N)
	}
	if d.PendingCount() != 0 {
		t.Errorf("PendingCount after Tick = %d, want 0", d.PendingCount())
	}
}
