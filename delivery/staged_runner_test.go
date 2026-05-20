package delivery_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"semp.dev/semp-go/delivery"
)

// stagedHarness wires up a StagedRunner with capture sinks so tests
// can assert which callback fired and with what arguments.
type stagedHarness struct {
	t       *testing.T
	clk     *fakeClock
	runner  *delivery.StagedRunner
	mu      sync.Mutex
	delivers []deliveryRecord
	suppresses []suppressRecord
	completes []string
}

type deliveryRecord struct {
	envelopeID string
	stage      int
	devices    []string
}
type suppressRecord struct {
	envelopeID string
	stage      int
}

func newStagedHarness(t *testing.T, timeout time.Duration) *stagedHarness {
	t.Helper()
	h := &stagedHarness{
		t:   t,
		clk: newFakeClock(time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)),
	}
	r, err := delivery.NewStagedRunner(delivery.StagedRunnerConfig{
		Deliver: func(_ context.Context, envelopeID string, stage int, devs []string) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			cp := make([]string, len(devs))
			copy(cp, devs)
			h.delivers = append(h.delivers, deliveryRecord{envelopeID, stage, cp})
			return nil
		},
		Suppress: func(_ context.Context, envelopeID string, stage int) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.suppresses = append(h.suppresses, suppressRecord{envelopeID, stage})
			return nil
		},
		Complete: func(_ context.Context, envelopeID string) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.completes = append(h.completes, envelopeID)
			return nil
		},
		StageTimeout: timeout,
		NowFn:        h.clk.Now,
	})
	if err != nil {
		t.Fatalf("NewStagedRunner: %v", err)
	}
	h.runner = r
	return h
}

func disp(envelopeID, deviceID string, decision delivery.DispositionDecision) delivery.Disposition {
	return delivery.Disposition{
		Kind:             delivery.DispositionKind,
		SourceEnvelopeID: envelopeID,
		Decision:         decision,
		DeviceID:         deviceID,
	}
}

// TestStagedHoldDeliversFirstStage confirms Hold immediately invokes
// Deliver for the lowest stage's pending devices.
func TestStagedHoldDeliversFirstStage(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam"}},
		{Stage: 2, PendingDeviceIDs: []string{"d-phone", "d-laptop"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.delivers) != 1 {
		t.Fatalf("delivers = %d, want 1", len(h.delivers))
	}
	if h.delivers[0].stage != 1 || len(h.delivers[0].devices) != 1 || h.delivers[0].devices[0] != "d-spam" {
		t.Errorf("first delivery = %+v, want stage=1 devices=[d-spam]", h.delivers[0])
	}
}

// TestStagedAdvanceOnAllDispositions confirms once every stage-N
// pending device emits a disposition, Tick advances to stage N+1.
func TestStagedAdvanceOnAllDispositions(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam"}},
		{Stage: 2, PendingDeviceIDs: []string{"d-phone"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if err := h.runner.IngestDisposition(context.Background(), "env-1", "d-spam",
		disp("env-1", "d-spam", delivery.DispositionAdvance)); err != nil {
		t.Fatalf("IngestDisposition: %v", err)
	}
	if _, err := h.runner.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	h.mu.Lock()
	if len(h.delivers) != 2 {
		t.Fatalf("delivers = %d, want 2", len(h.delivers))
	}
	if h.delivers[1].stage != 2 || h.delivers[1].devices[0] != "d-phone" {
		t.Errorf("second delivery = %+v, want stage=2 devices=[d-phone]", h.delivers[1])
	}
	h.mu.Unlock()
	// One more advance from stage 2 → completes.
	if err := h.runner.IngestDisposition(context.Background(), "env-1", "d-phone",
		disp("env-1", "d-phone", delivery.DispositionAdvance)); err != nil {
		t.Fatalf("IngestDisposition stage 2: %v", err)
	}
	if _, err := h.runner.Tick(context.Background()); err != nil {
		t.Fatalf("Tick stage 2: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.completes) != 1 || h.completes[0] != "env-1" {
		t.Errorf("completes = %v, want [env-1]", h.completes)
	}
	if h.runner.HeldCount() != 0 {
		t.Errorf("held count after complete = %d, want 0", h.runner.HeldCount())
	}
}

// TestStagedSuppressWinsOverAdvance confirms §3.2.3 conservative
// aggregation: if any stage-N device suppresses, the envelope is
// dropped even if other stage-N devices advance.
func TestStagedSuppressWinsOverAdvance(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam", "d-policy"}},
		{Stage: 2, PendingDeviceIDs: []string{"d-phone"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if err := h.runner.IngestDisposition(context.Background(), "env-1", "d-spam",
		disp("env-1", "d-spam", delivery.DispositionAdvance)); err != nil {
		t.Fatalf("ingest advance: %v", err)
	}
	if err := h.runner.IngestDisposition(context.Background(), "env-1", "d-policy",
		disp("env-1", "d-policy", delivery.DispositionSuppress)); err != nil {
		t.Fatalf("ingest suppress: %v", err)
	}
	if _, err := h.runner.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.suppresses) != 1 {
		t.Fatalf("suppresses = %v", h.suppresses)
	}
	if h.suppresses[0].envelopeID != "env-1" || h.suppresses[0].stage != 1 {
		t.Errorf("suppress = %+v, want env-1 at stage 1", h.suppresses[0])
	}
	// Stage 2 MUST NOT have been delivered.
	if len(h.delivers) != 1 {
		t.Errorf("delivers = %d, want 1 (stage 2 should not run after suppress)", len(h.delivers))
	}
	if h.runner.HeldCount() != 0 {
		t.Errorf("held count after suppress = %d, want 0", h.runner.HeldCount())
	}
}

// TestStagedFailOpenOnTimeout confirms the §3.2.4 fail-open rule:
// if no dispositions arrive before the deadline, the envelope
// advances to the next stage.
func TestStagedFailOpenOnTimeout(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam"}},
		{Stage: 2, PendingDeviceIDs: []string{"d-phone"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	// No dispositions; advance the clock past the deadline.
	h.clk.Advance(45 * time.Second)
	if _, err := h.runner.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.delivers) != 2 {
		t.Fatalf("delivers = %d, want 2 (fail-open advance)", len(h.delivers))
	}
	if h.delivers[1].stage != 2 {
		t.Errorf("second delivery stage = %d, want 2", h.delivers[1].stage)
	}
}

// TestStagedAuthRejectsMismatchedDeviceID confirms §3.2.5 session
// authentication: a disposition whose claimed device_id does not
// match the submitter (the device_id on the session) is rejected.
func TestStagedAuthRejectsMismatchedDeviceID(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	// Submitter (session-bound) is "d-attacker"; the disposition
	// claims to be from "d-spam". §3.2.5 says the server MUST verify
	// the submitting session belongs to the claimed device_id.
	err := h.runner.IngestDisposition(context.Background(), "env-1", "d-attacker",
		disp("env-1", "d-spam", delivery.DispositionSuppress))
	if err == nil {
		t.Error("IngestDisposition accepted mismatched submitter / device_id (§3.2.5 violation)")
	}
}

// TestStagedRejectsOffStageDevice confirms §3.2.5 stage-membership
// rule: a disposition from a device not in the current stage is
// discarded.
func TestStagedRejectsOffStageDevice(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam"}},
		{Stage: 2, PendingDeviceIDs: []string{"d-phone"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	// d-phone is at stage 2 but the current stage is 1.
	err := h.runner.IngestDisposition(context.Background(), "env-1", "d-phone",
		disp("env-1", "d-phone", delivery.DispositionSuppress))
	if err == nil {
		t.Error("IngestDisposition accepted disposition from non-current-stage device")
	}
}

// TestStagedRejectsUnknownEnvelope confirms a disposition for an
// envelope the runner is not holding is rejected.
func TestStagedRejectsUnknownEnvelope(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	err := h.runner.IngestDisposition(context.Background(), "env-ghost", "d-spam",
		disp("env-ghost", "d-spam", delivery.DispositionAdvance))
	if err == nil {
		t.Error("IngestDisposition accepted disposition for unknown envelope")
	}
}

// TestStagedDuplicateDispositionIdempotent confirms a repeat
// submission from the same device is silently dropped (the FIRST
// vote stands; a device cannot retroactively flip suppress to
// advance).
func TestStagedDuplicateDispositionIdempotent(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if err := h.runner.IngestDisposition(context.Background(), "env-1", "d-spam",
		disp("env-1", "d-spam", delivery.DispositionSuppress)); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}
	// Repeat with a different decision; should be a no-op.
	if err := h.runner.IngestDisposition(context.Background(), "env-1", "d-spam",
		disp("env-1", "d-spam", delivery.DispositionAdvance)); err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if _, err := h.runner.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.suppresses) != 1 {
		t.Errorf("suppresses = %v, want 1 (first vote should bind)", h.suppresses)
	}
}

// TestStagedHoldRejectsEmptyPartition confirms a partition with no
// pending devices in any stage is rejected.
func TestStagedHoldRejectsEmptyPartition(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	if err := h.runner.Hold(context.Background(), "env-1", nil); err == nil {
		t.Error("Hold accepted nil partition")
	}
	if err := h.runner.Hold(context.Background(), "env-1", []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: nil},
	}); err == nil {
		t.Error("Hold accepted partition with no pending devices")
	}
}

// TestStagedHoldRejectsNonMonotonicStages confirms an out-of-order
// stage list is rejected.
func TestStagedHoldRejectsNonMonotonicStages(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 2, PendingDeviceIDs: []string{"d-x"}},
		{Stage: 1, PendingDeviceIDs: []string{"d-y"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err == nil {
		t.Error("Hold accepted non-monotonic stage list")
	}
}

// TestStagedHoldRejectsDuplicate confirms the same envelope_id
// cannot be held twice.
func TestStagedHoldRejectsDuplicate(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err != nil {
		t.Fatalf("Hold 1: %v", err)
	}
	err := h.runner.Hold(context.Background(), "env-1", stages)
	if !errors.Is(err, delivery.ErrEnvelopeAlreadyHeld) {
		t.Errorf("Hold duplicate: got %v, want ErrEnvelopeAlreadyHeld", err)
	}
}

// TestStagedSnapshot confirms Snapshot returns a deep copy that is
// independent of the live runner state.
func TestStagedSnapshot(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam"}},
		{Stage: 2, PendingDeviceIDs: []string{"d-phone"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	snap := h.runner.Snapshot()
	if rec, ok := snap["env-1"]; !ok || len(rec.Stages) != 2 {
		t.Fatalf("snapshot missing env-1 or wrong stage count: %+v", snap)
	}
	// Mutate snapshot - live state must NOT change.
	snap["env-1"].Stages[0].PendingDeviceIDs[0] = "tampered"
	live := h.runner.Snapshot()
	if live["env-1"].Stages[0].PendingDeviceIDs[0] != "d-spam" {
		t.Error("snapshot mutation leaked into live state")
	}
}
