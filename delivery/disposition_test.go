package delivery_test

import (
	"testing"
	"time"

	"semp.dev/semp-go/delivery"
)

func TestDispositionValidateAccepts(t *testing.T) {
	good := delivery.Disposition{
		Kind:             delivery.DispositionKind,
		SourceEnvelopeID: "01HF3X7M8N9P0Q1R2S3T4U5V6W",
		Decision:         delivery.DispositionAdvance,
		DeviceID:         "filter-device",
	}
	if err := good.Validate(); err != nil {
		t.Errorf("Validate good: %v", err)
	}
}

func TestDispositionValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		d    delivery.Disposition
	}{
		{"wrong kind", delivery.Disposition{Kind: "other", SourceEnvelopeID: "id", Decision: "advance", DeviceID: "d"}},
		{"missing source", delivery.Disposition{Kind: delivery.DispositionKind, Decision: "advance", DeviceID: "d"}},
		{"missing device", delivery.Disposition{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", Decision: "advance"}},
		{"missing decision", delivery.Disposition{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", DeviceID: "d"}},
		{"bad decision", delivery.Disposition{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", Decision: "maybe", DeviceID: "d"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.d.Validate(); err == nil {
				t.Error("Validate accepted invalid disposition")
			}
		})
	}
}

func TestAggregateDispositionsSuppressWins(t *testing.T) {
	// Per §3.2.3: any suppress wins over any advance.
	dispositions := []delivery.Disposition{
		{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", Decision: delivery.DispositionAdvance, DeviceID: "d1"},
		{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", Decision: delivery.DispositionSuppress, DeviceID: "d2"},
		{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", Decision: delivery.DispositionAdvance, DeviceID: "d3"},
	}
	if got := delivery.AggregateDispositions(dispositions); got != delivery.StageOutcomeSuppress {
		t.Errorf("AggregateDispositions = %s, want suppress", got)
	}
}

func TestAggregateDispositionsAllAdvance(t *testing.T) {
	dispositions := []delivery.Disposition{
		{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", Decision: delivery.DispositionAdvance, DeviceID: "d1"},
		{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", Decision: delivery.DispositionAdvance, DeviceID: "d2"},
	}
	if got := delivery.AggregateDispositions(dispositions); got != delivery.StageOutcomeAdvance {
		t.Errorf("AggregateDispositions = %s, want advance", got)
	}
}

func TestAggregateDispositionsEmpty(t *testing.T) {
	// Per §3.2.4 fail-open on timeout: no dispositions = advance.
	if got := delivery.AggregateDispositions(nil); got != delivery.StageOutcomeAdvance {
		t.Errorf("AggregateDispositions(empty) = %s, want advance (fail-open)", got)
	}
}

func TestStagedHeldStageIsStageComplete(t *testing.T) {
	now := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	deadline := now.Add(30 * time.Second)

	// All pending devices have emitted; complete.
	s := &delivery.StagedHeldStage{
		Stage:            1,
		PendingDeviceIDs: []string{"d1", "d2"},
		Dispositions: []delivery.Disposition{
			{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", Decision: "advance", DeviceID: "d1"},
			{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", Decision: "advance", DeviceID: "d2"},
		},
	}
	if !s.IsStageComplete(now, deadline) {
		t.Error("IsStageComplete with all emitted: want true")
	}

	// Some pending devices haven't emitted; not complete.
	s = &delivery.StagedHeldStage{
		Stage:            1,
		PendingDeviceIDs: []string{"d1", "d2", "d3"},
		Dispositions: []delivery.Disposition{
			{Kind: delivery.DispositionKind, SourceEnvelopeID: "id", Decision: "advance", DeviceID: "d1"},
		},
	}
	if s.IsStageComplete(now, deadline) {
		t.Error("IsStageComplete with pending devices: want false")
	}

	// Timeout reached: complete regardless of pending.
	if !s.IsStageComplete(deadline.Add(time.Second), deadline) {
		t.Error("IsStageComplete after deadline: want true")
	}
}
