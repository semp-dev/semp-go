package closure_test

import (
	"testing"
	"time"

	"semp.dev/semp-go/closure"
	"semp.dev/semp-go/crypto"
)

func newKeypair(t *testing.T) (pub, priv []byte, fp string) {
	t.Helper()
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub, priv, "fp-" + string(pub[:4])
}

func TestClosureRequestRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, fp := newKeypair(t)

	r := &closure.Record{
		Step:               closure.StepRequest,
		UserID:             "alice@example.com",
		RequestedAt:        time.Now().UTC(),
		GracePeriodSeconds: int64(closure.RecommendedGracePeriod.Seconds()),
		IssuedBy:           "01JPRIMARY00000000000000001",
	}
	if err := closure.SignRecord(signer, priv, fp, r); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if r.Signature.Value == "" {
		t.Fatal("Signature.Value not populated")
	}
	if err := closure.VerifyRecord(signer, pub, r); err != nil {
		t.Errorf("VerifyRecord: %v", err)
	}
}

func TestClosureCancelRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, fp := newKeypair(t)

	r := &closure.Record{
		Step:        closure.StepCancel,
		UserID:      "alice@example.com",
		RequestedAt: time.Now().UTC(),
		IssuedBy:    "01JPRIMARY00000000000000001",
		// GracePeriodSeconds may be zero on cancel; the original
		// request's grace period is what matters and is server-side
		// state.
	}
	if err := closure.SignRecord(signer, priv, fp, r); err != nil {
		t.Fatalf("SignRecord (cancel): %v", err)
	}
	if err := closure.VerifyRecord(signer, pub, r); err != nil {
		t.Errorf("VerifyRecord (cancel): %v", err)
	}
}

func TestClosureGracePeriodBounds(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name   string
		grace  time.Duration
		ok     bool
	}{
		{"below minimum (1 day)", 24 * time.Hour, false},
		{"below minimum (6 days)", 6 * 24 * time.Hour, false},
		{"at minimum (7 days)", closure.MinGracePeriod, true},
		{"recommended (30 days)", closure.RecommendedGracePeriod, true},
		{"at maximum (90 days)", closure.MaxGracePeriod, true},
		{"above maximum (91 days)", 91 * 24 * time.Hour, false},
		{"above maximum (1 year)", 365 * 24 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &closure.Record{
				Type:               closure.RecordType,
				Step:               closure.StepRequest,
				Version:            closure.RecordVersion,
				UserID:             "u@x",
				RequestedAt:        now,
				GracePeriodSeconds: int64(tc.grace.Seconds()),
				IssuedBy:           "issuer",
			}
			err := r.Validate()
			if tc.ok && err != nil {
				t.Errorf("got %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}

func TestClosureCancelSkipsGracePeriodValidation(t *testing.T) {
	// A cancel record carries grace_period_seconds = 0 (or any
	// value). Validate must not reject the bound on cancel because
	// the request being canceled already validated.
	r := &closure.Record{
		Type:               closure.RecordType,
		Step:               closure.StepCancel,
		Version:            closure.RecordVersion,
		UserID:             "u@x",
		RequestedAt:        time.Now().UTC(),
		GracePeriodSeconds: 0,
		IssuedBy:           "issuer",
	}
	if err := r.Validate(); err != nil {
		t.Errorf("cancel with zero grace: got %v, want nil", err)
	}
}

func TestClosureValidateRejects(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name string
		r    *closure.Record
	}{
		{"missing user_id", &closure.Record{
			Type: closure.RecordType, Step: closure.StepRequest, Version: closure.RecordVersion,
			RequestedAt: now, GracePeriodSeconds: int64(closure.RecommendedGracePeriod.Seconds()),
			IssuedBy: "issuer",
		}},
		{"missing requested_at", &closure.Record{
			Type: closure.RecordType, Step: closure.StepRequest, Version: closure.RecordVersion,
			UserID: "u", GracePeriodSeconds: int64(closure.RecommendedGracePeriod.Seconds()),
			IssuedBy: "issuer",
		}},
		{"missing issued_by", &closure.Record{
			Type: closure.RecordType, Step: closure.StepRequest, Version: closure.RecordVersion,
			UserID: "u", RequestedAt: now, GracePeriodSeconds: int64(closure.RecommendedGracePeriod.Seconds()),
		}},
		{"unknown step", &closure.Record{
			Type: closure.RecordType, Step: "delete", Version: closure.RecordVersion,
			UserID: "u", RequestedAt: now, GracePeriodSeconds: int64(closure.RecommendedGracePeriod.Seconds()),
			IssuedBy: "issuer",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.r.Validate(); err == nil {
				t.Error("Validate accepted invalid record")
			}
		})
	}
}

func TestClosureTamperBreaksSignature(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, fp := newKeypair(t)
	r := &closure.Record{
		Step:               closure.StepRequest,
		UserID:             "alice@example.com",
		RequestedAt:        time.Now().UTC(),
		GracePeriodSeconds: int64(closure.RecommendedGracePeriod.Seconds()),
		IssuedBy:           "issuer",
	}
	if err := closure.SignRecord(signer, priv, fp, r); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	// Tamper with grace period.
	r.GracePeriodSeconds = int64(closure.MaxGracePeriod.Seconds())
	if err := closure.VerifyRecord(signer, pub, r); err == nil {
		t.Error("VerifyRecord accepted a tampered grace_period_seconds")
	}
}

func TestFinalizationAt(t *testing.T) {
	requested := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	r := &closure.Record{
		Step:               closure.StepRequest,
		UserID:             "u",
		RequestedAt:        requested,
		GracePeriodSeconds: int64((30 * 24 * time.Hour).Seconds()),
		IssuedBy:           "issuer",
	}
	want := requested.Add(30 * 24 * time.Hour)
	if got := r.FinalizationAt(); !got.Equal(want) {
		t.Errorf("FinalizationAt = %s, want %s", got, want)
	}
}

func TestIsFinalizable(t *testing.T) {
	requested := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	r := &closure.Record{
		Step:               closure.StepRequest,
		UserID:             "u",
		RequestedAt:        requested,
		GracePeriodSeconds: int64((30 * 24 * time.Hour).Seconds()),
		IssuedBy:           "issuer",
	}
	finalization := requested.Add(30 * 24 * time.Hour)
	if r.IsFinalizable(finalization.Add(-time.Hour)) {
		t.Error("IsFinalizable an hour before deadline: want false")
	}
	if !r.IsFinalizable(finalization) {
		t.Error("IsFinalizable at exactly the deadline: want true")
	}
	if !r.IsFinalizable(finalization.Add(time.Hour)) {
		t.Error("IsFinalizable an hour after deadline: want true")
	}

	// Cancel records never finalize.
	cancel := *r
	cancel.Step = closure.StepCancel
	if cancel.IsFinalizable(finalization.Add(time.Hour)) {
		t.Error("cancel record should never be finalizable")
	}
}
