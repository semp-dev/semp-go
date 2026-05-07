package closure_test

import (
	"context"
	"testing"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/closure"
)

// TestRecipientPolicyRejectsClosedAccount confirms an envelope
// addressed to a closed account inside the retention window
// returns AckRejected with reason_code policy_forbidden per §5.1.
func TestRecipientPolicyRejectsClosedAccount(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	d := closure.NewDriver(closure.DriverConfig{
		NowFn:              clk.Now,
		RetainFinalizedFor: 365 * 24 * time.Hour,
	})
	_ = d.Submit(context.Background(), requestRecord("alice@example.com", t0, 7*24*time.Hour))
	clk.Set(t0.Add(8 * 24 * time.Hour))
	if _, err := d.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	policy := d.RecipientPolicy(closure.RecipientPolicyOptions{NowFn: clk.Now})
	ack, code, _ := policy(context.Background(), brief.Address("alice@example.com"))
	if ack != semp.AckRejected {
		t.Errorf("ack = %s, want AckRejected", ack)
	}
	if code != semp.ReasonPolicyForbidden {
		t.Errorf("code = %s, want policy_forbidden", code)
	}
}

// TestRecipientPolicySilentVariant confirms the operator can opt
// into the §5.1 silent-acknowledgment posture.
func TestRecipientPolicySilentVariant(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	d := closure.NewDriver(closure.DriverConfig{
		NowFn:              clk.Now,
		RetainFinalizedFor: 365 * 24 * time.Hour,
	})
	_ = d.Submit(context.Background(), requestRecord("alice@example.com", t0, 7*24*time.Hour))
	clk.Set(t0.Add(8 * 24 * time.Hour))
	if _, err := d.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	policy := d.RecipientPolicy(closure.RecipientPolicyOptions{
		NowFn:                   clk.Now,
		UseSilentAcknowledgment: true,
	})
	ack, code, _ := policy(context.Background(), brief.Address("alice@example.com"))
	if ack != semp.AckSilent {
		t.Errorf("ack = %s, want AckSilent", ack)
	}
	if code != "" {
		t.Errorf("silent should not carry a reason_code, got %s", code)
	}
}

// TestRecipientPolicyPassesActiveAccount confirms an active
// account returns ("", "", "") so the envelope falls through to
// the rest of the pipeline (block-list, inbox).
func TestRecipientPolicyPassesActiveAccount(t *testing.T) {
	d := closure.NewDriver(closure.DriverConfig{})
	policy := d.RecipientPolicy(closure.RecipientPolicyOptions{})
	ack, code, _ := policy(context.Background(), brief.Address("alice@example.com"))
	if ack != "" || code != "" {
		t.Errorf("active account: ack=%s code=%s, want empty", ack, code)
	}
}

// TestRecipientPolicyPassesPostRetention confirms an account whose
// retention window has elapsed (per §6.2 the local-part MAY be
// reassigned) is no longer flagged.
func TestRecipientPolicyPassesPostRetention(t *testing.T) {
	t0 := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	clk := newFakeClock(t0)
	d := closure.NewDriver(closure.DriverConfig{
		NowFn:              clk.Now,
		RetainFinalizedFor: 180 * 24 * time.Hour,
	})
	_ = d.Submit(context.Background(), requestRecord("alice@example.com", t0, 7*24*time.Hour))
	clk.Set(t0.Add(8 * 24 * time.Hour))
	if _, err := d.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	// Advance past retention.
	clk.Set(clk.Now().Add(200 * 24 * time.Hour))
	policy := d.RecipientPolicy(closure.RecipientPolicyOptions{NowFn: clk.Now})
	ack, _, _ := policy(context.Background(), brief.Address("alice@example.com"))
	if ack != "" {
		t.Errorf("post-retention: ack = %s, want empty (account may be reassigned)", ack)
	}
}
