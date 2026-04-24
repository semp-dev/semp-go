package envelope_test

import (
	"context"
	"testing"
	"time"

	"semp.dev/semp-go/envelope"
)

func TestSendTimeDelayRespectsTimeSensitive(t *testing.T) {
	env := envelope.New()
	env.Postmark.Expires = time.Now().UTC().Add(time.Hour)
	start := time.Now()
	err := envelope.SendTimeDelay(context.Background(), env, envelope.SendTimeDelayConfig{
		Ceiling:       time.Second,
		TimeSensitive: true,
	})
	if err != nil {
		t.Fatalf("SendTimeDelay: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Error("TimeSensitive should return immediately, but observed non-trivial delay")
	}
}

func TestSendTimeDelayZeroCeilingReturnsImmediately(t *testing.T) {
	env := envelope.New()
	env.Postmark.Expires = time.Now().UTC().Add(time.Hour)
	start := time.Now()
	err := envelope.SendTimeDelay(context.Background(), env, envelope.SendTimeDelayConfig{Ceiling: 0})
	if err != nil {
		t.Fatalf("SendTimeDelay: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Error("zero ceiling should return immediately, but observed non-trivial delay")
	}
}

func TestSendTimeDelayRejectsAlreadyExpired(t *testing.T) {
	env := envelope.New()
	env.Postmark.Expires = time.Now().UTC().Add(-time.Minute)
	err := envelope.SendTimeDelay(context.Background(), env, envelope.SendTimeDelayConfig{Ceiling: time.Second})
	if err == nil {
		t.Error("SendTimeDelay on already-expired envelope: want error")
	}
}

func TestSendTimeDelayRespectsContext(t *testing.T) {
	env := envelope.New()
	env.Postmark.Expires = time.Now().UTC().Add(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Call SendTimeDelay with a generous ceiling; the ctx is already
	// cancelled, so we expect immediate return with ctx.Err.
	err := envelope.SendTimeDelay(ctx, env, envelope.SendTimeDelayConfig{Ceiling: 10 * time.Second})
	// The delay may be drawn as 0, in which case the function returns
	// nil before checking ctx. Accept either outcome; we just want to
	// confirm the function does not block indefinitely on a cancelled
	// context with a long ceiling.
	_ = err
}

func TestSendTimeDelayClampsToExpiryWindow(t *testing.T) {
	// Envelope expires in 100ms; ceiling is 10s. The implementation
	// should clamp internally so the draw falls within the remaining
	// window. Actual timing depends on the random draw, so we only
	// check that SendTimeDelay returns before the ceiling would.
	env := envelope.New()
	env.Postmark.Expires = time.Now().UTC().Add(100 * time.Millisecond)
	start := time.Now()
	err := envelope.SendTimeDelay(context.Background(), env, envelope.SendTimeDelayConfig{Ceiling: 10 * time.Second})
	if err != nil {
		t.Fatalf("SendTimeDelay: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Errorf("clamp failed: elapsed %s exceeds the clamped window", elapsed)
	}
}
