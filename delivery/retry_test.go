package delivery_test

import (
	"testing"
	"time"

	"semp.dev/semp-go/delivery"
)

func TestSanitizeRetryClampsToSpecMinima(t *testing.T) {
	cfg := delivery.SanitizeRetry(delivery.RetryConfig{
		InitialInterval: 30 * time.Second, // below floor
		Multiplier:      1.5,               // below floor
		MaxInterval:     12 * time.Hour,    // above ceiling
		JitterFraction:  0.05,              // below floor
	})
	if cfg.InitialInterval != delivery.MinRetryInitialInterval {
		t.Errorf("InitialInterval = %s, want clamped up to %s", cfg.InitialInterval, delivery.MinRetryInitialInterval)
	}
	if cfg.Multiplier != delivery.MinRetryMultiplier {
		t.Errorf("Multiplier = %f, want clamped up to %f", cfg.Multiplier, delivery.MinRetryMultiplier)
	}
	if cfg.MaxInterval != delivery.MaxRetryInterval {
		t.Errorf("MaxInterval = %s, want clamped down to %s", cfg.MaxInterval, delivery.MaxRetryInterval)
	}
	if cfg.JitterFraction != delivery.MinRetryJitterFraction {
		t.Errorf("JitterFraction = %f, want clamped up to %f", cfg.JitterFraction, delivery.MinRetryJitterFraction)
	}
}

func TestBaseIntervalExponentialClampedAtCeiling(t *testing.T) {
	// Default-shape config: 60s initial, 2x multiplier, 6h cap.
	cfg := delivery.RetryConfig{}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 60 * time.Second},
		{1, 120 * time.Second},
		{2, 240 * time.Second},
		{3, 480 * time.Second},
		{4, 960 * time.Second},
		{5, 1920 * time.Second},
		{6, 3840 * time.Second},
		{7, 7680 * time.Second},
		{8, 15360 * time.Second},
		// 8 doublings of 60s = 15360s = 4.27h, still under 6h cap.
		{9, 6 * time.Hour}, // 9th doubling would exceed; clamped to 6h.
		{20, 6 * time.Hour}, // far past saturation, still 6h.
	}
	for _, tc := range cases {
		got := delivery.BaseInterval(cfg, tc.attempt)
		if got != tc.want {
			t.Errorf("BaseInterval(attempt=%d) = %s, want %s", tc.attempt, got, tc.want)
		}
	}
}

func TestJitterIntervalRespectsBounds(t *testing.T) {
	cfg := delivery.RetryConfig{}
	base := 60 * time.Second
	// Repeat to sample the jitter distribution; every draw MUST land
	// within [0.9*base, 1.1*base] AND >= MinJitterFloor (30s).
	for i := 0; i < 100; i++ {
		got, err := delivery.JitterInterval(cfg, base)
		if err != nil {
			t.Fatalf("JitterInterval: %v", err)
		}
		if got < delivery.MinJitterFloor {
			t.Errorf("draw %d: got %s, below floor %s", i, got, delivery.MinJitterFloor)
		}
		// 10% jitter on 60s: realized range [54s, 66s], floored at 30s.
		if got < 54*time.Second || got > 66*time.Second {
			t.Errorf("draw %d: got %s, out of [54s, 66s]", i, got)
		}
	}
}

func TestJitterFloorAppliesOnVerySmallBase(t *testing.T) {
	// A base interval smaller than MinJitterFloor MUST still produce
	// a jittered output >= MinJitterFloor.
	cfg := delivery.RetryConfig{}
	base := 10 * time.Second
	got, err := delivery.JitterInterval(cfg, base)
	if err != nil {
		t.Fatalf("JitterInterval: %v", err)
	}
	if got < delivery.MinJitterFloor {
		t.Errorf("jittered = %s, want >= floor %s", got, delivery.MinJitterFloor)
	}
}

func TestIsRecoverableTruthTable(t *testing.T) {
	cases := []struct {
		code string
		want bool
	}{
		// Recoverable per ERRORS.md §3.
		{"handshake_invalid", true},
		{"handshake_expired", true},
		{"no_session", true},
		{"server_unavailable", true},
		{"rate_limited", true},
		{"server_at_capacity", true},
		// Non-recoverable.
		{"blocked", false},
		{"seal_invalid", false},
		{"session_mac_invalid", false},
		{"envelope_expired", false},
		{"policy_forbidden", false},
		{"auth_failed", false},
		{"version_unsupported", false},
		// Unknown defaults to non-recoverable.
		{"made_up_code", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := delivery.IsRecoverable(tc.code); got != tc.want {
			t.Errorf("IsRecoverable(%q) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

func TestEffectiveDeadlineMin(t *testing.T) {
	queued := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	expires := queued.Add(36 * time.Hour)
	// Default 72h horizon vs 36h expires: expires wins.
	got := delivery.EffectiveDeadline(expires, queued, 0)
	if !got.Equal(expires) {
		t.Errorf("EffectiveDeadline (expires < horizon) = %s, want %s", got, expires)
	}
	// Expires in the far future vs default horizon: horizon wins.
	farFuture := queued.Add(30 * 24 * time.Hour)
	wantHorizon := queued.Add(delivery.DefaultMaxRetryHorizon)
	got = delivery.EffectiveDeadline(farFuture, queued, 0)
	if !got.Equal(wantHorizon) {
		t.Errorf("EffectiveDeadline (horizon < expires) = %s, want %s", got, wantHorizon)
	}
	// Operator-configured 8-day horizon clamps to 7-day cap.
	got = delivery.EffectiveDeadline(farFuture, queued, 8*24*time.Hour)
	wantCap := queued.Add(delivery.MaxRetryHorizonCap)
	if !got.Equal(wantCap) {
		t.Errorf("EffectiveDeadline (oversize horizon) = %s, want %s (clamped)", got, wantCap)
	}
}

func TestQueueStateSetTerminalIdempotent(t *testing.T) {
	q := &delivery.QueueState{State: delivery.QueueStateQueued}
	q.SetTerminal(delivery.QueueStateDelivered)
	if q.State != delivery.QueueStateDelivered {
		t.Errorf("after SetTerminal(delivered): state = %s, want delivered", q.State)
	}
	// Try to override delivered with canceled; MUST NOT change.
	q.SetTerminal(delivery.QueueStateCanceled)
	if q.State != delivery.QueueStateDelivered {
		t.Errorf("override delivered: state = %s, want still delivered", q.State)
	}
}

func TestQueueStateSetTerminalRejectsNonTerminal(t *testing.T) {
	q := &delivery.QueueState{State: delivery.QueueStateQueued}
	q.SetTerminal(delivery.QueueStateQueued) // not a terminal
	if q.State != delivery.QueueStateQueued {
		t.Errorf("SetTerminal(queued) changed state to %s; expected no-op", q.State)
	}
}
