package clockskew_test

import (
	"testing"
	"time"

	"semp.dev/semp-go/clockskew"
)

func TestCheckFutureTimestampAcceptsPastAndNearFuture(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	tol := clockskew.Default()

	cases := []time.Time{
		now.Add(-time.Hour),
		now.Add(-time.Minute),
		now,
		now.Add(time.Minute),
		now.Add(5 * time.Minute),
		now.Add(14 * time.Minute),
		now.Add(15 * time.Minute),
	}
	for _, ts := range cases {
		if err := clockskew.CheckFutureTimestamp(ts, now, tol); err != nil {
			t.Errorf("CheckFutureTimestamp(%s) = %v, want nil", ts, err)
		}
	}
}

func TestCheckFutureTimestampRejectsFarFuture(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	tol := clockskew.Default()

	cases := []time.Time{
		now.Add(16 * time.Minute),
		now.Add(time.Hour),
		now.Add(24 * time.Hour),
	}
	for _, ts := range cases {
		if err := clockskew.CheckFutureTimestamp(ts, now, tol); err == nil {
			t.Errorf("CheckFutureTimestamp(%s) = nil, want error", ts)
		}
	}
}

func TestCheckExpiryAcceptsFutureAndNearPast(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	tol := clockskew.Default()

	cases := []time.Time{
		now.Add(time.Hour),
		now.Add(time.Minute),
		now,
		now.Add(-time.Minute),
		now.Add(-14 * time.Minute),
		now.Add(-15 * time.Minute),
	}
	for _, ts := range cases {
		if err := clockskew.CheckExpiry(ts, now, tol); err != nil {
			t.Errorf("CheckExpiry(%s) = %v, want nil", ts, err)
		}
	}
}

func TestCheckExpiryRejectsFarPast(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	tol := clockskew.Default()

	cases := []time.Time{
		now.Add(-16 * time.Minute),
		now.Add(-time.Hour),
		now.Add(-24 * time.Hour),
	}
	for _, ts := range cases {
		if err := clockskew.CheckExpiry(ts, now, tol); err == nil {
			t.Errorf("CheckExpiry(%s) = nil, want error", ts)
		}
	}
}

func TestCheckExpiryStrictNoGrace(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	tol := clockskew.Strict()

	// Strict mode: any past expiry rejects.
	if err := clockskew.CheckExpiry(now.Add(-time.Second), now, tol); err == nil {
		t.Error("Strict CheckExpiry on -1s: want error")
	}
	if err := clockskew.CheckExpiry(now.Add(time.Second), now, tol); err != nil {
		t.Errorf("Strict CheckExpiry on +1s: want nil, got %v", err)
	}
}

func TestCheckZeroTimestampsRejected(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	tol := clockskew.Default()
	if err := clockskew.CheckFutureTimestamp(time.Time{}, now, tol); err == nil {
		t.Error("CheckFutureTimestamp(zero): want error")
	}
	if err := clockskew.CheckExpiry(time.Time{}, now, tol); err == nil {
		t.Error("CheckExpiry(zero): want error")
	}
}
